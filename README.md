<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=200&section=header&text=Toggle&fontSize=80&fontColor=10b981&animation=twinkling&fontAlignY=38&desc=Password%20Manager&descAlignY=62&descSize=22&descColor=a7f3d0" alt="Toggle Password Manager Banner" />
</p>

<p align="center">
  <svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" viewBox="0 0 24 24" fill="none">
    <defs>
      <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#10b981"/>
        <stop offset="100%" stop-color="#059669"/>
      </linearGradient>
    </defs>
    <path fill="url(#shieldGrad)" d="M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4zm0 4a3 3 0 013 3c0 1.3-.84 2.4-2 2.82V15a1 1 0 11-2 0v-3.18A3.001 3.001 0 0112 6z"/>
  </svg>
</p>

<h1 align="center">Toggle Password Manager</h1>

<p align="center">
  <strong>Privacy-first · Zero-Knowledge · Local-First · Open Source</strong>
</p>

<p align="center">
  <a href="#features"><img src="https://img.shields.io/badge/AES--256--GCM-Encrypted-10b981?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyTDMgNnY2YzAgNS41NSAzLjg0IDEwLjc0IDkgMTIgNS4xNi0xLjI2IDktNi40NSA5LTEyVjZsLTktNHoiLz48L3N2Zz4=&labelColor=0f172a" alt="AES-256-GCM Badge" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Zero_Knowledge-No_Cloud-10b981?style=for-the-badge&logo=shield&logoColor=white&labelColor=0f172a" alt="Zero Knowledge" /></a>
  <a href="#"><img src="https://img.shields.io/badge/PBKDF2--SHA256-600K_Rounds-10b981?style=for-the-badge&logo=lock&logoColor=white&labelColor=0f172a" alt="PBKDF2" /></a>
  <a href="#"><img src="https://img.shields.io/badge/PWA-Installable-10b981?style=for-the-badge&logo=pwa&logoColor=white&labelColor=0f172a" alt="PWA" /></a>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-a7f3d0?style=flat-square&labelColor=0f172a" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Tests-48%20Passed-10b981?style=flat-square&labelColor=0f172a" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Version-1.0.0-6366f1?style=flat-square&labelColor=0f172a" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Node.js-20+-339933?style=flat-square&logo=node.js&logoColor=white&labelColor=0f172a" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Web_PWA-0ea5e9?style=flat-square&labelColor=0f172a" /></a>
</p>

<br/>

<p align="center">
  <a href="http://127.0.0.1:4242">
    <img src="https://img.shields.io/badge/▶%20Launch%20Locally-http%3A%2F%2F127.0.0.1%3A4242-10b981?style=for-the-badge&labelColor=0f172a" alt="Launch" />
  </a>
</p>

---

## 📖 Overview

> **Toggle** is a fully local, open-source password manager built as a direct alternative to Google Password Manager. Your credentials never leave your device. There is no server, no cloud sync, no telemetry — just pure, military-grade AES-256-GCM encryption in your browser.

<br/>

```
┌─────────────────────────────────────────────────────────┐
│                    YOUR DEVICE ONLY                     │
│                                                         │
│   ┌──────────┐    AES-256-GCM    ┌──────────────────┐  │
│   │  Master  │ ──────────────►  │   Encrypted      │  │
│   │Password  │   PBKDF2-SHA256  │  IndexedDB Vault │  │
│   └──────────┘   600k rounds    └──────────────────┘  │
│                                                         │
│   ✗ No Cloud   ✗ No API calls   ✗ No Telemetry         │
└─────────────────────────────────────────────────────────┘
```

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔒 Security
- **AES-256-GCM** end-to-end vault encryption
- **PBKDF2-SHA256** with 600,000 key-stretching iterations
- **Zero-Knowledge** — master password never stored
- **Biometric Unlock** via WebAuthn / Windows Hello / Face ID
- **Auto-lock** after inactivity with configurable timeout
- **Live Breach Scanning** via k-Anonymity HIBP API
- **12-word Emergency Recovery Kit** for vault restoration

</td>
<td width="50%">

### 🎯 Productivity
- **Real-time 2FA / TOTP** authenticator (RFC 6238) with live countdown
- **Password Generator** with custom length, symbols, passphrase modes
- **Real-time Strength Meter** with crack time estimates
- **Google CSV Import/Export** — 1-click migration
- **Google-style Security Checkup** — weak, reused, compromised detection
- **Keyboard Shortcuts** — `Ctrl+K` search, `Ctrl+L` lock, `Esc` close
- **Dark / Light Theme** toggle with persistence

</td>
</tr>
<tr>
<td width="50%">

### 🗃️ Vault Categories
- 🔑 **Logins** — URL, username, password, TOTP
- 🪪 **Passkeys** — WebAuthn credential store
- 💳 **Credit Cards** — formatted, brand-detected
- 🏠 **Addresses** — full postal records
- 🔐 **API Keys** — with environment & expiry tracking
- 📝 **Secure Notes** — rich freeform text
- 🗑️ **Trash & Restore** — soft-delete lifecycle

</td>
<td width="50%">

### 🌐 Platform
- **Progressive Web App** — installable on any OS
- **Service Worker** offline support
- **No dependencies** — pure HTML/CSS/JS + Node.js dev server
- **48 automated tests** — crypto, generator, security, import/export
- **Print-ready Emergency Kit** — A4 PDF recovery sheet
- **QR Code generation** for credentials
- **Password History** — tracks previous passwords per item

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- [Node.js](https://nodejs.org/) v20 or later

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/toggle-password-manager.git
cd toggle-password-manager

# Start the development server
npm run dev
```

Then open your browser and navigate to:

```
http://127.0.0.1:4242
```

> **Tip:** You can install Toggle as a PWA by clicking the install icon in your browser's address bar for a native app-like experience.

---

## 🏗️ Architecture

```
toggle-password-manager/
│
├── 📄 index.html               # Single-page application shell
├── 🖥️  server.js               # Lightweight static dev server
├── ⚙️  manifest.json            # PWA manifest
├── 🔧  sw.js                   # Service worker (offline support)
│
├── 📁 js/
│   ├── app.js                  # Main application controller (~2500 lines)
│   ├── crypto.js               # AES-256-GCM + PBKDF2 engine
│   ├── storage.js              # IndexedDB vault persistence
│   ├── generator.js            # Password & passphrase generator
│   ├── security.js             # Google-style security checkup
│   ├── totp.js                 # RFC 6238 TOTP authenticator engine
│   ├── importer.js             # Google CSV import/export
│   └── ui.js                   # UI utilities, toasts, QR codes
│
├── 📁 styles/
│   ├── theme.css               # CSS custom properties & tokens
│   ├── components.css          # Reusable UI components
│   └── main.css                # Vault & layout styles
│
└── 📁 test/
    └── verify.js               # 48 automated test suites
```

---

## 🔐 Security Model

<p align="center">

```
                    TOGGLE SECURITY ARCHITECTURE
                    ════════════════════════════

  User Input          Derivation              Storage
  ──────────          ──────────              ───────
  
  Master            ┌─────────────┐         ┌────────────────┐
  Password  ──────► │  PBKDF2     │ ──────► │ AES-256-GCM    │
                    │  SHA-256    │  Key    │ Encrypted Blob │
  Random Salt ────► │  600k iter  │         │ in IndexedDB   │
  (16 bytes)        └─────────────┘         └────────────────┘
                                                    │
  Biometric ──────► WebAuthn Key Wrap ─────────────►│ (optional)
                                                    │
                    ← Decrypted only in RAM ─────────┘
                      Never written to disk
```

</p>

| Property | Value |
|---|---|
| **Cipher** | AES-256-GCM (AEAD — authenticated encryption) |
| **KDF** | PBKDF2-SHA256 |
| **Iterations** | 600,000 (OWASP 2024 recommended minimum) |
| **Salt** | 16 bytes, cryptographically random per vault |
| **IV** | 12 bytes, random per encryption operation |
| **Key Storage** | RAM only — never persisted in plaintext |
| **Biometric** | WebAuthn-wrapped key via platform authenticator |
| **Recovery** | 12-word BIP39-style mnemonic phrase |
| **Breach Detection** | k-Anonymity (only first 5 chars of SHA-1 sent) |

---

## 🔑 TOTP / 2FA Authenticator

Toggle includes a **built-in RFC 6238 TOTP authenticator** — no separate app needed.

```
  ┌─────────────────────────────────────────────────┐
  │  🔐 GitHub                        [copy] [lock] │
  │  user@example.com                               │
  │                                                 │
  │  ●●●●●●●●●●●●  [👁]  [ 4 8 3 9 1 2 ]  ◕ 18s  │
  └─────────────────────────────────────────────────┘
```

- Accepts **raw Base32 secrets** or **`otpauth://`** URI format
- Live **countdown circle** with color-coded urgency (safe → warning → danger)
- **One-tap copy** from vault cards or edit drawer
- Codes auto-refresh every second

---

## 🧪 Running Tests

```bash
npm test
```

**Expected output:**

```
🔒 --- 1. Testing CryptoEngine (AES-256-GCM & PBKDF2) ---
  ✓ PASS: Random salt generation produces 16 bytes
  ✓ PASS: Derives valid AES-GCM CryptoKey from master password
  ✓ PASS: Encrypted payload produces ciphertext Base64 and IV Hex
  ...

🎲 --- 2. Testing GeneratorEngine & Strength Meter ---
🛡️ --- 3. Testing SecurityEngine (Google-style Checkup) ---
📂 --- 4. Testing ImportExportEngine (Google Chrome CSV) ---
💳 --- 5. Testing Category Schemas & Trash Lifecycle ---
🔑 --- 6. Testing Phase 3: Biometrics, k-Anonymity HIBP, and Emergency Kit ---

========================================
Verification Complete: 48 Passed, 0 Failed
========================================
```

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + K` | Open search |
| `Ctrl + L` | Lock vault immediately |
| `/` | Quick slash search |
| `Esc` | Close panels & modals |

---

## 📦 Import & Export

Toggle is **100% compatible** with Google Chrome's password export format.

```bash
# Google Chrome export → Settings → Passwords → Export
# Then drag-and-drop the .csv into Toggle's Import screen
```

Supported formats:
- ✅ **Google Chrome CSV** (import & export)
- ✅ **Toggle JSON** (full vault backup with all fields)

---

## 🌗 Theme Support

Toggle supports both **Dark** (default) and **Light** modes, with instant toggling and persistence across sessions via `localStorage`.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=100&section=footer&animation=twinkling" alt="Footer" />
</p>

<p align="center">
  <sub>Built with ❤️ by Toggle Security · Zero-knowledge · Local-first · Open source</sub>
</p>
