# PwMrg — Password Manager Hotkey Helper & GUI

A tiny Windows-only toolkit that lets you assign global hotkeys to auto‑type credentials into the focused window — plus a lightweight GUI to manage entries and a master password. fileciteturn0file0 fileciteturn0file1

---

## What’s inside

- **PwMrgSetup.pyw** — a simple management app (GUI) built with customtkinter. It stores a master‑password verifier and your accounts in the system keyring. Master passwords are checked via **scrypt**; accounts live in a JSON config. fileciteturn0file1  
- **PwMrg.pyw** — a tray app that reads that config, registers **global hotkeys** via the Win32 API, and auto‑types username → Tab → password (optionally **Enter**). It can also run external commands. fileciteturn0file0

> **Platform:** Windows only (uses RegisterHotKey, SendInput, and a message loop). fileciteturn0file0

---

## Features

- **Master password (scrypt‑protected)** with stored salt + parameters. fileciteturn0file1  
- **Secure-ish storage** via the OS keyring for both the admin record and the app config. fileciteturn0file1  
- **Account editor**: add/edit/remove entries, toggle “send Enter”, assign a hotkey (CTRL/ALT/SHIFT + key). fileciteturn0file1  
- **Global hotkeys** with fallback if ALT is blocked (auto‑swap to SHIFT on conflict). fileciteturn0file0  
- **Tray menu**: open the GUI, reload config, quit. fileciteturn0file0

---

## How it works

1. **GUI (PwMrgSetup.pyw)**  
   - On first run you create a master password; later starts ask for it.  
   - The app stores two keyring entries under service **“PwMrg”**:  
     - `admin` — base64‑encoded scrypt hash + parameters + salt.  
     - `config` — JSON with settings and accounts. fileciteturn0file1
2. **Tray app (PwMrg.pyw)**  
   - Loads the `config` from keyring, extracts hotkeys, and registers them on a background thread.  
   - When a hotkey fires, it types **username → Tab → password → [Enter]** into the active window. fileciteturn0file0

---

## Security notes (read this)

- The **master password** uses scrypt (default n=16384, r=8, p=1, dkLen=32) and is verified against the stored parameters. fileciteturn0file1  
- The **config currently stores plaintext passwords** in the keyring blob; if you need confidentiality, encrypt the config with a key derived from the master password (not implemented here). fileciteturn0file1  
- Auto‑typing passwords into whichever window is focused is convenient but **inherently risky**. Only use in a trusted local session. fileciteturn0file0

---

## Requirements

- **Windows 10/11** (Win32 RegisterHotKey + SendInput). fileciteturn0file0  
- **Python 3.8+**. fileciteturn0file1  
- Packages: `customtkinter`, `keyring`, `infi.systray`. (Plus stdlib modules used by the code.) fileciteturn0file0 fileciteturn0file1

Install the packages:

```bash
pip install customtkinter keyring infi.systray
```

---

## Quick start

1. **Open the manager GUI** to set a master password and create accounts:

```bash
python PwMrgSetup.pyw
```

- Each account has: `id`, `username`, `password`, `send_enter`, and a `hotkey` (modifiers + key).  
- Valid hotkey keys: **A–Z, 0–9, Tab, Enter**; modifiers: **CTRL, ALT, SHIFT**. The Windows key isn’t supported. fileciteturn0file1

2. **Run the tray helper** to enable global hotkeys:

```bash
python PwMrg.pyw
```

- Tray menu → **“Verwaltung öffnen”** launches the GUI; **“Aktualisieren”** reloads the config and re‑registers hotkeys. fileciteturn0file0

---

## Configuration format

Stored under keyring service **`PwMrg`**, entry **`config`** (JSON). Example: fileciteturn0file1 fileciteturn0file0

```json
{
  "version": 1,
  "logging": true,
  "accounts": [
    {
      "id": "mail",
      "username": "user@example.com",
      "password": "secret",
      "send_enter": true,
      "hotkey": { "modifiers": ["CTRL", "ALT"], "key": "H" }
    }
  ]
}
```

> The tray app converts each account’s `hotkey` into an internal list and registers it with the OS. fileciteturn0file0

---

## Troubleshooting

- **Hotkey won’t register:** Some combos are reserved; if **ALT** is blocked the app will try a **SHIFT** fallback automatically. Check the log output in the console. fileciteturn0file0  
- **Nothing is typed:** Ensure the target app has focus and that `send_enter` is set if you need automatic submit. fileciteturn0file0  
- **Appearance issues (GUI):** The manager adjusts its Treeview styling to match light/dark mode; if colors look off, toggle your appearance setting and re‑open. fileciteturn0file1

---

## Roadmap ideas

- Optional **encrypted config** using a key from the master password. fileciteturn0file1  
- Cross‑platform hotkeys via a dedicated library. fileciteturn0file1

---

## License

Add your preferred license here.
