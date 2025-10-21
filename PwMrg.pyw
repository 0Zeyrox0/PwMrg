# -*- coding: utf-8 -*-
"""
PwMrg - Password Manager Hotkey Helper (module docstring)
Summary
-------
This module implements a small Windows-only tray application that:
- Loads a JSON-like configuration stored via the system keyring.
- Extracts account entries and associated hotkeys from the configuration.
- Registers global system hotkeys using the Win32 RegisterHotKey API on a dedicated thread.
- When a hotkey is pressed, types the configured username/password into the currently focused window
    (optionally pressing Enter), or runs an external command.
High-level components
---------------------
- Configuration:
    - Stored as a JSON string retrieved with keyring.get_password(SERVICE, CONFIG_KEY).
    - Expected top-level keys: "logging" (bool) and "accounts" (list).
    - Account entries may contain: id, username, password, send_enter, hotkey (with key + modifiers).
    - extract_hotkeys_from_config() converts legacy account.hotkey entries into a unified hotkey/action list.
- Hotkey parsing and registration:
    - parse_hotkey_string(keys) accepts a hotkey expressed as a string like "CTRL+ALT+T" or a list of parts.
    - Recognized modifiers: CTRL/CONTROL, ALT, SHIFT, WIN/WINKEY/GUI.
    - A mapping VK_CODE provides virtual-key codes for letters, digits, function keys and arrows.
    - Hotkeys are registered on a background HotkeyManager thread which:
        - Creates a Windows message queue for itself.
        - Registers hotkeys and listens for WM_HOTKEY messages.
        - Supports reloading the set of hotkeys via a posted WM_RELOAD message.
        - Unregisters all hotkeys cleanly on shutdown or reload.
        - Implements a fallback (replacing ALT with SHIFT) if RegisterHotKey fails with ALT-specific conflicts.
- Input simulation:
    - Uses SendInput to emit keyboard events.
    - type_text() sends text as unicode scan codes (KEYEVENTF_UNICODE).
    - press_vk() sends virtual-key down/up events.
    - execute_account() orchestrates typing username, TAB, password and optional ENTER with a short delay buffer.
- Tray integration:
    - Uses infi.systray.SysTrayIcon to provide a system tray menu with options:
        - Open management GUI (PwMrgSetup.pyw, if present)
        - Reload configuration
        - Quit (stops the HotkeyManager and exits)
    - main() initializes logging, starts the HotkeyManager, loads and sets hotkeys, and runs the tray loop.
Important notes and limitations
-------------------------------
- Platform: Windows only. This module directly calls Win32 APIs via ctypes and depends on message-loop semantics.
- Security: Account passwords are retrieved from the system keyring and then typed into the currently focused application.
    This approach is inherently less secure than sending credentials over an authenticated channel — ensure you trust the active desktop session.
- Dependencies: infi.systray (tray icon), keyring (secure storage). These must be installed in the Python environment.
- Permissions: RegisterHotKey typically does not require elevation, but some global hotkeys may be reserved or conflict with system shortcuts.
- Threading: Hotkeys are handled on a dedicated daemon thread. Posting WM_RELOAD/WM_QUIT_THR is used to control that thread.
- Error handling: The module logs errors and uses a fallback for certain ALT registration conflicts (common with older Windows shells).
Usage examples
--------------
- Configure accounts in the keyring with a JSON structure containing accounts with hotkey fields, e.g.:
    {"logging": true, "accounts": [{"id": "mail", "username": "user", "password": "pw", "send_enter": true,
        "hotkey": {"key": "T", "modifiers": ["CTRL","ALT"]}}]}
- Run the script on Windows. Use the tray icon to reload configuration or open the management UI.
API (selected symbols)
----------------------
- load_config() -> bool: Loads configuration from keyring into internal _config.
- extract_hotkeys_from_config(cfg: dict) -> list: Converts config accounts into hotkey/action descriptors.
- parse_hotkey_string(keys) -> (mods:int, vk:int, label:str): Parse human-readable hotkey specification.
- HotkeyManager (thread): start(), set_hotkeys_and_reload(hotkey_list), stop()
- handle_hotkey(payload): Execute action described by a registered hotkey payload.
- main(): Start the tray app and hotkey manager.
Logging
-------
- Controlled by ENABLE_LOG and the "logging" key in the stored configuration.
- log(msg) emits timestamped messages to stdout.
"""
# Hauptscript: Tray, Hotkeys, Aktualisieren, Start der Verwaltung
import sys, os, json, subprocess, time, ctypes, threading
from ctypes import wintypes
from infi.systray import SysTrayIcon
import keyring

# ---------------- Basis-Setup ----------------
SERVICE   = "PwMrg"
CONFIG_KEY= "config"
ICON_PATH = "icon.ico"
APP_NAME  = "PwMrg"

ENABLE_LOG = True

# ---------------- Win32 (mit Fehlercode-Unterstützung) ----------------
user32   = ctypes.WinDLL("user32",   use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

WM_HOTKEY   = 0x0312
WM_APP      = 0x8000
WM_RELOAD   = WM_APP + 1
WM_QUIT_THR = WM_APP + 2

PM_NOREMOVE = 0x0000  # PeekMessage zum Anlegen der Thread-Message-Queue

MOD_ALT      = 0x0001
MOD_CONTROL  = 0x0002
MOD_SHIFT    = 0x0004
MOD_WIN      = 0x0008
MOD_NOREPEAT = 0x4000

# Pointerbreite für WPARAM/LPARAM/LRESULT
PTR_64 = ctypes.sizeof(ctypes.c_void_p) == 8
if PTR_64:
    WPARAM  = ctypes.c_uint64
    LPARAM  = ctypes.c_int64
    LRESULT = ctypes.c_int64
else:
    WPARAM  = ctypes.c_uint32
    LPARAM  = ctypes.c_int32
    LRESULT = ctypes.c_long

# Virtuelle Keycodes
VK_CODE = {c: ord(c) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}
VK_CODE.update({
    "F1":0x70,"F2":0x71,"F3":0x72,"F4":0x73,"F5":0x74,"F6":0x75,"F7":0x76,"F8":0x77,"F9":0x78,"F10":0x79,"F11":0x7A,"F12":0x7B,
    "TAB":0x09,"ENTER":0x0D,"SPACE":0x20,"BACKSPACE":0x08,
    "LEFT":0x25,"UP":0x26,"RIGHT":0x27,"DOWN":0x28,
})

VK_TAB    = 0x09
VK_RETURN = 0x0D

# Prototypen
user32.RegisterHotKey.restype  = wintypes.BOOL
user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
user32.UnregisterHotKey.restype  = wintypes.BOOL
user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetMessageW.restype  = ctypes.c_int
user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.PostThreadMessageW.restype  = wintypes.BOOL
user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, WPARAM, LPARAM]
user32.PeekMessageW.restype = wintypes.BOOL
user32.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT]
kernel32.GetCurrentThreadId.restype = wintypes.DWORD

def log(msg):
    if ENABLE_LOG:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts} {msg}", flush=True)

def _last_error():
    return ctypes.get_last_error()

def _explain_win_error(code):
    if code == 1409:
        return "ERROR_HOTKEY_ALREADY_REGISTERED"
    try:
        buf = ctypes.create_unicode_buffer(512)
        n = kernel32.FormatMessageW(0x00001000, None, code, 0, buf, len(buf), None)
        if n:
            return buf.value.strip()
    except Exception:
        pass
    return "unbekannter Fehler"

# ---------------- SendInput – Tastatureingaben ----------------
INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
INPUT_HARDWARE = 2
KEYEVENTF_KEYUP   = 0x0002
KEYEVENTF_UNICODE = 0x0004

# Fix für Python-Versionen ohne wintypes.ULONG_PTR
if not hasattr(wintypes, "ULONG_PTR"):
    if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_uint64):
        wintypes.ULONG_PTR = ctypes.c_uint64
    else:
        wintypes.ULONG_PTR = ctypes.c_uint32

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long), ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", wintypes.ULONG_PTR)]
class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", wintypes.ULONG_PTR)]
class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]
class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]
class INPUT(ctypes.Structure):
    _anonymous_ = ("U",)
    _fields_ = [("type", wintypes.DWORD), ("U", _INPUTUNION)]

user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
user32.SendInput.restype  = wintypes.UINT

def press_vk(vk):
    down = INPUT(type=INPUT_KEYBOARD, U=_INPUTUNION(ki=KEYBDINPUT(wVk=vk)))
    up   = INPUT(type=INPUT_KEYBOARD, U=_INPUTUNION(ki=KEYBDINPUT(wVk=vk, dwFlags=KEYEVENTF_KEYUP)))
    user32.SendInput(1, ctypes.byref(down), ctypes.sizeof(INPUT))
    user32.SendInput(1, ctypes.byref(up),   ctypes.sizeof(INPUT))

def type_text(txt):
    for ch in txt:
        scan = ord(ch)
        down = INPUT(type=INPUT_KEYBOARD, U=_INPUTUNION(ki=KEYBDINPUT(wVk=0, wScan=scan, dwFlags=KEYEVENTF_UNICODE)))
        up   = INPUT(type=INPUT_KEYBOARD, U=_INPUTUNION(ki=KEYBDINPUT(wVk=0, wScan=scan, dwFlags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)))
        user32.SendInput(1, ctypes.byref(down), ctypes.sizeof(INPUT))
        user32.SendInput(1, ctypes.byref(up),   ctypes.sizeof(INPUT))

def execute_account(acc):
    try:
        time.sleep(0.8)  # kurzer Fokus-Puffer
        type_text(acc.get("username", ""))
        press_vk(VK_TAB)
        type_text(acc.get("password", ""))
        if acc.get("send_enter", False):
            press_vk(VK_RETURN)
    except Exception as e:
        log(f"Aktionsfehler: {e}")

# ---------------- Config ----------------
_config = {"logging": True, "accounts": []}

def load_config():
    global _config, ENABLE_LOG
    try:
        raw = keyring.get_password(SERVICE, CONFIG_KEY)
        if raw:
            _config = json.loads(raw)
        ENABLE_LOG = bool(_config.get("logging", True))
        return True
    except Exception as e:
        log(f"Config laden fehlgeschlagen: {e}")
        return False

# ---------------- Hotkey-Parsing ----------------
def parse_hotkey_string(keys):
    if isinstance(keys, str):
        parts = [p.strip().upper() for p in keys.replace("+", " ").split()]
    else:
        parts = [str(p).strip().upper() for p in keys]

    mods = MOD_NOREPEAT
    vk = None
    human = []

    for p in parts:
        if p in ("CTRL","CONTROL"):
            mods |= MOD_CONTROL; human.append("CTRL")
        elif p == "ALT":
            mods |= MOD_ALT; human.append("ALT")
        elif p == "SHIFT":
            mods |= MOD_SHIFT; human.append("SHIFT")
        elif p in ("WIN","WINKEY","GUI"):
            mods |= MOD_WIN; human.append("WIN")
        else:
            if p in VK_CODE:
                vk = VK_CODE[p]; human.append(p)
            elif len(p) == 1:
                ch = p.upper()
                vk = ord(ch); human.append(ch)
            else:
                raise ValueError(f"Unbekannte Taste: {p}")

    if vk is None:
        raise ValueError("Keine Haupttaste gefunden")

    label = "+".join(human)
    return mods, vk, label

# ---------------- Config-Adapter: accounts[*].hotkey -> neuer Eintrag ----------------
def extract_hotkeys_from_config(cfg: dict):
    result = []
    for acc in cfg.get("accounts", []):
        hk = acc.get("hotkey") or {}
        key = (hk.get("key") or "").strip().upper()
        mods_list = [m.strip().upper() for m in hk.get("modifiers", []) if isinstance(m, str)]
        if key and (mods_list or key):
            parts = [*mods_list, key]
            keys_str = "+".join(parts)
            result.append({
                "name": acc.get("id") or acc.get("username") or "Eintrag",
                "keys": keys_str,
                "action": {
                    "type": "entry",
                    "id": acc.get("id"),
                    "username": acc.get("username"),
                    "password": acc.get("password"),
                    "send_enter": bool(acc.get("send_enter", False))
                }
            })
    return result

# ---------------- Hotkey-Thread ----------------
class HotkeyManager(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.thread_id = None
        self._next_id = 1
        self._registered = {}   # id -> {"mods":int,"vk":int,"name":str,"payload":dict}
        self._pending_hotkeys = []  # neuer Stand aus Config
        self._lock = threading.Lock()

    def run(self):
        self.thread_id = kernel32.GetCurrentThreadId()
        log(f"Hotkey-Thread gestartet. TID={self.thread_id}")

        # Message-Queue anlegen
        dummy = wintypes.MSG()
        user32.PeekMessageW(ctypes.byref(dummy), None, 0, 0, PM_NOREMOVE)

        # Erstregistrierung
        self._apply_pending_hotkeys()

        msg = wintypes.MSG()
        while True:
            res = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if res == 0 or res == -1:
                break

            if msg.message == WM_HOTKEY:
                hkid = int(msg.wParam)
                data = self._registered.get(hkid)
                if data:
                    log(f"Empfangen: {data.get('name')}")
                    handle_hotkey(data.get("payload"))
                else:
                    log(f"WM_HOTKEY für unbekannte ID: {hkid}")
            elif msg.message == WM_RELOAD:
                self._apply_pending_hotkeys()
            elif msg.message == WM_QUIT_THR:
                break

            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        self._unregister_all()
        log("Hotkey-Thread beendet.")

    def _unregister_all(self):
        for hkid in list(self._registered.keys()):
            try:
                user32.UnregisterHotKey(None, hkid)
            except Exception:
                pass
        for hkid in range(1, max(self._next_id, 2)):
            try:
                user32.UnregisterHotKey(None, hkid)
            except Exception:
                pass
        self._registered.clear()
        self._next_id = 1

    def _register_one(self, mods, vk, name, payload):
        hkid = self._next_id
        self._next_id += 1

        ok = user32.RegisterHotKey(None, hkid, mods, vk)
        if not ok:
            err = _last_error()
            log(f"Registrierung fehlgeschlagen: {name} (Mods={mods}, VK={vk}) Code={err} {_explain_win_error(err)}")
            if err == 1409 and (mods & MOD_ALT):
                fallback_mods = (mods & ~MOD_ALT) | MOD_SHIFT
                fb_label = name.replace("ALT", "SHIFT")
                ok2 = user32.RegisterHotKey(None, hkid, fallback_mods, vk)
                if ok2:
                    self._registered[hkid] = {"mods": fallback_mods, "vk": vk, "name": fb_label, "payload": payload}
                    log(f"Fallback genutzt: {fb_label}")
                    return True
            return False

        self._registered[hkid] = {"mods": mods, "vk": vk, "name": name, "payload": payload}
        log(f"Registriert: {name}")
        return True

    def _apply_pending_hotkeys(self):
        with self._lock:
            hotkeys = list(self._pending_hotkeys)
            self._pending_hotkeys.clear()

        self._unregister_all()

        any_fail = False
        for hk in hotkeys:
            try:
                keys = hk.get("keys") or hk.get("key") or hk.get("hotkey")
                mods, vk, label = parse_hotkey_string(keys)
                name = hk.get("name") or label
                if not self._register_one(mods, vk, name, hk):
                    any_fail = True
            except Exception as e:
                any_fail = True
                log(f"Registrierung fehlgeschlagen (Parsing): {e}")

        if not hotkeys:
            log("Hinweis: In der Config wurden keine Hotkeys gefunden.")
        elif any_fail:
            log("Mind. ein Hotkey nicht registriert.")
        else:
            names = ", ".join(h.get("keys") or h.get("key") or h.get("hotkey") for h in hotkeys)
            log(f"Hotkeys registriert: {names}")

    def set_hotkeys_and_reload(self, hotkey_list):
        with self._lock:
            self._pending_hotkeys = list(hotkey_list or [])
        if self.thread_id:
            user32.PostThreadMessageW(self.thread_id, WM_RELOAD, 0, 0)

    def stop(self):
        if self.thread_id:
            user32.PostThreadMessageW(self.thread_id, WM_QUIT_THR, 0, 0)

# ---------------- Aktionen bei Hotkey ----------------
def handle_hotkey(payload):
    action = (payload or {}).get("action") or {}
    a_type = action.get("type")
    if a_type == "entry":
        # direkt aus payload tippen (aus Config)
        execute_account({
            "username": action.get("username", ""),
            "password": action.get("password", ""),
            "send_enter": action.get("send_enter", False)
        })
        log(f"Hotkey-Aktion: entry id={action.get('id')}, user={action.get('username')}, send_enter={bool(action.get('send_enter', False))}")
    elif a_type == "run":
        cmd = action.get("cmd")
        if cmd:
            try:
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                log(f"Aktion run fehlgeschlagen: {e}")
    else:
        log(f"Unbekannte Aktion: {a_type}")

# ---------------- Tray & App ----------------
_hotkey_mgr = HotkeyManager()

def on_tray_open_setup(systray):
    try:
        pyw = os.path.join(os.path.dirname(sys.argv[0]), "PwMrgSetup.pyw")
        if os.path.exists(pyw):
            subprocess.Popen([sys.executable, pyw])
        else:
            log("PwMrgSetup.pyw nicht gefunden")
    except Exception as e:
        log(f"Verwaltung starten fehlgeschlagen: {e}")

def on_tray_reload(systray):
    log("Verwaltung gestartet.")
    if load_config():
        hk_list = extract_hotkeys_from_config(_config)
        _hotkey_mgr.set_hotkeys_and_reload(hk_list)
        log("Config neu eingelesen und Hotkeys neu registriert.")

def on_tray_quit(systray):
    _hotkey_mgr.stop()

def main():
    load_config()
    log("Starte...")

    _hotkey_mgr.start()

    # Initial: Hotkeys aus Config extrahieren
    hk_list = extract_hotkeys_from_config(_config)
    _hotkey_mgr.set_hotkeys_and_reload(hk_list)

    log("Bereit.")

    menu_options = (
        ("Verwaltung öffnen", None, on_tray_open_setup),
        ("Aktualisieren", None, on_tray_reload),
    )
    systray = SysTrayIcon(
        ICON_PATH if os.path.exists(ICON_PATH) else None,
        APP_NAME,
        menu_options,
        on_quit=on_tray_quit
    )
    systray.start()

    try:
        while _hotkey_mgr.is_alive():
            time.sleep(0.25)
    finally:
        try:
            systray.shutdown()
        except Exception:
            pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _hotkey_mgr.stop(); sys.exit(0)
    except Exception as e:
        log(f"Fatal: {e}")
        _hotkey_mgr.stop()
        sys.exit(1)
