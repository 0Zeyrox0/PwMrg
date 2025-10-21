# -*- coding: utf-8 -*-
"""
PwMrgSetup.pyw — Password manager GUI (module docstring)
Overview
--------
This module implements a small GUI-based password/account manager using
customtkinter for the interface and the platform keyring for secure
storage of configuration and a master-password verifier. It provides:
- creation and verification of a master password (scrypt hashed),
- persistent JSON configuration (stored in keyring),
- an account list editor (add/edit/delete),
- per-account hotkey configuration with modifier keys and a main key,
- a small treeview UI with light/dark theme adjustments.
The module is intended as a management utility for a separate runtime
component that would listen for configured hotkeys and perform credential
fill/send actions. It is not a general-purpose password library.
High-level behaviour
--------------------
- Master-password data (salt + scrypt digest + parameters) is stored under
    keyring service "PwMrg", entry "admin".
- The app configuration (JSON blob) is stored under the same service entry
    "config".
- On startup, if no admin data exists, the GUI forces the user to create a
    master password. Otherwise it requests the master password for access.
- After successful auth, the configuration is loaded into memory and shown.
- Accounts have fields: id, username, password, send_enter (bool), hotkey
    (dict with "modifiers" list and "key" string).
- Hotkeys are represented by a modifiers list of strings (subset of
    ["CTRL","ALT","SHIFT"]) and a single key string (A–Z, 0–9, TAB, ENTER).
Storage and format
------------------
Service name: "PwMrg"
Admin key (master password): keyring password entry "admin"
    Stored JSON structure:
        {
            "salt":   base64-encoded salt bytes,
            "hash":   base64-encoded scrypt digest,
            "n":      scrypt N parameter (int),
            "r":      scrypt r parameter (int),
            "p":      scrypt p parameter (int),
            "dk":     derived key length (int)
Config key (application data): keyring password entry "config"
    Stored JSON structure (example):
        {
            "version": 1,
            "logging": true,
            "accounts": [
                {
                    "id": "unique-id",
                    "username": "user@example.com",
                    "password": "plaintext-in-memory",
                    "send_enter": false,
                        "modifiers": ["CTRL","ALT"],
                        "key": "H"
                },
                ...
            ]
Public functions
----------------
scrypt_hash(pw: str, salt: bytes, n=2**14, r=8, p=1, dklen=32) -> bytes
        Compute an scrypt-derived key for given password and salt using the
        provided scrypt parameters. Returns raw bytes of the derived key.
admin_load() -> dict|None
        Load and return the admin JSON object from keyring decoded to a dict,
        or None if not present.
admin_set_new(pw: str) -> None
        Generate a random 16-byte salt, derive an scrypt digest using default
        parameters and store the admin JSON object into keyring. Overwrites any
        existing admin entry.
admin_verify(pw: str) -> bool
        Verify a provided password against the stored admin scrypt parameters.
        Returns True on match, False otherwise. Returns False if no admin data
        exists.
config_load() -> dict
        Load the config JSON blob from keyring and return it as a dict. If no
        config exists, returns a default configuration:
            {"version": 1, "logging": True, "accounts": []}
config_save(cfg: dict) -> None
        Serialize and store the provided configuration dict to keyring under the
        config key. Uses ensure_ascii=False to preserve non-ASCII characters.
parse_keysym(ks: str) -> str|None
        Normalize a tkinter keysym to a canonical key string used by the app:
        - single ASCII alphanumeric characters are upper-cased,
        - "TAB", "RETURN", "ENTER" map to either "TAB" or "ENTER",
        - anything else returns None.
Constants
---------
SERVICE (str): keyring service name ("PwMrg")
ADMIN_KEY (str): admin key name ("admin")
CONFIG_KEY (str): config key name ("config")
VALID_KEYS (list[str]): allowed key values for hotkey assignment (A–Z, 0–9, TAB, ENTER)
VALID_MODS (list[str]): allowed modifier names ["CTRL","ALT","SHIFT"]
GUI classes
-----------
App (ctk.CTk)
        The main application window. Responsibilities:
        - initialize the GUI (treeview, toolbar, checkboxes),
        - ensure master password exists and request it (ask_new_master/ask_master),
        - load/save configuration and update UI,
        - add/edit/delete accounts via the Editor dialog,
        - maintain Treeview appearance matching customtkinter light/dark modes
            (update_tree_colors and poll_appearance).
        Important methods:
        - ensure_admin(): check if admin exists and prompt for creation or login.
        - ask_new_master(): top-level dialog to set a new master password.
        - ask_master(): top-level dialog to request existing master password.
        - load_cfg(): call config_load() and refresh the list UI.
        - refresh_list(): render current config accounts into the Treeview.
        - on_new(), on_edit(), on_del(): handlers to open Editor or delete entries.
        - update_tree_colors(): apply appearance-specific colors to ttk styles
            and the Treeview widget to obtain consistent visuals.
        - poll_appearance(): periodically checks customtkinter appearance mode
            and updates styles when it changes.
Editor (ctk.CTkToplevel)
        Dialog for creating or editing a single account entry. Responsibilities:
        - display fields: ID, username, password (with optional show), send_enter
            checkbox, hotkey modifiers and key selection.
        - capture a hotkey by listening to a KeyPress event and parsing modifier
            state (uses event.state bitmasks).
        - validate data (non-empty ID and unique ID on creation) and save changes
            back into App.cfg, then persist with config_save().
        Important methods:
        - build(): create all widgets and initialize values from the provided acc.
        - capture_hotkey(): modal dialog that listens for a KeyPress, reads
            modifier state, parses the keysym via parse_keysym and updates selection.
        - on_save(): validate input, insert or update the entry list, persist,
            refresh app UI and close dialog.
Hotkey capture notes
--------------------
- Modifier detection uses event.state bitmasks and checks for bits corresponding
    typical of tkinter on Windows:
        - CTRL: event.state & 0x4
        - ALT: event.state & 0x20000 or event.state & 0x200 (both tested)
        - SHIFT: event.state & 0x1
    These masks are platform-dependent; behaviour may vary across platforms.
- The accepted main key set is restricted to VALID_KEYS (A-Z, 0-9, TAB, ENTER).
- The "Windows" / "Super" key is not supported (note shown in the GUI).
Security considerations
-----------------------
- Master password is hashed with scrypt; default parameters used in admin_set_new()
    are n=16384, r=8, p=1, dklen=32. These values are recorded in stored JSON so
    verification uses the stored parameters.
- The config JSON stored in keyring currently contains plaintext passwords in
    memory and in the stored blob. If confidentiality is required, consider
    encrypting the config payload using a key derived from the master password
    (not implemented here).
- The module relies on the system keyring backend for persistence. The
    security properties depend on the underlying keyring implementation.
- Admin data and config are stored under the same service; ensure proper
    access controls on the host system.
Dependencies and requirements
-----------------------------
- Python 3.8+ (typing uses | for union only on 3.10+; if run on older Python,
    minor annotation changes may be needed).
- customtkinter (for themed widgets)
- tkinter (standard library)
- keyring (for secure storage)
- Standard libraries: json, os, sys, base64, secrets, hashlib, tkinter.font, ttk
Running
-------
Run the file as a normal Python script. A top-level guard is provided:
Extensibility notes
-------------------
- To switch to encrypted config storage, replace config_save/load with
    symmetric encryption using a key derived from the master password.
- Hotkey registration (system-wide) is out of scope for this module and should
    be implemented in a separate runtime component that reads the stored config.
- If you need cross-platform hotkey masks, prefer a dedicated library (e.g.
    pynput or keyboard) for reliable modifier detection and system registration.
"""
# Verwaltungs-GUI: Master-Passwort, Konten anlegen/bearbeiten/löschen, Hotkey-Aufnahme, JSON in keyring
import json, os, sys, base64, secrets, hashlib, tkinter as tk
import tkinter.font as tkfont
import keyring
import customtkinter as ctk
from tkinter import ttk, messagebox

# set customtkinter appearance and theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

SERVICE = "PwMrg"
ADMIN_KEY = "admin"   # Master-Passwort-Hash/Params
CONFIG_KEY = "config" # JSON-Blob

# ------------- Hilfsfunktionen -------------
def scrypt_hash(pw: str, salt: bytes, n=2**14, r=8, p=1, dklen=32) -> bytes:
    return hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)

def admin_load():
    raw = keyring.get_password(SERVICE, ADMIN_KEY)
    return json.loads(raw) if raw else None

def admin_set_new(pw: str):
    salt = secrets.token_bytes(16)
    digest = scrypt_hash(pw, salt)
    data = {"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(digest).decode(),
            "n": 16384, "r": 8, "p": 1, "dk": 32}
    keyring.set_password(SERVICE, ADMIN_KEY, json.dumps(data))

def admin_verify(pw: str) -> bool:
    data = admin_load()
    if not data: return False
    salt = base64.b64decode(data["salt"])
    digest = scrypt_hash(pw, salt, n=data["n"], r=data["r"], p=data["p"], dklen=data["dk"])
    return base64.b64encode(digest).decode() == data["hash"]

def config_load():
    raw = keyring.get_password(SERVICE, CONFIG_KEY)
    if not raw:
        return {"version": 1, "logging": True, "accounts": []}
    return json.loads(raw)

def config_save(cfg: dict):
    keyring.set_password(SERVICE, CONFIG_KEY, json.dumps(cfg, ensure_ascii=False))

# ------------- Hotkey-Helfer -------------
VALID_KEYS = [*[chr(c) for c in range(65,91)], *[str(i) for i in range(0,10)], "TAB", "ENTER"]
VALID_MODS = ["CTRL", "ALT", "SHIFT"]

def parse_keysym(ks: str):
    k = ks.upper()
    if len(k) == 1 and ("A" <= k <= "Z" or "0" <= k <= "9"):
        return k
    if k in ("TAB", "RETURN", "ENTER"):
        return "ENTER" if k in ("RETURN","ENTER") else "TAB"
    return None

# ------------- GUI -------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PwMrg – Verwaltung")
        self.geometry("640x420")
        self.resizable(False, False)
        self.cfg = None
        self.create_widgets()
        self.after(100, self.ensure_admin)

    def ensure_admin(self):
        data = admin_load()
        if not data:
            self.ask_new_master()
        else:
            self.ask_master()

    def ask_new_master(self):
        dlg = ctk.CTkToplevel(self); dlg.title("Master-Passwort festlegen"); dlg.grab_set(); dlg.resizable(False, False)
        ctk.CTkLabel(dlg, text="Neues Master-Passwort:").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        e1 = ctk.CTkEntry(dlg, show="•", width=240); e1.grid(row=0, column=1, padx=10, pady=8)
        ctk.CTkLabel(dlg, text="Wiederholen:").grid(row=1, column=0, sticky="w", padx=10, pady=8)
        e2 = ctk.CTkEntry(dlg, show="•", width=240); e2.grid(row=1, column=1, padx=10, pady=8)
        def ok(event=None):
            if e1.get() and e1.get()==e2.get():
                admin_set_new(e1.get()); dlg.destroy(); self.load_cfg()
            else:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht.")
        ctk.CTkButton(dlg, text="OK", command=ok).grid(row=2, column=0, columnspan=2, pady=10)
        dlg.bind("<Return>", ok); dlg.bind("<KP_Enter>", ok)
        e1.focus_set()

    def ask_master(self):
        dlg = ctk.CTkToplevel(self); dlg.title("Master-Passwort"); dlg.grab_set(); dlg.resizable(False, False)
        ctk.CTkLabel(dlg, text="Master-Passwort:").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        e = ctk.CTkEntry(dlg, show="•", width=240); e.grid(row=0, column=1, padx=10, pady=8)
        def ok(event=None):
            if admin_verify(e.get()):
                dlg.destroy(); self.load_cfg()
            else:
                messagebox.showerror("Fehler", "Falsches Master-Passwort.")
        ctk.CTkButton(dlg, text="OK", command=ok).grid(row=1, column=0, columnspan=2, pady=10)
        dlg.bind("<Return>", ok); dlg.bind("<KP_Enter>", ok)
        e.focus_set()

    def load_cfg(self):
        self.cfg = config_load()
        self.refresh_list()

    def create_widgets(self):
        top = ctk.CTkFrame(self); top.pack(fill="x", padx=10, pady=8)
        # Treeview-Schrift vergrößern und Zeilenhöhe anpassen
        try:
            base_font = tkfont.nametofont("TkDefaultFont")
            fam = base_font.cget("family")
            size = int(base_font.cget("size"))
            # Style-Objekt speichern, damit wir später Farben ändern können
            self._ttk_style = ttk.Style(self)
            # use 'clam' theme so heading/background colors are honored on Windows
            try:
                self._ttk_style.theme_use('clam')
            except Exception:
                pass
            self._ttk_style.configure("Treeview", font=(fam, size + 3), rowheight=max(20, size + 10))
            self._ttk_style.configure("Treeview.Heading", font=(fam, size + 4, "bold"))
            # initiale Farben setzen und Polling für Modus-Änderungen starten
            self.update_tree_colors()
            self._appr = ctk.get_appearance_mode()
            self.after(1000, self.poll_appearance)
        except Exception:
            pass

        self.var_logging = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(top, text="Logging aktivieren", variable=self.var_logging,
                        command=self.on_toggle_logging).pack(side="left")
        ctk.CTkButton(top, text="Neu", command=self.on_new).pack(side="right")
        ctk.CTkButton(top, text="Bearbeiten", command=self.on_edit).pack(side="right", padx=6)
        ctk.CTkButton(top, text="Löschen", command=self.on_del).pack(side="right")

        cols = ("id","username","send_enter","hotkey")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c, txt in zip(cols, ("ID", "Benutzername", "Enter senden", "Hotkey")):
            self.tree.heading(c, text=txt)
            self.tree.column(c, anchor="w", width=140 if c!="username" else 220)
        self.tree.pack(fill="both", expand=True, padx=10, pady=6)

        # sofort Farben erneut anwenden, damit auch Header/Leere-Fläche korrekt gefärbt werden
        try:
            self.update_tree_colors()
        except Exception:
            pass

        ctk.CTkLabel(self, text="Hinweis: Windows-Taste wird nicht unterstützt. Gültige Tasten: A–Z, 0–9, Tab, Enter.").pack(anchor="w", padx=10)

    def on_toggle_logging(self):
        if not self.cfg: return
        self.cfg["logging"] = bool(self.var_logging.get())
        config_save(self.cfg)

    def refresh_list(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        if not self.cfg: return
        self.var_logging.set(bool(self.cfg.get("logging", True)))
        for acc in self.cfg.get("accounts", []):
            hk = acc.get("hotkey", {})
            mod = "+".join(hk.get("modifiers", []))
            key = hk.get("key","")
            self.tree.insert("", "end", iid=acc.get("id",""), values=(acc.get("id",""), acc.get("username",""),
                                 "Ja" if acc.get("send_enter", False) else "Nein", f"{mod}+{key}" if key else ""))

    def on_new(self):
        Editor(self, None)

    def on_edit(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Bitte einen Eintrag auswählen.")
            return
        acc_id = sel[0]
        acc = next((a for a in self.cfg["accounts"] if a.get("id")==acc_id), None)
        if not acc:
            messagebox.showerror("Fehler", "Eintrag nicht gefunden.")
            return
        Editor(self, acc)

    def on_del(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Bitte einen Eintrag auswählen.")
            return
        acc_id = sel[0]
        if messagebox.askyesno("Löschen", "Eintrag wirklich löschen?"):
            self.cfg["accounts"] = [a for a in self.cfg.get("accounts", []) if a.get("id") != acc_id]
            config_save(self.cfg)
            self.refresh_list()

    def update_tree_colors(self):
        """Setze Treeview-Farben entsprechend dem aktuellen customtkinter-Modus."""
        try:
            style = getattr(self, "_ttk_style", ttk.Style(self))
            mode = ctk.get_appearance_mode()
            if mode and mode.lower().startswith("dark"):
                bg = "#1e1e1e"
                fg = "#eaeaea"
                hdr_bg = "#2b2b2b"
                hdr_fg = "#ffffff"
                sel_bg = "#094a86"
                sel_fg = "#ffffff"
            else:
                bg = "#ffffff"
                fg = "#000000"
                hdr_bg = "#f0f0f0"
                hdr_fg = "#000000"
                sel_bg = "#3399ff"
                sel_fg = "#ffffff"

            # Stelle sicher, dass die Treeview-Treearea (leerer Bereich) das Feld-Hintergrund übernimmt
            style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
            # Farben für Zeilen / Feldhintergrund / Header setzen
            style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg, bordercolor=bg, borderwidth=0)
            # Heading-Style etwas anpassen, damit Hintergrundfarbe sichtbar ist
            style.configure("Treeview.Heading", background=hdr_bg, foreground=hdr_fg, relief='flat')
            style.map("Treeview",
                      background=[('selected', sel_bg)],
                      foreground=[('selected', sel_fg)])
            # Wenn das Treeview-Widget bereits existiert, konfiguriere es direkt, damit auch der leere Bereich sofort passt
            if hasattr(self, "tree") and self.tree is not None:
                try:
                    self.tree.configure(background=bg, foreground=fg, fieldbackground=bg)
                except Exception:
                    pass
        except Exception:
            pass

    def poll_appearance(self):
        """Prüft periodisch auf Modus-Änderungen und aktualisiert Farben."""
        try:
            mode = ctk.get_appearance_mode()
            if getattr(self, "_appr", None) != mode:
                self._appr = mode
                self.update_tree_colors()
        finally:
            # weiter pollen
            self.after(1000, self.poll_appearance)

class Editor(ctk.CTkToplevel):
    def __init__(self, app: App, acc: dict|None):
        super().__init__(app)
        self.app = app
        self.title("Eintrag bearbeiten" if acc else "Neuer Eintrag")
        self.resizable(False, False)
        self.acc = acc or {"id":"", "username":"", "password":"", "send_enter":False,
                           "hotkey":{"modifiers":["CTRL","ALT"], "key":"H"}}
        self.build()

    def build(self):
        ctk.CTkLabel(self, text="ID:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.e_id = ctk.CTkEntry(self, width=220)
        self.e_id.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.e_id.insert(0, self.acc.get("id",""))

        ctk.CTkLabel(self, text="Benutzername:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.e_user = ctk.CTkEntry(self, width=320); self.e_user.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        self.e_user.insert(0, self.acc.get("username",""))

        ctk.CTkLabel(self, text="Passwort:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.e_pass = ctk.CTkEntry(self, width=320, show="•"); self.e_pass.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        self.e_pass.insert(0, self.acc.get("password",""))
        self.var_show = tk.BooleanVar(value=False)
        def toggle():
            self.e_pass.configure(show="" if self.var_show.get() else "•")
        ctk.CTkCheckBox(self, text="anzeigen", variable=self.var_show, command=toggle).grid(row=2, column=2, padx=6)

        self.var_enter = tk.BooleanVar(value=bool(self.acc.get("send_enter", False)))
        ctk.CTkCheckBox(self, text="Enter am Ende senden", variable=self.var_enter).grid(row=3, column=1, sticky="w", padx=10, pady=5)

        frm_hk = ctk.CTkFrame(self)
        frm_hk.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="we")
        ctk.CTkLabel(frm_hk, text="Hotkey").grid(row=0, column=0, columnspan=6, pady=(4,8))

        self.var_ctrl = tk.BooleanVar(value=("CTRL" in self.acc["hotkey"].get("modifiers", [])))
        self.var_alt  = tk.BooleanVar(value=("ALT"  in self.acc["hotkey"].get("modifiers", [])))
        self.var_shift= tk.BooleanVar(value=("SHIFT"in self.acc["hotkey"].get("modifiers", [])))
        ctk.CTkCheckBox(frm_hk, text="CTRL", variable=self.var_ctrl).grid(row=1, column=0, padx=6, pady=4)
        ctk.CTkCheckBox(frm_hk, text="ALT",  variable=self.var_alt).grid(row=1, column=1, padx=6, pady=4)
        ctk.CTkCheckBox(frm_hk, text="SHIFT",variable=self.var_shift).grid(row=1, column=2, padx=6, pady=4)

        ctk.CTkLabel(frm_hk, text="Taste:").grid(row=1, column=3, padx=6)
        self.var_key = tk.StringVar(value=self.acc["hotkey"].get("key","H"))
        cb = ctk.CTkComboBox(frm_hk, values=VALID_KEYS, variable=self.var_key, width=80)
        cb.grid(row=1, column=4, padx=6)

        ctk.CTkButton(frm_hk, text="Hotkey aufnehmen", command=self.capture_hotkey).grid(row=1, column=5, padx=10)

        btns = ctk.CTkFrame(self); btns.grid(row=5, column=0, columnspan=3, pady=10)
        ctk.CTkButton(btns, text="Speichern", command=self.on_save).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Abbrechen", command=self.destroy).pack(side="left")

    def capture_hotkey(self):
        cap = ctk.CTkToplevel(self); cap.title("Hotkey aufnehmen"); cap.resizable(False, False); cap.grab_set()
        ctk.CTkLabel(cap, text="Gewünschte Tastenkombination drücken (z. B. CTRL+ALT+H)").pack(padx=14, pady=12)
        mods = set()
        def on_key(event):
            nonlocal mods
            mods = set()
            if (event.state & 0x4):  mods.add("CTRL")
            if (event.state & 0x20000) or (event.state & 0x200): mods.add("ALT")
            if (event.state & 0x1):  mods.add("SHIFT")
            k = parse_keysym(event.keysym)
            if k:
                self.var_ctrl.set("CTRL" in mods)
                self.var_alt.set("ALT" in mods)
                self.var_shift.set("SHIFT" in mods)
                self.var_key.set(k)
                cap.destroy()
        cap.bind("<KeyPress>", on_key)
        cap.focus_set()

    def on_save(self):
        acc_id = self.e_id.get().strip()
        if not acc_id:
            messagebox.showerror("Fehler", "ID darf nicht leer sein.")
            return
        entry = {
            "id": acc_id,
            "username": self.e_user.get(),
            "password": self.e_pass.get(),
            "send_enter": bool(self.var_enter.get()),
            "hotkey": {
                "modifiers": [m for m,b in (("CTRL",self.var_ctrl.get()),("ALT",self.var_alt.get()),("SHIFT",self.var_shift.get())) if b],
                "key": self.var_key.get()
            }
        }
        lst = self.app.cfg.get("accounts", [])
        if self.acc and any(a for a in lst if a.get("id")==self.acc.get("id")):
            for i,a in enumerate(lst):
                if a.get("id")==self.acc.get("id"):
                    lst[i] = entry
                    break
        else:
            if any(a for a in lst if a.get("id")==acc_id):
                messagebox.showerror("Fehler", "ID existiert bereits.")
                return
            lst.append(entry)
        self.app.cfg["accounts"] = lst
        config_save(self.app.cfg)
        self.app.refresh_list()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()
