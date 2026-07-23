import os
import json
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


# Dark Mode Farben
BG_COLOR = "#1e1e1e"
FG_COLOR = "#e0e0e0"
ACCENT_COLOR = "#4CAF50"
ACCENT_HOVER = "#45a049"
ENTRY_BG = "#2d2d2d"
ENTRY_FG = "#e0e0e0"
BUTTON_BG = "#3d3d3d"
BUTTON_FG = "#e0e0e0"
TREE_BG = "#252525"
TREE_FG = "#e0e0e0"
TREE_SELECTED = "#4CAF50"


class PasswortManager:
    def __init__(self, datenbank_pfad="passwoerter.enc", salt_pfad="salt.bin"):
        self.datenbank_pfad = datenbank_pfad
        self.salt_pfad = salt_pfad
        self.schluessel = None
        self.eintraege = {}

    def master_passwort_setzen(self, passwort: str):
        salt = os.urandom(16)
        kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
        self.schluessel = kdf.derive(passwort.encode('utf-8'))
        return salt

    def master_passwort_pruefen(self, passwort: str, salt: bytes):
        kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
        self.schluessel = kdf.derive(passwort.encode('utf-8'))

    def verschluesseln(self, daten: dict) -> bytes:
        aesgcm = AESGCM(self.schluessel)
        nonce = os.urandom(12)
        plaintext = json.dumps(daten).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def entschluesseln(self, verschluesselt: bytes) -> dict:
        aesgcm = AESGCM(self.schluessel)
        nonce = verschluesselt[:12]
        ciphertext = verschluesselt[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))

    def speichern(self):
        if not self.schluessel:
            raise ValueError("Kein Schlüssel vorhanden!")
        daten = {'eintraege': self.eintraege}
        verschluesselt = self.verschluesseln(daten)
        with open(self.datenbank_pfad, 'wb') as f:
            f.write(verschluesselt)

    def laden(self):
        if not os.path.exists(self.datenbank_pfad):
            return False
        with open(self.datenbank_pfad, 'rb') as f:
            verschluesselt = f.read()
        try:
            daten = self.entschluesseln(verschluesselt)
            self.eintraege = daten.get('eintraege', {})
            return True
        except Exception:
            return False

    def passwort_hinzufuegen(self, name: str, passwort: str, benutzername: str = "", url: str = ""):
        self.eintraege[name] = {
            'passwort': passwort,
            'benutzername': benutzername,
            'url': url
        }

    def passwort_loeschen(self, name: str) -> bool:
        if name in self.eintraege:
            del self.eintraege[name]
            return True
        return False

    @staticmethod
    def passwort_generieren(laenge: int = 20) -> str:
        zeichen = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(zeichen) for _ in range(laenge))


class HauptFenster:
    def __init__(self, master, pm):
        self.master = master
        self.pm = pm
        self.zeige_hauptfenster()

    def zeige_hauptfenster(self):
        # Titel
        tk.Label(self.master, text="🔐 Passwort-Manager", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=15)

        # Listenframe
        frame_liste = tk.Frame(self.master, bg=BG_COLOR)
        frame_liste.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

        tk.Label(frame_liste, text="Gespeicherte Einträge:", font=("Segoe UI", 11), bg=BG_COLOR, fg="#888").pack(anchor="w")

        # Style für Treeview
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Custom.Treeview", background=TREE_BG, foreground=TREE_FG, fieldbackground=TREE_BG, borderwidth=0)
        style.configure("Custom.Treeview.Heading", background=BUTTON_BG, foreground=FG_COLOR, font=("Segoe UI", 10, "bold"))
        style.map("Custom.Treeview", background=[("selected", TREE_SELECTED)])

        # Treeview (Tabelle)
        columns = ("Name", "Benutzer", "URL")
        self.tree = ttk.Treeview(frame_liste, columns=columns, show="headings", height=12, style="Custom.Treeview")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Benutzer", text="Benutzername")
        self.tree.heading("URL", text="URL")
        self.tree.column("Name", width=150)
        self.tree.column("Benutzer", width=250)
        self.tree.column("URL", width=250)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=5)

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame_liste, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Buttons
        frame_buttons = tk.Frame(self.master, bg=BG_COLOR)
        frame_buttons.pack(pady=15)

        buttons = [
            ("➕ Hinzufügen", self.hinzufuegen, "#4CAF50", "#45a049"),
            ("👁 Anzeigen", self.anzeigen, "#2196F3", "#1976D2"),
            ("✏️ Bearbeiten", self.bearbeiten, "#FF9800", "#F57C00"),
            ("🗑 Löschen", self.loeschen, "#f44336", "#d32f2f"),
            ("🔑 Generieren", self.generieren, "#9C27B0", "#7B1FA2"),
        ]

        for text, cmd, bg, hover in buttons:
            btn = tk.Button(frame_buttons, text=text, command=cmd, width=14, bg=bg, fg="white", font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2", activebackground=hover)
            btn.pack(side=tk.LEFT, padx=4)

        tk.Button(self.master, text="💾 Speichern & Beenden", command=self.beenden, width=25, bg="#607D8B", fg="white", font=("Segoe UI", 11, "bold"), relief="flat", cursor="hand2", activebackground="#455A64").pack(pady=15)

        self.aktualisiere_liste()

    def aktualisiere_liste(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for name, eintrag in self.pm.eintraege.items():
            self.tree.insert("", tk.END, values=(name, eintrag['benutzername'], eintrag['url']))

    def _create_dialog(self, title, fields, save_callback):
        dialog = tk.Toplevel(self.master)
        dialog.title(title)
        dialog.geometry("450x450")
        dialog.transient(self.master)
        dialog.grab_set()
        dialog.configure(bg=BG_COLOR)
        dialog.resizable(False, False)

        entries = {}
        for label_text, default in fields:
            tk.Label(dialog, text=label_text + ":", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 10)).pack(pady=(15, 5))
            entry = tk.Entry(dialog, width=35, font=("Segoe UI", 11), bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=FG_COLOR, relief="flat", bd=5)
            entry.insert(0, default)
            entry.pack()
            entries[label_text] = entry

        def on_save():
            result = {k: v.get().strip() for k, v in entries.items()}
            if save_callback(result):
                dialog.destroy()

        tk.Button(dialog, text="💾 SPEICHERN", command=on_save, width=20, 
          bg=ACCENT_COLOR, fg="white", font=("Segoe UI", 12, "bold"), 
          relief="flat", cursor="hand2", activebackground=ACCENT_HOVER,
          padx=10, pady=5).pack(pady=15)
        
        # DEBUG
        print(f"DEBUG: {len(dialog.winfo_children())} Widgets im Dialog")
        for w in dialog.winfo_children():
            print(f"  - {type(w).__name__}: {w.cget('text') if hasattr(w, 'cget') and 
        'text' in w.keys() else 'kein text'}")

        return dialog, entries

    def hinzufuegen(self):
        def save(data):
            name = data["Name"]
            if not name:
                messagebox.showerror("Fehler", "Name darf nicht leer sein!")
                return False
            if name in self.pm.eintraege:
                messagebox.showerror("Fehler", "Eintrag existiert bereits!")
                return False
            
            pw = data["Passwort (leer = generieren)"]
            if not pw:
                pw = self.pm.passwort_generieren()
                messagebox.showinfo("Passwort generiert", f"Generiertes Passwort:\n{pw}")
            
            self.pm.passwort_hinzufuegen(name, pw, data["Benutzername"], data["URL"])
            self.aktualisiere_liste()
            return True

        self._create_dialog("Eintrag hinzufügen", [
            ("Name", ""),
            ("Benutzername", ""),
            ("URL", ""),
            ("Passwort (leer = generieren)", "")
        ], save)

    def anzeigen(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Hinweis", "Bitte einen Eintrag auswählen!")
            return
        
        name = self.tree.item(selected[0])['values'][0]
        eintrag = self.pm.eintraege.get(name)
        if eintrag:
            dialog = tk.Toplevel(self.master)
            dialog.title(f"Eintrag: {name}")
            dialog.geometry("400x250")
            dialog.configure(bg=BG_COLOR)
            dialog.resizable(False, False)
            dialog.transient(self.master)

            info_text = f"""📛 Name: {name}
👤 Benutzername: {eintrag['benutzername']}
🔑 Passwort: {eintrag['passwort']}
🌐 URL: {eintrag['url']}"""

            tk.Label(dialog, text=info_text, bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 11), justify="left", wraplength=350).pack(pady=30, padx=20)

            def copy_pw():
                self.master.clipboard_clear()
                self.master.clipboard_append(eintrag['passwort'])
                messagebox.showinfo("Kopiert", "Passwort in Zwischenablage kopiert!")

            tk.Button(dialog, text="📋 Passwort kopieren", command=copy_pw, bg=ACCENT_COLOR, fg="white", font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2").pack(pady=10)

    def bearbeiten(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Hinweis", "Bitte einen Eintrag auswählen!")
            return
        
        old_name = self.tree.item(selected[0])['values'][0]
        eintrag = self.pm.eintraege[old_name]

        def save(data):
            new_name = data["Name"] or old_name
            if new_name != old_name and new_name in self.pm.eintraege:
                messagebox.showerror("Fehler", "Name existiert bereits!")
                return False
            
            if new_name != old_name:
                self.pm.eintraege[new_name] = self.pm.eintraege.pop(old_name)
            
            self.pm.eintraege[new_name]['benutzername'] = data["Benutzername"]
            self.pm.eintraege[new_name]['url'] = data["URL"]
            
            pw = data["Passwort (leer = gleich)"]
            if pw:
                self.pm.eintraege[new_name]['passwort'] = pw
            
            self.aktualisiere_liste()
            return True

        self._create_dialog("Eintrag bearbeiten", [
            ("Name", old_name),
            ("Benutzername", eintrag['benutzername']),
            ("URL", eintrag['url']),
            ("Passwort (leer = gleich)", "")
        ], save)

    def loeschen(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Hinweis", "Bitte einen Eintrag auswählen!")
            return
        
        name = self.tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Löschen", f"Eintrag '{name}' wirklich löschen?"):
            self.pm.passwort_loeschen(name)
            self.aktualisiere_liste()

    def generieren(self):
        laenge = simpledialog.askinteger("Passwort generieren", "Länge:", initialvalue=20, minvalue=4, maxvalue=100)
        if laenge:
            pw = self.pm.passwort_generieren(laenge)
            dialog = tk.Toplevel(self.master)
            dialog.title("Generiertes Passwort")
            dialog.geometry("400x150")
            dialog.configure(bg=BG_COLOR)
            dialog.resizable(False, False)
            dialog.transient(self.master)

            tk.Label(dialog, text="🔑 Generiertes Passwort:", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 11)).pack(pady=10)
            tk.Label(dialog, text=pw, bg=ENTRY_BG, fg=ACCENT_COLOR, font=("Consolas", 14, "bold"), wraplength=350).pack(pady=5, padx=20)

            def copy():
                self.master.clipboard_clear()
                self.master.clipboard_append(pw)
                messagebox.showinfo("Kopiert", "Passwort kopiert!")

            tk.Button(dialog, text="📋 Kopieren", command=copy, bg=ACCENT_COLOR, fg="white", font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2").pack(pady=10)

    def beenden(self):
        self.pm.speichern()
        self.master.destroy()


def main():
    # Zuerst Login
    login_root = tk.Tk()
    login_root.withdraw()
    
    pm = PasswortManager()
    login_erfolgreich = [False]
    
    def on_login_success():
        login_erfolgreich[0] = True
        login_root.destroy()
    
    def on_login_cancel():
        login_root.destroy()
    
    login_fenster = tk.Toplevel(login_root)
    login_fenster.title("Passwort-Manager - Login")
    login_fenster.geometry("400x280")
    login_fenster.resizable(False, False)
    login_fenster.configure(bg=BG_COLOR)
    
    ist_neu = not os.path.exists(pm.datenbank_pfad)
    
    tk.Label(login_fenster, text="🔐 Passwort-Manager", font=("Segoe UI", 18, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
    
    if ist_neu:
        tk.Label(login_fenster, text="Neue Datenbank erstellen", font=("Segoe UI", 10), bg=BG_COLOR, fg="#888").pack()
    else:
        tk.Label(login_fenster, text="Datenbank entsperren", font=("Segoe UI", 10), bg=BG_COLOR, fg="#888").pack()
    
    tk.Label(login_fenster, text="Master-Passwort:", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 10)).pack(pady=(20, 5))
    entry_pw = tk.Entry(login_fenster, show="●", width=30, font=("Segoe UI", 12), bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=FG_COLOR, relief="flat", bd=5)
    entry_pw.pack()
    entry_pw.focus()
    
    entry_pw2 = None
    if ist_neu:
        tk.Label(login_fenster, text="Wiederholen:", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 10)).pack(pady=(10, 5))
        entry_pw2 = tk.Entry(login_fenster, show="●", width=30, font=("Segoe UI", 12), bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=FG_COLOR, relief="flat", bd=5)
        entry_pw2.pack()
    
    def do_login():
        pw = entry_pw.get()
        
        if ist_neu:
            pw2 = entry_pw2.get()
            if pw != pw2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein!")
                return
            if len(pw) < 4:
                messagebox.showerror("Fehler", "Passwort zu kurz!")
                return
            salt = pm.master_passwort_setzen(pw)
            with open(pm.salt_pfad, 'wb') as f:
                f.write(salt)
            pm.speichern()
        else:
            if not os.path.exists(pm.salt_pfad):
                messagebox.showerror("Fehler", "Salt-Datei fehlt!")
                return
            with open(pm.salt_pfad, 'rb') as f:
                salt = f.read()
            pm.master_passwort_pruefen(pw, salt)
            if not pm.laden():
                messagebox.showerror("Fehler", "Falsches Master-Passwort!")
                return
        
        on_login_success()
    
    tk.Button(login_fenster, text="OK", command=do_login, width=15, bg=ACCENT_COLOR, fg="white", font=("Segoe UI", 11, "bold"), relief="flat", cursor="hand2", activebackground=ACCENT_HOVER).pack(pady=20)
    
    login_fenster.bind('<Return>', lambda e: do_login())
    login_fenster.protocol("WM_DELETE_WINDOW", on_login_cancel)
    
    login_root.mainloop()
    
    # Wenn Login erfolgreich, Hauptfenster öffnen
    if login_erfolgreich[0]:
        root = tk.Tk()
        root.title("🔐 Passwort-Manager")
        root.geometry("700x550")
        root.configure(bg=BG_COLOR)
        root.resizable(True, True)
        
        app = HauptFenster(root, pm)
        root.mainloop()


if __name__ == "__main__":
    main()