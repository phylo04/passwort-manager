import os
import json
import base64
import getpass
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


class PasswortManager:
    def __init__(self, datenbank_pfad="passwoerter.enc", salt_pfad="salt.bin"):
        self.datenbank_pfad = datenbank_pfad
        self.salt_pfad = salt_pfad
        self.schluessel = None
        self.eintraege = {}

    def master_passwort_setzen(self, passwort: str):
        """Erzeugt einen Schlüssel aus dem Master-Passwort."""
        salt = os.urandom(16)
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536
        )
        schluessel = kdf.derive(passwort.encode('utf-8'))
        self.schluessel = schluessel
        return salt

    def master_passwort_pruefen(self, passwort: str, salt: bytes):
        """Prüft ein Master-Passwort gegen den gespeicherten Salt."""
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536
        )
        self.schluessel = kdf.derive(passwort.encode('utf-8'))

    def verschluesseln(self, daten: dict) -> bytes:
        """Verschlüsselt ein Dictionary mit AES-GCM."""
        aesgcm = AESGCM(self.schluessel)
        nonce = os.urandom(12)
        plaintext = json.dumps(daten).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def entschluesseln(self, verschluesselt: bytes) -> dict:
        """Entschlüsselt Daten mit AES-GCM."""
        aesgcm = AESGCM(self.schluessel)
        nonce = verschluesselt[:12]
        ciphertext = verschluesselt[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))

    def speichern(self):
        """Speichert alle Einträge verschlüsselt."""
        if not self.schluessel:
            raise ValueError("Kein Schlüssel vorhanden!")
        
        daten = {
            'eintraege': self.eintraege
        }
        verschluesselt = self.verschluesseln(daten)
        
        with open(self.datenbank_pfad, 'wb') as f:
            f.write(verschluesselt)

    def laden(self):
        """Lädt und entschlüsselt die Datenbank."""
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
        """Fügt einen neuen Eintrag hinzu."""
        self.eintraege[name] = {
            'passwort': passwort,
            'benutzername': benutzername,
            'url': url
        }

    def passwort_anzeigen(self, name: str) -> dict:
        """Zeigt einen Eintrag an."""
        return self.eintraege.get(name, None)

    def passwort_loeschen(self, name: str) -> bool:
        """Löscht einen Eintrag."""
        if name in self.eintraege:
            del self.eintraege[name]
            return True
        return False

    def passwort_bearbeiten(self, name: str, neuer_name: str = None, passwort: str = None, 
                           benutzername: str = None, url: str = None) -> bool:
        """Bearbeitet einen bestehenden Eintrag."""
        if name not in self.eintraege:
            return False
        
        eintrag = self.eintraege[name]
        
        # Wenn neuer Name angegeben, Eintrag umbenennen
        if neuer_name and neuer_name != name:
            self.eintraege[neuer_name] = self.eintraege.pop(name)
            eintrag = self.eintraege[neuer_name]
        
        # Felder aktualisieren (nur wenn angegeben)
        if passwort is not None:
            eintrag['passwort'] = passwort
        if benutzername is not None:
            eintrag['benutzername'] = benutzername
        if url is not None:
            eintrag['url'] = url
        
        return True

    def alle_anzeigen(self):
        """Listet alle gespeicherten Namen auf."""
        return list(self.eintraege.keys())

    @staticmethod
    def passwort_generieren(laenge: int = 20) -> str:
        """Erzeugt ein sicheres zufälliges Passwort."""
        zeichen = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(zeichen) for _ in range(laenge))


def main():
    pm = PasswortManager()
    
    print("=" * 50)
    print("  🔐 Passwort-Manager v2.0")
    print("=" * 50)
    
    # Prüfen ob Datenbank existiert
    if os.path.exists(pm.datenbank_pfad):
        print("\nDatenbank gefunden. Master-Passwort eingeben:")
        passwort = getpass.getpass("> ")
        
        if os.path.exists(pm.salt_pfad):
            with open(pm.salt_pfad, 'rb') as f:
                salt = f.read()
            pm.master_passwort_pruefen(passwort, salt)
            if not pm.laden():
                print("❌ FALSCHE PASSWORT!")
                return
            print("✅ Entschlüsselt!")
        else:
            print("❌ Fehler: Salt-Datei fehlt!")
            return
    else:
        print("\nNeue Datenbank erstellen. Master-Passwort wählen:")
        passwort = getpass.getpass("> ")
        passwort2 = getpass.getpass("Wiederholen: ")
        
        if passwort != passwort2:
            print("❌ Passwörter stimmen nicht überein!")
            return
        
        salt = pm.master_passwort_setzen(passwort)
        with open(pm.salt_pfad, 'wb') as f:
            f.write(salt)
        pm.speichern()
        print("✅ Datenbank erstellt!")

    # Hauptmenü
    while True:
        print("\n" + "=" * 50)
        print("  [1] ➕ Passwort hinzufügen")
        print("  [2] 👁  Passwort anzeigen")
        print("  [3] 📋 Alle Einträge anzeigen")
        print("  [4] ✏️  Eintrag bearbeiten")
        print("  [5] 🗑️  Eintrag löschen")
        print("  [6] 🔑 Passwort generieren")
        print("  [7] 💾 Beenden & speichern")
        print("=" * 50)
        
        wahl = input("Wahl: ").strip()
        
        if wahl == "1":
            name = input("Name (z.B. 'Google'): ").strip()
            if not name:
                print("❌ Name darf nicht leer sein!")
                continue
            if name in pm.eintraege:
                print("❌ Eintrag existiert bereits! Nutze 'Bearbeiten'.")
                continue
                
            benutzer = input("Benutzername: ").strip()
            url = input("URL (optional): ").strip()
            
            print("\n[1] Eigenes Passwort eingeben")
            print("[2] Passwort generieren")
            pw_wahl = input("Wahl: ").strip()
            
            if pw_wahl == "2":
                laenge = int(input("Länge (Standard 20): ") or "20")
                passwort = pm.passwort_generieren(laenge)
                print(f"🔑 Generiert: {passwort}")
            else:
                passwort = getpass.getpass("Passwort: ")
            
            pm.passwort_hinzufuegen(name, passwort, benutzer, url)
            print("✅ Gespeichert!")
            
        elif wahl == "2":
            name = input("Name: ").strip()
            eintrag = pm.passwort_anzeigen(name)
            if eintrag:
                print(f"\n  📛 Name: {name}")
                print(f"  👤 Benutzer: {eintrag['benutzername'] or '(leer)'}")
                print(f"  🔑 Passwort: {eintrag['passwort']}")
                print(f"  🌐 URL: {eintrag['url'] or '(leer)'}")
            else:
                print("❌ Eintrag nicht gefunden!")
                
        elif wahl == "3":
            eintraege = pm.alle_anzeigen()
            if eintraege:
                print("\n📋 Gespeicherte Einträge:")
                for i, e in enumerate(eintraege, 1):
                    print(f"  {i}. {e}")
            else:
                print("📭 Keine Einträge vorhanden.")
                
        elif wahl == "4":
            name = input("Name des zu bearbeitenden Eintrags: ").strip()
            if name not in pm.eintraege:
                print("❌ Eintrag nicht gefunden!")
                continue
            
            print("\nAktuelle Werte (Enter drücken um beizubehalten):")
            eintrag = pm.eintraege[name]
            
            neuer_name = input(f"Neuer Name [{name}]: ").strip() or None
            neuer_benutzer = input(f"Neuer Benutzername [{eintrag['benutzername']}]: ").strip()
            neuer_benutzer = neuer_benutzer if neuer_benutzer else None
            
            neuer_url = input(f"Neue URL [{eintrag['url']}]: ").strip()
            neuer_url = neuer_url if neuer_url else None
            
            print("\n[1] Aktuelles Passwort behalten")
            print("[2] Neues Passwort eingeben")
            print("[3] Passwort generieren")
            pw_wahl = input("Wahl: ").strip()
            
            neues_passwort = None
            if pw_wahl == "2":
                neues_passwort = getpass.getpass("Neues Passwort: ")
            elif pw_wahl == "3":
                laenge = int(input("Länge (Standard 20): ") or "20")
                neues_passwort = pm.passwort_generieren(laenge)
                print(f"🔑 Generiert: {neues_passwort}")
            
            if pm.passwort_bearbeiten(name, neuer_name, neues_passwort, neuer_benutzer, neuer_url):
                print("✅ Eintrag aktualisiert!")
            else:
                print("❌ Fehler beim Bearbeiten!")
                
        elif wahl == "5":
            name = input("Name des zu löschenden Eintrags: ").strip()
            if name not in pm.eintraege:
                print("❌ Eintrag nicht gefunden!")
                continue
            
            bestaetigung = input(f"Wirklich '{name}' löschen? (ja/nein): ").strip().lower()
            if bestaetigung == "ja":
                if pm.passwort_loeschen(name):
                    print("✅ Eintrag gelöscht!")
                else:
                    print("❌ Fehler beim Löschen!")
            else:
                print("❌ Abgebrochen.")
                
        elif wahl == "6":
            laenge = int(input("Länge (Standard 20): ") or "20")
            print(f"🔑 Generiertes Passwort: {pm.passwort_generieren(laenge)}")
            
        elif wahl == "7":
            pm.speichern()
            print("💾 Gespeichert. Auf Wiedersehen! 👋")
            break
            
        else:
            print("❌ Ungültige Eingabe!")


if __name__ == "__main__":
    main()