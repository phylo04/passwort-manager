import sys
import json
import struct
import os
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def send_message(message):
    """Sendet JSON-Nachricht an den Browser."""
    encoded = json.dumps(message).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('I', len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def read_message():
    """Liest JSON-Nachricht vom Browser."""
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    length = struct.unpack('I', raw_length)[0]
    message = sys.stdin.buffer.read(length).decode('utf-8')
    return json.loads(message)


class NativePasswortManager:
    def __init__(self):
        self.schluessel = None
        self.eintraege = {}
        self.entsperrt = False

    def entsperren(self, master_passwort):
        """Datenbank entsperren."""
        try:
            with open('salt.bin', 'rb') as f:
                salt = f.read()
            
            kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
            self.schluessel = kdf.derive(master_passwort.encode('utf-8'))
            
            with open('passwoerter.enc', 'rb') as f:
                data = f.read()
            
            aesgcm = AESGCM(self.schluessel)
            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            self.eintraege = json.loads(plaintext.decode('utf-8'))['eintraege']
            self.entsperrt = True
            return True
        except Exception:
            return False

    def suche_url(self, url):
        """Sucht Einträge, die zur URL passen."""
        if not self.entsperrt:
            return []
        
        ergebnisse = []
        for name, eintrag in self.eintraege.items():
            eintrag_url = eintrag.get('url', '')
            # Einfache Übereinstimmung: Domain extrahieren
            if eintrag_url and self._domain_match(url, eintrag_url):
                ergebnisse.append({
                    'name': name,
                    'benutzername': eintrag['benutzername'],
                    'passwort': eintrag['passwort']
                })
        return ergebnisse

    def _domain_match(self, browser_url, eintrag_url):
        """Prüft, ob Domains übereinstimmen (vereinfacht)."""
        # Entferne Protokoll und www
        def clean(url):
            url = url.lower()
            url = url.replace('https://', '').replace('http://', '')
            url = url.replace('www.', '')
            url = url.split('/')[0]  # Nur Domain
            return url
        
        return clean(browser_url) in clean(eintrag_url) or clean(eintrag_url) in clean(browser_url)


def main():
    pm = NativePasswortManager()
    
    while True:
        message = read_message()
        if message is None:
            break
        
        action = message.get('action')
        response = {'status': 'error', 'message': 'Unbekannte Aktion'}
        
        if action == 'unlock':
            if pm.entsperren(message.get('password', '')):
                response = {'status': 'success', 'message': 'Entsperrt'}
            else:
                response = {'status': 'error', 'message': 'Falsches Passwort'}
        
        elif action == 'get_passwords':
            if not pm.entsperrt:
                response = {'status': 'error', 'message': 'Nicht entsperrt'}
            else:
                url = message.get('url', '')
                passwoerter = pm.suche_url(url)
                response = {
                    'status': 'success',
                    'passwoerter': passwoerter
                }
        
        elif action == 'ping':
            response = {'status': 'success', 'message': 'pong'}
        
        send_message(response)


if __name__ == '__main__':
    main()