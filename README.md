# 🔐 Passwort-Manager

&gt; Ein simpler, lokaler Passwort-Manager mit Browser-Integration. Kein Cloud-Zeug, keine Abos – deine Daten bleiben auf deinem Rechner.

---

## Was ist das?

Ich hab das gebaut, weil ich wissen wollte, wie Passwort-Manager eigentlich funktionieren. Statt 1Password oder Bitwarden zu nutzen, wollte ich selbst verstehen, wie die Verschlüsselung funktioniert und wie man so was sicher baut.

**Achtung:** Das ist ein Lernprojekt. Für den produktiven Alltag würde ich trotzdem Bitwarden oder 1Password empfehlen. Aber für's Verständnis ist es super.

---

## Features

- **AES-256-GCM** Verschlüsselung mit **Argon2id** Schlüsselableitung
- Lokale verschlüsselte Datenbank (JSON-Datei)
- CLI zum Verwalten deiner Passwörter
- GUI mit Dark Mode (Tkinter)
- Chrome/Edge Extension mit **Auto-Fill** auf Webseiten
- Passwort-Generator
- Einträge bearbeiten & löschen

---

## Tech Stack

| Teil | Technologie |
|------|-------------|
| Backend | Python 3.14 |
| Krypto | `cryptography` (AES-GCM), `argon2-cffi` |
| GUI | Tkinter (Dark Mode) |
| Browser-Extension | Manifest V3, Native Messaging |
| Datenbank | Verschlüsselte JSON-Datei |

---

## Installation

### 1. Repo klonen

```bash
git clone https://github.com/phylo04/passwort-manager.git
cd passwort-manager

