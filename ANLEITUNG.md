# Vereinszentrale FC Sender Kickers United – Einrichtung

**Aufbau:** Die Seite (Ordner `docs/`) läuft kostenlos auf **GitHub Pages**. Die Daten liegen in einer **SQLite-Datenbank (Cloudflare D1)** in der EU. Login und Rechte prüft ein kleiner **Cloudflare Worker** (Ordner `worker/`), ebenfalls kostenlos.

```
Browser ──► GitHub Pages (docs/)          nur Oberfläche, keine Daten
   │
   └──────► Cloudflare Worker (worker/)   prüft Login + Rolle bei JEDER Anfrage
                 └──► D1 / SQLite (EU)    Einträge, Dokumente, Benutzer, Protokoll
```

## Rollen

| | Vorstand | Ausschuss | Admin (zusätzlich) |
|---|---|---|---|
| Satzung & Beschlüsse, Vorstand & Ausschuss, Gründungsplan, Offene Entscheidungen | lesen + bearbeiten | **unsichtbar** | – |
| Beiträge & Ehrenamt, Mannschaften, Elternkommunikation, Sponsoren, Kalender | lesen + bearbeiten | lesen + bearbeiten | – |
| Mitglieder, Eltern-Verteiler, Datei-Anhänge an Einträgen | lesen + bearbeiten | lesen + bearbeiten (in seinen Bereichen) | – |
| Einträge löschen | ✓ | ✗ | – |
| Dokumente, Änderungsprotokoll, JSON-Sicherung | ✓ | **unsichtbar** | – |
| Benutzer anlegen, Rollen vergeben, Passwörter zurücksetzen, deaktivieren | – | – | ✓ |

Admin ist nur zusammen mit der Rolle Vorstand möglich. Registrieren kann sich niemand selbst – nur Admins legen Konten an.

---

## Einmalige Einrichtung (ca. 30 Minuten)

### 1. Vorbereitung
- **Node.js** (LTS) installieren: https://nodejs.org
- Kostenloses **Cloudflare-Konto** anlegen: https://dash.cloudflare.com/sign-up (keine Kreditkarte nötig)
- Kostenloses **GitHub-Konto**

### 2. Server (Worker + Datenbank) einrichten
Im Terminal / in der Eingabeaufforderung im Ordner `worker`:

```bash
npm install
npx wrangler login
npx wrangler d1 create vereinszentrale --jurisdiction eu
```

Der letzte Befehl gibt eine `database_id` aus → in **`worker/wrangler.toml`** bei `database_id` eintragen.
(`--jurisdiction eu` sorgt dafür, dass die Datenbank nur in der EU gespeichert wird. Das lässt sich später nicht mehr ändern.)

In `wrangler.toml` bei `ALLOWED_ORIGINS` deine GitHub-Pages-Adresse eintragen, z. B.
`ALLOWED_ORIGINS = "https://deinname.github.io"`. Nur von dort darf die Seite den Server ansprechen.

### 3. Geheimnisse setzen
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
npx wrangler secret put PEPPER
```
Den ausgegebenen Zufallswert als PEPPER einfügen. **Gut aufbewahren** (z. B. im Passwortmanager des Vereins). Geht er verloren, funktionieren alle Passwörter nicht mehr.

```bash
npx wrangler secret put SETUP_TOKEN
```
Einen Einrichtungs-Code ausdenken (z. B. `Kickers-Start-2026!`). Den brauchst du nur einmal für Schritt 6.

### 4. Datenbank anlegen und Server veröffentlichen
```bash
npm run db:migrate
npx wrangler deploy
```
`deploy` zeigt die Server-Adresse, z. B. `https://sku-vereinszentrale-api.deinname.workers.dev`.

### 5. Seite auf GitHub Pages
1. In **`docs/config.js`** bei `API_URL` die Server-Adresse aus Schritt 4 eintragen.
2. Neues GitHub-Repository anlegen (z. B. `vereinszentrale`) und den **ganzen Ordner** hochladen (`docs/`, `worker/`, `ANLEITUNG.md`, `.gitignore`). Im Code stehen keine Passwörter oder Vereinsdaten.
3. Settings → Pages → *Deploy from a branch* → Branch `main`, Ordner **`/docs`** → Save.
4. Nach 1–2 Minuten: `https://deinname.github.io/vereinszentrale/`

### 6. Ersteinrichtung
Seite öffnen → **Ersteinrichtung** erscheint automatisch → Einrichtungs-Code + Namen und Passwörter für **Admin 1, 2 und 3** eingeben. Danach ist die Einrichtung gesperrt und kann nicht wiederholt werden.

### 7. Weitere Personen anlegen
Als Admin anmelden → **Benutzer** → **＋ Benutzer** → Rolle wählen. Die Seite erzeugt ein Startpasswort. Gib es persönlich oder telefonisch weiter, nicht per WhatsApp oder E-Mail. Beim ersten Login muss jede Person ein eigenes Passwort festlegen.

---

## Dateien hochladen, Mitglieder, Eltern-E-Mails

- **In jedem „＋ Eintrag“-Fenster** gibt es unten den Bereich *Datei*:
  - **PDF, Word, Bilder …** werden beim Speichern an den Eintrag angehängt (max. 10 MB) und auf der Karte als 📎 angezeigt.
  - **Excel (.xlsx) oder CSV:** Die Seite zeigt, wie viele Zeilen sie gefunden hat. Mit *Jede Zeile als eigenen Eintrag übernehmen* wird jede Zeile ein Eintrag im gewählten Bereich. Die Spalten (Titel/Mannschaft/Sponsor, Datum, Uhrzeit, Ort, Zuständig/Trainer, Status, Beschreibung) werden an der Überschrift erkannt. Alle anderen Spalten landen im Inhalt. Alternativ: *Nur als Datei anhängen*.
  - Alte **.xls**-Dateien bitte in Excel als **.xlsx** oder **.csv** speichern.
- **Mitglieder:** Von Hand mit *＋ Mitglied* oder als ganze Liste mit *CSV/Excel-Datei hochladen*. Erkannte Spalten: Vorname, Nachname (oder „Name“), Geburtsdatum, Mannschaft, E-Mail, Telefon, Mitglied seit, Status, Notiz. Wer schon in der Liste steht (gleicher Name + Geburtsdatum), wird nicht doppelt angelegt.
- **Elternkommunikation → Eltern-Verteiler:** Eltern mit E-Mail-Adresse eintragen oder importieren. Auf jeder Nachricht gibt es den Knopf *✉ Per E-Mail an Eltern*. Damit öffnet sich dein E-Mail-Programm mit Betreff, Text und allen Eltern (oder nur einer Mannschaft) im **BCC**. Bei sehr vielen Adressen werden sie in die Zwischenablage kopiert und du fügst sie selbst bei BCC ein.

**Datenschutz:** Mitglieder- und Elterndaten sind personenbezogen. Nur eintragen, was der Verein braucht. Ausgetretene Mitglieder auf Status *Ausgetreten* setzen oder löschen (lassen).

---

## Sicherheit – was eingebaut ist
- Passwörter werden im Browser mit PBKDF2 (250.000 Runden) gestreckt und auf dem Server zusätzlich mit geheimem PEPPER + PBKDF2 und Zufalls-Salt gehasht. Klartext-Passwörter werden nirgends gespeichert.
- Nach 5 Fehlversuchen ist das Konto für 15 Minuten gesperrt.
- Anmeldung gilt 12 Stunden (bzw. 30 Tage mit „angemeldet bleiben“). Ohne „angemeldet bleiben“ erfolgt nach 60 Minuten Inaktivität eine automatische Abmeldung.
- Rollenprüfung findet **auf dem Server** statt: Ein Ausschussmitglied bekommt gesperrte Daten auch mit technischen Tricks nicht.
- Nur die eigene Seite darf den Server ansprechen (CORS), Suchmaschinen sollen die Seite nicht aufnehmen (`noindex`).
- Passwortänderung, Deaktivieren oder Rollenwechsel beenden die laufenden Anmeldungen des Kontos.

## Kostenlose Grenzen (Cloudflare Free)
100.000 Anfragen pro Tag, 5 Mio. Datenbank-Lesezugriffe und 100.000 Schreibzugriffe pro Tag, 5 GB Speicher. Für einen Verein reicht das bei weitem. Dateien sind auf 10 MB pro Dokument begrenzt.

## Sicherungen
- **In der App:** Mein Konto → *Sicherung (JSON)* (nur Vorstand)
- **Komplette SQL-Sicherung:** im Ordner `worker`: `npm run db:backup` → `backup.sql` (nicht ins Repository hochladen!)
- **Zeitreise:** Cloudflare D1 kann die Datenbank im Free-Tarif auf jeden Zeitpunkt der letzten 7 Tage zurücksetzen: `npx wrangler d1 time-travel restore vereinszentrale --timestamp=...`

## Eigene Domain (optional, ca. 5 €/Jahr)
1. .de-Domain kaufen (z. B. INWX, netcup) und die Nameserver auf Cloudflare umstellen (Cloudflare → *Add a site*, kostenlos).
2. Seite: in GitHub Pages → *Custom domain* `www.deine-domain.de` eintragen, bei Cloudflare einen CNAME `www` → `deinname.github.io` anlegen.
3. Server: Cloudflare → Workers → *sku-vereinszentrale-api* → *Domains & Routes* → `api.deine-domain.de` hinzufügen.
4. `ALLOWED_ORIGINS` um `https://www.deine-domain.de` ergänzen, `docs/config.js` auf `https://api.deine-domain.de` ändern, `npx wrangler deploy`.

## Datenschutz (kein Rechtsrat)
- In die **Datenschutzerklärung** aufnehmen: GitHub (Hosting der Seite) und Cloudflare (Server und Datenbank, Speicherort EU).
- Cloudflare stellt einen Auftragsverarbeitungsvertrag (DPA) für alle Kunden bereit. Den im Dashboard nachlesen und intern dokumentieren.
- Nur nötige Daten speichern. Telefonnummern und Adressen von Eltern und Kindern möglichst nicht in Freitexte schreiben.
- Ausgeschiedene Personen sofort **deaktivieren**.

## Lokal testen
```bash
cd worker
cp .dev.vars.example .dev.vars        # Werte eintragen
npm run db:migrate:local
npm run dev                           # Server auf http://localhost:8787
```
Zweites Terminal: `cd docs && python -m http.server 8000`. In `docs/config.js` vorübergehend `http://localhost:8787` eintragen und `http://localhost:8000` öffnen.
