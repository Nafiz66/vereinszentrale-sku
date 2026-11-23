# Vereinszentrale FC Sender Kickers United – Einrichtung

**Aufbau:** Die Seite (Ordner `docs/`) läuft kostenlos auf **GitHub Pages**. Die Daten liegen in einer **SQLite-Datenbank (Cloudflare D1)** in der EU. Login und Rechte prüft ein kleiner **Cloudflare Worker** (Ordner `worker/`), ebenfalls kostenlos.

```
Browser ──► GitHub Pages (docs/)          nur Oberfläche, keine Daten
   │
   └──────► Cloudflare Worker (worker/)   prüft Login + Rolle bei JEDER Anfrage
                 └──► D1 / SQLite (EU)    Einträge, Dokumente, Benutzer, Protokoll
```

## Rollen, Funktionen und Rechte (ab Version 6)

Jedes Konto hat **eine Grundrolle** und **beliebig viele Vereinsfunktionen**:

- **Grundrollen:** Vorstand · Ausschuss · Trainer · Helfer (ohne Gremium, z. B. Festwirt-Team)
- **Funktionen** (Startliste, Admins können eigene anlegen, umbenennen, deaktivieren):
  - *Vorstand:* 1./2. Vorsitzende/r, Schatzmeister/in (Kassenwart), Schriftführer/in, Jugendleiter/in, Sportliche Leitung, Mitgliederverwaltung
  - *Ausschuss:* Ausschussbeisitzer/in, Pressewart/Öffentlichkeitsarbeit, Sponsoring-Beauftragte/r, Ehrenamtskoordination, Platz- und Gerätewart, Schiedsrichter-Obmann, Elternvertreter/in, Datenschutzbeauftragte/r, Kassenprüfer/in
  - *Sport:* Trainer/in, Co-Trainer/in, Betreuer/in · *Fest:* Festwirt/in (Leitung), Festwirt-Team
- **Admin** ist ein Zusatzrecht (nur mit Grundrolle Vorstand): Benutzer, Funktionen, Rechte, Chat-Räume – und überall alle Rechte.

**Rechte-Matrix** (*Benutzer → Rechte*, nur Admins): Für jede Grundrolle und Funktion × jeden Bereich gibt es eine Stufe:
**– keine** (Bereich ist komplett unsichtbar – auch in Menü, Suche, Kalender, Übersicht, Export) · **L lesen** · **B bearbeiten** · **X löschen**.
Wer mehrere Funktionen hat, bekommt die **höchste** Stufe. Änderungen wirken sofort. Bereiche: die 9 bisherigen, **Festwirtschaft**, Mitglieder, Downloads, Dokumente, Änderungsprotokoll.

Startwerte: Vorstand wie bisher (alles, Festwirtschaft lesen) · Ausschuss wie bisher · Festwirt/in: Festwirtschaft löschen · Festwirt-Team: Festwirtschaft bearbeiten · Jugendleiter/in: Mannschaften, Elternkommunikation, Mitglieder bearbeiten · Mitgliederverwaltung: Mitglieder löschen · Sponsoring-Beauftragte/r: Sponsoren · Ehrenamtskoordination: Beiträge & Ehrenamt · Pressewart: Downloads.

**Feste Regeln** (nicht über die Matrix änderbar, der Server erzwingt sie):

| Regel | Wer |
|---|---|
| **Rechnungen und Kasse** | nur Admins und Schatzmeister/in (anlegen, buchen). **Stornieren nur Schatzmeister/in.** Kassenprüfer/in nur lesen, wenn unter *Rechte* eingeschaltet (Standard: aus) |
| Benutzer, Funktionen, Rechte-Matrix, JSON-Sicherung | nur Admins |
| Vorstandsbereiche (Satzung, Vorstand, Gründungsplan, Entscheidungen, Dokumente, Protokoll) | nie für Trainer, Co-Trainer, Betreuer, Festwirt-Team, Helfer (in der Matrix grau) |
| **Eltern-Kontakte** | nur Admins, Jugendleiter/in und Trainer/Co-Trainer/Betreuer der jeweiligen Mannschaft – E-Mails nur mit Einwilligung |
| Trainer-Weg | Einträge mit „🏃 Für Trainer sichtbar“ (ggf. nur eine Mannschaft) + eigene Mannschaft (Vorname, Nachname, Alter, Status) |

Was jemand nicht lesen darf, liefert der Server mit **404 „Nicht gefunden“** (die Existenz wird nicht verraten). Lesen erlaubt, aber nicht bearbeiten → 403.
Registrieren kann sich niemand selbst – nur Admins (und für ihr Team der Festwirt) legen Konten an.

**Festwirt/in (Leitung)** hat den Reiter **Mein Team**: Konten anlegen, deaktivieren, Passwort zurücksetzen – aber **nur** für Konten mit Grundrolle Helfer und genau der Funktion Festwirt-Team (beliebig viele). Er sieht nur diese Konten. Das Festwirt-Team selbst darf niemanden anlegen. Im Protokoll steht, wer wen angelegt hat.

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

- **Wer sieht was?** Im Eintrag-Fenster steht, ob nur der Vorstand (🔒) oder auch der Ausschuss (👥) den Eintrag sieht. Termine für alle gehören in den Bereich **Kalender**. Achtung: Der Bereich „Vorstand & Ausschuss“ ist trotz seines Namens **nur für den Vorstand** sichtbar.
- **Zu- und Absagen:** Mit dem Häkchen *Rückmeldung erwünscht* bekommt ein Eintrag die Knöpfe *✓ Ich nehme teil / ? Vielleicht / ✗ Leider nicht*. Im aufklappbaren Bereich darunter steht, wer zugesagt hat und wer noch nicht geantwortet hat. Offene Antworten erscheinen auf der **Übersicht** unter *Deine Rückmeldung fehlt*. Ein zweiter Klick auf die eigene Antwort nimmt sie zurück.

- **Downloads** (laut Rechte-Matrix, Standard: Vorstand + Ausschuss, nur nach Login): Dateien in den Kategorien Formulare, Sponsoren, Logos & Werbematerial, Sonstiges hochladen. Löschen darf nur der Vorstand. Fertig eingebaut: **Mitgliedsantrag** (mit SEPA-Mandat, Einwilligungen; zum Drucken oder als PDF) und **Logo-Paket**. Hinweis: Das vorhandene Logo hat nur 400 × 400 Pixel. Für Druckereien eine Vektordatei (SVG/PDF/EPS) vom Designer besorgen und hochladen.
- **Rechnungen / Rechnung erstellen** (ab Version 6: nur Admins und Schatzmeister/in): Die Rechnungsnummer **SKU-Jahr-laufende Nummer** (z. B. SKU-2026-0001) wird beim Erstellen automatisch und lückenlos vergeben und kann nicht geändert werden. Fest sind außerdem Vereinsname und Logo. Alles andere ist frei: Empfänger, Positionen, MwSt.-Satz je Position (auch 0 %), Zahlungsziel, Texte, Absender, Bank, Ersteller. Die Standardwerte stehen unter **Vereinsdaten & Vorlage**. Rechnungen werden nie gelöscht. Sie werden nur **storniert** (nur Vorstand), denn so verlangt es die Buchhaltung. *Drucken / als PDF speichern* erzeugt eine A4-Rechnung. Im Druckfenster „Als PDF speichern“ wählen.

## Mannschaftsliste, Trainer, Kasse

- **Mannschaftsliste** (Reiter *Mitglieder* → „Mannschaftsliste“, pflegt nur der Vorstand): Mannschaften anlegen, umbenennen, sortieren, deaktivieren. Bei Mitgliedern und Eltern wird die Mannschaft aus dieser Liste gewählt. Beim Excel/CSV-Import wird über den Namen zugeordnet (Groß-/Kleinschreibung, Leerzeichen und Bindestriche egal: „u 11“ = „U11“). Unbekannte Namen werden in der Vorschau mit ⚠ markiert und erscheinen danach unter **„Nicht zugeordnet“**. Dort kann man sie einer Mannschaft zuordnen oder als neue Mannschaft anlegen.
- **Termine für Trainer:** Im Eintrag-Fenster gibt es **„🏃 Für Trainer sichtbar“** und darunter die Auswahl „Alle Trainer“ oder „Nur Trainer von …“. Das geht nur in Bereichen, die auch der Ausschuss sieht. Vorstands-Bereiche bleiben immer verborgen. Die Liste „noch offen“ bei Zu-/Absagen enthält nur Personen, die den Termin wirklich sehen.
- **Kasse** (im Menü über *Rechnungen*): Kassenbuch mit Einnahmen und Ausgaben, Kategorie, Bar oder Bank, Beleg (PDF/Bild) und Bezug zu einer Rechnung. Die **Belegnummer K-Jahr-0001** wird automatisch und lückenlos vergeben. Buchungen werden **nie gelöscht oder geändert**, nur mit Grund storniert. Oben stehen Kassenstand Bar, Kontostand Bank sowie Einnahmen und Ausgaben des Jahres. Unter *Einstellungen* (nur Schatzmeister) stehen die Anfangsbestände mit Stichtag und die Kategorien. *CSV* exportiert die gefilterte Auswahl, z. B. ein ganzes Jahr für den Steuerberater. Wird eine Rechnung auf *Bezahlt* gesetzt, fragt die Seite den Schatzmeister, ob eine Einnahme gebucht werden soll.
- **JSON-Sicherung:** Sie enthält jetzt auch Mannschaften, Trainer-Zuordnungen, Konten (ohne Passwörter), Kassenbuchungen und Kasse-Einstellungen. Beim Import werden Mannschaften über den Namen ergänzt. **Rechnungen und Kassenbuchungen** werden nur in eine **leere** Liste zurückgespielt, mit ihren festen Nummern (Kasse nur durch den Schatzmeister). Dateien (Anhänge, Downloads, Belege) und Konten sind nicht in der Sicherung.

**Migration auf Version 5** (einmalig, im Ordner `worker`, Reihenfolge einhalten):

```bash
npm run db:backup                                              # Sicherung → backup.sql (nicht hochladen!)
npx.cmd wrangler d1 migrations apply vereinszentrale --remote  # baut u. a. die Benutzertabelle neu auf
npx.cmd wrangler deploy                                        # neuer Server
```

Danach die Seite (Ordner `docs/`) zu GitHub hochladen. Die Migration behält alle Konten, Anmeldungen und Zusagen und legt aus den vorhandenen Mannschafts-Namen die Mannschaftsliste an.

## Chat, Festwirtschaft, WhatsApp (ab Version 6)

- **Chat** (Reiter *Chat*): Räume mit Name und Beschreibung. Mitglied ist, wer zur gewählten Grundrolle oder Funktion gehört oder einzeln eingetragen ist (oder „alle angemeldeten“). Wer kein Mitglied ist, sieht den Raum gar nicht.
  - Standardräume: *Alle – Beschlüsse & Infos*, *Vorstand*, *Ausschuss*, *Trainer* (Trainer, Co-Trainer, Betreuer), *Festwirtschaft* (Festwirt/in + Festwirt-Team).
  - Räume anlegen: Admins (alle Räume) · Festwirt/in (nur Räume für sein Festwirt-Team). **Admins verwalten Räume, lesen Nachrichten aber nur, wenn sie selbst Mitglied sind.**
  - Eigene Nachricht bearbeiten/löschen; Raum-Admin (Ersteller bzw. Admin, der Mitglied ist) darf Nachrichten entfernen. Ungelesen-Zähler im Menü und je Raum, **@Name** wird hervorgehoben. Max. 4000 Zeichen, keine Dateien (dafür Downloads/Dokumente nutzen).
  - Neue Nachrichten werden alle 5 Sekunden abgeholt (offener Chat), die Zähler alle 30 Sekunden – kostenlos, ohne Zusatzdienste.
  - **Aufbewahrung:** Nachrichten älter als 12 Monate löscht der Server automatisch (täglich um 3:17 Uhr UTC, Cron Trigger in `wrangler.toml`). Chat-Nachrichten sind bewusst **nicht** in der JSON-Sicherung.
- **Festwirtschaft:** eigener Bereich für Planung, Einkauf, Schichtplan, Helferliste (Einträge mit Datum erscheinen im Kalender).
- **WhatsApp – kostenlos, ohne WhatsApp Business:**
  - In der **Mannschaftsliste** pro Mannschaft den **Gruppen-Einladungslink** hinterlegen (WhatsApp → Gruppe → Gruppeninfo → *Per Link einladen* → Link kopieren, Form `https://chat.whatsapp.com/…`).
  - Knopf **„💬 WhatsApp-Gruppe …“** in Elternkommunikation und *Meine Mannschaft* öffnet die Gruppe.
  - **„💬 Per WhatsApp teilen“** an jeder Nachricht der Elternkommunikation öffnet WhatsApp mit dem fertigen Text.
  - **„✉ Per E-Mail an Eltern“** öffnet das eigene E-Mail-Programm, alle Empfänger im **BCC**.
- **Eltern-E-Mails nur mit Einwilligung:** Häkchen + Datum im Eltern-Fenster. Ohne Einwilligung keine E-Mail und für Trainer unsichtbar. Am besten gar keine Kontaktdaten speichern und nur die WhatsApp-Gruppenlinks nutzen.
- **Handy:** große Knöpfe, Chat im Vollbild mit Zurück-Pfeil, Tabellen scrollen seitlich.

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
- **In der App:** Mein Konto → *Sicherung (JSON)* (nur Admins)
- **Komplette SQL-Sicherung:** im Ordner `worker`: `npm.cmd run db:backup` → `backup.sql` (nicht ins Repository hochladen! Enthält persönliche Daten.)
- **Zeitreise (am einfachsten):** Cloudflare D1 kann die Datenbank im Free-Tarif auf jeden Zeitpunkt der letzten 7 Tage zurücksetzen: `npx.cmd wrangler d1 time-travel restore vereinszentrale --timestamp=...`
- **SQL-Sicherung wieder einspielen:** Die Datei aus `wrangler d1 export` lässt sich **nicht direkt** einspielen (Tabellen in falscher Reihenfolge, große Dateien über der 100-KB-Grenze von D1). Deshalb vorher sortieren:

  ```bash
  node tools/sicherung-sortieren.mjs backup.sql backup_sortiert.sql
  npx.cmd wrangler d1 execute vereinszentrale --local --file=backup_sortiert.sql   # erst lokal ausprobieren!
  ```

  Getestet: alle Tabellen, Konten, Anmeldungen und hochgeladenen Dateien kommen byte-genau zurück. In eine bestehende (nicht leere) Datenbank nicht einspielen – dafür die Zeitreise nutzen.

**Migration auf Version 6** (einmalig, im Ordner `worker`, Reihenfolge einhalten):

```bash
npx.cmd wrangler d1 export vereinszentrale --remote --output=backup_vorher.sql   # Sicherung (nicht hochladen!)
npx.cmd wrangler d1 migrations apply vereinszentrale --remote                    # Funktionen, Rechte, Chat …
npx.cmd wrangler deploy                                                          # neuer Server + täglicher Cron
```

Danach `docs/` zu GitHub hochladen. Die Migration baut die Benutzertabelle neu auf und behält dabei alle Konten, Anmeldungen, Zusagen und Trainer-Zuordnungen. Das Schatzmeister-Recht wird zur Funktion „Schatzmeister/in“, Trainer bekommen die Funktion „Trainer/in“. **Achtung:** Vorstand ohne Admin und Ausschuss sehen danach **keine Rechnungen und keine Kasse** mehr (feste Regel), und Eltern-Kontakte nur noch Admins, Jugendleitung und Trainer.

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
