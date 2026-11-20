-- Vereinszentrale · Erweiterung: Rolle Trainer, Zusatzrecht Schatzmeister, Mannschaftsliste, Kasse
--
-- benutzer.rolle hat einen CHECK-Constraint, den SQLite nicht ändern kann → Tabelle neu aufbauen.
-- ACHTUNG: sitzungen und zusagen verweisen mit ON DELETE CASCADE auf benutzer. Beim DROP TABLE benutzer
-- würden deren Zeilen mitgelöscht. Deshalb vorher sichern und danach zurückspielen.

-- 1. Abhängige Daten sichern
CREATE TABLE _sicherung_sitzungen AS SELECT * FROM sitzungen;
CREATE TABLE _sicherung_zusagen AS SELECT * FROM zusagen;

-- 2. Neue Benutzertabelle (gleiche Spalten + ist_schatzmeister, Rolle trainer)
CREATE TABLE benutzer_neu (
  id            TEXT PRIMARY KEY,
  benutzername  TEXT NOT NULL UNIQUE COLLATE NOCASE,
  anzeigename   TEXT NOT NULL,
  rolle         TEXT NOT NULL CHECK (rolle IN ('vorstand','ausschuss','trainer')),
  ist_admin     INTEGER NOT NULL DEFAULT 0,
  ist_schatzmeister INTEGER NOT NULL DEFAULT 0,
  aktiv         INTEGER NOT NULL DEFAULT 1,
  pw_hash       TEXT NOT NULL,
  pw_salt       TEXT NOT NULL,
  pw_iter       INTEGER NOT NULL,
  pw_aendern    INTEGER NOT NULL DEFAULT 1,
  fehlversuche  INTEGER NOT NULL DEFAULT 0,
  gesperrt_bis  TEXT,
  letzter_login TEXT,
  erstellt      TEXT NOT NULL
);
INSERT INTO benutzer_neu (id,benutzername,anzeigename,rolle,ist_admin,ist_schatzmeister,aktiv,pw_hash,pw_salt,pw_iter,pw_aendern,fehlversuche,gesperrt_bis,letzter_login,erstellt)
  SELECT id,benutzername,anzeigename,rolle,ist_admin,0,aktiv,pw_hash,pw_salt,pw_iter,pw_aendern,fehlversuche,gesperrt_bis,letzter_login,erstellt FROM benutzer;

-- 3. Austauschen (Fremdschlüssel in sitzungen/zusagen heißen weiter "benutzer" und zeigen danach auf die neue Tabelle)
DROP TABLE benutzer;
ALTER TABLE benutzer_neu RENAME TO benutzer;

-- 4. Gesicherte Daten zurückspielen und Sicherung entfernen
INSERT OR IGNORE INTO sitzungen SELECT * FROM _sicherung_sitzungen;
INSERT OR IGNORE INTO zusagen SELECT * FROM _sicherung_zusagen;
DROP TABLE _sicherung_sitzungen;
DROP TABLE _sicherung_zusagen;

-- 5. Mannschaftsliste + Zuordnung Trainer ↔ Mannschaft
CREATE TABLE mannschaften (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
  sortierung INTEGER NOT NULL DEFAULT 0,
  aktiv      INTEGER NOT NULL DEFAULT 1,
  erstellt   TEXT NOT NULL,
  geaendert  TEXT NOT NULL
);
CREATE TABLE trainer_mannschaften (
  benutzer_id   TEXT NOT NULL REFERENCES benutzer(id) ON DELETE CASCADE,
  mannschaft_id TEXT NOT NULL REFERENCES mannschaften(id) ON DELETE CASCADE,
  PRIMARY KEY (benutzer_id, mannschaft_id)
);
CREATE INDEX ix_trainer_mannschaften_m ON trainer_mannschaften(mannschaft_id);

ALTER TABLE eintraege ADD COLUMN fuer_trainer INTEGER NOT NULL DEFAULT 0;
ALTER TABLE eintraege ADD COLUMN mannschaft_id TEXT NOT NULL DEFAULT '';
ALTER TABLE mitglieder ADD COLUMN mannschaft_id TEXT NOT NULL DEFAULT '';
ALTER TABLE eltern ADD COLUMN mannschaft_id TEXT NOT NULL DEFAULT '';

-- Startliste aus den vorhandenen Freitext-Werten. Die ID ist der normalisierte Name
-- (klein, ohne Leerzeichen/Bindestriche) → „U 11“, „u11“, „U-11“ werden eine Mannschaft.
INSERT OR IGNORE INTO mannschaften (id, name, sortierung, aktiv, erstellt, geaendert)
  SELECT 'm_' || lower(replace(replace(m, ' ', ''), '-', '')), m, 0, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now')
  FROM (SELECT trim(mannschaft) AS m FROM mitglieder WHERE trim(mannschaft) <> ''
        UNION SELECT trim(mannschaft) FROM eltern WHERE trim(mannschaft) <> '')
  ORDER BY m;
UPDATE mitglieder SET mannschaft_id = 'm_' || lower(replace(replace(trim(mannschaft), ' ', ''), '-', ''))
  WHERE trim(mannschaft) <> '' AND ('m_' || lower(replace(replace(trim(mannschaft), ' ', ''), '-', ''))) IN (SELECT id FROM mannschaften);
UPDATE eltern SET mannschaft_id = 'm_' || lower(replace(replace(trim(mannschaft), ' ', ''), '-', ''))
  WHERE trim(mannschaft) <> '' AND ('m_' || lower(replace(replace(trim(mannschaft), ' ', ''), '-', ''))) IN (SELECT id FROM mannschaften);

-- 6. Kasse: Buchungen werden nie gelöscht, nur storniert. Belegnummer K-<jahr>-<lfd>, lückenlos je Jahr.
CREATE TABLE kassenbuchungen (
  id           TEXT PRIMARY KEY,
  jahr         INTEGER NOT NULL,
  lfd          INTEGER NOT NULL,
  belegnr      TEXT NOT NULL UNIQUE,
  datum        TEXT NOT NULL,
  art          TEXT NOT NULL CHECK (art IN ('einnahme','ausgabe')),
  betrag       INTEGER NOT NULL CHECK (betrag > 0),   -- Cent
  kategorie    TEXT NOT NULL,
  beschreibung TEXT NOT NULL DEFAULT '',
  zahlungsweg  TEXT NOT NULL CHECK (zahlungsweg IN ('bar','bank')),
  rechnung_id  TEXT NOT NULL DEFAULT '',
  rechnung_nr  TEXT NOT NULL DEFAULT '',
  storniert    INTEGER NOT NULL DEFAULT 0,
  storno_grund TEXT NOT NULL DEFAULT '',
  storno_am    TEXT NOT NULL DEFAULT '',
  storno_von   TEXT NOT NULL DEFAULT '',
  erstellt     TEXT NOT NULL,
  erstellt_von TEXT NOT NULL DEFAULT '',
  UNIQUE (jahr, lfd)
);
CREATE INDEX ix_kasse_datum ON kassenbuchungen(datum);
CREATE INDEX ix_kasse_rechnung ON kassenbuchungen(rechnung_id);

CREATE TABLE kassen_belege (
  id           TEXT PRIMARY KEY,
  buchung_id   TEXT NOT NULL REFERENCES kassenbuchungen(id),
  dateiname    TEXT NOT NULL,
  mime         TEXT NOT NULL DEFAULT '',
  groesse      INTEGER NOT NULL DEFAULT 0,
  erstellt     TEXT NOT NULL,
  erstellt_von TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_kassen_belege_buchung ON kassen_belege(buchung_id);
CREATE TABLE kassen_beleg_teile (
  beleg_id TEXT NOT NULL REFERENCES kassen_belege(id) ON DELETE CASCADE,
  nr       INTEGER NOT NULL,
  daten    BLOB NOT NULL,
  PRIMARY KEY (beleg_id, nr)
);
