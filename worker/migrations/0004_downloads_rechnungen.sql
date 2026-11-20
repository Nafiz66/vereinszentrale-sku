-- Vereinszentrale · Erweiterung: Downloads (Formulare, Logos, Sponsoren), Rechnungen, Vereinsdaten

CREATE TABLE downloads (
  id           TEXT PRIMARY KEY,
  titel        TEXT NOT NULL,
  kategorie    TEXT NOT NULL,
  beschreibung TEXT NOT NULL DEFAULT '',
  dateiname    TEXT NOT NULL DEFAULT '',
  mime         TEXT NOT NULL DEFAULT '',
  groesse      INTEGER NOT NULL DEFAULT 0,
  erstellt     TEXT NOT NULL,
  geaendert    TEXT NOT NULL,
  geaendert_von TEXT NOT NULL DEFAULT ''
);

CREATE TABLE download_teile (
  download_id TEXT NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
  nr          INTEGER NOT NULL,
  daten       BLOB NOT NULL,
  PRIMARY KEY (download_id, nr)
);

-- Rechnungsnummer: SKU-<jahr>-<lfd 4-stellig>, fortlaufend je Jahr, nie doppelt, nie löschbar (nur stornieren)
CREATE TABLE rechnungen (
  id             TEXT PRIMARY KEY,
  jahr           INTEGER NOT NULL,
  lfd            INTEGER NOT NULL,
  nummer         TEXT NOT NULL UNIQUE,
  datum          TEXT NOT NULL,
  leistungsdatum TEXT NOT NULL DEFAULT '',
  faellig        TEXT NOT NULL DEFAULT '',
  empfaenger     TEXT NOT NULL,
  betreff        TEXT NOT NULL DEFAULT '',
  einleitung     TEXT NOT NULL DEFAULT '',
  positionen     TEXT NOT NULL,          -- JSON: [{beschreibung, menge, einheit, preis (Cent, netto), mwst (%)}]
  schlusstext    TEXT NOT NULL DEFAULT '',
  absender       TEXT NOT NULL,          -- JSON: Vereinsdaten zum Zeitpunkt der Rechnung (Adresse, Bank, Steuernr., Ersteller …)
  netto          INTEGER NOT NULL,       -- Cent
  steuer         INTEGER NOT NULL,       -- Cent
  brutto         INTEGER NOT NULL,       -- Cent
  status         TEXT NOT NULL DEFAULT 'Offen' CHECK (status IN ('Offen','Bezahlt','Storniert')),
  bezahlt_am     TEXT NOT NULL DEFAULT '',
  erstellt       TEXT NOT NULL,
  erstellt_von   TEXT NOT NULL DEFAULT '',
  geaendert      TEXT NOT NULL,
  geaendert_von  TEXT NOT NULL DEFAULT '',
  UNIQUE (jahr, lfd)
);
CREATE INDEX ix_rechnungen_datum ON rechnungen(datum);

CREATE TABLE einstellungen (
  schluessel TEXT PRIMARY KEY,
  wert       TEXT NOT NULL,              -- JSON
  geaendert  TEXT NOT NULL,
  geaendert_von TEXT NOT NULL DEFAULT ''
);
