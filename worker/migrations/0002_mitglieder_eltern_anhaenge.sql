-- Vereinszentrale · Erweiterung: Mitglieder, Eltern-Verteiler, Datei-Anhänge an Einträgen

CREATE TABLE mitglieder (
  id            TEXT PRIMARY KEY,
  vorname       TEXT NOT NULL DEFAULT '',
  nachname      TEXT NOT NULL DEFAULT '',
  geburtsdatum  TEXT NOT NULL DEFAULT '',
  mannschaft    TEXT NOT NULL DEFAULT '',
  email         TEXT NOT NULL DEFAULT '',
  telefon       TEXT NOT NULL DEFAULT '',
  eintritt      TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'Aktiv',
  notiz         TEXT NOT NULL DEFAULT '',
  erstellt      TEXT NOT NULL,
  geaendert     TEXT NOT NULL,
  geaendert_von TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_mitglieder_name ON mitglieder(nachname, vorname);

CREATE TABLE eltern (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL DEFAULT '',
  email         TEXT NOT NULL COLLATE NOCASE,
  kind          TEXT NOT NULL DEFAULT '',
  mannschaft    TEXT NOT NULL DEFAULT '',
  notiz         TEXT NOT NULL DEFAULT '',
  erstellt      TEXT NOT NULL,
  geaendert     TEXT NOT NULL,
  geaendert_von TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_eltern_email ON eltern(email);

CREATE TABLE anhaenge (
  id           TEXT PRIMARY KEY,
  eintrag_id   TEXT NOT NULL REFERENCES eintraege(id) ON DELETE CASCADE,
  dateiname    TEXT NOT NULL,
  mime         TEXT NOT NULL DEFAULT '',
  groesse      INTEGER NOT NULL DEFAULT 0,
  erstellt     TEXT NOT NULL,
  erstellt_von TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_anhaenge_eintrag ON anhaenge(eintrag_id);

-- Dateien in Stücken (max. 1 MB), wie bei den Dokumenten
CREATE TABLE anhang_teile (
  anhang_id TEXT NOT NULL REFERENCES anhaenge(id) ON DELETE CASCADE,
  nr        INTEGER NOT NULL,
  daten     BLOB NOT NULL,
  PRIMARY KEY (anhang_id, nr)
);
