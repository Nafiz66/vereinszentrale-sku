-- Vereinszentrale · Erweiterung: Rückmeldung (Zusage/Absage) zu Terminen und Einträgen

ALTER TABLE eintraege ADD COLUMN rueckmeldung INTEGER NOT NULL DEFAULT 0;

CREATE TABLE zusagen (
  eintrag_id  TEXT NOT NULL REFERENCES eintraege(id) ON DELETE CASCADE,
  benutzer_id TEXT NOT NULL REFERENCES benutzer(id) ON DELETE CASCADE,
  antwort     TEXT NOT NULL CHECK (antwort IN ('ja','vielleicht','nein')),
  geaendert   TEXT NOT NULL,
  PRIMARY KEY (eintrag_id, benutzer_id)
);
CREATE INDEX ix_zusagen_benutzer ON zusagen(benutzer_id);
