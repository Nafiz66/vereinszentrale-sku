-- Vereinszentrale FC Sender Kickers United · SQLite-Schema (Cloudflare D1)

CREATE TABLE benutzer (
  id            TEXT PRIMARY KEY,
  benutzername  TEXT NOT NULL UNIQUE COLLATE NOCASE,
  anzeigename   TEXT NOT NULL,
  rolle         TEXT NOT NULL CHECK (rolle IN ('vorstand','ausschuss')),
  ist_admin     INTEGER NOT NULL DEFAULT 0,
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

CREATE TABLE sitzungen (
  token_hash TEXT PRIMARY KEY,
  benutzer_id TEXT NOT NULL REFERENCES benutzer(id) ON DELETE CASCADE,
  erstellt   TEXT NOT NULL,
  laeuft_ab  TEXT NOT NULL
);
CREATE INDEX ix_sitzungen_benutzer ON sitzungen(benutzer_id);

CREATE TABLE eintraege (
  id TEXT PRIMARY KEY,
  titel TEXT NOT NULL,
  bereich TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Offen',
  datum TEXT NOT NULL DEFAULT '',
  uhrzeit TEXT NOT NULL DEFAULT '',
  ort TEXT NOT NULL DEFAULT '',
  zustaendig TEXT NOT NULL DEFAULT '',
  inhalt TEXT NOT NULL DEFAULT '',
  quelle TEXT NOT NULL DEFAULT '',
  erstellt TEXT NOT NULL,
  geaendert TEXT NOT NULL,
  geaendert_von TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_eintraege_bereich ON eintraege(bereich);
CREATE INDEX ix_eintraege_datum ON eintraege(datum);

CREATE TABLE dokumente (
  id TEXT PRIMARY KEY,
  titel TEXT NOT NULL,
  beschreibung TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  datum TEXT NOT NULL DEFAULT '',
  dateiname TEXT NOT NULL DEFAULT '',
  mime TEXT NOT NULL DEFAULT '',
  groesse INTEGER NOT NULL DEFAULT 0,
  erstellt TEXT NOT NULL,
  geaendert TEXT NOT NULL
);

-- Dateien werden in Stücken (max. 1 MB) gespeichert, weil eine D1-Zeile max. 2 MB groß sein darf.
CREATE TABLE dokument_teile (
  dokument_id TEXT NOT NULL REFERENCES dokumente(id) ON DELETE CASCADE,
  nr INTEGER NOT NULL,
  daten BLOB NOT NULL,
  PRIMARY KEY (dokument_id, nr)
);

CREATE TABLE protokoll (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  zeit TEXT NOT NULL,
  benutzer TEXT NOT NULL,
  aktion TEXT NOT NULL,
  titel TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT ''
);

-- Startdaten (aus der bisherigen Vereinszentrale)
INSERT INTO eintraege (id,titel,bereich,status,datum,zustaendig,inhalt,quelle,erstellt,geaendert,geaendert_von) VALUES
('seed-1','Gründungsversammlung – Satzung angenommen','Satzung & Beschlüsse','Bestätigt','2026-10-25','','Gründung des Vereins und Annahme der Satzung.','Alte Vereinszentrale','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z','System'),
('seed-2','Satzung unverändert bestätigt','Satzung & Beschlüsse','Bestätigt','2026-11-08','','Mitgliederversammlung: Satzung inhaltlich unverändert bestätigt.
Abstimmung: 12 Ja, 0 Nein, 0 Enthaltungen.','Alte Vereinszentrale','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z','System'),
('seed-3','Mitgliederversammlung mit Wahlen','Vorstand & Ausschuss','Erledigt','2026-11-08','','Wahlen des Vorstands. Protokoll liegt zur Prüfung und Unterzeichnung vor.','Alte Vereinszentrale','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z','System'),
('seed-4','Satzung unterschreiben (10 Unterschriftsfelder)','Gründungsplan','Offen','','','Satzung in der Fassung vom 08.11.2026 – zehn namentliche Unterschriftsfelder.','Alte Vereinszentrale','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z','System'),
('seed-5','Gründungsprotokoll prüfen und unterzeichnen','Gründungsplan','Offen','','Ugur Muzaffer Cebeci','Gründungsprotokoll vom 25.10.2026 prüfen und unterzeichnen.','Alte Vereinszentrale','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z','System'),
('seed-6','Protokoll Mitgliederversammlung unterzeichnen','Gründungsplan','Offen','','Friedrich Talmon','Mitgliederversammlungs- und Wahlprotokoll vom 08.11.2026 prüfen und unterzeichnen.','Alte Vereinszentrale','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z','System'),
('seed-7','Registeranmeldung beim Notariat einreichen','Gründungsplan','Offen','','','Registeranmeldung mit drei Vorständen und Vereinsanschrift Bahnhofstraße 37, 75417 Mühlacker.
Notarielle Prüfung und öffentliche Beglaubigung stehen aus.','Alte Vereinszentrale','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z','System');

INSERT INTO dokumente (id,titel,beschreibung,status,datum,erstellt,geaendert) VALUES
('doc-1','Satzung','Angenommen am 25.10.2026 und inhaltlich unverändert bestätigt am 08.11.2026. Zehn namentliche Unterschriftsfelder.','Zur Unterzeichnung','2026-11-19','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z'),
('doc-2','Gründungsprotokoll vom 25. Oktober','Gründung, Satzungsannahme und Teilnehmerübersicht. Zur Prüfung und Unterzeichnung durch Ugur Muzaffer Cebeci.','Zur Unterzeichnung','2026-11-19','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z'),
('doc-3','Mitgliederversammlungs- und Wahlprotokoll','Versammlung vom 08.11.2026 mit Wahlen und unveränderter Bestätigung der Satzung: 12 Ja, 0 Nein, 0 Enthaltungen. Zur Prüfung und Unterzeichnung durch Friedrich Talmon.','Zur Unterzeichnung','2026-11-19','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z'),
('doc-4','Registeranmeldung für das Notariat','Ausgefüllt mit drei Vorständen und der Vereinsanschrift Bahnhofstraße 37, 75417 Mühlacker. Zur notariellen Prüfung und öffentlichen Beglaubigung.','Für das Notariat','2026-11-19','2026-11-19T12:00:00Z','2026-11-19T12:00:00Z');
