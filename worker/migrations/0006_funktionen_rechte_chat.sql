-- Vereinszentrale · Erweiterung: Vereinsfunktionen, Rechte-Matrix, Grundrolle Helfer, Festwirtschaft, Chat, WhatsApp-Links, Einwilligung
--
-- benutzer wird neu aufgebaut (neue Grundrolle 'helfer', Spalte erstellt_von, ist_schatzmeister → Funktion).
-- ACHTUNG: sitzungen, zusagen und trainer_mannschaften verweisen mit ON DELETE CASCADE auf benutzer.
-- Beim DROP TABLE benutzer würden deren Zeilen mitgelöscht → vorher sichern, danach zurückspielen.

-- 1. Sichern
CREATE TABLE _s_sitzungen AS SELECT * FROM sitzungen;
CREATE TABLE _s_zusagen AS SELECT * FROM zusagen;
CREATE TABLE _s_trainer AS SELECT * FROM trainer_mannschaften;
CREATE TABLE _s_schatz AS SELECT id FROM benutzer WHERE ist_schatzmeister = 1;
CREATE TABLE _s_trainerrolle AS SELECT id FROM benutzer WHERE rolle = 'trainer';

-- 2. Neue Benutzertabelle
CREATE TABLE benutzer_neu (
  id            TEXT PRIMARY KEY,
  benutzername  TEXT NOT NULL UNIQUE COLLATE NOCASE,
  anzeigename   TEXT NOT NULL,
  rolle         TEXT NOT NULL CHECK (rolle IN ('vorstand','ausschuss','trainer','helfer')),
  ist_admin     INTEGER NOT NULL DEFAULT 0,
  aktiv         INTEGER NOT NULL DEFAULT 1,
  pw_hash       TEXT NOT NULL,
  pw_salt       TEXT NOT NULL,
  pw_iter       INTEGER NOT NULL,
  pw_aendern    INTEGER NOT NULL DEFAULT 1,
  fehlversuche  INTEGER NOT NULL DEFAULT 0,
  gesperrt_bis  TEXT,
  letzter_login TEXT,
  erstellt      TEXT NOT NULL,
  erstellt_von  TEXT NOT NULL DEFAULT ''
);
INSERT INTO benutzer_neu (id,benutzername,anzeigename,rolle,ist_admin,aktiv,pw_hash,pw_salt,pw_iter,pw_aendern,fehlversuche,gesperrt_bis,letzter_login,erstellt)
  SELECT id,benutzername,anzeigename,rolle,ist_admin,aktiv,pw_hash,pw_salt,pw_iter,pw_aendern,fehlversuche,gesperrt_bis,letzter_login,erstellt FROM benutzer;
DROP TABLE benutzer;
ALTER TABLE benutzer_neu RENAME TO benutzer;

-- 3. Zurückspielen
INSERT OR IGNORE INTO sitzungen SELECT * FROM _s_sitzungen;
INSERT OR IGNORE INTO zusagen SELECT * FROM _s_zusagen;
INSERT OR IGNORE INTO trainer_mannschaften SELECT * FROM _s_trainer;

-- 4. Vereinsfunktionen (schluessel = feste Bedeutung für Regeln im Code; Name frei änderbar)
CREATE TABLE funktionen (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
  gruppe     TEXT NOT NULL CHECK (gruppe IN ('Vorstand','Ausschuss','Sport','Fest','Sonstige')),
  schluessel TEXT NOT NULL DEFAULT '',
  sortierung INTEGER NOT NULL DEFAULT 0,
  aktiv      INTEGER NOT NULL DEFAULT 1,
  erstellt   TEXT NOT NULL
);
INSERT INTO funktionen (id,name,gruppe,schluessel,sortierung,erstellt) VALUES
  ('f_vorsitz1','1. Vorsitzende/r','Vorstand','',1,'2026-11-23T00:00:00Z'),
  ('f_vorsitz2','2. Vorsitzende/r','Vorstand','',2,'2026-11-23T00:00:00Z'),
  ('f_schatz','Schatzmeister/in (Kassenwart)','Vorstand','schatzmeister',3,'2026-11-23T00:00:00Z'),
  ('f_schrift','Schriftführer/in','Vorstand','',4,'2026-11-23T00:00:00Z'),
  ('f_jugend','Jugendleiter/in','Vorstand','jugendleitung',5,'2026-11-23T00:00:00Z'),
  ('f_sport','Sportliche Leitung','Vorstand','',6,'2026-11-23T00:00:00Z'),
  ('f_mitglieder','Mitgliederverwaltung','Vorstand','',7,'2026-11-23T00:00:00Z'),
  ('f_beisitz','Ausschussbeisitzer/in','Ausschuss','',10,'2026-11-23T00:00:00Z'),
  ('f_presse','Pressewart/Öffentlichkeitsarbeit','Ausschuss','',11,'2026-11-23T00:00:00Z'),
  ('f_sponsoring','Sponsoring-Beauftragte/r','Ausschuss','',12,'2026-11-23T00:00:00Z'),
  ('f_ehrenamt','Ehrenamtskoordination','Ausschuss','',13,'2026-11-23T00:00:00Z'),
  ('f_platz','Platz- und Gerätewart','Ausschuss','',14,'2026-11-23T00:00:00Z'),
  ('f_schiri','Schiedsrichter-Obmann','Ausschuss','',15,'2026-11-23T00:00:00Z'),
  ('f_elternvertr','Elternvertreter/in','Ausschuss','',16,'2026-11-23T00:00:00Z'),
  ('f_datenschutz','Datenschutzbeauftragte/r','Ausschuss','',17,'2026-11-23T00:00:00Z'),
  ('f_kassenpruef','Kassenprüfer/in','Ausschuss','kassenpruefer',18,'2026-11-23T00:00:00Z'),
  ('f_trainer','Trainer/in','Sport','trainer',20,'2026-11-23T00:00:00Z'),
  ('f_cotrainer','Co-Trainer/in','Sport','co_trainer',21,'2026-11-23T00:00:00Z'),
  ('f_betreuer','Betreuer/in','Sport','betreuer',22,'2026-11-23T00:00:00Z'),
  ('f_festwirt','Festwirt/in (Leitung)','Fest','festwirt',30,'2026-11-23T00:00:00Z'),
  ('f_festteam','Festwirt-Team','Fest','festwirt_team',31,'2026-11-23T00:00:00Z');

CREATE TABLE benutzer_funktionen (
  benutzer_id TEXT NOT NULL REFERENCES benutzer(id) ON DELETE CASCADE,
  funktion_id TEXT NOT NULL REFERENCES funktionen(id) ON DELETE CASCADE,
  PRIMARY KEY (benutzer_id, funktion_id)
);
CREATE INDEX ix_benutzer_funktionen_f ON benutzer_funktionen(funktion_id);
-- Schatzmeister-Flag → Funktion; Trainer-Rolle → zusätzlich Funktion Trainer/in (niemand verliert Rechte)
INSERT INTO benutzer_funktionen (benutzer_id, funktion_id) SELECT id, 'f_schatz' FROM _s_schatz;
INSERT INTO benutzer_funktionen (benutzer_id, funktion_id) SELECT id, 'f_trainer' FROM _s_trainerrolle;

DROP TABLE _s_sitzungen;
DROP TABLE _s_zusagen;
DROP TABLE _s_trainer;
DROP TABLE _s_schatz;
DROP TABLE _s_trainerrolle;

-- 5. Rechte-Matrix: subjekt = 'rolle:<rolle>' oder 'funktion:<id>', stufe 0 keine · 1 lesen · 2 bearbeiten · 3 löschen
CREATE TABLE rechte (
  subjekt TEXT NOT NULL,
  bereich TEXT NOT NULL,
  stufe   INTEGER NOT NULL CHECK (stufe BETWEEN 0 AND 3),
  PRIMARY KEY (subjekt, bereich)
);
INSERT INTO rechte (subjekt, bereich, stufe) VALUES
  -- Vorstand: wie bisher alles, Festwirtschaft lesen, Protokoll lesen
  ('rolle:vorstand','Satzung & Beschlüsse',3), ('rolle:vorstand','Vorstand & Ausschuss',3), ('rolle:vorstand','Beiträge & Ehrenamt',3),
  ('rolle:vorstand','Mannschaften',3), ('rolle:vorstand','Elternkommunikation',3), ('rolle:vorstand','Sponsoren',3),
  ('rolle:vorstand','Kalender',3), ('rolle:vorstand','Gründungsplan',3), ('rolle:vorstand','Offene Entscheidungen',3),
  ('rolle:vorstand','Festwirtschaft',1), ('rolle:vorstand','Mitglieder',3), ('rolle:vorstand','Downloads',3),
  ('rolle:vorstand','Dokumente',3), ('rolle:vorstand','Änderungsprotokoll',1),
  -- Ausschuss: wie bisher
  ('rolle:ausschuss','Beiträge & Ehrenamt',2), ('rolle:ausschuss','Mannschaften',2), ('rolle:ausschuss','Elternkommunikation',2),
  ('rolle:ausschuss','Sponsoren',2), ('rolle:ausschuss','Kalender',2), ('rolle:ausschuss','Mitglieder',2), ('rolle:ausschuss','Downloads',2),
  -- Funktionen
  ('funktion:f_festwirt','Festwirtschaft',3), ('funktion:f_festteam','Festwirtschaft',2),
  ('funktion:f_jugend','Mannschaften',2), ('funktion:f_jugend','Elternkommunikation',2), ('funktion:f_jugend','Mitglieder',2),
  ('funktion:f_mitglieder','Mitglieder',3),
  ('funktion:f_sponsoring','Sponsoren',2),
  ('funktion:f_ehrenamt','Beiträge & Ehrenamt',2),
  ('funktion:f_presse','Downloads',2);

-- 6. WhatsApp-Gruppenlink je Mannschaft, Einwilligung bei Eltern-Kontakten
ALTER TABLE mannschaften ADD COLUMN whatsapp_link TEXT NOT NULL DEFAULT '';
ALTER TABLE eltern ADD COLUMN einwilligung INTEGER NOT NULL DEFAULT 0;
ALTER TABLE eltern ADD COLUMN einwilligung_datum TEXT NOT NULL DEFAULT '';

-- 7. Chat
CREATE TABLE chat_raeume (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  beschreibung TEXT NOT NULL DEFAULT '',
  alle         INTEGER NOT NULL DEFAULT 0,      -- 1 = alle angemeldeten
  fest         INTEGER NOT NULL DEFAULT 0,      -- 1 = vom Festwirt angelegt (nur Festwirt-Team erlaubt)
  aktiv        INTEGER NOT NULL DEFAULT 1,
  sortierung   INTEGER NOT NULL DEFAULT 0,
  erstellt     TEXT NOT NULL,
  erstellt_von TEXT NOT NULL DEFAULT ''
);
CREATE TABLE chat_raum_mitglieder (
  raum_id TEXT NOT NULL REFERENCES chat_raeume(id) ON DELETE CASCADE,
  typ     TEXT NOT NULL CHECK (typ IN ('rolle','funktion','person')),
  wert    TEXT NOT NULL,
  PRIMARY KEY (raum_id, typ, wert)
);
CREATE TABLE chat_nachrichten (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  raum_id     TEXT NOT NULL REFERENCES chat_raeume(id) ON DELETE CASCADE,
  benutzer_id TEXT NOT NULL,
  autor       TEXT NOT NULL,                    -- Anzeigename zum Zeitpunkt der Nachricht
  text        TEXT NOT NULL,
  erstellt    TEXT NOT NULL,
  bearbeitet  TEXT NOT NULL DEFAULT '',
  geloescht   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_chat_raum_id ON chat_nachrichten(raum_id, id);
CREATE INDEX ix_chat_erstellt ON chat_nachrichten(erstellt);
CREATE TABLE chat_gelesen (
  raum_id     TEXT NOT NULL REFERENCES chat_raeume(id) ON DELETE CASCADE,
  benutzer_id TEXT NOT NULL,
  letzte_id   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (raum_id, benutzer_id)
);
INSERT INTO chat_raeume (id,name,beschreibung,alle,sortierung,erstellt) VALUES
  ('r_alle','Alle – Beschlüsse & Infos','Für alle angemeldeten Mitglieder der Vereinszentrale.',1,1,'2026-11-23T00:00:00Z'),
  ('r_vorstand','Vorstand','Nur für den Vorstand.',0,2,'2026-11-23T00:00:00Z'),
  ('r_ausschuss','Ausschuss','Für den Ausschuss.',0,3,'2026-11-23T00:00:00Z'),
  ('r_trainer','Trainer','Für Trainer, Co-Trainer und Betreuer.',0,4,'2026-11-23T00:00:00Z'),
  ('r_fest','Festwirtschaft','Für Festwirt/in und Festwirt-Team.',0,5,'2026-11-23T00:00:00Z');
INSERT INTO chat_raum_mitglieder (raum_id,typ,wert) VALUES
  ('r_vorstand','rolle','vorstand'),
  ('r_ausschuss','rolle','ausschuss'),
  ('r_trainer','rolle','trainer'), ('r_trainer','funktion','f_trainer'), ('r_trainer','funktion','f_cotrainer'), ('r_trainer','funktion','f_betreuer'),
  ('r_fest','funktion','f_festwirt'), ('r_fest','funktion','f_festteam');
