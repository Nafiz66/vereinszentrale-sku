/**
 * Vereinszentrale · FC Sender Kickers United – API (Cloudflare Worker + D1/SQLite)
 *
 * Rechte
 *   Grundrolle (vorstand | ausschuss | trainer | helfer) + beliebig viele Vereinsfunktionen (Tabelle funktionen).
 *   Stufe je Bereich = Maximum aus Rechte-Matrix (Tabelle rechte) für Grundrolle und Funktionen; Admin: überall.
 *   Feste Regeln siehe Abschnitt „Rechte“ (Geld, Benutzer, Eltern-Kontakte, Vorstandsbereiche, Festwirt-Team).
 *   ist_admin – Zusatz für Vorstand: Benutzer, Funktionen, Rechte-Matrix, Chat-Räume
 *
 * Passwörter
 *   Der Browser streckt das Passwort mit PBKDF2 (250.000 Runden, Salt = Benutzername).
 *   Der Server rechnet darauf HMAC mit geheimem PEPPER + PBKDF2 mit zufälligem Salt.
 *   So bleibt der Hash stark, obwohl der Free-Tarif nur 10 ms CPU pro Anfrage erlaubt.
 */

const GROUPS = ["Satzung & Beschlüsse","Vorstand & Ausschuss","Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender","Gründungsplan","Offene Entscheidungen","Festwirtschaft"];
// Bereiche, in denen Einträge „Für Trainer sichtbar“ sein dürfen
const AUSSCHUSS_GROUPS = ["Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender"];
// Rechte-Matrix: Bereiche (Spalten), Stufen 0 keine · 1 lesen · 2 bearbeiten · 3 löschen
const AREAS = [...GROUPS, "Mitglieder", "Downloads", "Dokumente", "Änderungsprotokoll"];
const STUFEN = ["keine","lesen","bearbeiten","löschen"];
// Feste Regel: Trainer/Co-Trainer/Betreuer/Festwirt-Team (und Grundrollen Trainer/Helfer) bekommen über die Matrix nie Vorstandsbereiche
const VORSTAND_AREAS = ["Satzung & Beschlüsse","Vorstand & Ausschuss","Gründungsplan","Offene Entscheidungen","Dokumente","Änderungsprotokoll"];
const TEAM_KEYS = ["trainer","co_trainer","betreuer"];
const LOCKED_KEYS = [...TEAM_KEYS, "festwirt_team"], LOCKED_ROLES = ["trainer","helfer"];
const ROLE_LABEL = { vorstand: "Vorstand", ausschuss: "Ausschuss", trainer: "Trainer", helfer: "Helfer" };
const FUNC_GROUPS = ["Vorstand","Ausschuss","Sport","Fest","Sonstige"];
const CHAT_MAX = 4000, CHAT_KEEP_DAYS = 365;
const WA_RE = /^https:\/\/chat\.whatsapp\.com\/[A-Za-z0-9]{10,40}$/;
const STATUSES = ["Bestätigt","Geplant","Entwurf","Offen","Schätzung","Erledigt"];
const SERVER_ITER = 10000;
const SESSION_HOURS = 12, SESSION_HOURS_LONG = 24 * 30;
const MAX_FAILS = 5, LOCK_MINUTES = 15;
const MAX_FILE = 10 * 1024 * 1024, CHUNK = 1024 * 1024;
const ENTRY_FIELDS = ["titel","bereich","status","datum","uhrzeit","ort","zustaendig","inhalt","quelle","rueckmeldung","fuer_trainer","mannschaft_id"];
const ROLES = ["vorstand","ausschuss","trainer","helfer"];
const KASSE_DEFAULTS = { kategorien: ["Mitgliedsbeiträge","Sponsoring","Spenden","Sportmaterial","Platz/Hallen","Fahrtkosten","Sonstiges"], anfang_bar: 0, anfang_bank: 0, stichtag: "" };
const ANSWERS = { ja: "Nimmt teil", vielleicht: "Vielleicht", nein: "Nimmt nicht teil" };
const LIMITS = { titel: 160, ort: 120, zustaendig: 120, inhalt: 60000, quelle: 200 };
const MAX_IMPORT = 1000;
const MEMBER_FIELDS = ["vorname","nachname","geburtsdatum","mannschaft","mannschaft_id","email","telefon","eintritt","status","notiz"];
const MEMBER_LIMITS = { vorname: 80, nachname: 80, geburtsdatum: 10, mannschaft: 80, mannschaft_id: 60, email: 160, telefon: 60, eintritt: 10, status: 30, notiz: 2000 };
const MEMBER_STATUSES = ["Aktiv","Passiv","Ausgetreten"];
const PARENT_FIELDS = ["name","email","kind","mannschaft","mannschaft_id","notiz","einwilligung","einwilligung_datum"];
const PARENT_LIMITS = { name: 120, email: 160, kind: 120, mannschaft: 80, mannschaft_id: 60, notiz: 1000, einwilligung: 5, einwilligung_datum: 10 };
const EMAIL_RE = /^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/;
const DL_CATS = ["Formulare","Sponsoren","Logos & Werbematerial","Sonstiges"];
// Vereinsdaten (Absender auf Rechnungen und Formularen) – alles frei änderbar außer Vereinsname, Logo, Rechnungsnummer
const VEREIN_FIELDS = { adresse: 300, telefon: 60, email: 160, web: 160, vorsitz: 200, register: 160, steuernummer: 60, ustid: 40,
  bank: 120, iban: 42, bic: 20, glaeubiger_id: 40, ersteller: 120, mwst: 6, zahlungsziel: 4, einleitung: 2000, schlusstext: 4000, fusszeile: 1000, beitrag_text: 2000 };
const VEREIN_DEFAULTS = { adresse: "Bahnhofstraße 37\n75417 Mühlacker", mwst: "19", zahlungsziel: "14",
  einleitung: "Vielen Dank für Ihre Unterstützung. Wir stellen Ihnen folgende Leistungen in Rechnung:",
  schlusstext: "Bitte überweisen Sie den Rechnungsbetrag bis zum {faellig} unter Angabe der Rechnungsnummer {nummer} auf das unten genannte Konto.\n\nMit sportlichen Grüßen\n{ersteller}" };
const INVOICE_STATUSES = ["Offen","Bezahlt","Storniert"];

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };

/* ---------------- Hilfsfunktionen ---------------- */
const enc = new TextEncoder();
const nowIso = () => new Date().toISOString();
const uid = () => crypto.randomUUID();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const sha256 = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  if (crypto.subtle.timingSafeEqual) return crypto.subtle.timingSafeEqual(a, b);
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
}

async function serverHash(clientHash, saltBytes, iter, pepper) {
  const pk = await crypto.subtle.importKey("raw", enc.encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const peppered = await crypto.subtle.sign("HMAC", pk, enc.encode(clientHash));
  const key = await crypto.subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iter }, key, 256));
}
async function makePassword(clientHash, pepper) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const h = await serverHash(clientHash, salt, SERVER_ITER, pepper);
  return { pw_hash: b64(h), pw_salt: b64(salt), pw_iter: SERVER_ITER };
}
function checkClientHash(v) {
  // Browser liefert 64 Hex-Zeichen (PBKDF2-Ergebnis); alles andere ablehnen
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) fail(400, "Ungültiges Passwortformat.");
  return v;
}

function clean(v, max) { return String(v ?? "").trim().slice(0, max); }
function validDate(v) { return v === "" || /^\d{4}-\d{2}-\d{2}$/.test(v); }
function validTime(v) { return v === "" || /^\d{2}:\d{2}$/.test(v); }
function cleanUsername(v) {
  const u = String(v ?? "").trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,40}$/.test(u)) fail(400, "Benutzername: 3–40 Zeichen, nur a–z, 0–9, Punkt, Minus, Unterstrich.");
  return u;
}

/* ---------------- HTTP ---------------- */
function corsHeaders(req, env) {
  const origin = req.headers.get("Origin");
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  const h = { "Vary": "Origin" };
  if (origin && allowed.includes(origin)) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-Dateiname";
    h["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
    h["Access-Control-Expose-Headers"] = "Content-Disposition";
    h["Access-Control-Max-Age"] = "86400";
  }
  return h;
}
const SECURITY = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
};
function json(data, status, cors) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY, ...cors } });
}
async function body(req) {
  try { return await req.json(); } catch { fail(400, "Ungültige Anfrage."); }
}

/* ---------------- Rechte ----------------
 * Stufe je Bereich = Maximum aus Grundrolle + allen aktiven Funktionen (Rechte-Matrix in der DB). Admin: überall 3.
 * Feste Regeln (nicht über die Matrix änderbar): Geld (Rechnungen/Kasse) nur Admin + Schatzmeister/in (Kassenprüfer/in
 * optional lesen), Benutzer/Rechte nur Admin, Eltern-Kontakte nur Admin/Jugendleitung/Trainer der Mannschaft,
 * Trainer & Festwirt-Team nie in Vorstandsbereichen. Nicht lesbar → 404 (Existenz wird nicht verraten). */
const isVorstand = u => u.rolle === "vorstand";
const has = (u, key) => !!u.keys?.has(key);
const lvl = (u, area) => u.levels?.[area] || 0;
const isSchatz = u => has(u, "schatzmeister");
const isTeamish = u => u.rolle === "trainer" || TEAM_KEYS.some(k => has(u, k));
const isFestwirt = u => has(u, "festwirt");
const moneyRead = u => !!u.ist_admin || isSchatz(u) || (has(u, "kassenpruefer") && !!u.cfg?.kassenpruefer_lesen);
const moneyWrite = u => !!u.ist_admin || isSchatz(u);
const elternAll = u => !!u.ist_admin || has(u, "jugendleitung");
const teamsManage = u => !!u.ist_admin || has(u, "jugendleitung") || lvl(u, "Mitglieder") >= 3;
const canSeeGroup = (u, g) => lvl(u, g) >= 1;
// Einen einzelnen Eintrag sehen (für Liste, Anhänge, Zusagen, „noch offen“); Trainer zusätzlich über „Für Trainer sichtbar“
function canSeeEntry(u, e) {
  if (canSeeGroup(u, e.bereich)) return true;
  return isTeamish(u) && !!e.fuer_trainer && AUSSCHUSS_GROUPS.includes(e.bereich) && (!e.mannschaft_id || (u.teams || []).includes(e.mannschaft_id));
}
const hidden = () => fail(404, "Nicht gefunden.");
// Bereich: nicht lesbar → 404; lesbar, aber Stufe zu klein → 403
function needArea(u, area, stufe) {
  const l = lvl(u, area);
  if (l < 1) hidden();
  if (l < stufe) fail(403, stufe >= 3 ? "Löschen ist für dich in diesem Bereich nicht freigegeben." : "Bearbeiten ist für dich in diesem Bereich nicht freigegeben.");
}
function needAdmin(u) { if (!u.ist_admin) hidden(); }
function needMoney(u, write) { if (!moneyRead(u)) hidden(); if (write && !moneyWrite(u)) fail(403, "Nur Admins und Schatzmeister/in dürfen hier etwas ändern."); }
function needStorno(u) { if (!moneyRead(u)) hidden(); if (!isSchatz(u)) fail(403, "Stornieren darf nur Schatzmeister/in."); }

function computeLevels(rolle, isAdmin, funcs, rechteRows) {
  const lv = Object.fromEntries(AREAS.map(a => [a, isAdmin ? 3 : 0]));
  if (isAdmin) return lv;
  const subj = new Map([["rolle:" + rolle, LOCKED_ROLES.includes(rolle)], ...funcs.map(f => ["funktion:" + f.id, LOCKED_KEYS.includes(f.schluessel)])]);
  for (const r of rechteRows) {
    if (!subj.has(r.subjekt) || !(r.bereich in lv)) continue;
    if (subj.get(r.subjekt) && VORSTAND_AREAS.includes(r.bereich)) continue;   // feste Regel
    lv[r.bereich] = Math.max(lv[r.bereich], r.stufe);
  }
  return lv;
}
async function getRightsCfg(env) {
  const row = await env.DB.prepare("SELECT wert FROM einstellungen WHERE schluessel='rechte'").first();
  try { return row ? JSON.parse(row.wert) : {}; } catch { return {}; }
}
// Rechte des angemeldeten Benutzers bei jeder Anfrage frisch aus der DB (Änderungen wirken sofort)
async function enrich(env, u) {
  const [f, r, t, c] = await env.DB.batch([
    env.DB.prepare("SELECT f.id, f.name, f.schluessel, f.gruppe FROM benutzer_funktionen bf JOIN funktionen f ON f.id=bf.funktion_id WHERE bf.benutzer_id=? AND f.aktiv=1 ORDER BY f.sortierung").bind(u.id),
    env.DB.prepare("SELECT * FROM rechte"),
    env.DB.prepare("SELECT mannschaft_id FROM trainer_mannschaften WHERE benutzer_id=?").bind(u.id),
    env.DB.prepare("SELECT wert FROM einstellungen WHERE schluessel='rechte'"),
  ]);
  u.funcs = f.results; u.keys = new Set(u.funcs.map(x => x.schluessel).filter(Boolean));
  u.levels = computeLevels(u.rolle, !!u.ist_admin, u.funcs, r.results);
  u.teams = t.results.map(x => x.mannschaft_id);
  try { u.cfg = c.results[0] ? JSON.parse(c.results[0].wert) : {}; } catch { u.cfg = {}; }
  return u;
}
// Alle aktiven Benutzer mit Rechten (für „noch offen“ und Chat-Mitgliedschaft)
async function allUsersEnriched(env) {
  const [b, bf, r, t] = await env.DB.batch([
    env.DB.prepare("SELECT id, anzeigename, rolle, ist_admin FROM benutzer WHERE aktiv=1 ORDER BY anzeigename"),
    env.DB.prepare("SELECT bf.benutzer_id, f.id, f.schluessel FROM benutzer_funktionen bf JOIN funktionen f ON f.id=bf.funktion_id WHERE f.aktiv=1"),
    env.DB.prepare("SELECT * FROM rechte"),
    env.DB.prepare("SELECT benutzer_id, mannschaft_id FROM trainer_mannschaften"),
  ]);
  return b.results.map(x => {
    const funcs = bf.results.filter(y => y.benutzer_id === x.id);
    return { ...x, funcs, keys: new Set(funcs.map(y => y.schluessel).filter(Boolean)), levels: computeLevels(x.rolle, !!x.ist_admin, funcs, r.results),
      teams: t.results.filter(y => y.benutzer_id === x.id).map(y => y.mannschaft_id) };
  });
}
function publicUser(u) {
  return { id: u.id, benutzername: u.benutzername, anzeigename: u.anzeigename, rolle: u.rolle, ist_admin: !!u.ist_admin,
    aktiv: !!u.aktiv, pw_aendern: !!u.pw_aendern, letzter_login: u.letzter_login, erstellt: u.erstellt, erstellt_von: u.erstellt_von || "",
    ...(u.funktionen ? { funktionen: u.funktionen } : {}), ...(u.teams ? { mannschaften: u.teams } : {}) };
}
// Für /api/ich: alles, was die Oberfläche zum Ein-/Ausblenden braucht (der Server prüft trotzdem jede Anfrage)
async function meUser(env, u) {
  const rechte = (await env.DB.prepare("SELECT * FROM rechte WHERE stufe>0").all()).results;
  const funcs = (await env.DB.prepare("SELECT id, name, schluessel FROM funktionen WHERE aktiv=1").all()).results;
  const label = s => s.startsWith("rolle:") ? ROLE_LABEL[s.slice(6)] : funcs.find(f => "funktion:" + f.id === s)?.name;
  const lockedSubj = s => s.startsWith("rolle:") ? LOCKED_ROLES.includes(s.slice(6)) : LOCKED_KEYS.includes(funcs.find(f => "funktion:" + f.id === s)?.schluessel);
  const sichtbar = Object.fromEntries(AREAS.map(a => [a, [...new Set(rechte.filter(r => r.bereich === a && !(VORSTAND_AREAS.includes(a) && lockedSubj(r.subjekt))).map(r => label(r.subjekt)).filter(Boolean))]]));
  return { ...publicUser(u), funktionen: u.funcs.map(f => ({ id: f.id, name: f.name, schluessel: f.schluessel })), mannschaften: u.teams, rechte: u.levels, sichtbar,
    darf: { geld_lesen: moneyRead(u), geld_schreiben: moneyWrite(u), stornieren: isSchatz(u), eltern_alle: elternAll(u), eltern_team: isTeamish(u) && !elternAll(u),
      mannschaften_pflegen: teamsManage(u), team_verwalten: isFestwirt(u), benutzer: !!u.ist_admin, export: !!u.ist_admin, trainer: isTeamish(u),
      vereinsdaten: moneyRead(u) || lvl(u, "Downloads") >= 1, raeume_anlegen: !!u.ist_admin || isFestwirt(u) } };
}
const normTeam = s => String(s ?? "").trim().toLowerCase().replace(/[\s-]+/g, "");
async function teamList(env) { return (await env.DB.prepare("SELECT * FROM mannschaften ORDER BY sortierung, name").all()).results; }

async function log(env, user, aktion, titel, details = "") {
  await env.DB.prepare("INSERT INTO protokoll(zeit,benutzer,aktion,titel,details) VALUES(?,?,?,?,?)")
    .bind(nowIso(), user ? user.anzeigename : "System", aktion, titel, details).run();
}

async function authenticate(req, env) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer ([A-Za-z0-9_-]{40,})$/);
  if (!m) fail(401, "Bitte anmelden.");
  const th = await sha256(m[1]);
  const row = await env.DB.prepare(
    "SELECT b.*, s.laeuft_ab FROM sitzungen s JOIN benutzer b ON b.id=s.benutzer_id WHERE s.token_hash=?").bind(th).first();
  if (!row || row.laeuft_ab < nowIso() || !row.aktiv) {
    if (row) await env.DB.prepare("DELETE FROM sitzungen WHERE token_hash=?").bind(th).run();
    fail(401, "Sitzung abgelaufen. Bitte neu anmelden.");
  }
  row.token_hash = th;
  return row;
}

/* ---------------- Endpunkte ---------------- */
async function setupStatus(env) {
  const n = (await env.DB.prepare("SELECT COUNT(*) n FROM benutzer").first()).n;
  return { einrichtung_noetig: n === 0 };
}

async function setup(req, env) {
  const b = await body(req);
  if (!env.SETUP_TOKEN || typeof b.token !== "string") fail(403, "Einrichtung nicht möglich.");
  const ok = equalBytes(enc.encode(await sha256(b.token)), enc.encode(await sha256(env.SETUP_TOKEN)));
  if (!ok) fail(403, "Einrichtungs-Code ist falsch.");
  if (!(await setupStatus(env)).einrichtung_noetig) fail(409, "Die Einrichtung wurde bereits abgeschlossen.");
  if (!Array.isArray(b.admins) || b.admins.length !== 3) fail(400, "Bitte genau drei Admins angeben.");
  const t = nowIso(), stmts = [];
  for (const a of b.admins) {
    const name = cleanUsername(a.benutzername);
    const pw = await makePassword(checkClientHash(a.passwort), env.PEPPER);
    stmts.push(env.DB.prepare(`INSERT INTO benutzer(id,benutzername,anzeigename,rolle,ist_admin,pw_hash,pw_salt,pw_iter,pw_aendern,erstellt)
      VALUES(?,?,?,'vorstand',1,?,?,?,0,?)`).bind(uid(), name, clean(a.anzeigename, 80) || name, pw.pw_hash, pw.pw_salt, pw.pw_iter, t));
  }
  stmts.push(env.DB.prepare("INSERT INTO protokoll(zeit,benutzer,aktion,titel,details) VALUES(?,?,?,?,?)")
    .bind(t, "System", "Eingerichtet", "Vereinszentrale", "Drei Admin-Konten angelegt."));
  try { await env.DB.batch(stmts); } catch { fail(400, "Benutzernamen müssen verschieden sein."); }
  return { ok: true };
}

async function login(req, env) {
  const b = await body(req);
  const name = String(b.benutzername ?? "").trim().toLowerCase();
  const clientHash = checkClientHash(b.passwort);
  const u = await env.DB.prepare("SELECT * FROM benutzer WHERE benutzername=?").bind(name).first();
  const generic = "Benutzername oder Passwort falsch.";
  if (!u) { await serverHash(clientHash, new Uint8Array(16), SERVER_ITER, env.PEPPER); fail(401, generic); }
  if (u.gesperrt_bis && u.gesperrt_bis > nowIso()) fail(429, "Zu viele Fehlversuche. Bitte in 15 Minuten erneut versuchen.");
  const h = await serverHash(clientHash, unb64(u.pw_salt), u.pw_iter, env.PEPPER);
  if (!equalBytes(h, unb64(u.pw_hash)) || !u.aktiv) {
    const f = u.fehlversuche + 1;
    const lock = f >= MAX_FAILS ? new Date(Date.now() + LOCK_MINUTES * 60000).toISOString() : null;
    await env.DB.prepare("UPDATE benutzer SET fehlversuche=?, gesperrt_bis=? WHERE id=?").bind(lock ? 0 : f, lock, u.id).run();
    fail(401, u.aktiv ? generic : "Dieses Konto ist deaktiviert.");
  }
  const token = b64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const t = nowIso();
  const exp = new Date(Date.now() + (b.angemeldet_bleiben ? SESSION_HOURS_LONG : SESSION_HOURS) * 3600000).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sitzungen WHERE laeuft_ab < ?").bind(t),
    env.DB.prepare("INSERT INTO sitzungen(token_hash,benutzer_id,erstellt,laeuft_ab) VALUES(?,?,?,?)").bind(await sha256(token), u.id, t, exp),
    env.DB.prepare("UPDATE benutzer SET fehlversuche=0, gesperrt_bis=NULL, letzter_login=? WHERE id=?").bind(t, u.id),
  ]);
  return { token, laeuft_ab: exp, benutzer: publicUser(u) };
}

async function changeOwnPassword(req, env, u) {
  const b = await body(req);
  const h = await serverHash(checkClientHash(b.alt), unb64(u.pw_salt), u.pw_iter, env.PEPPER);
  if (!equalBytes(h, unb64(u.pw_hash))) fail(400, "Das aktuelle Passwort ist falsch.");
  const pw = await makePassword(checkClientHash(b.neu), env.PEPPER);
  await env.DB.batch([
    env.DB.prepare("UPDATE benutzer SET pw_hash=?, pw_salt=?, pw_iter=?, pw_aendern=0 WHERE id=?").bind(pw.pw_hash, pw.pw_salt, pw.pw_iter, u.id),
    env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=? AND token_hash<>?").bind(u.id, u.token_hash),
  ]);
  await log(env, u, "Passwort geändert", u.anzeigename);
  return { ok: true };
}

/* ---- Einträge ---- */
async function listEntries(env, u) {
  // Lesbare Bereiche laut Matrix; Trainer zusätzlich „Für Trainer sichtbar“ (genauer Filter danach mit canSeeEntry)
  const groups = GROUPS.filter(g => canSeeGroup(u, g));
  if (!groups.length && !isTeamish(u)) return { eintraege: [] };
  const ph = groups.length ? groups.map(() => "?").join(",") : "''";
  const where = `(e.bereich IN (${ph})${isTeamish(u) ? " OR e.fuer_trainer=1" : ""})`;
  const [e, a, z] = await env.DB.batch([
    env.DB.prepare(`SELECT * FROM eintraege e WHERE ${where} ORDER BY datum, uhrzeit, titel`).bind(...groups),
    env.DB.prepare(`SELECT a.id, a.eintrag_id, a.dateiname, a.mime, a.groesse, a.erstellt, a.erstellt_von FROM anhaenge a
      JOIN eintraege e ON e.id=a.eintrag_id WHERE ${where} ORDER BY a.erstellt`).bind(...groups),
    env.DB.prepare(`SELECT z.eintrag_id, z.benutzer_id, z.antwort, z.geaendert, b.anzeigename FROM zusagen z
      JOIN eintraege e ON e.id=z.eintrag_id JOIN benutzer b ON b.id=z.benutzer_id WHERE ${where} ORDER BY b.anzeigename`).bind(...groups),
  ]);
  const files = {}, answers = {};
  for (const x of a.results) (files[x.eintrag_id] ||= []).push(x);
  for (const x of z.results) (answers[x.eintrag_id] ||= []).push({ benutzer_id: x.benutzer_id, name: x.anzeigename, antwort: x.antwort, geaendert: x.geaendert });
  const people = e.results.some(r => r.rueckmeldung) ? await allUsersEnriched(env) : [];
  return { eintraege: e.results.filter(r => canSeeEntry(u, r)).map(r => {
    const out = { ...r, anhaenge: files[r.id] || [] };
    if (r.rueckmeldung) {
      out.zusagen = answers[r.id] || [];
      const done = new Set(out.zusagen.map(x => x.benutzer_id));
      // Nur wer den Eintrag wirklich sehen darf und noch nicht geantwortet hat
      out.offen = people.filter(x => !done.has(x.id) && canSeeEntry(x, r)).map(x => x.anzeigename);
    }
    return out;
  }) };
}
async function answerEntry(req, env, u, id) {
  const b = await body(req);
  const e = await visibleEntry(env, u, id);
  if (!e.rueckmeldung) fail(400, "Für diesen Eintrag ist keine Rückmeldung vorgesehen.");
  const antwort = String(b.antwort ?? "");
  if (antwort && !ANSWERS[antwort]) fail(400, "Ungültige Antwort.");
  if (antwort) await env.DB.prepare(`INSERT INTO zusagen(eintrag_id,benutzer_id,antwort,geaendert) VALUES(?,?,?,?)
      ON CONFLICT(eintrag_id,benutzer_id) DO UPDATE SET antwort=excluded.antwort, geaendert=excluded.geaendert`).bind(id, u.id, antwort, nowIso()).run();
  else await env.DB.prepare("DELETE FROM zusagen WHERE eintrag_id=? AND benutzer_id=?").bind(id, u.id).run();
  await log(env, u, "Rückmeldung", e.titel, antwort ? ANSWERS[antwort] : "Antwort zurückgenommen");
  return { ok: true };
}
function readEntry(b, u) {
  const v = {};
  for (const k of ENTRY_FIELDS) v[k] = clean(b[k], LIMITS[k] || 60);
  const yes = x => x === true || x === 1 || x === "1";
  v.rueckmeldung = yes(b.rueckmeldung) ? 1 : 0;
  // Vorstands-Bereiche bleiben immer vor Trainern verborgen
  v.fuer_trainer = yes(b.fuer_trainer) && AUSSCHUSS_GROUPS.includes(v.bereich) ? 1 : 0;
  if (!v.fuer_trainer) v.mannschaft_id = "";
  if (!v.titel) fail(400, "Bitte einen Titel eingeben.");
  if (!GROUPS.includes(v.bereich)) fail(400, "Unbekannter Bereich.");
  if (!STATUSES.includes(v.status)) fail(400, "Unbekannter Status.");
  if (!validDate(v.datum) || !validTime(v.uhrzeit)) fail(400, "Datum oder Uhrzeit ungültig.");
  needArea(u, v.bereich, 2);
  return v;
}
async function checkTeam(env, id) {
  if (id && !(await env.DB.prepare("SELECT id FROM mannschaften WHERE id=?").bind(id).first())) fail(400, "Unbekannte Mannschaft.");
}
async function createEntry(req, env, u) {
  const v = readEntry(await body(req), u), t = nowIso(), id = uid();
  await checkTeam(env, v.mannschaft_id);
  await env.DB.prepare(`INSERT INTO eintraege(id,${ENTRY_FIELDS.join(",")},erstellt,geaendert,geaendert_von) VALUES(?,${ENTRY_FIELDS.map(() => "?").join(",")},?,?,?)`)
    .bind(id, ...ENTRY_FIELDS.map(k => v[k]), t, t, u.anzeigename).run();
  await log(env, u, "Angelegt", v.titel, `${v.bereich} · ${v.status}${v.datum ? " · " + v.datum : ""}`);
  return { eintrag: await env.DB.prepare("SELECT * FROM eintraege WHERE id=?").bind(id).first() };
}
async function updateEntry(req, env, u, id) {
  const b = await body(req);
  const old = await env.DB.prepare("SELECT * FROM eintraege WHERE id=?").bind(id).first();
  if (!old || !canSeeEntry(u, old)) hidden();
  needArea(u, old.bereich, 2);
  if (b.geaendert && b.geaendert !== old.geaendert) fail(409, "Jemand anderes hat diesen Eintrag inzwischen geändert. Bitte neu laden.");
  const v = readEntry(b, u);
  await checkTeam(env, v.mannschaft_id);
  const changed = ENTRY_FIELDS.filter(k => String(old[k] ?? "") !== String(v[k]));
  if (!changed.length) return { eintrag: old };
  const t = nowIso();
  await env.DB.prepare(`UPDATE eintraege SET ${ENTRY_FIELDS.map(k => k + "=?").join(",")}, geaendert=?, geaendert_von=? WHERE id=?`)
    .bind(...ENTRY_FIELDS.map(k => v[k]), t, u.anzeigename, id).run();
  const label = { rueckmeldung: x => `Rückmeldung erwünscht: ${x ? "ja" : "nein"}`, fuer_trainer: x => `Für Trainer sichtbar: ${x ? "ja" : "nein"}`, mannschaft_id: x => `Mannschaft: ${x || "alle"}` };
  await log(env, u, "Geändert", v.titel, changed.map(k => k === "inhalt" ? "Inhalt bearbeitet" : label[k] ? label[k](v[k]) : `${k}: „${old[k] || "–"}“ → „${v[k] || "–"}“`).join("\n"));
  return { eintrag: await env.DB.prepare("SELECT * FROM eintraege WHERE id=?").bind(id).first() };
}
async function deleteEntry(env, u, id) {
  const old = await env.DB.prepare("SELECT * FROM eintraege WHERE id=?").bind(id).first();
  if (!old || !canSeeEntry(u, old)) hidden();
  needArea(u, old.bereich, 3);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM anhang_teile WHERE anhang_id IN (SELECT id FROM anhaenge WHERE eintrag_id=?)").bind(id),
    env.DB.prepare("DELETE FROM anhaenge WHERE eintrag_id=?").bind(id),
    env.DB.prepare("DELETE FROM zusagen WHERE eintrag_id=?").bind(id),
    env.DB.prepare("DELETE FROM eintraege WHERE id=?").bind(id),
  ]);
  await log(env, u, "Gelöscht", old.titel);
  return { ok: true };
}
async function importEntries(req, env, u) {
  const b = await body(req);
  if (!Array.isArray(b.eintraege) || !b.eintraege.length) fail(400, "Keine Zeilen zum Importieren.");
  if (b.eintraege.length > MAX_IMPORT) fail(400, `Höchstens ${MAX_IMPORT} Zeilen auf einmal.`);
  const rows = b.eintraege.map(r => readEntry(r, u)), t = nowIso();
  const known = new Set((await teamList(env)).map(x => x.id));
  for (const r of rows) if (r.mannschaft_id && !known.has(r.mannschaft_id)) r.mannschaft_id = "";
  await bulkInsert(env, "eintraege", ENTRY_FIELDS, rows.map(v => ({ ...v, id: uid(), erstellt: t, geaendert: t, geaendert_von: u.anzeigename })));
  const bereiche = [...new Set(rows.map(r => r.bereich))].join(", ");
  await log(env, u, "Importiert", `${rows.length} Einträge`, `${bereiche}${b.datei ? " · aus " + clean(b.datei, 200) : ""}`);
  return { ok: true, anzahl: rows.length };
}

// Viele Zeilen mit wenigen Abfragen einfügen: Der Free-Tarif erlaubt nur 50 Abfragen pro Anfrage
// und 100 Parameter pro Abfrage – deshalb als JSON-Paket über json_each().
async function bulkInsert(env, table, fields, rows) {
  const cols = ["id", ...fields, "erstellt", "geaendert", "geaendert_von"];
  const sql = `INSERT INTO ${table}(${cols.join(",")}) SELECT ${cols.map(c => `json_extract(value,'$.${c}')`).join(",")} FROM json_each(?)`;
  const stmts = []; let chunk = [], size = 0;
  for (const r of rows) {
    const s = JSON.stringify(r).length;
    if (chunk.length && size + s > 800000) { stmts.push(env.DB.prepare(sql).bind(JSON.stringify(chunk))); chunk = []; size = 0; }
    chunk.push(r); size += s;
  }
  if (chunk.length) stmts.push(env.DB.prepare(sql).bind(JSON.stringify(chunk)));
  await env.DB.batch(stmts);
}

/* ---- Anhänge an Einträgen (gleiche Rechte wie der Eintrag; löschen nur Vorstand) ---- */
async function visibleEntry(env, u, id) {
  const e = await env.DB.prepare("SELECT id, titel, bereich, rueckmeldung, fuer_trainer, mannschaft_id FROM eintraege WHERE id=?").bind(id).first();
  if (!e || !canSeeEntry(u, e)) fail(404, "Eintrag nicht gefunden.");
  return e;
}
async function visibleAttachment(env, u, id) {
  const a = await env.DB.prepare("SELECT a.*, e.bereich, e.titel, e.fuer_trainer, e.mannschaft_id FROM anhaenge a JOIN eintraege e ON e.id=a.eintrag_id WHERE a.id=?").bind(id).first();
  if (!a || !canSeeEntry(u, a)) fail(404, "Anhang nicht gefunden.");
  return a;
}
async function readUpload(req) {
  const len = Number(req.headers.get("Content-Length") || 0);
  if (len > MAX_FILE) fail(413, "Datei zu groß (max. 10 MB).");
  const buf = new Uint8Array(await req.arrayBuffer());
  if (!buf.length) fail(400, "Leere Datei.");
  if (buf.length > MAX_FILE) fail(413, "Datei zu groß (max. 10 MB).");
  let raw = req.headers.get("X-Dateiname") || "datei";
  try { raw = decodeURIComponent(raw); } catch {}
  const name = clean(raw, 200).replace(/[\\/:*?"<>|\r\n]/g, "_") || "datei";
  const mime = clean(req.headers.get("Content-Type") || "application/octet-stream", 100);
  return { buf, name, mime };
}
async function addAttachment(req, env, u, entryId) {
  const e = await visibleEntry(env, u, entryId);
  needArea(u, e.bereich, 2);
  const { buf, name, mime } = await readUpload(req);
  const id = uid(), t = nowIso();
  const stmts = [env.DB.prepare("INSERT INTO anhaenge(id,eintrag_id,dateiname,mime,groesse,erstellt,erstellt_von) VALUES(?,?,?,?,?,?,?)")
    .bind(id, entryId, name, mime, buf.length, t, u.anzeigename)];
  for (let i = 0, nr = 0; i < buf.length; i += CHUNK, nr++)
    stmts.push(env.DB.prepare("INSERT INTO anhang_teile(anhang_id,nr,daten) VALUES(?,?,?)").bind(id, nr, buf.slice(i, i + CHUNK)));
  await env.DB.batch(stmts);
  await log(env, u, "Datei angehängt", e.titel, name);
  return { ok: true, id };
}
async function downloadAttachment(env, u, id, cors) {
  const a = await visibleAttachment(env, u, id);
  const { results } = await env.DB.prepare("SELECT daten FROM anhang_teile WHERE anhang_id=? ORDER BY nr").bind(id).all();
  const out = new Uint8Array(a.groesse); let o = 0;
  for (const r of results) { const part = new Uint8Array(r.daten); out.set(part, o); o += part.length; }
  return new Response(out, { headers: { "Content-Type": a.mime || "application/octet-stream",
    "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(a.dateiname)}`, ...SECURITY, ...cors } });
}
async function deleteAttachment(env, u, id) {
  const a = await visibleAttachment(env, u, id);
  needArea(u, a.bereich, 3);
  await env.DB.batch([env.DB.prepare("DELETE FROM anhang_teile WHERE anhang_id=?").bind(id), env.DB.prepare("DELETE FROM anhaenge WHERE id=?").bind(id)]);
  await log(env, u, "Anhang gelöscht", a.titel, a.dateiname);
  return { ok: true };
}

/* ---- Mitglieder & Eltern-Verteiler (Vorstand + Ausschuss; löschen nur Vorstand) ---- */
function readMember(b) {
  const v = {};
  for (const k of MEMBER_FIELDS) v[k] = clean(b[k], MEMBER_LIMITS[k]);
  if (!v.vorname && !v.nachname) fail(400, "Bitte Vor- oder Nachnamen eingeben.");
  if (!validDate(v.geburtsdatum) || !validDate(v.eintritt)) fail(400, `${v.vorname} ${v.nachname}: Datum ungültig.`);
  if (v.email && !EMAIL_RE.test(v.email)) fail(400, `${v.vorname} ${v.nachname}: E-Mail-Adresse ungültig.`);
  if (!MEMBER_STATUSES.includes(v.status)) v.status = "Aktiv";
  return v;
}
function readParent(b) {
  const v = {};
  for (const k of PARENT_FIELDS) v[k] = clean(b[k], PARENT_LIMITS[k]);
  v.email = v.email.toLowerCase();
  if (!EMAIL_RE.test(v.email)) fail(400, `E-Mail-Adresse ungültig: „${v.email || "leer"}“`);
  // Einwilligung: ohne Häkchen kein Datum; mit Häkchen und ohne Datum → heute
  v.einwilligung = b.einwilligung === true || b.einwilligung === 1 || b.einwilligung === "1" ? 1 : 0;
  if (!validDate(v.einwilligung_datum)) fail(400, "Datum der Einwilligung ungültig.");
  v.einwilligung_datum = v.einwilligung ? (v.einwilligung_datum || nowIso().slice(0, 10)) : "";
  return v;
}
// Wer darf Mitglieder/Eltern lesen bzw. schreiben (feste Regel für Eltern-Kontakte)
function needPeople(u, P, stufe) {
  if (P.table === "mitglieder") return needArea(u, "Mitglieder", stufe);
  if (elternAll(u)) return;
  if (isTeamish(u) && stufe <= 1) return;
  if (isTeamish(u)) fail(403, "Eltern-Kontakte pflegen nur Admins und Jugendleitung.");
  hidden();
}
const PEOPLE = {
  mitglieder: { table: "mitglieder", fields: MEMBER_FIELDS, read: readMember, order: "nachname, vorname", label: "Mitglied",
    name: v => `${v.vorname} ${v.nachname}`.trim(), key: v => `${v.vorname}|${v.nachname}|${v.geburtsdatum}`.toLowerCase() },
  eltern: { table: "eltern", fields: PARENT_FIELDS, read: readParent, order: "mannschaft, name, email", label: "Eltern-Adresse",
    name: v => v.name || v.email, key: v => v.email.toLowerCase() },
};
function ageOf(d) {
  if (!d) return null;
  const [y, m, dd] = d.split("-").map(Number), [ty, tm, td] = nowIso().slice(0, 10).split("-").map(Number);
  return ty - y - (tm < m || (tm === m && td < dd) ? 1 : 0);
}
async function listPeople(env, P, u) {
  if (!u) { /* interner Aufruf nach dem Speichern: volle Liste */ }
  else if (P.table === "mitglieder" ? lvl(u, "Mitglieder") < 1 : !elternAll(u)) {
    if (!isTeamish(u)) hidden();
    // Trainer/Co-Trainer/Betreuer: nur eigene Mannschaft(en), nur nötige Felder; Eltern nur mit Einwilligung
    const teams = u.teams || [];
    if (!teams.length) return { liste: [] };
    const { results } = await env.DB.prepare(`SELECT * FROM ${P.table} WHERE mannschaft_id IN (${teams.map(() => "?").join(",")})${P.table === "eltern" ? " AND einwilligung=1" : ""} ORDER BY ${P.order}`).bind(...teams).all();
    return { liste: results.map(P.table === "mitglieder"
      ? r => ({ id: r.id, vorname: r.vorname, nachname: r.nachname, alter: ageOf(r.geburtsdatum), status: r.status, mannschaft: r.mannschaft, mannschaft_id: r.mannschaft_id })
      : r => ({ id: r.id, name: r.name, email: r.email, kind: r.kind, mannschaft: r.mannschaft, mannschaft_id: r.mannschaft_id, einwilligung: 1 })) };
  }
  const { results } = await env.DB.prepare(`SELECT * FROM ${P.table} ORDER BY ${P.order}`).all();
  return { liste: results };
}
// Mannschaft zuordnen: gültige ID → Name übernehmen; sonst über den Namen (ohne Groß/klein, Leerzeichen, Bindestriche)
function resolveTeam(v, teams) {
  const byId = teams.find(x => x.id === v.mannschaft_id);
  const t = byId || (v.mannschaft ? teams.find(x => normTeam(x.name) === normTeam(v.mannschaft)) : null);
  if (t) { v.mannschaft_id = t.id; v.mannschaft = t.name; } else v.mannschaft_id = "";
  return v;
}
async function savePerson(req, env, u, P, id) {
  needPeople(u, P, 2);
  const b = await body(req), v = resolveTeam(P.read(b), await teamList(env)), t = nowIso(), isNew = !id;
  if (id) {
    const old = await env.DB.prepare(`SELECT geaendert FROM ${P.table} WHERE id=?`).bind(id).first();
    if (!old) fail(404, "Nicht gefunden.");
    if (b.geaendert && b.geaendert !== old.geaendert) fail(409, "Jemand anderes hat diesen Datensatz inzwischen geändert. Bitte neu laden.");
    await env.DB.prepare(`UPDATE ${P.table} SET ${P.fields.map(k => k + "=?").join(",")}, geaendert=?, geaendert_von=? WHERE id=?`)
      .bind(...P.fields.map(k => v[k]), t, u.anzeigename, id).run();
  } else {
    id = uid();
    await env.DB.prepare(`INSERT INTO ${P.table}(id,${P.fields.join(",")},erstellt,geaendert,geaendert_von) VALUES(?,${P.fields.map(() => "?").join(",")},?,?,?)`)
      .bind(id, ...P.fields.map(k => v[k]), t, t, u.anzeigename).run();
  }
  await log(env, u, isNew ? `${P.label} angelegt` : `${P.label} geändert`, P.name(v));
  return listPeople(env, P);
}
async function importPeople(req, env, u, P) {
  needPeople(u, P, 2);
  const b = await body(req);
  if (!Array.isArray(b.liste) || !b.liste.length) fail(400, "Keine Zeilen zum Importieren.");
  if (b.liste.length > MAX_IMPORT) fail(400, `Höchstens ${MAX_IMPORT} Zeilen auf einmal.`);
  const teams = await teamList(env);
  const rows = b.liste.map(x => resolveTeam(P.read(x), teams)), t = nowIso();
  const { results } = await env.DB.prepare(`SELECT ${P.fields.join(",")} FROM ${P.table}`).all();
  const seen = new Set(results.map(P.key)), neu = [];
  for (const v of rows) { const k = P.key(v); if (!seen.has(k)) { seen.add(k); neu.push(v); } }
  if (neu.length) {
    await bulkInsert(env, P.table, P.fields, neu.map(v => ({ ...v, id: uid(), erstellt: t, geaendert: t, geaendert_von: u.anzeigename })));
    await log(env, u, "Importiert", `${neu.length} × ${P.label}`, b.datei ? "aus " + clean(b.datei, 200) : "");
  }
  return { ...(await listPeople(env, P)), neu: neu.length, doppelt: rows.length - neu.length };
}
async function deletePerson(env, u, P, id) {
  needPeople(u, P, 3);
  const old = await env.DB.prepare(`SELECT * FROM ${P.table} WHERE id=?`).bind(id).first();
  if (!old) fail(404, "Nicht gefunden.");
  await env.DB.prepare(`DELETE FROM ${P.table} WHERE id=?`).bind(id).run();
  await log(env, u, `${P.label} gelöscht`, P.name(old));
  return listPeople(env, P);
}

/* ---- Dokumente (nur Vorstand) ---- */
async function listDocs(env) {
  const { results } = await env.DB.prepare("SELECT * FROM dokumente ORDER BY datum DESC, titel").all();
  return { dokumente: results };
}
function readDoc(b) {
  const v = { titel: clean(b.titel, 160), beschreibung: clean(b.beschreibung, 4000), status: clean(b.status, 60), datum: clean(b.datum, 10) };
  if (!v.titel) fail(400, "Bitte einen Titel eingeben.");
  if (!validDate(v.datum)) fail(400, "Datum ungültig.");
  return v;
}
async function saveDoc(req, env, u, id) {
  const v = readDoc(await body(req)), t = nowIso();
  if (id) {
    const r = await env.DB.prepare("UPDATE dokumente SET titel=?,beschreibung=?,status=?,datum=?,geaendert=? WHERE id=?").bind(v.titel, v.beschreibung, v.status, v.datum, t, id).run();
    if (!r.meta.changes) fail(404, "Dokument nicht gefunden.");
  } else {
    id = uid();
    await env.DB.prepare("INSERT INTO dokumente(id,titel,beschreibung,status,datum,erstellt,geaendert) VALUES(?,?,?,?,?,?,?)").bind(id, v.titel, v.beschreibung, v.status, v.datum, t, t).run();
  }
  await log(env, u, id ? "Gespeichert" : "Angelegt", "Dokument: " + v.titel, v.status);
  return { dokument: await env.DB.prepare("SELECT * FROM dokumente WHERE id=?").bind(id).first() };
}
async function uploadFile(req, env, u, id) {
  const d = await env.DB.prepare("SELECT titel FROM dokumente WHERE id=?").bind(id).first();
  if (!d) fail(404, "Dokument nicht gefunden.");
  const len = Number(req.headers.get("Content-Length") || 0);
  if (len > MAX_FILE) fail(413, "Datei zu groß (max. 10 MB).");
  const buf = new Uint8Array(await req.arrayBuffer());
  if (!buf.length) fail(400, "Leere Datei.");
  if (buf.length > MAX_FILE) fail(413, "Datei zu groß (max. 10 MB).");
  const name = clean(decodeURIComponent(req.headers.get("X-Dateiname") || "datei"), 200).replace(/[\\/:*?"<>|\r\n]/g, "_");
  const mime = clean(req.headers.get("Content-Type") || "application/octet-stream", 100);
  const stmts = [env.DB.prepare("DELETE FROM dokument_teile WHERE dokument_id=?").bind(id)];
  for (let i = 0, nr = 0; i < buf.length; i += CHUNK, nr++)
    stmts.push(env.DB.prepare("INSERT INTO dokument_teile(dokument_id,nr,daten) VALUES(?,?,?)").bind(id, nr, buf.slice(i, i + CHUNK)));
  stmts.push(env.DB.prepare("UPDATE dokumente SET dateiname=?, mime=?, groesse=?, geaendert=? WHERE id=?").bind(name, mime, buf.length, nowIso(), id));
  await env.DB.batch(stmts);
  await log(env, u, "Datei hochgeladen", "Dokument: " + d.titel, name);
  return { ok: true };
}
async function downloadFile(env, id, cors) {
  const d = await env.DB.prepare("SELECT dateiname, mime, groesse FROM dokumente WHERE id=?").bind(id).first();
  if (!d || !d.groesse) fail(404, "Keine Datei hinterlegt.");
  const { results } = await env.DB.prepare("SELECT daten FROM dokument_teile WHERE dokument_id=? ORDER BY nr").bind(id).all();
  const out = new Uint8Array(d.groesse); let o = 0;
  for (const r of results) { const part = new Uint8Array(r.daten); out.set(part, o); o += part.length; }
  return new Response(out, { headers: { "Content-Type": d.mime || "application/octet-stream",
    "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(d.dateiname)}`, ...SECURITY, ...cors } });
}
async function deleteDoc(env, u, id) {
  const d = await env.DB.prepare("SELECT titel FROM dokumente WHERE id=?").bind(id).first();
  if (!d) fail(404, "Dokument nicht gefunden.");
  await env.DB.batch([env.DB.prepare("DELETE FROM dokument_teile WHERE dokument_id=?").bind(id), env.DB.prepare("DELETE FROM dokumente WHERE id=?").bind(id)]);
  await log(env, u, "Gelöscht", "Dokument: " + d.titel);
  return { ok: true };
}

/* ---- Downloads (Vorstand + Ausschuss; löschen nur Vorstand) ---- */
async function listDownloads(env) {
  const { results } = await env.DB.prepare("SELECT * FROM downloads ORDER BY kategorie, titel").all();
  return { downloads: results };
}
async function saveDownload(req, env, u, id) {
  const b = await body(req), t = nowIso();
  const v = { titel: clean(b.titel, 160), kategorie: clean(b.kategorie, 60), beschreibung: clean(b.beschreibung, 2000) };
  if (!v.titel) fail(400, "Bitte einen Titel eingeben.");
  if (!DL_CATS.includes(v.kategorie)) fail(400, "Unbekannte Kategorie.");
  if (id) {
    const r = await env.DB.prepare("UPDATE downloads SET titel=?, kategorie=?, beschreibung=?, geaendert=?, geaendert_von=? WHERE id=?").bind(v.titel, v.kategorie, v.beschreibung, t, u.anzeigename, id).run();
    if (!r.meta.changes) fail(404, "Download nicht gefunden.");
  } else {
    id = uid();
    await env.DB.prepare("INSERT INTO downloads(id,titel,kategorie,beschreibung,erstellt,geaendert,geaendert_von) VALUES(?,?,?,?,?,?,?)").bind(id, v.titel, v.kategorie, v.beschreibung, t, t, u.anzeigename).run();
  }
  await log(env, u, "Download gespeichert", v.titel, v.kategorie);
  return { download: await env.DB.prepare("SELECT * FROM downloads WHERE id=?").bind(id).first() };
}
async function uploadDownload(req, env, u, id) {
  const d = await env.DB.prepare("SELECT titel FROM downloads WHERE id=?").bind(id).first();
  if (!d) fail(404, "Download nicht gefunden.");
  const { buf, name, mime } = await readUpload(req);
  const stmts = [env.DB.prepare("DELETE FROM download_teile WHERE download_id=?").bind(id)];
  for (let i = 0, nr = 0; i < buf.length; i += CHUNK, nr++)
    stmts.push(env.DB.prepare("INSERT INTO download_teile(download_id,nr,daten) VALUES(?,?,?)").bind(id, nr, buf.slice(i, i + CHUNK)));
  stmts.push(env.DB.prepare("UPDATE downloads SET dateiname=?, mime=?, groesse=?, geaendert=?, geaendert_von=? WHERE id=?").bind(name, mime, buf.length, nowIso(), u.anzeigename, id));
  await env.DB.batch(stmts);
  await log(env, u, "Datei hochgeladen", "Download: " + d.titel, name);
  return { ok: true };
}
async function getDownload(env, id, cors) {
  const d = await env.DB.prepare("SELECT dateiname, mime, groesse FROM downloads WHERE id=?").bind(id).first();
  if (!d || !d.groesse) fail(404, "Keine Datei hinterlegt.");
  const { results } = await env.DB.prepare("SELECT daten FROM download_teile WHERE download_id=? ORDER BY nr").bind(id).all();
  const out = new Uint8Array(d.groesse); let o = 0;
  for (const r of results) { const part = new Uint8Array(r.daten); out.set(part, o); o += part.length; }
  return new Response(out, { headers: { "Content-Type": d.mime || "application/octet-stream",
    "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(d.dateiname)}`, ...SECURITY, ...cors } });
}
async function deleteDownload(env, u, id) {
  needArea(u, "Downloads", 3);
  const d = await env.DB.prepare("SELECT titel FROM downloads WHERE id=?").bind(id).first();
  if (!d) fail(404, "Download nicht gefunden.");
  await env.DB.batch([env.DB.prepare("DELETE FROM download_teile WHERE download_id=?").bind(id), env.DB.prepare("DELETE FROM downloads WHERE id=?").bind(id)]);
  await log(env, u, "Gelöscht", "Download: " + d.titel);
  return { ok: true };
}

/* ---- Vereinsdaten / Rechnungs-Vorlage ---- */
function readVerein(b) {
  const v = {};
  for (const [k, max] of Object.entries(VEREIN_FIELDS)) v[k] = clean(b?.[k], max);
  if (v.mwst && !(Number(v.mwst.replace(",", ".")) >= 0 && Number(v.mwst.replace(",", ".")) <= 100)) fail(400, "MwSt-Satz muss zwischen 0 und 100 liegen.");
  if (v.zahlungsziel && !/^\d{1,3}$/.test(v.zahlungsziel)) fail(400, "Zahlungsziel: Anzahl Tage (z. B. 14).");
  if (v.email && !EMAIL_RE.test(v.email)) fail(400, "E-Mail-Adresse des Vereins ungültig.");
  return v;
}
async function getSettings(env) {
  const row = await env.DB.prepare("SELECT wert, geaendert, geaendert_von FROM einstellungen WHERE schluessel='verein'").first();
  let v = {}; try { v = row ? JSON.parse(row.wert) : {}; } catch {}
  return { verein: { ...VEREIN_DEFAULTS, ...v }, geaendert: row?.geaendert || "", geaendert_von: row?.geaendert_von || "" };
}
async function saveSettings(req, env, u) {
  const v = readVerein(await body(req)), t = nowIso();
  await env.DB.prepare(`INSERT INTO einstellungen(schluessel,wert,geaendert,geaendert_von) VALUES('verein',?,?,?)
    ON CONFLICT(schluessel) DO UPDATE SET wert=excluded.wert, geaendert=excluded.geaendert, geaendert_von=excluded.geaendert_von`).bind(JSON.stringify(v), t, u.anzeigename).run();
  await log(env, u, "Vereinsdaten geändert", "Rechnungs-Vorlage");
  return getSettings(env);
}

/* ---- Rechnungen (Vorstand + Ausschuss; stornieren nur Vorstand; nie löschen) ---- */
function readInvoice(b) {
  const v = { datum: clean(b.datum, 10), leistungsdatum: clean(b.leistungsdatum, 10), faellig: clean(b.faellig, 10),
    empfaenger: clean(b.empfaenger, 600), betreff: clean(b.betreff, 200), einleitung: clean(b.einleitung, 4000), schlusstext: clean(b.schlusstext, 4000) };
  if (!v.datum || !validDate(v.datum)) fail(400, "Bitte ein gültiges Rechnungsdatum angeben.");
  if (!validDate(v.leistungsdatum) || !validDate(v.faellig)) fail(400, "Leistungsdatum oder Fälligkeit ungültig.");
  if (!v.empfaenger) fail(400, "Bitte den Rechnungsempfänger (Name und Anschrift) eingeben.");
  if (!Array.isArray(b.positionen) || !b.positionen.length) fail(400, "Bitte mindestens eine Position eingeben.");
  if (b.positionen.length > 100) fail(400, "Höchstens 100 Positionen.");
  const pos = b.positionen.map((p, i) => {
    const x = { beschreibung: clean(p?.beschreibung, 1000), menge: Math.round(Number(p?.menge) * 1000) / 1000, einheit: clean(p?.einheit, 20),
      preis: Math.round(Number(p?.preis)), mwst: Math.round(Number(p?.mwst) * 100) / 100 };
    if (!x.beschreibung) fail(400, `Position ${i + 1}: Bitte eine Beschreibung eingeben.`);
    if (!Number.isFinite(x.menge) || Math.abs(x.menge) > 1e6) fail(400, `Position ${i + 1}: Menge ungültig.`);
    if (!Number.isFinite(x.preis) || Math.abs(x.preis) > 1e9) fail(400, `Position ${i + 1}: Preis ungültig.`);
    if (!Number.isFinite(x.mwst) || x.mwst < 0 || x.mwst > 100) fail(400, `Position ${i + 1}: MwSt-Satz muss zwischen 0 und 100 liegen.`);
    return x;
  });
  // Summen: Netto je Position gerundet, Steuer je Steuersatz gerundet
  const byRate = {};
  for (const p of pos) byRate[p.mwst] = (byRate[p.mwst] || 0) + Math.round(p.menge * p.preis);
  v.netto = Object.values(byRate).reduce((a, n) => a + n, 0);
  v.steuer = Object.entries(byRate).reduce((a, [r, n]) => a + Math.round(n * Number(r) / 100), 0);
  v.brutto = v.netto + v.steuer;
  v.positionen = JSON.stringify(pos);
  v.absender = JSON.stringify(readVerein(b.absender || {}));
  return v;
}
const INV_COLS = ["datum","leistungsdatum","faellig","empfaenger","betreff","einleitung","positionen","schlusstext","absender","netto","steuer","brutto"];
async function listInvoices(env) {
  const { results } = await env.DB.prepare("SELECT * FROM rechnungen ORDER BY jahr DESC, lfd DESC").all();
  return { rechnungen: results };
}
async function createInvoice(req, env, u) {
  // Jahr als Text binden: JS-Zahlen würden als Kommazahl (2026.0) in der Nummer landen
  const v = readInvoice(await body(req)), t = nowIso(), id = uid(), jahr = v.datum.slice(0, 4);
  // Nummer in derselben Abfrage vergeben: fortlaufend, ohne Lücke, nie doppelt (UNIQUE)
  const vals = INV_COLS.map(k => v[k]);
  await env.DB.prepare(`INSERT INTO rechnungen(id,jahr,lfd,nummer,${INV_COLS.join(",")},status,erstellt,erstellt_von,geaendert,geaendert_von)
    SELECT ?1, ?2, n, 'SKU-' || ?2 || '-' || printf('%04d', n), ${INV_COLS.map((_, i) => "?" + (i + 3)).join(",")}, 'Offen', ?${INV_COLS.length + 3}, ?${INV_COLS.length + 4}, ?${INV_COLS.length + 3}, ?${INV_COLS.length + 4}
    FROM (SELECT COALESCE(MAX(lfd), 0) + 1 AS n FROM rechnungen WHERE jahr = ?2)`).bind(id, jahr, ...vals, t, u.anzeigename).run();
  const r = await env.DB.prepare("SELECT * FROM rechnungen WHERE id=?").bind(id).first();
  await log(env, u, "Rechnung erstellt", r.nummer, `${v.empfaenger.split("\n")[0]} · ${(v.brutto / 100).toFixed(2).replace(".", ",")} €`);
  return { rechnung: r };
}
async function updateInvoice(req, env, u, id) {
  const b = await body(req);
  const old = await env.DB.prepare("SELECT * FROM rechnungen WHERE id=?").bind(id).first();
  if (!old) fail(404, "Rechnung nicht gefunden.");
  if (old.status === "Storniert") fail(409, "Stornierte Rechnungen können nicht mehr geändert werden.");
  if (b.geaendert && b.geaendert !== old.geaendert) fail(409, "Jemand anderes hat diese Rechnung inzwischen geändert. Bitte neu laden.");
  const v = readInvoice(b), t = nowIso();
  await env.DB.prepare(`UPDATE rechnungen SET ${INV_COLS.map(k => k + "=?").join(",")}, geaendert=?, geaendert_von=? WHERE id=?`).bind(...INV_COLS.map(k => v[k]), t, u.anzeigename, id).run();
  await log(env, u, "Rechnung geändert", old.nummer, `${(old.brutto / 100).toFixed(2).replace(".", ",")} € → ${(v.brutto / 100).toFixed(2).replace(".", ",")} €`);
  return { rechnung: await env.DB.prepare("SELECT * FROM rechnungen WHERE id=?").bind(id).first() };
}
async function setInvoiceStatus(req, env, u, id) {
  const b = await body(req);
  const old = await env.DB.prepare("SELECT * FROM rechnungen WHERE id=?").bind(id).first();
  if (!old) fail(404, "Rechnung nicht gefunden.");
  if (!INVOICE_STATUSES.includes(b.status)) fail(400, "Unbekannter Status.");
  if (old.status === "Storniert") fail(409, "Die Rechnung ist storniert und bleibt es.");
  if (b.status === "Storniert") needStorno(u);
  const am = b.status === "Bezahlt" ? clean(b.bezahlt_am, 10) || nowIso().slice(0, 10) : "";
  if (!validDate(am)) fail(400, "Datum ungültig.");
  await env.DB.prepare("UPDATE rechnungen SET status=?, bezahlt_am=?, geaendert=?, geaendert_von=? WHERE id=?").bind(b.status, am, nowIso(), u.anzeigename, id).run();
  await log(env, u, b.status === "Storniert" ? "Rechnung storniert" : "Rechnungsstatus", old.nummer, b.status + (am ? " am " + am : ""));
  return { rechnung: await env.DB.prepare("SELECT * FROM rechnungen WHERE id=?").bind(id).first() };
}

/* ---- Mannschaftsliste (Namen für alle; WhatsApp-Link nur wer Elternkommunikation sieht bzw. Trainer der Mannschaft;
        pflegen: Admin, Jugendleitung, Mitglieder-Stufe „löschen“) ---- */
async function listTeams(env, u) {
  const all = await teamList(env);
  const broad = teamsManage(u) || elternAll(u) || lvl(u, "Mitglieder") >= 1 || lvl(u, "Elternkommunikation") >= 1 || lvl(u, "Mannschaften") >= 1;
  if (!broad) {
    // Trainer/Helfer ohne weitere Rechte: nur die eigenen Mannschaften
    return { mannschaften: isTeamish(u) ? all.filter(t => (u.teams || []).includes(t.id)) : [] };
  }
  const linkOk = t => teamsManage(u) || elternAll(u) || lvl(u, "Elternkommunikation") >= 1 || (isTeamish(u) && (u.teams || []).includes(t.id));
  const out = { mannschaften: all.map(t => linkOk(t) ? t : { ...t, whatsapp_link: "" }) };
  if (teamsManage(u)) {
    // Freitext-Werte ohne Zuordnung (aus alter Zeit oder Import)
    const { results } = await env.DB.prepare(`SELECT name, SUM(m) mitglieder, SUM(e) eltern FROM (
        SELECT trim(mannschaft) name, 1 m, 0 e FROM mitglieder WHERE mannschaft_id='' AND trim(mannschaft)<>''
        UNION ALL SELECT trim(mannschaft), 0, 1 FROM eltern WHERE mannschaft_id='' AND trim(mannschaft)<>'') GROUP BY name ORDER BY name`).all();
    out.nicht_zugeordnet = results;
  }
  return out;
}
function readTeam(b) {
  const v = { name: clean(b.name, 60), sortierung: Math.round(Number(b.sortierung) || 0), aktiv: b.aktiv === false || b.aktiv === 0 ? 0 : 1,
    whatsapp_link: clean(b.whatsapp_link, 200) };
  if (!v.name) fail(400, "Bitte einen Namen für die Mannschaft eingeben.");
  if (v.whatsapp_link && !WA_RE.test(v.whatsapp_link)) fail(400, "WhatsApp-Link bitte so: https://chat.whatsapp.com/… (Gruppe → Einladen per Link).");
  return v;
}
function needTeams(u) { if (!teamsManage(u)) { if (lvl(u, "Mitglieder") >= 1 || isTeamish(u)) fail(403, "Die Mannschaftsliste pflegen Admins, Jugendleitung und Mitgliederverwaltung."); hidden(); } }
async function saveTeam(req, env, u, id) {
  needTeams(u);
  const v = readTeam(await body(req)), t = nowIso();
  const clash = (await teamList(env)).find(x => x.id !== id && normTeam(x.name) === normTeam(v.name));
  if (clash) fail(409, `Die Mannschaft „${clash.name}“ gibt es schon.`);
  if (id) {
    const old = await env.DB.prepare("SELECT * FROM mannschaften WHERE id=?").bind(id).first();
    if (!old) fail(404, "Mannschaft nicht gefunden.");
    await env.DB.batch([
      env.DB.prepare("UPDATE mannschaften SET name=?, sortierung=?, aktiv=?, whatsapp_link=?, geaendert=? WHERE id=?").bind(v.name, v.sortierung, v.aktiv, v.whatsapp_link, t, id),
      env.DB.prepare("UPDATE mitglieder SET mannschaft=? WHERE mannschaft_id=?").bind(v.name, id),
      env.DB.prepare("UPDATE eltern SET mannschaft=? WHERE mannschaft_id=?").bind(v.name, id),
    ]);
    await log(env, u, "Mannschaft geändert", v.name, [old.name !== v.name && `Name: „${old.name}“ → „${v.name}“`, old.aktiv !== v.aktiv && (v.aktiv ? "wieder aktiv" : "deaktiviert"),
      old.sortierung !== v.sortierung && `Sortierung: ${v.sortierung}`, old.whatsapp_link !== v.whatsapp_link && (v.whatsapp_link ? "WhatsApp-Gruppenlink gesetzt" : "WhatsApp-Gruppenlink entfernt")].filter(Boolean).join("\n"));
  } else {
    id = uid();
    await env.DB.prepare("INSERT INTO mannschaften(id,name,sortierung,aktiv,whatsapp_link,erstellt,geaendert) VALUES(?,?,?,?,?,?,?)").bind(id, v.name, v.sortierung, v.aktiv, v.whatsapp_link, t, t).run();
    await log(env, u, "Mannschaft angelegt", v.name);
  }
  return listTeams(env, u);
}
// Freitext-Wert („nicht zugeordnet“) einer Mannschaft der Liste zuordnen
async function assignTeam(req, env, u) {
  needTeams(u);
  const b = await body(req), text = clean(b.text, 80);
  const team = await env.DB.prepare("SELECT * FROM mannschaften WHERE id=?").bind(clean(b.mannschaft_id, 60)).first();
  if (!text || !team) fail(400, "Bitte Wert und Mannschaft angeben.");
  const r = await env.DB.batch([
    env.DB.prepare("UPDATE mitglieder SET mannschaft_id=?, mannschaft=? WHERE mannschaft_id='' AND trim(mannschaft)=?").bind(team.id, team.name, text),
    env.DB.prepare("UPDATE eltern SET mannschaft_id=?, mannschaft=? WHERE mannschaft_id='' AND trim(mannschaft)=?").bind(team.id, team.name, text),
  ]);
  await log(env, u, "Mannschaft zugeordnet", team.name, `„${text}“ → ${team.name} (${r[0].meta.changes} Mitglieder, ${r[1].meta.changes} Eltern)`);
  return listTeams(env, u);
}
// Aus der JSON-Sicherung: fehlende Mannschaften anlegen (über den Namen)
async function importTeams(req, env, u) {
  needTeams(u);
  const b = await body(req);
  if (!Array.isArray(b.liste)) fail(400, "Keine Mannschaften.");
  const have = await teamList(env), t = nowIso(), stmts = [], neu = [];
  for (const x of b.liste.slice(0, 200)) {
    const v = readTeam(x);
    if (have.some(h => normTeam(h.name) === normTeam(v.name)) || neu.some(n => normTeam(n) === normTeam(v.name))) continue;
    neu.push(v.name);
    stmts.push(env.DB.prepare("INSERT INTO mannschaften(id,name,sortierung,aktiv,erstellt,geaendert) VALUES(?,?,?,?,?,?)").bind(uid(), v.name, v.sortierung, v.aktiv, t, t));
  }
  if (stmts.length) { await env.DB.batch(stmts); await log(env, u, "Importiert", `${neu.length} Mannschaften`, neu.join(", ")); }
  return { ...(await listTeams(env, u)), neu: neu.length };
}

/* ---- Kasse (nur Admin + Schatzmeister/in; Kassenprüfer/in optional lesen; Storno nur Schatzmeister/in; nie löschen) ---- */
async function getKasseSettings(env) {
  const row = await env.DB.prepare("SELECT wert, geaendert, geaendert_von FROM einstellungen WHERE schluessel='kasse'").first();
  let v = {}; try { v = row ? JSON.parse(row.wert) : {}; } catch {}
  return { ...KASSE_DEFAULTS, ...v, geaendert: row?.geaendert || "", geaendert_von: row?.geaendert_von || "" };
}
async function listKasse(env) {
  const [b, d] = await env.DB.batch([
    env.DB.prepare("SELECT * FROM kassenbuchungen ORDER BY datum DESC, jahr DESC, lfd DESC"),
    env.DB.prepare("SELECT id, buchung_id, dateiname, mime, groesse, erstellt, erstellt_von FROM kassen_belege ORDER BY erstellt"),
  ]);
  const belege = {};
  for (const x of d.results) (belege[x.buchung_id] ||= []).push(x);
  return { buchungen: b.results.map(x => ({ ...x, belege: belege[x.id] || [] })), einstellungen: await getKasseSettings(env) };
}
async function saveKasseSettings(req, env, u) {
  needMoney(u, true);
  const b = await body(req);
  const cents = x => { const n = Math.round(Number(x)); if (!Number.isFinite(n) || Math.abs(n) > 1e11) fail(400, "Anfangsbestand ungültig."); return n; };
  const kat = [...new Set((Array.isArray(b.kategorien) ? b.kategorien : []).map(k => clean(k, 60)).filter(Boolean))].slice(0, 50);
  if (!kat.length) fail(400, "Bitte mindestens eine Kategorie angeben.");
  const v = { kategorien: kat, anfang_bar: cents(b.anfang_bar), anfang_bank: cents(b.anfang_bank), stichtag: clean(b.stichtag, 10) };
  if (!validDate(v.stichtag)) fail(400, "Stichtag ungültig.");
  await env.DB.prepare(`INSERT INTO einstellungen(schluessel,wert,geaendert,geaendert_von) VALUES('kasse',?,?,?)
    ON CONFLICT(schluessel) DO UPDATE SET wert=excluded.wert, geaendert=excluded.geaendert, geaendert_von=excluded.geaendert_von`).bind(JSON.stringify(v), nowIso(), u.anzeigename).run();
  await log(env, u, "Kasse: Einstellungen geändert", "Kasse", `Anfang Bar ${(v.anfang_bar / 100).toFixed(2)} € · Bank ${(v.anfang_bank / 100).toFixed(2)} €${v.stichtag ? " · Stichtag " + v.stichtag : ""}\nKategorien: ${kat.join(", ")}`);
  return listKasse(env);
}
async function createBooking(req, env, u) {
  needMoney(u, true);
  const b = await body(req), s = await getKasseSettings(env);
  const v = { datum: clean(b.datum, 10), art: clean(b.art, 10), betrag: Math.round(Number(b.betrag)), kategorie: clean(b.kategorie, 60),
    beschreibung: clean(b.beschreibung, 1000), zahlungsweg: clean(b.zahlungsweg, 10), rechnung_id: clean(b.rechnung_id, 60), rechnung_nr: "" };
  if (!v.datum || !validDate(v.datum)) fail(400, "Bitte ein gültiges Datum angeben.");
  if (!["einnahme","ausgabe"].includes(v.art)) fail(400, "Bitte Einnahme oder Ausgabe wählen.");
  if (!Number.isFinite(v.betrag) || v.betrag <= 0 || v.betrag > 1e11) fail(400, "Bitte einen Betrag größer als 0 eingeben.");
  if (!s.kategorien.includes(v.kategorie)) fail(400, "Unbekannte Kategorie.");
  if (!["bar","bank"].includes(v.zahlungsweg)) fail(400, "Bitte Bar oder Bank wählen.");
  if (!v.beschreibung) fail(400, "Bitte eine Beschreibung eingeben.");
  if (v.rechnung_id) {
    const r = await env.DB.prepare("SELECT nummer FROM rechnungen WHERE id=?").bind(v.rechnung_id).first();
    if (!r) fail(400, "Rechnung nicht gefunden.");
    v.rechnung_nr = r.nummer;
    const dup = await env.DB.prepare("SELECT belegnr FROM kassenbuchungen WHERE rechnung_id=? AND storniert=0").bind(v.rechnung_id).first();
    if (dup && !b.trotzdem) fail(409, `Für Rechnung ${r.nummer} gibt es schon die Buchung ${dup.belegnr}.`);
  }
  const id = uid(), t = nowIso(), jahr = v.datum.slice(0, 4);   // Jahr als Text (sonst „2026.0“)
  const cols = ["datum","art","betrag","kategorie","beschreibung","zahlungsweg","rechnung_id","rechnung_nr"];
  await env.DB.prepare(`INSERT INTO kassenbuchungen(id,jahr,lfd,belegnr,${cols.join(",")},erstellt,erstellt_von)
    SELECT ?1, ?2, n, 'K-' || ?2 || '-' || printf('%04d', n), ${cols.map((_, i) => "?" + (i + 3)).join(",")}, ?${cols.length + 3}, ?${cols.length + 4}
    FROM (SELECT COALESCE(MAX(lfd), 0) + 1 AS n FROM kassenbuchungen WHERE jahr = ?2)`).bind(id, jahr, ...cols.map(k => v[k]), t, u.anzeigename).run();
  const row = await env.DB.prepare("SELECT * FROM kassenbuchungen WHERE id=?").bind(id).first();
  await log(env, u, "Kasse: gebucht", row.belegnr, `${v.art === "einnahme" ? "Einnahme" : "Ausgabe"} ${(v.betrag / 100).toFixed(2).replace(".", ",")} € · ${v.kategorie} · ${v.zahlungsweg === "bar" ? "Bar" : "Bank"}${v.rechnung_nr ? " · " + v.rechnung_nr : ""}\n${v.beschreibung}`);
  return { buchung: row };
}
async function stornoBooking(req, env, u, id) {
  needStorno(u);
  const b = await body(req), grund = clean(b.grund, 500);
  if (!grund) fail(400, "Bitte einen Grund für das Storno angeben.");
  const old = await env.DB.prepare("SELECT * FROM kassenbuchungen WHERE id=?").bind(id).first();
  if (!old) fail(404, "Buchung nicht gefunden.");
  if (old.storniert) fail(409, "Die Buchung ist bereits storniert.");
  await env.DB.prepare("UPDATE kassenbuchungen SET storniert=1, storno_grund=?, storno_am=?, storno_von=? WHERE id=?").bind(grund, nowIso(), u.anzeigename, id).run();
  await log(env, u, "Kasse: storniert", old.belegnr, grund);
  return listKasse(env);
}
async function addReceipt(req, env, u, id) {
  needMoney(u, true);
  const k = await env.DB.prepare("SELECT belegnr FROM kassenbuchungen WHERE id=?").bind(id).first();
  if (!k) fail(404, "Buchung nicht gefunden.");
  const { buf, name, mime } = await readUpload(req);
  const bid = uid(), stmts = [env.DB.prepare("INSERT INTO kassen_belege(id,buchung_id,dateiname,mime,groesse,erstellt,erstellt_von) VALUES(?,?,?,?,?,?,?)").bind(bid, id, name, mime, buf.length, nowIso(), u.anzeigename)];
  for (let i = 0, nr = 0; i < buf.length; i += CHUNK, nr++)
    stmts.push(env.DB.prepare("INSERT INTO kassen_beleg_teile(beleg_id,nr,daten) VALUES(?,?,?)").bind(bid, nr, buf.slice(i, i + CHUNK)));
  await env.DB.batch(stmts);
  await log(env, u, "Kasse: Beleg angehängt", k.belegnr, name);
  return { ok: true, id: bid };
}
async function getReceipt(env, id, cors) {
  const d = await env.DB.prepare("SELECT dateiname, mime, groesse FROM kassen_belege WHERE id=?").bind(id).first();
  if (!d) fail(404, "Beleg nicht gefunden.");
  const { results } = await env.DB.prepare("SELECT daten FROM kassen_beleg_teile WHERE beleg_id=? ORDER BY nr").bind(id).all();
  const out = new Uint8Array(d.groesse); let o = 0;
  for (const r of results) { const part = new Uint8Array(r.daten); out.set(part, o); o += part.length; }
  return new Response(out, { headers: { "Content-Type": d.mime || "application/octet-stream",
    "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(d.dateiname)}`, ...SECURITY, ...cors } });
}

/* ---- Wiederherstellen aus der JSON-Sicherung (nur in leere Tabellen – feste Nummern dürfen nie doppelt sein) ---- */
async function jsonInsert(env, table, cols, rows) {
  const sql = `INSERT INTO ${table}(${cols.join(",")}) SELECT ${cols.map(c => `json_extract(value,'$.${c}')`).join(",")} FROM json_each(?)`;
  const stmts = []; let chunk = [], size = 0;
  for (const r of rows) {
    const s = JSON.stringify(r).length;
    if (chunk.length && size + s > 800000) { stmts.push(env.DB.prepare(sql).bind(JSON.stringify(chunk))); chunk = []; size = 0; }
    chunk.push(r); size += s;
  }
  if (chunk.length) stmts.push(env.DB.prepare(sql).bind(JSON.stringify(chunk)));
  if (stmts.length) await env.DB.batch(stmts);
}
const RESTORE = {
  rechnungen: { need: u => needMoney(u, true), label: "Rechnungen", nr: "nummer", prefix: "SKU",
    cols: ["id","jahr","lfd","nummer","datum","leistungsdatum","faellig","empfaenger","betreff","einleitung","positionen","schlusstext","absender","netto","steuer","brutto","status","bezahlt_am","erstellt","erstellt_von","geaendert","geaendert_von"],
    check: r => INVOICE_STATUSES.includes(r.status) && validDate(r.datum) },
  kassenbuchungen: { need: u => needMoney(u, true), label: "Kassenbuchungen", nr: "belegnr", prefix: "K",
    cols: ["id","jahr","lfd","belegnr","datum","art","betrag","kategorie","beschreibung","zahlungsweg","rechnung_id","rechnung_nr","storniert","storno_grund","storno_am","storno_von","erstellt","erstellt_von"],
    check: r => ["einnahme","ausgabe"].includes(r.art) && ["bar","bank"].includes(r.zahlungsweg) && Number(r.betrag) > 0 && validDate(r.datum) },
};
async function restoreTable(req, env, u, name) {
  const R = RESTORE[name]; R.need(u);
  const b = await body(req);
  if (!Array.isArray(b.liste) || !b.liste.length) fail(400, "Nichts zum Wiederherstellen.");
  const n = (await env.DB.prepare(`SELECT COUNT(*) n FROM ${name}`).first()).n;
  if (n > 0) fail(409, `${R.label} werden nur in eine leere Liste zurückgespielt (es gibt schon ${n}). Feste Nummern dürfen nie doppelt vorkommen.`);
  const rows = b.liste.slice(0, 20000).map(r => {
    const x = {}; for (const c of R.cols) x[c] = r[c] ?? (["jahr","lfd","netto","steuer","brutto","betrag","storniert"].includes(c) ? 0 : "");
    x.jahr = String(x.jahr); x.lfd = Number(x.lfd);
    if (!x.id || !R.check(x) || !new RegExp(`^${R.prefix}-\\d{4}-\\d{4,}$`).test(x[R.nr])) fail(400, `Ungültiger Datensatz: ${x[R.nr] || "ohne Nummer"}`);
    return x;
  });
  await jsonInsert(env, name, R.cols, rows);
  await log(env, u, "Wiederhergestellt", `${rows.length} ${R.label}`, b.datei ? "aus " + clean(b.datei, 200) : "");
  return { ok: true, anzahl: rows.length };
}

/* ---- Benutzer (nur Admins) ---- */
async function funcList(env) { return (await env.DB.prepare("SELECT * FROM funktionen ORDER BY sortierung, name").all()).results; }
async function listUsers(env) {
  const [b, tm, bf] = await env.DB.batch([
    env.DB.prepare("SELECT * FROM benutzer ORDER BY rolle DESC, anzeigename"),
    env.DB.prepare("SELECT benutzer_id, mannschaft_id FROM trainer_mannschaften"),
    env.DB.prepare("SELECT benutzer_id, funktion_id FROM benutzer_funktionen"),
  ]);
  return { benutzer: b.results.map(x => publicUser({ ...x, teams: tm.results.filter(y => y.benutzer_id === x.id).map(y => y.mannschaft_id),
    funktionen: bf.results.filter(y => y.benutzer_id === x.id).map(y => y.funktion_id) })) };
}
async function adminCount(env) { return (await env.DB.prepare("SELECT COUNT(*) n FROM benutzer WHERE ist_admin=1 AND aktiv=1").first()).n; }
// Mannschaften prüfen (nur gültige IDs)
async function readTrainerTeams(env, list) {
  if (!Array.isArray(list)) return null;
  const known = new Set((await teamList(env)).map(x => x.id));
  const ids = [...new Set(list.map(x => String(x)))];
  if (ids.some(x => !known.has(x))) fail(400, "Unbekannte Mannschaft.");
  return ids;
}
// Funktionen prüfen: nur bekannte; Schatzmeister/in nur mit Grundrolle Vorstand
function readFuncs(list, rolle, funcs) {
  if (!Array.isArray(list)) return null;
  const ids = [...new Set(list.map(x => String(x)))];
  for (const id of ids) {
    const f = funcs.find(x => x.id === id);
    if (!f) fail(400, "Unbekannte Funktion.");
    if (f.schluessel === "schatzmeister" && rolle !== "vorstand") fail(400, `„${f.name}“ geht nur mit der Grundrolle Vorstand.`);
  }
  return ids;
}
const teamCapable = (rolle, ids, funcs) => rolle === "trainer" || ids.some(id => TEAM_KEYS.includes(funcs.find(f => f.id === id)?.schluessel));
const rightsText = (rolle, admin, ids, funcs, teams, all) => `Grundrolle: ${ROLE_LABEL[rolle]}${admin ? " + Admin" : ""}`
  + ` · Funktionen: ${ids.map(id => funcs.find(f => f.id === id)?.name || id).join(", ") || "keine"}`
  + (teams.length ? ` · Mannschaften: ${teams.map(id => all.find(x => x.id === id)?.name || id).join(", ")}` : "");
async function createUser(req, env, u) {
  const b = await body(req);
  const name = cleanUsername(b.benutzername);
  if (!ROLES.includes(b.rolle)) fail(400, "Unbekannte Grundrolle.");
  const funcs = await funcList(env);
  const admin = b.rolle === "vorstand" && b.ist_admin ? 1 : 0;   // Admin nur mit Grundrolle Vorstand
  const ids = readFuncs(b.funktionen, b.rolle, funcs) || [];
  const teams = teamCapable(b.rolle, ids, funcs) ? (await readTrainerTeams(env, b.mannschaften)) || [] : [];
  const pw = await makePassword(checkClientHash(b.passwort), env.PEPPER);
  const id = uid();
  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO benutzer(id,benutzername,anzeigename,rolle,ist_admin,pw_hash,pw_salt,pw_iter,pw_aendern,erstellt,erstellt_von) VALUES(?,?,?,?,?,?,?,?,1,?,?)`)
        .bind(id, name, clean(b.anzeigename, 80) || name, b.rolle, admin, pw.pw_hash, pw.pw_salt, pw.pw_iter, nowIso(), u.id),
      ...ids.map(f => env.DB.prepare("INSERT INTO benutzer_funktionen(benutzer_id,funktion_id) VALUES(?,?)").bind(id, f)),
      ...teams.map(m => env.DB.prepare("INSERT INTO trainer_mannschaften(benutzer_id,mannschaft_id) VALUES(?,?)").bind(id, m)),
    ]);
  } catch { fail(409, "Diesen Benutzernamen gibt es schon."); }
  await log(env, u, "Benutzer angelegt", clean(b.anzeigename, 80) || name, rightsText(b.rolle, admin, ids, funcs, teams, await teamList(env)) + ` · angelegt von ${u.anzeigename}`);
  return listUsers(env);
}
async function updateUser(req, env, u, id) {
  const b = await body(req);
  const t = await env.DB.prepare("SELECT * FROM benutzer WHERE id=?").bind(id).first();
  if (!t) fail(404, "Benutzer nicht gefunden.");
  const funcs = await funcList(env);
  const rolle = ROLES.includes(b.rolle) ? b.rolle : t.rolle;
  const ist_admin = rolle === "vorstand" && (b.ist_admin ?? !!t.ist_admin) ? 1 : 0;
  const aktiv = (b.aktiv ?? !!t.aktiv) ? 1 : 0;
  const anzeigename = clean(b.anzeigename ?? t.anzeigename, 80) || t.benutzername;
  if (t.ist_admin && t.aktiv && (!ist_admin || !aktiv) && (await adminCount(env)) <= 1) fail(400, "Mindestens ein aktiver Admin muss bleiben.");
  if (id === u.id && (!aktiv || !ist_admin)) fail(400, "Du kannst dir nicht selbst die Admin-Rechte nehmen oder dich deaktivieren.");
  const oldIds = (await env.DB.prepare("SELECT funktion_id FROM benutzer_funktionen WHERE benutzer_id=?").bind(id).all()).results.map(x => x.funktion_id);
  const ids = readFuncs(b.funktionen ?? oldIds.filter(f => rolle === "vorstand" || funcs.find(x => x.id === f)?.schluessel !== "schatzmeister"), rolle, funcs);
  const oldTeams = (await env.DB.prepare("SELECT mannschaft_id FROM trainer_mannschaften WHERE benutzer_id=?").bind(id).all()).results.map(x => x.mannschaft_id);
  const teams = !teamCapable(rolle, ids, funcs) ? [] : (await readTrainerTeams(env, b.mannschaften)) ?? oldTeams;
  const stmts = [env.DB.prepare("UPDATE benutzer SET anzeigename=?, rolle=?, ist_admin=?, aktiv=? WHERE id=?").bind(anzeigename, rolle, ist_admin, aktiv, id),
    env.DB.prepare("DELETE FROM benutzer_funktionen WHERE benutzer_id=?").bind(id),
    ...ids.map(f => env.DB.prepare("INSERT INTO benutzer_funktionen(benutzer_id,funktion_id) VALUES(?,?)").bind(id, f)),
    env.DB.prepare("DELETE FROM trainer_mannschaften WHERE benutzer_id=?").bind(id),
    ...teams.map(m => env.DB.prepare("INSERT INTO trainer_mannschaften(benutzer_id,mannschaft_id) VALUES(?,?)").bind(id, m))];
  if (!aktiv || rolle !== t.rolle) stmts.push(env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=?").bind(id));
  await env.DB.batch(stmts);
  await log(env, u, "Benutzer geändert", anzeigename, rightsText(rolle, ist_admin, ids, funcs, teams, await teamList(env)) + (aktiv ? "" : " · deaktiviert"));
  return listUsers(env);
}

/* ---- Delegierte Benutzerverwaltung: Festwirt/in verwaltet NUR reine Festwirt-Team-Konten ---- */
async function festTeamId(env) { return (await env.DB.prepare("SELECT id FROM funktionen WHERE schluessel='festwirt_team'").first())?.id; }
function needFestwirt(u) { if (!isFestwirt(u)) hidden(); }
// Reines Festwirt-Team-Konto: Grundrolle Helfer, kein Admin, genau die eine Funktion Festwirt-Team
async function teamAccounts(env, ft) {
  const { results } = await env.DB.prepare(`SELECT b.* FROM benutzer b WHERE b.rolle='helfer' AND b.ist_admin=0
    AND (SELECT COUNT(*) FROM benutzer_funktionen bf WHERE bf.benutzer_id=b.id)=1
    AND EXISTS (SELECT 1 FROM benutzer_funktionen bf WHERE bf.benutzer_id=b.id AND bf.funktion_id=?) ORDER BY b.anzeigename`).bind(ft).all();
  return results;
}
async function listTeam(env, u) {
  needFestwirt(u);
  const ft = await festTeamId(env);
  return { benutzer: (await teamAccounts(env, ft)).map(x => publicUser({ ...x, funktionen: [ft] })) };
}
async function teamTarget(env, u, id) {
  needFestwirt(u);
  const ft = await festTeamId(env);
  const t = (await teamAccounts(env, ft)).find(x => x.id === id);
  if (!t) hidden();   // fremde Konten gibt es für den Festwirt nicht
  return t;
}
async function createTeamAccount(req, env, u) {
  needFestwirt(u);
  const b = await body(req), name = cleanUsername(b.benutzername), ft = await festTeamId(env);
  const pw = await makePassword(checkClientHash(b.passwort), env.PEPPER), id = uid(), anzeige = clean(b.anzeigename, 80) || name;
  // Rolle, Admin und Funktion werden erzwungen – was sonst im Request steht, wird ignoriert
  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO benutzer(id,benutzername,anzeigename,rolle,ist_admin,pw_hash,pw_salt,pw_iter,pw_aendern,erstellt,erstellt_von) VALUES(?,?,?,'helfer',0,?,?,?,1,?,?)`)
        .bind(id, name, anzeige, pw.pw_hash, pw.pw_salt, pw.pw_iter, nowIso(), u.id),
      env.DB.prepare("INSERT INTO benutzer_funktionen(benutzer_id,funktion_id) VALUES(?,?)").bind(id, ft),
    ]);
  } catch { fail(409, "Diesen Benutzernamen gibt es schon."); }
  await log(env, u, "Festwirt-Team: Konto angelegt", anzeige, `Benutzername ${name} · Grundrolle Helfer · Funktion Festwirt-Team · angelegt von ${u.anzeigename}`);
  return listTeam(env, u);
}
async function updateTeamAccount(req, env, u, id) {
  const t = await teamTarget(env, u, id), b = await body(req);
  const aktiv = (b.aktiv ?? !!t.aktiv) ? 1 : 0, anzeige = clean(b.anzeigename ?? t.anzeigename, 80) || t.benutzername;
  await env.DB.batch([env.DB.prepare("UPDATE benutzer SET aktiv=?, anzeigename=? WHERE id=?").bind(aktiv, anzeige, id),
    ...(aktiv ? [] : [env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=?").bind(id)])]);
  await log(env, u, "Festwirt-Team: Konto geändert", anzeige, `${aktiv ? "aktiv" : "deaktiviert"} · von ${u.anzeigename}`);
  return listTeam(env, u);
}
async function resetTeamPassword(req, env, u, id) {
  const t = await teamTarget(env, u, id), b = await body(req);
  const pw = await makePassword(checkClientHash(b.passwort), env.PEPPER);
  await env.DB.batch([
    env.DB.prepare("UPDATE benutzer SET pw_hash=?, pw_salt=?, pw_iter=?, pw_aendern=1, fehlversuche=0, gesperrt_bis=NULL WHERE id=?").bind(pw.pw_hash, pw.pw_salt, pw.pw_iter, id),
    env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=?").bind(id),
  ]);
  await log(env, u, "Festwirt-Team: Passwort zurückgesetzt", t.anzeigename, `von ${u.anzeigename}`);
  return { ok: true };
}

/* ---- Funktionen & Rechte-Matrix (nur Admins; Liste der Funktionen für alle lesbar) ---- */
async function listFuncs(env) { return { funktionen: await funcList(env) }; }
async function saveFunc(req, env, u, id) {
  needAdmin(u);
  const b = await body(req), name = clean(b.name, 80), gruppe = FUNC_GROUPS.includes(b.gruppe) ? b.gruppe : "Sonstige";
  if (!name) fail(400, "Bitte einen Namen eingeben.");
  const all = await funcList(env);
  if (all.some(f => f.id !== id && f.name.toLowerCase() === name.toLowerCase())) fail(409, `Die Funktion „${name}“ gibt es schon.`);
  if (id) {
    const old = all.find(f => f.id === id); if (!old) hidden();
    const aktiv = (b.aktiv ?? !!old.aktiv) ? 1 : 0, sort = Number.isFinite(Number(b.sortierung)) ? Math.round(Number(b.sortierung)) : old.sortierung;
    await env.DB.prepare("UPDATE funktionen SET name=?, gruppe=?, aktiv=?, sortierung=? WHERE id=?").bind(name, b.gruppe ? gruppe : old.gruppe, aktiv, sort, id).run();
    await log(env, u, "Funktion geändert", name, [old.name !== name && `Name: „${old.name}“ → „${name}“`, old.aktiv !== aktiv && (aktiv ? "wieder aktiv" : "deaktiviert")].filter(Boolean).join("\n"));
  } else {
    await env.DB.prepare("INSERT INTO funktionen(id,name,gruppe,schluessel,sortierung,aktiv,erstellt) VALUES(?,?,?,'',?,1,?)").bind(uid(), name, gruppe, all.length + 100, nowIso()).run();
    await log(env, u, "Funktion angelegt", name, gruppe);
  }
  return listFuncs(env);
}
async function getMatrix(env) {
  const funcs = await funcList(env), rows = (await env.DB.prepare("SELECT * FROM rechte").all()).results, cfg = await getRightsCfg(env);
  const subjekte = [...ROLES.map(r => ({ key: "rolle:" + r, label: ROLE_LABEL[r], gruppe: "Grundrolle", gesperrt: LOCKED_ROLES.includes(r), aktiv: true })),
    ...funcs.map(f => ({ key: "funktion:" + f.id, label: f.name, gruppe: f.gruppe, gesperrt: LOCKED_KEYS.includes(f.schluessel), aktiv: !!f.aktiv, schluessel: f.schluessel }))];
  const werte = {};
  for (const r of rows) (werte[r.subjekt] ||= {})[r.bereich] = r.stufe;
  return { bereiche: AREAS, stufen: STUFEN, vorstand_bereiche: VORSTAND_AREAS, subjekte, werte, kassenpruefer_lesen: !!cfg.kassenpruefer_lesen };
}
async function setMatrixCell(req, env, u) {
  needAdmin(u);
  const b = await body(req), m = await getMatrix(env);
  const s = m.subjekte.find(x => x.key === b.subjekt), stufe = Math.round(Number(b.stufe));
  if (!s || !AREAS.includes(b.bereich) || !(stufe >= 0 && stufe <= 3)) fail(400, "Ungültige Angabe.");
  if (s.gesperrt && VORSTAND_AREAS.includes(b.bereich) && stufe > 0) fail(400, `Feste Regel: ${s.label} bekommt keine Vorstandsbereiche.`);
  const alt = m.werte[s.key]?.[b.bereich] || 0;
  if (stufe) await env.DB.prepare("INSERT INTO rechte(subjekt,bereich,stufe) VALUES(?,?,?) ON CONFLICT(subjekt,bereich) DO UPDATE SET stufe=excluded.stufe").bind(s.key, b.bereich, stufe).run();
  else await env.DB.prepare("DELETE FROM rechte WHERE subjekt=? AND bereich=?").bind(s.key, b.bereich).run();
  await log(env, u, "Rechte geändert", `${s.label} × ${b.bereich}`, `${STUFEN[alt]} → ${STUFEN[stufe]}`);
  return getMatrix(env);
}
async function setKassenpruefer(req, env, u) {
  needAdmin(u);
  const b = await body(req), cfg = { ...(await getRightsCfg(env)), kassenpruefer_lesen: !!b.an };
  await env.DB.prepare(`INSERT INTO einstellungen(schluessel,wert,geaendert,geaendert_von) VALUES('rechte',?,?,?)
    ON CONFLICT(schluessel) DO UPDATE SET wert=excluded.wert, geaendert=excluded.geaendert, geaendert_von=excluded.geaendert_von`).bind(JSON.stringify(cfg), nowIso(), u.anzeigename).run();
  await log(env, u, "Rechte geändert", "Kassenprüfer/in", cfg.kassenpruefer_lesen ? "darf Rechnungen und Kasse lesen" : "kein Zugriff auf Rechnungen und Kasse");
  return getMatrix(env);
}

/* ---- Chat: Räume, Nachrichten (Polling), ungelesen-Zähler ----
 * Mitglied = Raum „alle“ ODER passende Grundrolle/Funktion ODER Person. Admins verwalten Räume,
 * lesen Nachrichten aber nur als Mitglied. Festwirt/in darf Räume nur für sein Festwirt-Team anlegen. */
async function chatData(env) {
  const [r, m] = await env.DB.batch([env.DB.prepare("SELECT * FROM chat_raeume ORDER BY sortierung, name"), env.DB.prepare("SELECT * FROM chat_raum_mitglieder")]);
  return r.results.map(x => ({ ...x, regeln: m.results.filter(y => y.raum_id === x.id).map(y => ({ typ: y.typ, wert: y.wert })) }));
}
function isMember(u, room) {
  if (!room.aktiv) return false;
  if (room.alle) return true;
  return room.regeln.some(r => (r.typ === "rolle" && r.wert === u.rolle) || (r.typ === "funktion" && (u.funcs || []).some(f => f.id === r.wert)) || (r.typ === "person" && r.wert === u.id));
}
const canManageRoom = (u, room) => !!u.ist_admin || (isFestwirt(u) && !!room.fest && room.erstellt_von === u.id);
const canModerate = (u, room) => isMember(u, room) && (room.erstellt_von === u.id || !!u.ist_admin);
async function memberRoom(env, u, id) {
  const room = (await chatData(env)).find(x => x.id === id);
  if (!room || !isMember(u, room)) hidden();
  return room;
}
async function listChat(env, u) {
  const rooms = await chatData(env);
  const like = "%@" + u.anzeigename.replace(/[\\%_]/g, c => "\\" + c) + "%";
  const [cnt, last] = await env.DB.batch([
    env.DB.prepare(`SELECT n.raum_id, COUNT(*) c, SUM(CASE WHEN n.text LIKE ? ESCAPE '\\' THEN 1 ELSE 0 END) m FROM chat_nachrichten n
      LEFT JOIN chat_gelesen g ON g.raum_id=n.raum_id AND g.benutzer_id=? WHERE n.geloescht=0 AND n.benutzer_id<>? AND n.id > COALESCE(g.letzte_id, 0) GROUP BY n.raum_id`).bind(like, u.id, u.id),
    env.DB.prepare("SELECT raum_id, MAX(id) id, MAX(erstellt) zeit FROM chat_nachrichten WHERE geloescht=0 GROUP BY raum_id"),
  ]);
  const out = [];
  for (const r of rooms) {
    const member = isMember(u, r), manage = canManageRoom(u, r);
    if (!member && !manage) continue;   // fremde Räume gibt es nicht
    const c = cnt.results.find(x => x.raum_id === r.id), l = last.results.find(x => x.raum_id === r.id);
    out.push({ id: r.id, name: r.name, beschreibung: r.beschreibung, alle: !!r.alle, fest: !!r.fest, aktiv: !!r.aktiv, mitglied: member, verwalten: manage,
      moderieren: canModerate(u, r), ungelesen: member ? c?.c || 0 : 0, erwaehnt: member ? c?.m || 0 : 0, letzte: member ? l?.zeit || "" : "",
      ...(manage ? { regeln: r.regeln, erstellt_von: r.erstellt_von } : {}) });
  }
  return { raeume: out };
}
async function getMessages(env, u, id, url) {
  const room = await memberRoom(env, u, id);
  const seit = Math.max(0, Math.floor(Number(url.searchParams.get("seit")) || 0)), t = clean(url.searchParams.get("t"), 30);
  let rows;
  if (!seit) rows = (await env.DB.prepare("SELECT * FROM (SELECT * FROM chat_nachrichten WHERE raum_id=? ORDER BY id DESC LIMIT 150) ORDER BY id").bind(id).all()).results;
  else rows = (await env.DB.prepare("SELECT * FROM chat_nachrichten WHERE raum_id=? AND (id>? OR (bearbeitet<>'' AND bearbeitet>?)) ORDER BY id LIMIT 300").bind(id, seit, t || "9").all()).results;
  return { nachrichten: rows.map(x => ({ id: x.id, benutzer_id: x.benutzer_id, autor: x.autor, text: x.geloescht ? "" : x.text, erstellt: x.erstellt, bearbeitet: x.bearbeitet, geloescht: !!x.geloescht })),
    jetzt: nowIso(), moderieren: canModerate(u, room) };
}
function readChatText(b) {
  const text = String(b.text ?? "").replace(/\r\n/g, "\n").trim();
  if (!text) fail(400, "Leere Nachricht.");
  if (text.length > CHAT_MAX) fail(400, `Höchstens ${CHAT_MAX} Zeichen.`);
  return text;
}
async function postMessage(req, env, u, id) {
  await memberRoom(env, u, id);
  const text = readChatText(await body(req)), t = nowIso();
  const r = await env.DB.prepare("INSERT INTO chat_nachrichten(raum_id,benutzer_id,autor,text,erstellt) VALUES(?,?,?,?,?)").bind(id, u.id, u.anzeigename, text, t).run();
  const nid = r.meta.last_row_id;
  await env.DB.prepare(`INSERT INTO chat_gelesen(raum_id,benutzer_id,letzte_id) VALUES(?,?,?) ON CONFLICT(raum_id,benutzer_id) DO UPDATE SET letzte_id=MAX(letzte_id, excluded.letzte_id)`).bind(id, u.id, nid).run();
  return { nachricht: { id: nid, benutzer_id: u.id, autor: u.anzeigename, text, erstellt: t, bearbeitet: "", geloescht: false } };
}
async function chatMessage(env, u, mid) {
  const n = await env.DB.prepare("SELECT * FROM chat_nachrichten WHERE id=?").bind(Number(mid)).first();
  if (!n) hidden();
  const room = await memberRoom(env, u, n.raum_id);
  return { n, room };
}
async function editMessage(req, env, u, mid) {
  const { n } = await chatMessage(env, u, mid);
  if (n.benutzer_id !== u.id || n.geloescht) fail(403, "Nur eigene Nachrichten können bearbeitet werden.");
  const text = readChatText(await body(req));
  await env.DB.prepare("UPDATE chat_nachrichten SET text=?, bearbeitet=? WHERE id=?").bind(text, nowIso(), n.id).run();
  return { ok: true };
}
async function deleteMessage(env, u, mid) {
  const { n, room } = await chatMessage(env, u, mid);
  const own = n.benutzer_id === u.id;
  if (!own && !canModerate(u, room)) fail(403, "Nur eigene Nachrichten (oder als Raum-Admin) löschen.");
  await env.DB.prepare("UPDATE chat_nachrichten SET geloescht=1, text='', bearbeitet=? WHERE id=?").bind(nowIso(), n.id).run();
  if (!own) await log(env, u, "Chat: Nachricht entfernt (Moderation)", room.name, `Nachricht von ${n.autor} vom ${n.erstellt.slice(0, 10)}`);
  return { ok: true };
}
async function markRead(req, env, u, id) {
  await memberRoom(env, u, id);
  const bis = Math.max(0, Math.floor(Number((await body(req)).bis) || 0));
  await env.DB.prepare(`INSERT INTO chat_gelesen(raum_id,benutzer_id,letzte_id) VALUES(?,?,?) ON CONFLICT(raum_id,benutzer_id) DO UPDATE SET letzte_id=MAX(letzte_id, excluded.letzte_id)`).bind(id, u.id, bis).run();
  return { ok: true };
}
async function readRoom(env, u, b) {
  const v = { name: clean(b.name, 80), beschreibung: clean(b.beschreibung, 300), alle: b.alle ? 1 : 0, aktiv: b.aktiv === false ? 0 : 1 };
  if (!v.name) fail(400, "Bitte einen Namen für den Raum eingeben.");
  const funcs = await funcList(env), users = (await env.DB.prepare("SELECT id FROM benutzer").all()).results.map(x => x.id);
  let regeln = (Array.isArray(b.regeln) ? b.regeln : []).map(r => ({ typ: String(r?.typ), wert: String(r?.wert) }));
  for (const r of regeln) {
    if (r.typ === "rolle" && ROLES.includes(r.wert)) continue;
    if (r.typ === "funktion" && funcs.some(f => f.id === r.wert)) continue;
    if (r.typ === "person" && users.includes(r.wert)) continue;
    fail(400, "Ungültige Mitgliedschaft im Raum.");
  }
  if (!u.ist_admin) {
    // Festwirt/in: nur Festwirt-Team (Funktion oder reine Team-Konten) + sich selbst
    const ft = await festTeamId(env), team = (await teamAccounts(env, ft)).map(x => x.id);
    if (v.alle || regeln.some(r => !(r.typ === "funktion" && r.wert === ft) && !(r.typ === "person" && (team.includes(r.wert) || r.wert === u.id))))
      fail(403, "Als Festwirt/in kannst du Räume nur für dein Festwirt-Team anlegen.");
    if (!regeln.some(r => r.typ === "person" && r.wert === u.id)) regeln.push({ typ: "person", wert: u.id });
  }
  regeln = [...new Map(regeln.map(r => [r.typ + ":" + r.wert, r])).values()];
  return { v, regeln };
}
async function saveRoom(req, env, u, id) {
  if (!u.ist_admin && !isFestwirt(u)) hidden();
  const { v, regeln } = await readRoom(env, u, await body(req));
  if (id) {
    const room = (await chatData(env)).find(x => x.id === id);
    if (!room || !canManageRoom(u, room)) hidden();
    await env.DB.batch([
      env.DB.prepare("UPDATE chat_raeume SET name=?, beschreibung=?, alle=?, aktiv=? WHERE id=?").bind(v.name, v.beschreibung, v.alle, v.aktiv, id),
      env.DB.prepare("DELETE FROM chat_raum_mitglieder WHERE raum_id=?").bind(id),
      ...regeln.map(r => env.DB.prepare("INSERT INTO chat_raum_mitglieder(raum_id,typ,wert) VALUES(?,?,?)").bind(id, r.typ, r.wert)),
    ]);
    await log(env, u, "Chat-Raum geändert", v.name, `${v.alle ? "alle angemeldeten" : regeln.length + " Mitgliedschafts-Regeln"}${v.aktiv ? "" : " · deaktiviert"}`);
  } else {
    id = uid();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO chat_raeume(id,name,beschreibung,alle,fest,aktiv,sortierung,erstellt,erstellt_von) VALUES(?,?,?,?,?,?,100,?,?)").bind(id, v.name, v.beschreibung, v.alle, u.ist_admin ? 0 : 1, v.aktiv, nowIso(), u.id),
      ...regeln.map(r => env.DB.prepare("INSERT INTO chat_raum_mitglieder(raum_id,typ,wert) VALUES(?,?,?)").bind(id, r.typ, r.wert)),
    ]);
    await log(env, u, "Chat-Raum angelegt", v.name, v.alle ? "alle angemeldeten" : `${regeln.length} Mitgliedschafts-Regeln`);
  }
  return listChat(env, u);
}
// Cron (täglich): Nachrichten älter als 12 Monate löschen
async function chatCleanup(env) {
  const grenze = new Date(Date.now() - CHAT_KEEP_DAYS * 864e5).toISOString();
  const r = await env.DB.prepare("DELETE FROM chat_nachrichten WHERE erstellt < ?").bind(grenze).run();
  if (r.meta.changes) await log(env, null, "Chat aufgeräumt", `${r.meta.changes} Nachrichten`, `älter als ${grenze.slice(0, 10)} gelöscht`);
  return r.meta.changes;
}
async function resetPassword(req, env, u, id) {
  const b = await body(req);
  const t = await env.DB.prepare("SELECT anzeigename FROM benutzer WHERE id=?").bind(id).first();
  if (!t) fail(404, "Benutzer nicht gefunden.");
  const pw = await makePassword(checkClientHash(b.passwort), env.PEPPER);
  await env.DB.batch([
    env.DB.prepare("UPDATE benutzer SET pw_hash=?, pw_salt=?, pw_iter=?, pw_aendern=1, fehlversuche=0, gesperrt_bis=NULL WHERE id=?").bind(pw.pw_hash, pw.pw_salt, pw.pw_iter, id),
    env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=?").bind(id),
  ]);
  await log(env, u, "Passwort zurückgesetzt", t.anzeigename);
  return { ok: true };
}
async function deleteUser(env, u, id) {
  if (id === u.id) fail(400, "Du kannst dich nicht selbst löschen.");
  const t = await env.DB.prepare("SELECT * FROM benutzer WHERE id=?").bind(id).first();
  if (!t) fail(404, "Benutzer nicht gefunden.");
  if (t.ist_admin && t.aktiv && (await adminCount(env)) <= 1) fail(400, "Mindestens ein aktiver Admin muss bleiben.");
  await env.DB.batch([env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=?").bind(id), env.DB.prepare("DELETE FROM zusagen WHERE benutzer_id=?").bind(id),
    env.DB.prepare("DELETE FROM trainer_mannschaften WHERE benutzer_id=?").bind(id), env.DB.prepare("DELETE FROM benutzer_funktionen WHERE benutzer_id=?").bind(id),
    env.DB.prepare("DELETE FROM chat_gelesen WHERE benutzer_id=?").bind(id), env.DB.prepare("DELETE FROM chat_raum_mitglieder WHERE typ='person' AND wert=?").bind(id),
    env.DB.prepare("DELETE FROM benutzer WHERE id=?").bind(id)]);
  await log(env, u, "Benutzer gelöscht", t.anzeigename);
  return listUsers(env);
}

/* ---- Protokoll & Export (nur Vorstand) ---- */
async function listLog(env) {
  const { results } = await env.DB.prepare("SELECT * FROM protokoll ORDER BY id DESC LIMIT 500").all();
  return { protokoll: results };
}
async function exportAll(env) {
  const e = await env.DB.prepare("SELECT * FROM eintraege ORDER BY bereich, datum").all();
  const d = await env.DB.prepare("SELECT * FROM dokumente").all();
  const p = await env.DB.prepare("SELECT * FROM protokoll ORDER BY id").all();
  const mg = await env.DB.prepare("SELECT * FROM mitglieder ORDER BY nachname, vorname").all();
  const el = await env.DB.prepare("SELECT * FROM eltern ORDER BY mannschaft, name").all();
  const an = await env.DB.prepare("SELECT id, eintrag_id, dateiname, mime, groesse, erstellt, erstellt_von FROM anhaenge").all();
  const zs = await env.DB.prepare("SELECT z.eintrag_id, b.anzeigename, z.antwort, z.geaendert FROM zusagen z JOIN benutzer b ON b.id=z.benutzer_id").all();
  const re = await env.DB.prepare("SELECT * FROM rechnungen ORDER BY jahr, lfd").all();
  const dl = await env.DB.prepare("SELECT * FROM downloads").all();
  const ms = await env.DB.prepare("SELECT * FROM mannschaften ORDER BY sortierung, name").all();
  const tm = await env.DB.prepare("SELECT b.benutzername, b.anzeigename, t.mannschaft_id, m.name mannschaft FROM trainer_mannschaften t JOIN benutzer b ON b.id=t.benutzer_id JOIN mannschaften m ON m.id=t.mannschaft_id").all();
  const bn = await env.DB.prepare("SELECT benutzername, anzeigename, rolle, ist_admin, aktiv, letzter_login, erstellt FROM benutzer ORDER BY anzeigename").all();
  const fn = await env.DB.prepare("SELECT * FROM funktionen ORDER BY sortierung").all();
  const bf = await env.DB.prepare("SELECT b.benutzername, f.id funktion_id, f.name funktion FROM benutzer_funktionen x JOIN benutzer b ON b.id=x.benutzer_id JOIN funktionen f ON f.id=x.funktion_id").all();
  const rt = await env.DB.prepare("SELECT * FROM rechte ORDER BY subjekt, bereich").all();
  const cr = await chatData(env);
  const kb = await env.DB.prepare("SELECT * FROM kassenbuchungen ORDER BY jahr, lfd").all();
  const kl = await env.DB.prepare("SELECT id, buchung_id, dateiname, mime, groesse, erstellt, erstellt_von FROM kassen_belege").all();
  const ks = await getKasseSettings(env);
  // Chat-Nachrichten sind bewusst NICHT in der Sicherung (Datenschutz), nur die Räume
  return { format: "sku-vereinszentrale", version: 6, exportiert: nowIso(), eintraege: e.results, dokumente: d.results, protokoll: p.results,
    mitglieder: mg.results, eltern: el.results, anhaenge: an.results, zusagen: zs.results, rechnungen: re.results, downloads: dl.results,
    einstellungen: (await getSettings(env)).verein, mannschaften: ms.results, trainer_mannschaften: tm.results, benutzer: bn.results,
    funktionen: fn.results, benutzer_funktionen: bf.results, rechte: rt.results, chat_raeume: cr,
    kassenbuchungen: kb.results, kassen_belege: kl.results,
    kasse_einstellungen: { kategorien: ks.kategorien, anfang_bar: ks.anfang_bar, anfang_bank: ks.anfang_bank, stichtag: ks.stichtag } };
}

/* ---------------- Router ---------------- */
async function route(req, env, cors) {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "") || "/";
  const M = req.method;
  let m;

  if (p === "/" || p === "/api") return json({ name: "Vereinszentrale API", ok: true }, 200, cors);
  if (p === "/api/einrichtung" && M === "GET") return json(await setupStatus(env), 200, cors);
  if (p === "/api/einrichtung" && M === "POST") return json(await setup(req, env), 200, cors);
  if (p === "/api/login" && M === "POST") return json(await login(req, env), 200, cors);

  const u = await enrich(env, await authenticate(req, env));

  if (p === "/api/logout" && M === "POST") { await env.DB.prepare("DELETE FROM sitzungen WHERE token_hash=?").bind(u.token_hash).run(); return json({ ok: true }, 200, cors); }
  if (p === "/api/ich" && M === "GET") return json({ benutzer: await meUser(env, u) }, 200, cors);
  if (p === "/api/ich/passwort" && M === "POST") return json(await changeOwnPassword(req, env, u), 200, cors);
  if (u.pw_aendern) fail(403, "Bitte zuerst ein eigenes Passwort festlegen.");

  if (p === "/api/eintraege" && M === "GET") return json(await listEntries(env, u), 200, cors);
  if (p === "/api/eintraege" && M === "POST") return json(await createEntry(req, env, u), 200, cors);
  if (p === "/api/eintraege/import" && M === "POST") return json(await importEntries(req, env, u), 200, cors);
  if ((m = p.match(/^\/api\/eintraege\/([\w-]+)$/))) {
    if (M === "PUT") return json(await updateEntry(req, env, u, m[1]), 200, cors);
    if (M === "DELETE") return json(await deleteEntry(env, u, m[1]), 200, cors);
  }
  if ((m = p.match(/^\/api\/eintraege\/([\w-]+)\/zusage$/)) && M === "PUT") return json(await answerEntry(req, env, u, m[1]), 200, cors);
  if ((m = p.match(/^\/api\/eintraege\/([\w-]+)\/anhaenge$/)) && M === "POST") return json(await addAttachment(req, env, u, m[1]), 200, cors);
  if ((m = p.match(/^\/api\/anhaenge\/([\w-]+)$/))) {
    if (M === "GET") return downloadAttachment(env, u, m[1], cors);
    if (M === "DELETE") return json(await deleteAttachment(env, u, m[1]), 200, cors);
  }
  if (p === "/api/mannschaften" && M === "GET") return json(await listTeams(env, u), 200, cors);
  if ((m = p.match(/^\/api\/(mitglieder|eltern)$/)) && M === "GET") return json(await listPeople(env, PEOPLE[m[1]], u), 200, cors);

  if (p === "/api/mannschaften" && M === "POST") return json(await saveTeam(req, env, u, null), 200, cors);
  if (p === "/api/mannschaften/zuordnen" && M === "POST") return json(await assignTeam(req, env, u), 200, cors);
  if (p === "/api/mannschaften/import" && M === "POST") return json(await importTeams(req, env, u), 200, cors);
  if ((m = p.match(/^\/api\/mannschaften\/([\w-]+)$/)) && M === "PUT") return json(await saveTeam(req, env, u, m[1]), 200, cors);

  // Geld: feste Regel – nur Admin + Schatzmeister/in (Kassenprüfer/in optional lesen); alle anderen bekommen 404
  if (p.startsWith("/api/kasse") || p.startsWith("/api/rechnungen")) needMoney(u, false);
  if (p === "/api/kasse" && M === "GET") return json(await listKasse(env), 200, cors);
  if (p === "/api/kasse" && M === "POST") return json(await createBooking(req, env, u), 200, cors);
  if (p === "/api/kasse/einstellungen" && M === "PUT") return json(await saveKasseSettings(req, env, u), 200, cors);
  if (p === "/api/kasse/wiederherstellen" && M === "POST") return json(await restoreTable(req, env, u, "kassenbuchungen"), 200, cors);
  if ((m = p.match(/^\/api\/kasse\/belege\/([\w-]+)$/)) && M === "GET") return getReceipt(env, m[1], cors);
  if ((m = p.match(/^\/api\/kasse\/([\w-]+)\/storno$/)) && M === "POST") return json(await stornoBooking(req, env, u, m[1]), 200, cors);
  if ((m = p.match(/^\/api\/kasse\/([\w-]+)\/belege$/)) && M === "POST") return json(await addReceipt(req, env, u, m[1]), 200, cors);
  if (p === "/api/rechnungen/wiederherstellen" && M === "POST") return json(await restoreTable(req, env, u, "rechnungen"), 200, cors);
  if (p === "/api/rechnungen" && M === "GET") return json(await listInvoices(env), 200, cors);
  if (p === "/api/rechnungen" && M === "POST") { needMoney(u, true); return json(await createInvoice(req, env, u), 200, cors); }
  if ((m = p.match(/^\/api\/rechnungen\/([\w-]+)$/)) && M === "PUT") { needMoney(u, true); return json(await updateInvoice(req, env, u, m[1]), 200, cors); }
  if ((m = p.match(/^\/api\/rechnungen\/([\w-]+)\/status$/)) && M === "POST") { needMoney(u, true); return json(await setInvoiceStatus(req, env, u, m[1]), 200, cors); }

  if (p.startsWith("/api/downloads")) needArea(u, "Downloads", M === "GET" ? 1 : M === "DELETE" ? 3 : 2);
  if (p === "/api/downloads" && M === "GET") return json(await listDownloads(env), 200, cors);
  if (p === "/api/downloads" && M === "POST") return json(await saveDownload(req, env, u, null), 200, cors);
  if ((m = p.match(/^\/api\/downloads\/([\w-]+)$/))) {
    if (M === "PUT") return json(await saveDownload(req, env, u, m[1]), 200, cors);
    if (M === "DELETE") return json(await deleteDownload(env, u, m[1]), 200, cors);
  }
  if ((m = p.match(/^\/api\/downloads\/([\w-]+)\/datei$/))) {
    if (M === "PUT") return json(await uploadDownload(req, env, u, m[1]), 200, cors);
    if (M === "GET") return getDownload(env, m[1], cors);
  }
  // Vereinsdaten: lesen, wer Rechnungen oder Downloads (Mitgliedsantrag) sieht; ändern nur Admin + Schatzmeister/in
  if (p === "/api/einstellungen" && M === "GET") { if (!moneyRead(u) && lvl(u, "Downloads") < 1) hidden(); return json(await getSettings(env), 200, cors); }
  if (p === "/api/einstellungen/verein" && M === "PUT") { needMoney(u, true); return json(await saveSettings(req, env, u), 200, cors); }

  if ((m = p.match(/^\/api\/(mitglieder|eltern)(?:\/([\w-]+))?$/))) {
    const P = PEOPLE[m[1]], id = m[2];
    if (!id && M === "POST") return json(await savePerson(req, env, u, P, null), 200, cors);
    if (id === "import" && M === "POST") return json(await importPeople(req, env, u, P), 200, cors);
    if (id && id !== "import" && M === "PUT") return json(await savePerson(req, env, u, P, id), 200, cors);
    if (id && id !== "import" && M === "DELETE") return json(await deletePerson(env, u, P, id), 200, cors);
  }

  if (p.startsWith("/api/dokumente")) needArea(u, "Dokumente", M === "GET" ? 1 : M === "DELETE" ? 3 : 2);
  if (p === "/api/protokoll") needArea(u, "Änderungsprotokoll", 1);
  if (p === "/api/export") needAdmin(u);
  if (p === "/api/dokumente" && M === "GET") return json(await listDocs(env), 200, cors);
  if (p === "/api/dokumente" && M === "POST") return json(await saveDoc(req, env, u, null), 200, cors);
  if ((m = p.match(/^\/api\/dokumente\/([\w-]+)$/))) {
    if (M === "PUT") return json(await saveDoc(req, env, u, m[1]), 200, cors);
    if (M === "DELETE") return json(await deleteDoc(env, u, m[1]), 200, cors);
  }
  if ((m = p.match(/^\/api\/dokumente\/([\w-]+)\/datei$/))) {
    if (M === "PUT") return json(await uploadFile(req, env, u, m[1]), 200, cors);
    if (M === "GET") return downloadFile(env, m[1], cors);
  }
  if (p === "/api/protokoll" && M === "GET") return json(await listLog(env), 200, cors);
  if (p === "/api/export" && M === "GET") return json(await exportAll(env), 200, cors);

  if (p.startsWith("/api/benutzer")) needAdmin(u);
  if (p === "/api/benutzer" && M === "GET") return json(await listUsers(env), 200, cors);
  if (p === "/api/benutzer" && M === "POST") return json(await createUser(req, env, u), 200, cors);
  if ((m = p.match(/^\/api\/benutzer\/([\w-]+)$/))) {
    if (M === "PUT") return json(await updateUser(req, env, u, m[1]), 200, cors);
    if (M === "DELETE") return json(await deleteUser(env, u, m[1]), 200, cors);
  }
  if ((m = p.match(/^\/api\/benutzer\/([\w-]+)\/passwort$/)) && M === "POST") return json(await resetPassword(req, env, u, m[1]), 200, cors);

  // Funktionen (Liste für alle; ändern nur Admin) und Rechte-Matrix (nur Admin)
  if (p === "/api/funktionen" && M === "GET") return json(await listFuncs(env), 200, cors);
  if (p === "/api/funktionen" && M === "POST") return json(await saveFunc(req, env, u, null), 200, cors);
  if ((m = p.match(/^\/api\/funktionen\/([\w-]+)$/)) && M === "PUT") return json(await saveFunc(req, env, u, m[1]), 200, cors);
  if (p.startsWith("/api/rechte")) needAdmin(u);
  if (p === "/api/rechte" && M === "GET") return json(await getMatrix(env), 200, cors);
  if (p === "/api/rechte" && M === "PUT") return json(await setMatrixCell(req, env, u), 200, cors);
  if (p === "/api/rechte/kassenpruefer" && M === "PUT") return json(await setKassenpruefer(req, env, u), 200, cors);

  // Festwirt/in: eigenes Team verwalten
  if (p === "/api/team" && M === "GET") return json(await listTeam(env, u), 200, cors);
  if (p === "/api/team" && M === "POST") return json(await createTeamAccount(req, env, u), 200, cors);
  if ((m = p.match(/^\/api\/team\/([\w-]+)$/)) && M === "PUT") return json(await updateTeamAccount(req, env, u, m[1]), 200, cors);
  if ((m = p.match(/^\/api\/team\/([\w-]+)\/passwort$/)) && M === "POST") return json(await resetTeamPassword(req, env, u, m[1]), 200, cors);

  // Chat
  if (p === "/api/chat" && M === "GET") return json(await listChat(env, u), 200, cors);
  if (p === "/api/chat/raeume" && M === "POST") return json(await saveRoom(req, env, u, null), 200, cors);
  if ((m = p.match(/^\/api\/chat\/raeume\/([\w-]+)$/)) && M === "PUT") return json(await saveRoom(req, env, u, m[1]), 200, cors);
  if ((m = p.match(/^\/api\/chat\/nachricht\/(\d+)$/))) {
    if (M === "PUT") return json(await editMessage(req, env, u, m[1]), 200, cors);
    if (M === "DELETE") return json(await deleteMessage(env, u, m[1]), 200, cors);
  }
  if ((m = p.match(/^\/api\/chat\/([\w-]+)$/))) {
    if (M === "GET") return json(await getMessages(env, u, m[1], url), 200, cors);
    if (M === "POST") return json(await postMessage(req, env, u, m[1]), 200, cors);
  }
  if ((m = p.match(/^\/api\/chat\/([\w-]+)\/gelesen$/)) && M === "POST") return json(await markRead(req, env, u, m[1]), 200, cors);

  fail(404, "Nicht gefunden.");
}

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (!env.PEPPER || env.PEPPER.length < 32) return json({ fehler: "Server nicht eingerichtet: PEPPER fehlt." }, 500, cors);
    try {
      return await route(req, env, cors);
    } catch (e) {
      if (e instanceof HttpError) return json({ fehler: e.message }, e.status, cors);
      console.error(e);
      return json({ fehler: "Interner Fehler. Bitte später erneut versuchen." }, 500, cors);
    }
  },
  // Cron Trigger (wrangler.toml [triggers]): täglich alte Chat-Nachrichten löschen
  async scheduled(event, env, ctx) {
    ctx.waitUntil(chatCleanup(env));
  },
};
