/**
 * Vereinszentrale · FC Sender Kickers United – API (Cloudflare Worker + D1/SQLite)
 *
 * Rollen
 *   vorstand  – darf alles lesen und ändern (Einträge, Dokumente, Protokoll, Export)
 *   ausschuss – liest/bearbeitet nur die freigegebenen Bereiche, darf nicht löschen
 *   ist_admin – zusätzlich Benutzerverwaltung (nur Admins legen Benutzer an)
 *
 * Passwörter
 *   Der Browser streckt das Passwort mit PBKDF2 (250.000 Runden, Salt = Benutzername).
 *   Der Server rechnet darauf HMAC mit geheimem PEPPER + PBKDF2 mit zufälligem Salt.
 *   So bleibt der Hash stark, obwohl der Free-Tarif nur 10 ms CPU pro Anfrage erlaubt.
 */

const GROUPS = ["Satzung & Beschlüsse","Vorstand & Ausschuss","Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender","Gründungsplan","Offene Entscheidungen"];
const AUSSCHUSS_GROUPS = ["Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender"];
const STATUSES = ["Bestätigt","Geplant","Entwurf","Offen","Schätzung","Erledigt"];
const SERVER_ITER = 10000;
const SESSION_HOURS = 12, SESSION_HOURS_LONG = 24 * 30;
const MAX_FAILS = 5, LOCK_MINUTES = 15;
const MAX_FILE = 10 * 1024 * 1024, CHUNK = 1024 * 1024;
const ENTRY_FIELDS = ["titel","bereich","status","datum","uhrzeit","ort","zustaendig","inhalt","quelle","rueckmeldung"];
const ANSWERS = { ja: "Nimmt teil", vielleicht: "Vielleicht", nein: "Nimmt nicht teil" };
const LIMITS = { titel: 160, ort: 120, zustaendig: 120, inhalt: 60000, quelle: 200 };
const MAX_IMPORT = 1000;
const MEMBER_FIELDS = ["vorname","nachname","geburtsdatum","mannschaft","email","telefon","eintritt","status","notiz"];
const MEMBER_LIMITS = { vorname: 80, nachname: 80, geburtsdatum: 10, mannschaft: 80, email: 160, telefon: 60, eintritt: 10, status: 30, notiz: 2000 };
const MEMBER_STATUSES = ["Aktiv","Passiv","Ausgetreten"];
const PARENT_FIELDS = ["name","email","kind","mannschaft","notiz"];
const PARENT_LIMITS = { name: 120, email: 160, kind: 120, mannschaft: 80, notiz: 1000 };
const EMAIL_RE = /^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/;

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

/* ---------------- Rechte ---------------- */
const isVorstand = u => u.rolle === "vorstand";
const canSeeGroup = (u, g) => isVorstand(u) || AUSSCHUSS_GROUPS.includes(g);
function needVorstand(u) { if (!isVorstand(u)) fail(403, "Nur für den Vorstand."); }
function needAdmin(u) { if (!u.ist_admin) fail(403, "Nur für Admins."); }
function publicUser(u) {
  return { id: u.id, benutzername: u.benutzername, anzeigename: u.anzeigename, rolle: u.rolle, ist_admin: !!u.ist_admin,
    aktiv: !!u.aktiv, pw_aendern: !!u.pw_aendern, letzter_login: u.letzter_login, erstellt: u.erstellt,
    bereiche: isVorstand(u) ? GROUPS : AUSSCHUSS_GROUPS, darf_loeschen: isVorstand(u) };
}

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
  const groups = isVorstand(u) ? GROUPS : AUSSCHUSS_GROUPS;
  const ph = groups.map(() => "?").join(",");
  const [e, a, z, b] = await env.DB.batch([
    env.DB.prepare(`SELECT * FROM eintraege WHERE bereich IN (${ph}) ORDER BY datum, uhrzeit, titel`).bind(...groups),
    env.DB.prepare(`SELECT a.id, a.eintrag_id, a.dateiname, a.mime, a.groesse, a.erstellt, a.erstellt_von FROM anhaenge a
      JOIN eintraege e ON e.id=a.eintrag_id WHERE e.bereich IN (${ph}) ORDER BY a.erstellt`).bind(...groups),
    env.DB.prepare(`SELECT z.eintrag_id, z.benutzer_id, z.antwort, z.geaendert, b.anzeigename FROM zusagen z
      JOIN eintraege e ON e.id=z.eintrag_id JOIN benutzer b ON b.id=z.benutzer_id WHERE e.bereich IN (${ph}) ORDER BY b.anzeigename`).bind(...groups),
    env.DB.prepare("SELECT id, anzeigename, rolle FROM benutzer WHERE aktiv=1 ORDER BY anzeigename"),
  ]);
  const files = {}, answers = {};
  for (const x of a.results) (files[x.eintrag_id] ||= []).push(x);
  for (const x of z.results) (answers[x.eintrag_id] ||= []).push({ benutzer_id: x.benutzer_id, name: x.anzeigename, antwort: x.antwort, geaendert: x.geaendert });
  return { eintraege: e.results.map(r => {
    const out = { ...r, anhaenge: files[r.id] || [] };
    if (r.rueckmeldung) {
      out.zusagen = answers[r.id] || [];
      const done = new Set(out.zusagen.map(x => x.benutzer_id));
      // Wer den Eintrag sehen kann und noch nicht geantwortet hat
      out.offen = b.results.filter(x => !done.has(x.id) && canSeeGroup(x, r.bereich)).map(x => x.anzeigename);
    }
    return out;
  }) };
}
async function answerEntry(req, env, u, id) {
  const b = await body(req);
  const e = await visibleEntry(env, u, id);
  const full = await env.DB.prepare("SELECT rueckmeldung FROM eintraege WHERE id=?").bind(id).first();
  if (!full.rueckmeldung) fail(400, "Für diesen Eintrag ist keine Rückmeldung vorgesehen.");
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
  for (const k of ENTRY_FIELDS) v[k] = clean(b[k], LIMITS[k] || 40);
  v.rueckmeldung = b.rueckmeldung === true || b.rueckmeldung === 1 || b.rueckmeldung === "1" ? 1 : 0;
  if (!v.titel) fail(400, "Bitte einen Titel eingeben.");
  if (!GROUPS.includes(v.bereich)) fail(400, "Unbekannter Bereich.");
  if (!STATUSES.includes(v.status)) fail(400, "Unbekannter Status.");
  if (!validDate(v.datum) || !validTime(v.uhrzeit)) fail(400, "Datum oder Uhrzeit ungültig.");
  if (!canSeeGroup(u, v.bereich)) fail(403, "Für diesen Bereich hast du keine Berechtigung.");
  return v;
}
async function createEntry(req, env, u) {
  const v = readEntry(await body(req), u), t = nowIso(), id = uid();
  await env.DB.prepare(`INSERT INTO eintraege(id,${ENTRY_FIELDS.join(",")},erstellt,geaendert,geaendert_von) VALUES(?,${ENTRY_FIELDS.map(() => "?").join(",")},?,?,?)`)
    .bind(id, ...ENTRY_FIELDS.map(k => v[k]), t, t, u.anzeigename).run();
  await log(env, u, "Angelegt", v.titel, `${v.bereich} · ${v.status}${v.datum ? " · " + v.datum : ""}`);
  return { eintrag: await env.DB.prepare("SELECT * FROM eintraege WHERE id=?").bind(id).first() };
}
async function updateEntry(req, env, u, id) {
  const b = await body(req);
  const old = await env.DB.prepare("SELECT * FROM eintraege WHERE id=?").bind(id).first();
  if (!old || !canSeeGroup(u, old.bereich)) fail(404, "Eintrag nicht gefunden.");
  if (b.geaendert && b.geaendert !== old.geaendert) fail(409, "Jemand anderes hat diesen Eintrag inzwischen geändert. Bitte neu laden.");
  const v = readEntry(b, u);
  const changed = ENTRY_FIELDS.filter(k => String(old[k] ?? "") !== String(v[k]));
  if (!changed.length) return { eintrag: old };
  const t = nowIso();
  await env.DB.prepare(`UPDATE eintraege SET ${ENTRY_FIELDS.map(k => k + "=?").join(",")}, geaendert=?, geaendert_von=? WHERE id=?`)
    .bind(...ENTRY_FIELDS.map(k => v[k]), t, u.anzeigename, id).run();
  await log(env, u, "Geändert", v.titel, changed.map(k => k === "inhalt" ? "Inhalt bearbeitet" : k === "rueckmeldung" ? `Rückmeldung erwünscht: ${v[k] ? "ja" : "nein"}` : `${k}: „${old[k] || "–"}“ → „${v[k] || "–"}“`).join("\n"));
  return { eintrag: await env.DB.prepare("SELECT * FROM eintraege WHERE id=?").bind(id).first() };
}
async function deleteEntry(env, u, id) {
  needVorstand(u);
  const old = await env.DB.prepare("SELECT titel FROM eintraege WHERE id=?").bind(id).first();
  if (!old) fail(404, "Eintrag nicht gefunden.");
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
  const e = await env.DB.prepare("SELECT id, titel, bereich FROM eintraege WHERE id=?").bind(id).first();
  if (!e || !canSeeGroup(u, e.bereich)) fail(404, "Eintrag nicht gefunden.");
  return e;
}
async function visibleAttachment(env, u, id) {
  const a = await env.DB.prepare("SELECT a.*, e.bereich, e.titel FROM anhaenge a JOIN eintraege e ON e.id=a.eintrag_id WHERE a.id=?").bind(id).first();
  if (!a || !canSeeGroup(u, a.bereich)) fail(404, "Anhang nicht gefunden.");
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
  needVorstand(u);
  const a = await visibleAttachment(env, u, id);
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
  return v;
}
const PEOPLE = {
  mitglieder: { table: "mitglieder", fields: MEMBER_FIELDS, read: readMember, order: "nachname, vorname", label: "Mitglied",
    name: v => `${v.vorname} ${v.nachname}`.trim(), key: v => `${v.vorname}|${v.nachname}|${v.geburtsdatum}`.toLowerCase() },
  eltern: { table: "eltern", fields: PARENT_FIELDS, read: readParent, order: "mannschaft, name, email", label: "Eltern",
    name: v => v.name || v.email, key: v => v.email.toLowerCase() },
};
async function listPeople(env, P) {
  const { results } = await env.DB.prepare(`SELECT * FROM ${P.table} ORDER BY ${P.order}`).all();
  return { liste: results };
}
async function savePerson(req, env, u, P, id) {
  const b = await body(req), v = P.read(b), t = nowIso(), isNew = !id;
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
  const b = await body(req);
  if (!Array.isArray(b.liste) || !b.liste.length) fail(400, "Keine Zeilen zum Importieren.");
  if (b.liste.length > MAX_IMPORT) fail(400, `Höchstens ${MAX_IMPORT} Zeilen auf einmal.`);
  const rows = b.liste.map(P.read), t = nowIso();
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
  needVorstand(u);
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

/* ---- Benutzer (nur Admins) ---- */
async function listUsers(env) {
  const { results } = await env.DB.prepare("SELECT * FROM benutzer ORDER BY rolle DESC, anzeigename").all();
  return { benutzer: results.map(publicUser) };
}
async function adminCount(env) { return (await env.DB.prepare("SELECT COUNT(*) n FROM benutzer WHERE ist_admin=1 AND aktiv=1").first()).n; }
async function createUser(req, env, u) {
  const b = await body(req);
  const name = cleanUsername(b.benutzername);
  if (!["vorstand","ausschuss"].includes(b.rolle)) fail(400, "Rolle muss Vorstand oder Ausschuss sein.");
  const admin = b.rolle === "vorstand" && b.ist_admin ? 1 : 0;
  const pw = await makePassword(checkClientHash(b.passwort), env.PEPPER);
  try {
    await env.DB.prepare(`INSERT INTO benutzer(id,benutzername,anzeigename,rolle,ist_admin,pw_hash,pw_salt,pw_iter,pw_aendern,erstellt) VALUES(?,?,?,?,?,?,?,?,1,?)`)
      .bind(uid(), name, clean(b.anzeigename, 80) || name, b.rolle, admin, pw.pw_hash, pw.pw_salt, pw.pw_iter, nowIso()).run();
  } catch { fail(409, "Diesen Benutzernamen gibt es schon."); }
  await log(env, u, "Benutzer angelegt", clean(b.anzeigename, 80) || name, `Rolle: ${b.rolle}${admin ? " + Admin" : ""}`);
  return listUsers(env);
}
async function updateUser(req, env, u, id) {
  const b = await body(req);
  const t = await env.DB.prepare("SELECT * FROM benutzer WHERE id=?").bind(id).first();
  if (!t) fail(404, "Benutzer nicht gefunden.");
  const rolle = ["vorstand","ausschuss"].includes(b.rolle) ? b.rolle : t.rolle;
  const ist_admin = rolle === "vorstand" && (b.ist_admin ?? !!t.ist_admin) ? 1 : 0;
  const aktiv = (b.aktiv ?? !!t.aktiv) ? 1 : 0;
  const anzeigename = clean(b.anzeigename ?? t.anzeigename, 80) || t.benutzername;
  if (t.ist_admin && t.aktiv && (!ist_admin || !aktiv) && (await adminCount(env)) <= 1) fail(400, "Mindestens ein aktiver Admin muss bleiben.");
  if (id === u.id && (!aktiv || !ist_admin)) fail(400, "Du kannst dir nicht selbst die Admin-Rechte nehmen oder dich deaktivieren.");
  const stmts = [env.DB.prepare("UPDATE benutzer SET anzeigename=?, rolle=?, ist_admin=?, aktiv=? WHERE id=?").bind(anzeigename, rolle, ist_admin, aktiv, id)];
  if (!aktiv || rolle !== t.rolle) stmts.push(env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=?").bind(id));
  await env.DB.batch(stmts);
  await log(env, u, "Benutzer geändert", anzeigename, `Rolle: ${rolle}${ist_admin ? " + Admin" : ""}${aktiv ? "" : " · deaktiviert"}`);
  return listUsers(env);
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
  await env.DB.batch([env.DB.prepare("DELETE FROM sitzungen WHERE benutzer_id=?").bind(id), env.DB.prepare("DELETE FROM zusagen WHERE benutzer_id=?").bind(id), env.DB.prepare("DELETE FROM benutzer WHERE id=?").bind(id)]);
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
  return { format: "sku-vereinszentrale", exportiert: nowIso(), eintraege: e.results, dokumente: d.results, protokoll: p.results,
    mitglieder: mg.results, eltern: el.results, anhaenge: an.results, zusagen: zs.results };
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

  const u = await authenticate(req, env);

  if (p === "/api/logout" && M === "POST") { await env.DB.prepare("DELETE FROM sitzungen WHERE token_hash=?").bind(u.token_hash).run(); return json({ ok: true }, 200, cors); }
  if (p === "/api/ich" && M === "GET") return json({ benutzer: publicUser(u) }, 200, cors);
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

  if ((m = p.match(/^\/api\/(mitglieder|eltern)(?:\/([\w-]+))?$/))) {
    const P = PEOPLE[m[1]], id = m[2];
    if (!id && M === "GET") return json(await listPeople(env, P), 200, cors);
    if (!id && M === "POST") return json(await savePerson(req, env, u, P, null), 200, cors);
    if (id === "import" && M === "POST") return json(await importPeople(req, env, u, P), 200, cors);
    if (id && id !== "import" && M === "PUT") return json(await savePerson(req, env, u, P, id), 200, cors);
    if (id && id !== "import" && M === "DELETE") return json(await deletePerson(env, u, P, id), 200, cors);
  }

  if (p.startsWith("/api/dokumente") || p === "/api/protokoll" || p === "/api/export") needVorstand(u);
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
};
