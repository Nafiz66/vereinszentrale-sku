/* Vereinszentrale · FC Sender Kickers United – Frontend (GitHub Pages)
 * Alle Daten liegen in der SQLite-Datenbank (Cloudflare D1) hinter dem Worker.
 * Der Server prüft bei jeder Anfrage Anmeldung und Rolle – die Oberfläche blendet nur zusätzlich aus.
 */
"use strict";

const API = String(window.VZ_CONFIG?.API_URL || "").replace(/\/+$/, "");
const GROUPS = ["Satzung & Beschlüsse","Vorstand & Ausschuss","Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender","Gründungsplan","Offene Entscheidungen","Festwirtschaft"];
const STATUSES = ["Bestätigt","Geplant","Entwurf","Offen","Schätzung","Erledigt"];
const CLIENT_ITER = 250000;
const IDLE_MINUTES = 60;

const $ = id => document.getElementById(id);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
const dateText = d => d ? d.split("-").reverse().join(".") : "";
const today = () => new Intl.DateTimeFormat("sv-SE",{timeZone:"Europe/Berlin"}).format(new Date());
const fmtTime = iso => iso ? new Intl.DateTimeFormat("de-DE",{timeZone:"Europe/Berlin",dateStyle:"medium",timeStyle:"short"}).format(new Date(iso)) : "–";
const fmtBytes = n => n < 1024 ? n+" B" : n < 1048576 ? (n/1024).toFixed(0)+" KB" : (n/1048576).toFixed(1)+" MB";
const options = (values, sel) => values.map(v => `<option${v===sel?" selected":""}>${esc(v)}</option>`).join("");
const badge = s => s ? `<span class="badge" data-s="${esc(s)}">${esc(s)}</span>` : "";
const ROLE = { vorstand: "Vorstand", ausschuss: "Ausschuss", trainer: "Trainer", helfer: "Helfer" };
const rightsLabel = u => [ROLE[u.rolle], u.ist_admin && "Admin", ...(u.funktionen || []).map(f => typeof f === "string" ? funcName(f) : f.name)].filter(Boolean).join(" · ");
// Rechte kommen vom Server (/api/ich): Stufe je Bereich + feste Sonderrechte. Der Server prüft trotzdem jede Anfrage.
const D = () => me?.darf || {};
const lv = a => me?.rechte?.[a] || 0, canW = a => lv(a) >= 2, canD = a => lv(a) >= 3;
let funktionen = [], chatRooms = [], teamUsers = [];
const funcName = id => funktionen.find(f => f.id === id)?.name || "";
let teams = [], teamsUnassigned = [], kasse = { buchungen: [], einstellungen: { kategorien: [] } };
let kFilter = { q: "", jahr: "", monat: "", kategorie: "", art: "" }, kasseFromInvoice = null;

const AUSSCHUSS_GROUPS = ["Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender"];
// „nur Vorstand“: laut Rechte-Matrix sieht nur die Grundrolle Vorstand (und Admins) diesen Bereich
const vorstandOnly = bereich => { const s = me?.sichtbar?.[bereich] || []; return s.length > 0 && s.every(x => x === "Vorstand"); };
const ANSWERS = [["ja", "✓ Ich nehme teil"], ["vielleicht", "? Vielleicht"], ["nein", "✗ Leider nicht"]];
const MEMBER_STATUSES = ["Aktiv","Passiv","Ausgetreten"];
const MAX_FILE = 10 * 1024 * 1024, MAX_IMPORT = 1000;
const EMAIL_RE = /^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/;

const DL_CATS = ["Formulare","Sponsoren","Logos & Werbematerial","Sonstiges"];
const CLUB = "FC Sender Kickers United";
let downloads = [], invoices = [], settings = {}, editingInvoiceId = null, viewInvoiceId = null, activeDlId = null;
let iFilter = { q: "", status: "", jahr: "" };
let me = null, entries = [], docs = [], users = [], members = [], parents = [];
let sections = [], section = 0, filter = "", search = "", calMonth = today().slice(0,7), calView = "monat";
let mFilter = { q: "", team: "", status: "" };
let activeId = null, activeDocId = null, activeUserId = null, activeMemberId = null, activeParentId = null;
let pendingSheet = null, pendingPeople = null;

/* ---------------- Sitzung & API ---------------- */
const store = () => localStorage.getItem("vz_token") ? localStorage : sessionStorage;
const getToken = () => localStorage.getItem("vz_token") || sessionStorage.getItem("vz_token");
function setToken(t, remember) { clearToken(); (remember ? localStorage : sessionStorage).setItem("vz_token", t); }
function clearToken() { localStorage.removeItem("vz_token"); sessionStorage.removeItem("vz_token"); }

async function api(path, { method = "GET", data, raw, headers = {}, blob = false } = {}) {
  const h = { ...headers };
  const t = getToken(); if (t) h.Authorization = "Bearer " + t;
  let bodyData;
  if (raw) bodyData = raw; else if (data !== undefined) { h["Content-Type"] = "application/json"; bodyData = JSON.stringify(data); }
  let res;
  try { res = await fetch(API + path, { method, headers: h, body: bodyData, credentials: "omit", referrerPolicy: "no-referrer" }); }
  catch { throw new Error("Server nicht erreichbar. Internetverbindung prüfen."); }
  if (res.status === 401 && path !== "/api/login") { clearToken(); me = null; showLogin("Bitte erneut anmelden."); throw new Error("Bitte erneut anmelden."); }
  if (!res.ok) { let msg = "Fehler " + res.status; try { msg = (await res.json()).fehler || msg; } catch {} throw new Error(msg); }
  return blob ? res.blob() : res.json();
}

// Passwort im Browser strecken (PBKDF2, 250.000 Runden) – der Server bekommt nie das Klartext-Passwort
async function clientHash(username, password) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode("sku-vereinszentrale:" + username.trim().toLowerCase()), iterations: CLIENT_ITER }, key, 256);
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function genPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const r = crypto.getRandomValues(new Uint32Array(14));
  return [...r].map(n => chars[n % chars.length]).join("").replace(/(.{4})(?=.)/g, "$1-");
}

/* ---------------- Anmeldebildschirme ---------------- */
function authMode(mode, title, text) {
  $("appScreen").hidden = true; $("authScreen").hidden = false;
  for (const f of ["loginForm","pwForm","setupForm"]) $(f).hidden = f !== mode;
  $("authTitle").textContent = title; $("authText").textContent = text; $("authError").textContent = "";
}
function showLogin(msg) {
  authMode("loginForm", "Vereinszentrale", msg || "Bitte melde dich an.");
  $("loginForm").reset(); $("loginForm").elements.benutzername.focus();
}
function showSetup() {
  authMode("setupForm", "Ersteinrichtung", "Lege die drei Admin-Konten an. Den Einrichtungs-Code hast du beim Einrichten des Servers festgelegt.");
  $("setupAdmins").innerHTML = [1,2,3].map(i => `<fieldset class="adminblock"><legend>Admin ${i}</legend>
    <label>Benutzername<input name="u${i}" required value="admin${i}" autocapitalize="none" spellcheck="false"></label>
    <label>Anzeigename<input name="n${i}" placeholder="Vor- und Nachname"></label>
    <label>Passwort (mind. 10 Zeichen)<input name="p${i}" type="password" required minlength="10" autocomplete="new-password"></label></fieldset>`).join("");
}
function showPwChange() {
  authMode("pwForm", "Neues Passwort", `Hallo ${me.anzeigename}, bitte lege jetzt dein eigenes Passwort fest.`);
  $("pwForm").reset();
}
async function busy(form, fn) {
  const btn = form.querySelector("button:not([type=button])"); const label = btn.textContent;
  btn.disabled = true; btn.textContent = "Bitte warten …"; $("authError").textContent = "";
  try { await fn(); } catch (e) { $("authError").textContent = e.message; }
  finally { btn.disabled = false; btn.textContent = label; }
}

$("loginForm").onsubmit = e => { e.preventDefault(); busy(e.target, async () => {
  const f = e.target.elements, name = f.benutzername.value.trim().toLowerCase();
  const r = await api("/api/login", { method: "POST", data: { benutzername: name, passwort: await clientHash(name, f.passwort.value), angemeldet_bleiben: f.angemeldet_bleiben.checked } });
  setToken(r.token, f.angemeldet_bleiben.checked); me = r.benutzer;
  me.pw_aendern ? showPwChange() : startApp();
}); };
$("pwForm").onsubmit = e => { e.preventDefault(); busy(e.target, async () => {
  const f = e.target.elements;
  if (f.neu.value !== f.neu2.value) throw new Error("Die neuen Passwörter stimmen nicht überein.");
  if (f.neu.value.length < 10) throw new Error("Mindestens 10 Zeichen.");
  if (f.neu.value === f.alt.value) throw new Error("Bitte ein anderes Passwort als das bisherige wählen.");
  await api("/api/ich/passwort", { method: "POST", data: { alt: await clientHash(me.benutzername, f.alt.value), neu: await clientHash(me.benutzername, f.neu.value) } });
  me.pw_aendern = false; startApp(); notice("Passwort gespeichert.", true);
}); };
$("setupForm").onsubmit = e => { e.preventDefault(); busy(e.target, async () => {
  const f = e.target.elements, admins = [];
  for (const i of [1,2,3]) {
    const name = f["u"+i].value.trim().toLowerCase();
    if (f["p"+i].value.length < 10) throw new Error(`Admin ${i}: Passwort mindestens 10 Zeichen.`);
    admins.push({ benutzername: name, anzeigename: f["n"+i].value.trim(), passwort: await clientHash(name, f["p"+i].value) });
  }
  await api("/api/einrichtung", { method: "POST", data: { token: f.token.value, admins } });
  showLogin("Einrichtung abgeschlossen. Melde dich jetzt mit einem der Admin-Konten an.");
}); };

async function logout() {
  try { await api("/api/logout", { method: "POST" }); } catch {}
  clearToken(); me = null; entries = docs = users = members = parents = downloads = invoices = teams = teamsUnassigned = []; settings = {}; invDraft = null;
  kasse = { buchungen: [], einstellungen: { kategorien: [] } }; chatRooms = []; chatMsgs = []; chatOpen = null; teamUsers = []; clearInterval(chatTimer);
  showLogin("Du wurdest abgemeldet.");
}
let idleTimer;
function resetIdle() {
  clearTimeout(idleTimer);
  if (me && store() === sessionStorage) idleTimer = setTimeout(() => { logout().then(() => showLogin("Wegen Inaktivität abgemeldet.")); }, IDLE_MINUTES * 60000);
}
["click","keydown"].forEach(ev => document.addEventListener(ev, resetIdle, { passive: true }));

/* ---------------- App-Aufbau ---------------- */
const isTrainer = () => !!D().trainer;            // Trainer/Co-Trainer/Betreuer (Mannschafts-Ansicht)
const isSchatz = () => !!D().geld_schreiben;      // darf in Rechnungen/Kasse schreiben (Admin, Schatzmeister/in)
const readable = () => GROUPS.filter(g => lv(g) >= 1);
const writable = () => GROUPS.filter(g => lv(g) >= 2);
// Navigation komplett aus den Rechten: was man nicht lesen darf, gibt es nicht
function buildSections() {
  const groups = readable();
  // Kalender auch für Trainer und Festwirtschaft (zeigt alle Termine, die man sehen darf)
  if (!groups.includes("Kalender") && (isTrainer() || lv("Festwirtschaft") >= 1)) groups.splice(0, 0, "Kalender");
  if (!groups.includes("Elternkommunikation") && (isTrainer() || D().eltern_alle)) groups.push("Elternkommunikation");
  sections = ["Übersicht", ...GROUPS.filter(g => groups.includes(g))];
  if (isTrainer() && (me.mannschaften || []).length) sections.push("Meine Mannschaft");
  if (lv("Mitglieder") >= 1) sections.push("Mitglieder");
  if (lv("Downloads") >= 1) sections.push("Downloads");
  sections.push("Chat");
  if (D().geld_lesen) sections.push("Kasse", "Rechnungen");
  if (D().geld_schreiben) sections.push("Rechnung erstellen");
  if (lv("Dokumente") >= 1) sections.push("Dokumente");
  if (lv("Änderungsprotokoll") >= 1) sections.push("Änderungsprotokoll");
  if (D().team_verwalten) sections.push("Mein Team");
  if (me.ist_admin) sections.push("Benutzer");
  sections.push("Mein Konto");
}
const IDX = name => sections.indexOf(name);
const route = i => i ? "#bereich-" + i : "#start";

async function startApp() {
  $("authScreen").hidden = true; $("appScreen").hidden = false;
  me = (await api("/api/ich")).benutzer;   // aktuelle Rechte (Grundrolle + Funktionen + Matrix)
  buildSections();
  $("userName").textContent = me.anzeigename;
  $("userRole").textContent = rightsLabel(me);
  $("heroText").textContent = lv("Gründungsplan") >= 1 ? "Gründung, Aufgaben und Termine an einem Ort." : isTrainer() ? "Deine Termine, deine Mannschaft und die Eltern an einem Ort."
    : lv("Festwirtschaft") >= 1 && readable().length === 1 ? "Planung, Einkauf und Schichten für unsere Feste." : "Termine, Aufgaben und Austausch an einem Ort.";
  resetIdle();
  await reload();
  startChatPolling();
}
async function reload() {
  try {
    const jobs = [api("/api/eintraege").then(r => entries = r.eintraege),
      api("/api/mannschaften").then(r => { teams = r.mannschaften; teamsUnassigned = r.nicht_zugeordnet || []; }),
      api("/api/funktionen").then(r => funktionen = r.funktionen), api("/api/chat").then(r => chatRooms = r.raeume)];
    if (lv("Mitglieder") >= 1 || isTrainer()) jobs.push(api("/api/mitglieder").then(r => members = r.liste));
    if (D().eltern_alle || D().eltern_team) jobs.push(api("/api/eltern").then(r => parents = r.liste));
    if (lv("Downloads") >= 1) jobs.push(api("/api/downloads").then(r => downloads = r.downloads));
    if (D().vereinsdaten) jobs.push(api("/api/einstellungen").then(r => settings = r));
    if (D().geld_lesen) jobs.push(api("/api/rechnungen").then(r => invoices = r.rechnungen), api("/api/kasse").then(r => kasse = r));
    if (lv("Dokumente") >= 1) jobs.push(api("/api/dokumente").then(r => docs = r.dokumente));
    if (me.ist_admin) jobs.push(api("/api/benutzer").then(r => users = r.benutzer));
    if (D().team_verwalten) jobs.push(api("/api/team").then(r => teamUsers = r.benutzer));
    await Promise.all(jobs);
    render();
  } catch (e) { $("view").innerHTML = `<p class="muted">${esc(e.message)}</p>`; }
}

function notice(text, ok = false) { const n = $("notice"); n.textContent = text; n.className = ok ? "ok" : ""; clearTimeout(notice.t); notice.t = setTimeout(() => n.textContent = "", 6000); }

function renderNav() {
  const c = {}; for (const r of entries) if (r.status !== "Erledigt") c[r.bereich] = (c[r.bereich] || 0) + 1;
  $("nav").innerHTML = sections.map((s, i) => {
    const sep = ["Mitglieder","Dokumente","Benutzer","Mein Konto"].includes(s) && !["Mitglieder","Dokumente","Benutzer"].includes(sections[i-1]) ? '<div class="navsep"></div>' : "";
    const unread = s === "Chat" ? chatRooms.reduce((a, r) => a + (r.ungelesen || 0), 0) : 0;
    const n = s === "Chat" ? (unread ? `<span class="count unread">${unread}</span>` : "") : c[s] && lv(s) >= 1 ? `<span class="count">${c[s]}</span>` : "";
    return `${sep}<a href="${route(i)}"${i===section?' aria-current="page"':""}>${esc(s)}${n}</a>`;
  }).join("");
}

function card(r, showGroup = false) {
  const meta = [dateText(r.datum) + (r.uhrzeit ? " · " + r.uhrzeit + " Uhr" : ""), r.ort, r.zustaendig, r.quelle].filter(Boolean).map(esc).join(" · ");
  const body = r.inhalt ? `<p class="body">${esc(r.inhalt)}</p>` : "";
  const parent = r.bereich === "Elternkommunikation";
  const files = (r.anhaenge || []).map(a => `<button class="quiet chip" data-att="${esc(a.id)}" title="${esc(a.dateiname)} öffnen">📎 ${esc(a.dateiname)} <small>(${fmtBytes(a.groesse)})</small></button>`).join("");
  let lock = vorstandOnly(r.bereich) ? ' <span class="lockmark" title="Nur der Vorstand (und Admins) sieht diesen Bereich">🔒 nur Vorstand</span>' : "";
  if (r.fuer_trainer && canW(r.bereich)) lock += ` <span class="trainermark" title="Trainer sehen diesen Eintrag">🏃 ${esc(teamName(r.mannschaft_id) || "alle Trainer")}</span>`;
  return `<article class="card">${showGroup ? `<div class="meta">${esc(r.bereich)}${lock}</div>` : ""}<div class="cardtop"><h3>${esc(r.titel)}${showGroup ? "" : lock}</h3>${badge(r.status)}</div>
    ${meta ? `<div class="meta">${meta}</div>` : ""}
    ${r.inhalt.length > 1700 ? `<details><summary>Volltext anzeigen</summary>${body}</details>` : body}
    ${files ? `<div class="attachments">${files}</div>` : ""}
    ${r.rueckmeldung ? rsvpBlock(r) : ""}
    <div class="actions">
      ${canW(r.bereich) ? `<button class="quiet" data-edit="${esc(r.id)}">Bearbeiten</button>` : ""}
      ${canW(r.bereich) && !["Erledigt","Bestätigt"].includes(r.status) ? `<button class="quiet" data-done="${esc(r.id)}">✓ Erledigt</button>` : ""}
      ${parent ? `${D().eltern_alle || D().eltern_team ? `<button class="quiet" data-mail="${esc(r.id)}">✉ Per E-Mail an Eltern</button>` : ""}<button class="quiet" data-copy="${esc(r.id)}">Text kopieren</button><a class="btnlink wa" target="_blank" rel="noopener noreferrer" href="https://wa.me/?text=${encodeURIComponent((r.titel ? r.titel + "\n\n" : "") + r.inhalt)}">💬 Per WhatsApp teilen</a>` : ""}
    </div></article>`;
}
const myAnswer = r => (r.zusagen || []).find(z => z.benutzer_id === me.id)?.antwort || "";
const rsvpButtons = r => ANSWERS.map(([a, label]) => `<button class="quiet rsvpbtn" data-rsvp="${esc(r.id)}" data-a="${a}" aria-pressed="${myAnswer(r) === a}">${label}</button>`).join("");
function rsvpBlock(r) {
  const z = r.zusagen || [], by = a => z.filter(x => x.antwort === a).map(x => x.name), offen = r.offen || [];
  const ja = by("ja"), vl = by("vielleicht"), nein = by("nein");
  const list = (label, names) => names.length ? `<li><b>${label} (${names.length}):</b> ${esc(names.join(", "))}</li>` : "";
  return `<div class="rsvp"><div class="rsvpbtns"><span class="muted small">Deine Antwort:</span>${rsvpButtons(r)}</div>
    <details><summary>✓ ${ja.length} Zusagen · ? ${vl.length} Vielleicht · ✗ ${nein.length} Absagen · ${offen.length} noch offen</summary>
    <ul>${list("Nehmen teil", ja)}${list("Vielleicht", vl)}${list("Nehmen nicht teil", nein)}${list("Noch keine Antwort", offen)}</ul></details></div>`;
}
async function answer(id, a) {
  const r = entries.find(x => x.id === id); if (!r) return;
  const neu = myAnswer(r) === a ? "" : a; // nochmal klicken = Antwort zurücknehmen
  try {
    await api(`/api/eintraege/${id}/zusage`, { method: "PUT", data: { antwort: neu } });
    notice(neu ? `Danke! Deine Antwort „${ANSWERS.find(x => x[0] === neu)[1].slice(2)}“ ist gespeichert.` : "Antwort zurückgenommen.", true);
    await reload();
  } catch (e) { notice(e.message); }
}
function mini(items, empty) {
  return items.length ? items.map(r => `<button class="mini" data-edit="${esc(r.id)}">${esc(r.titel)}<small>${esc([dateText(r.datum), r.zustaendig, r.status].filter(Boolean).join(" · "))}</small></button>`).join("")
    : `<p class="muted">${empty}</p>`;
}

function render(reset = false) {
  if (!me) return;
  const next = Number(location.hash.match(/^#bereich-(\d+)$/)?.[1]) || 0;
  if (reset || next !== section) {
    filter = ""; search = ""; mFilter = { q: "", team: "", status: "" }; iFilter = { q: "", status: "", jahr: "" };
    kFilter = { q: "", jahr: today().slice(0, 4), monat: "", kategorie: "", art: "" };
    if (sections[next] !== "Rechnung erstellen" && editingInvoiceId) { editingInvoiceId = null; invDraft = null; }
  }
  section = next < sections.length ? next : 0;
  const name = sections[section];
  $("hero").hidden = section !== 0;
  $("crumb").textContent = section ? name : "Vereinszentrale";
  // „＋“ nur, wo man auch anlegen darf
  const addOk = { "Übersicht": writable().length > 0, Kalender: writable().length > 0, Mitglieder: canW("Mitglieder"), Downloads: canW("Downloads"), Dokumente: canW("Dokumente"),
    Kasse: isSchatz(), Rechnungen: isSchatz(), Benutzer: !!me.ist_admin, "Mein Team": !!D().team_verwalten, Chat: !!D().raeume_anlegen }[name] ?? (GROUPS.includes(name) && canW(name));
  $("add").hidden = !addOk;
  $("add").textContent = { Dokumente: "＋ Dokument", Benutzer: "＋ Benutzer", Mitglieder: "＋ Mitglied", Downloads: "＋ Datei hochladen", Rechnungen: "＋ Rechnung erstellen", Kasse: "＋ Buchung", "Mein Team": "＋ Team-Konto", Chat: "＋ Raum" }[name] || "＋ Eintrag";
  renderNav();
  if (name !== "Chat") chatOpen = null;
  if (!section) readable().length ? renderHome() : renderTrainerHome();
  else if (name === "Meine Mannschaft") renderTrainerTeam();
  else if (name === "Chat") renderChat();
  else if (name === "Mein Team") renderTeam();
  else if (name === "Mitglieder") renderMembers();
  else if (name === "Kasse") renderKasse();
  else if (name === "Downloads") renderDownloads();
  else if (name === "Rechnungen") renderInvoices();
  else if (name === "Rechnung erstellen") renderInvoiceForm();
  else if (name === "Dokumente") renderDocs();
  else if (name === "Änderungsprotokoll") renderLog();
  else if (name === "Benutzer") renderUsers();
  else if (name === "Mein Konto") renderAccount();
  else renderGroup(name);
}

function renderHome() {
  const t = today();
  const by = s => entries.filter(r => r.status === s);
  const open = by("Offen").slice(0, 6);
  const upcoming = entries.filter(r => r.datum >= t && r.status !== "Erledigt").sort((a,b) => (a.datum+a.uhrzeit).localeCompare(b.datum+b.uhrzeit)).slice(0, 6);
  const recent = [...entries].sort((a,b) => b.geaendert.localeCompare(a.geaendert)).slice(0, 5);
  const stat = (num, label, href) => `<a class="stat" href="${href}"><strong>${num}</strong>${label}</a>`;
  const cal = IDX("Kalender") > 0 ? route(IDX("Kalender")) : "#start";
  const pending = entries.filter(r => r.rueckmeldung && !myAnswer(r) && (!r.datum || r.datum >= t) && r.status !== "Erledigt")
    .sort((a,b) => (a.datum || "9999").localeCompare(b.datum || "9999"));
  let extra = pending.length ? `<section class="card warnbox"><h2>Deine Rückmeldung fehlt (${pending.length})</h2>
    ${pending.map(r => `<div class="rsvprow"><div><b>${esc(r.titel)}</b><small>${esc([dateText(r.datum) + (r.uhrzeit ? " · " + r.uhrzeit + " Uhr" : ""), r.ort].filter(Boolean).join(" · ") || r.bereich)}</small></div>
      <div class="rsvpbtns">${rsvpButtons(r)}</div></div>`).join("")}</section>` : "";
  const link = name => IDX(name) > 0 ? route(IDX(name)) : cal;
  extra += chatHomeCard();
  if (lv("Gründungsplan") >= 1) {
    const plan = entries.filter(r => r.bereich === "Gründungsplan"), done = plan.filter(r => ["Erledigt","Bestätigt"].includes(r.status)).length;
    const pct = plan.length ? Math.round(done / plan.length * 100) : 0;
    extra += `<section class="card"><div class="cardtop"><h2>Gründungsfortschritt</h2><a class="link" href="${link("Gründungsplan")}">Gründungsplan</a></div>
        <div class="progress" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><span style="width:${pct}%"></span></div>
        <p class="muted">${done} von ${plan.length} Schritten erledigt (${pct} %)</p></section>`;
  }
  if (lv("Dokumente") >= 1) extra += `<section class="card"><div class="cardtop"><h2>Unterlagen</h2><a class="link" href="${link("Dokumente")}">Dokumente</a></div>
        <p class="muted" style="margin-top:8px">${docs.length} Dokumente erfasst, ${docs.filter(d => d.groesse).length} mit hinterlegter Datei.</p></section>`;
  if (isTrainer()) extra += myTeamCard();
  $("view").innerHTML = `
    <div class="stats">
      ${stat(by("Offen").length, "Offen", IDX("Offene Entscheidungen") > 0 ? link("Offene Entscheidungen") : cal)}
      ${stat(by("Geplant").length, "Geplant", cal)}
      ${stat(by("Bestätigt").length, "Bestätigt", IDX("Satzung & Beschlüsse") > 0 ? link("Satzung & Beschlüsse") : cal)}
      ${stat(by("Schätzung").length, "Schätzungen", link("Beiträge & Ehrenamt"))}
    </div>
    <div class="homegrid">${extra}
      <section class="card"><div class="cardtop"><h2>Nächste Termine</h2><a class="link" href="${cal}">Kalender</a></div>${mini(upcoming, "Keine anstehenden Termine.")}</section>
      <section class="card"><h2>Offene Punkte</h2>${mini(open, "Keine offenen Punkte.")}</section>
      <section class="card"><h2>Zuletzt geändert</h2>${recent.map(r => `<button class="mini" data-edit="${esc(r.id)}">${esc(r.titel)}<small>${esc(fmtTime(r.geaendert))} · ${esc(r.geaendert_von)}</small></button>`).join("") || '<p class="muted">Noch nichts.</p>'}</section>
    </div>`;
}

// Startseite für Konten ohne eigene Bereiche (Trainer, Helfer, Festwirt-Team ohne Matrix-Rechte)
function renderTrainerHome() {
  const t = today();
  const pending = entries.filter(r => r.rueckmeldung && !myAnswer(r) && (!r.datum || r.datum >= t) && r.status !== "Erledigt")
    .sort((a,b) => (a.datum || "9999").localeCompare(b.datum || "9999"));
  const upcoming = entries.filter(r => r.datum >= t && r.status !== "Erledigt").sort((a,b) => (a.datum+a.uhrzeit).localeCompare(b.datum+b.uhrzeit)).slice(0, 8);
  $("view").innerHTML = `<div class="homegrid">
    ${pending.length ? `<section class="card warnbox"><h2>Deine Rückmeldung fehlt (${pending.length})</h2>
      ${pending.map(r => `<div class="rsvprow"><div><b>${esc(r.titel)}</b><small>${esc([dateText(r.datum) + (r.uhrzeit ? " · " + r.uhrzeit + " Uhr" : ""), r.ort].filter(Boolean).join(" · "))}</small></div>
        <div class="rsvpbtns">${rsvpButtons(r)}</div></div>`).join("")}</section>` : ""}
    ${IDX("Kalender") > 0 ? `<section class="card"><div class="cardtop"><h2>Nächste Termine</h2><a class="link" href="${route(IDX("Kalender"))}">Kalender</a></div>${mini(upcoming, "Keine anstehenden Termine.")}</section>` : ""}
    ${isTrainer() ? myTeamCard() : ""}
    ${chatHomeCard(true)}
  </div>`;
}
const myTeams = () => teams.filter(t => (me.mannschaften || []).includes(t.id));
function myTeamCard() {
  const my = myTeams().map(tm => `<div class="rsvprow"><div><b>${esc(tm.name)}</b><small>${members.filter(m => m.mannschaft_id === tm.id).length} Mitglieder · ${new Set(parents.filter(p => p.mannschaft_id === tm.id).map(p => p.email)).size} Eltern-Adressen</small></div>
    <div class="rsvpbtns">${tm.whatsapp_link ? waButton(tm) : ""}<a class="btnlink quiet" href="${route(IDX("Meine Mannschaft"))}">ansehen</a></div></div>`).join("");
  return `<section class="card"><h2>Meine Mannschaft${myTeams().length > 1 ? "en" : ""}</h2>${my || '<p class="muted">Dir ist noch keine Mannschaft zugeordnet. Bitte beim Admin melden.</p>'}</section>`;
}
// WhatsApp-Gruppe der Mannschaft öffnen (Einladungslink, kein WhatsApp-Business nötig)
const waButton = tm => `<a class="btnlink wa" target="_blank" rel="noopener noreferrer" href="${esc(tm.whatsapp_link)}">💬 WhatsApp-Gruppe ${esc(tm.name)}</a>`;
function renderTrainerTeam() {
  $("view").innerHTML = `<div class="sectionhead"><h2>Meine Mannschaft${myTeams().length > 1 ? "en" : ""}</h2></div>` + (myTeams().map(tm => {
    const list = members.filter(m => m.mannschaft_id === tm.id);
    return `<div class="sectionhead teamhead"><h3 style="margin:0">${esc(tm.name)} <span class="muted small">${list.length} Mitglieder · ${list.filter(m => m.status === "Aktiv").length} aktiv</span></h3>${tm.whatsapp_link ? waButton(tm) : ""}</div>
      <div class="tablewrap"><table class="table"><thead><tr><th>Vorname</th><th>Nachname</th><th>Alter</th><th>Status</th></tr></thead><tbody>
      ${list.map(m => `<tr><td>${esc(m.vorname)}</td><td>${esc(m.nachname)}</td><td>${m.alter ?? age(m.geburtsdatum)}</td><td>${m.status === "Aktiv" ? "aktiv" : `<span class="lock">${esc(m.status.toLowerCase())}</span>`}</td></tr>`).join("")
        || '<tr><td colspan="4" class="muted">Noch keine Mitglieder in dieser Mannschaft.</td></tr>'}</tbody></table></div>`;
  }).join("") || '<p class="muted">Dir ist noch keine Mannschaft zugeordnet. Bitte beim Admin melden.</p>');
}

function renderGroup(name) {
  const cal = name === "Kalender";
  $("view").innerHTML = `<div class="sectionhead"><h2>${esc(name)}</h2>${cal ? `<div class="filters" style="margin:0">
      <button class="quiet" data-act="calView" data-v="monat"${calView==="monat"?" disabled":""}>Monat</button>
      <button class="quiet" data-act="calView" data-v="liste"${calView==="liste"?" disabled":""}>Liste</button>
      <button class="quiet" data-act="ics">Kalender exportieren (.ics)</button></div>` : ""}</div>
    ${cal && calView === "monat" ? '<div id="calendar"></div>' : ""}
    ${name === "Elternkommunikation" ? parentsPanel() : ""}
    <div class="filters">
      <input id="search" type="search" placeholder="Einträge durchsuchen" aria-label="Einträge durchsuchen" value="${esc(search)}">
      <select id="filter" aria-label="Status filtern"><option value="">Alle Status</option>${options(STATUSES, filter)}</select>
      ${cal ? `<input id="month" type="month" aria-label="Monat" value="${esc(calMonth)}">` : ""}
    </div><div id="cards"></div>`;
  $("search").oninput = e => { search = e.target.value; renderCards(); };
  $("filter").onchange = e => { filter = e.target.value; renderCards(); renderCalendar(); };
  if (cal) $("month").onchange = e => { calMonth = e.target.value || today().slice(0,7); renderCalendar(); renderCards(); };
  renderCalendar(); renderCards();
}
const matches = (r, term) => [r.titel, r.inhalt, r.zustaendig, r.quelle, r.ort].join(" ").toLocaleLowerCase("de").includes(term.trim().toLocaleLowerCase("de"));
function renderCards() {
  const name = sections[section], cal = name === "Kalender";
  let rows = entries.filter(r => cal ? (r.datum ? r.datum.startsWith(calMonth) : r.bereich === "Kalender") : r.bereich === name);
  rows = rows.filter(r => (!filter || r.status === filter) && (!search || matches(r, search)));
  rows.sort(cal ? (a,b) => ((a.datum||"9999")+a.uhrzeit).localeCompare((b.datum||"9999")+b.uhrzeit)
                : (a,b) => (a.status==="Erledigt") - (b.status==="Erledigt") || (a.datum||"9999").localeCompare(b.datum||"9999"));
  $("cards").innerHTML = rows.map(r => card(r, cal)).join("") || '<p class="muted">Keine passenden Einträge.</p>';
}
function renderCalendar() {
  const el = $("calendar"); if (!el) return;
  const [y, m] = calMonth.split("-").map(Number);
  const first = new Date(Date.UTC(y, m - 1, 1));
  const start = new Date(first); start.setUTCDate(1 - ((first.getUTCDay() + 6) % 7));
  const byDay = {};
  for (const r of entries) if (r.datum && (!filter || r.status === filter)) (byDay[r.datum] ||= []).push(r);
  const label = new Intl.DateTimeFormat("de-DE", {month:"long", year:"numeric", timeZone:"UTC"}).format(first);
  const t = today(); let cells = "";
  for (let i = 0; i < 42; i++) {
    const d = new Date(start.getTime() + i * 864e5), iso = d.toISOString().slice(0,10);
    const ev = (byDay[iso] || []).sort((a,b) => a.uhrzeit.localeCompare(b.uhrzeit)).map(r => {
      const lock = vorstandOnly(r.bereich), tr = r.fuer_trainer && canW(r.bereich);
      return `<button class="ev" data-s="${esc(r.status)}" data-edit="${esc(r.id)}" title="${esc(r.titel)}${lock ? " (nur Vorstand sichtbar)" : ""}${tr ? " (auch für Trainer)" : ""}">${lock ? "🔒 " : ""}${tr ? "🏃 " : ""}${r.uhrzeit ? esc(r.uhrzeit)+" " : ""}${esc(r.titel)}</button>`;
    }).join("");
    cells += `<div class="day${d.getUTCMonth() !== m-1 ? " other" : ""}${iso === t ? " today" : ""}" data-day="${iso}"><span class="num">${d.getUTCDate()}</span>${ev}</div>`;
  }
  el.innerHTML = `<div class="calhead"><button class="quiet" data-act="calPrev" aria-label="Vorheriger Monat">‹</button><h3>${label}</h3><button class="quiet" data-act="calNext" aria-label="Nächster Monat">›</button><button class="quiet" data-act="calToday">Heute</button></div>
    <div class="calgrid">${["Mo","Di","Mi","Do","Fr","Sa","So"].map(d => `<div class="dow">${d}</div>`).join("")}${cells}</div>`;
}
function shiftMonth(delta) {
  const [y, m] = calMonth.split("-").map(Number);
  calMonth = new Date(Date.UTC(y, m - 1 + delta, 1)).toISOString().slice(0,7);
  if ($("month")) $("month").value = calMonth; renderCalendar(); renderCards();
}

/* ---------------- Mitglieder ---------------- */
const distinct = list => [...new Set(list.map(s => String(s || "").trim()).filter(Boolean))].sort((a,b) => a.localeCompare(b, "de"));
const memberName = m => [m.vorname, m.nachname].filter(Boolean).join(" ");
function age(d) {
  if (!d) return "";
  const [y, m, dd] = d.split("-").map(Number), [ty, tm, td] = today().split("-").map(Number);
  return ty - y - (tm < m || (tm === m && td < dd) ? 1 : 0);
}
/* Mannschaftsliste */
const normTeam = s => String(s ?? "").trim().toLowerCase().replace(/[\s-]+/g, "");
const teamName = id => teams.find(t => t.id === id)?.name || "";
const findTeam = name => name ? teams.find(t => normTeam(t.name) === normTeam(name)) : null;
const teamCell = x => x.mannschaft_id ? esc(teamName(x.mannschaft_id)) : x.mannschaft ? `${esc(x.mannschaft)} <span class="unassigned" title="Steht nicht in der Mannschaftsliste">⚠ nicht zugeordnet</span>` : "";
function teamOptions(selId, legacyText) {
  return `<option value="">– keine –</option>` + teams.filter(t => t.aktiv || t.id === selId).map(t => `<option value="${esc(t.id)}"${t.id === selId ? " selected" : ""}>${esc(t.name)}${t.aktiv ? "" : " (inaktiv)"}</option>`).join("")
    + (!selId && legacyText ? `<option value="__alt" selected>„${esc(legacyText)}“ (nicht zugeordnet)</option>` : "");
}
function teamsCard() {
  if (!D().mannschaften_pflegen) return "";
  return `<details class="card" style="margin-bottom:14px"${teams.length && !teamsUnassigned.length ? "" : " open"}><summary><b>Mannschaftsliste</b> <span class="muted small">${teams.filter(t => t.aktiv).length} aktiv${teamsUnassigned.length ? ` · ⚠ ${teamsUnassigned.length} Werte nicht zugeordnet` : ""}</span></summary>
    <div class="tablewrap" style="margin-top:10px"><table class="table"><thead><tr><th>Mannschaft</th><th>Sortierung</th><th>Mitglieder</th><th>Eltern</th><th>WhatsApp-Gruppe</th><th>Status</th><th></th></tr></thead><tbody>
      ${teams.map(t => `<tr><td><b>${esc(t.name)}</b></td><td>${t.sortierung}</td><td>${members.filter(m => m.mannschaft_id === t.id).length}</td><td>${parents.filter(p => p.mannschaft_id === t.id).length}</td>
        <td><button class="quiet" data-walink="${esc(t.id)}">${t.whatsapp_link ? "✓ Link ändern" : "＋ Link eintragen"}</button></td>
        <td>${t.aktiv ? "aktiv" : '<span class="lock">inaktiv</span>'}</td><td><button class="quiet" data-teamedit="${esc(t.id)}">Ändern</button></td></tr>`).join("") || '<tr><td colspan="6" class="muted">Noch keine Mannschaften.</td></tr>'}
    </tbody></table></div>
    <div class="actions"><button class="quiet" data-act="addTeam">＋ Mannschaft</button></div>
    ${teamsUnassigned.length ? `<h3 style="margin-top:16px">Nicht zugeordnet</h3><p class="muted small">Diese Mannschafts-Namen stehen bei Mitgliedern oder Eltern, aber nicht in der Liste. Ordne sie einer Mannschaft zu oder lege sie als neue Mannschaft an.</p>
      <div class="tablewrap" style="margin-top:8px"><table class="table"><tbody>${teamsUnassigned.map((u, i) => `<tr><td><b>„${esc(u.name)}“</b> <span class="lock">${u.mitglieder} Mitglieder · ${u.eltern} Eltern</span></td>
        <td><select data-assignsel="${i}"><option value="">Mannschaft wählen …</option>${teams.filter(t => t.aktiv).map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join("")}</select></td>
        <td><button class="quiet" data-assign="${i}">Zuordnen</button> <button class="quiet" data-assignnew="${i}">Als neue Mannschaft</button></td></tr>`).join("")}</tbody></table></div>` : ""}
  </details>`;
}
async function teamApi(path, method, data, msg) {
  try { await api(path, { method, data }); await reload(); notice(msg, true); }
  catch (e) { notice(e.message); }
}
function editTeam(id) {
  const t = teams.find(x => x.id === id);
  const name = prompt(t ? "Name der Mannschaft:" : "Name der neuen Mannschaft (z. B. U11):", t?.name || ""); if (name === null || !name.trim()) return;
  const sort = prompt("Sortierung (kleine Zahl = weiter oben):", String(t?.sortierung ?? teams.length + 1)); if (sort === null) return;
  const wa = prompt("WhatsApp-Gruppenlink (optional).\nIn WhatsApp: Gruppe → Gruppeninfo → „Per Link einladen“ → Link kopieren.\nBeispiel: https://chat.whatsapp.com/AbCdEf123…\nLeer lassen = kein Link.", t?.whatsapp_link || "");
  if (wa === null) return;
  const aktiv = t ? confirm(`Soll „${name.trim()}“ aktiv sein?\n\nOK = aktiv · Abbrechen = inaktiv (bleibt erhalten, ist aber nicht mehr auswählbar)`) : true;
  teamApi(t ? "/api/mannschaften/" + t.id : "/api/mannschaften", t ? "PUT" : "POST", { name: name.trim(), sortierung: Number(sort) || 0, aktiv, whatsapp_link: wa.trim() }, "Mannschaftsliste gespeichert.");
}

// WhatsApp-Gruppenlink einer Mannschaft direkt eintragen/ändern/entfernen
function editWaLink(id) {
  const t = teams.find(x => x.id === id); if (!t) return;
  const wa = prompt(`WhatsApp-Gruppenlink für „${t.name}“:\n\nSo bekommst du ihn: WhatsApp öffnen → Gruppe → oben auf den Gruppennamen tippen → „Per Link einladen“ → „Link kopieren“. Dann hier einfügen.\n\nEr sieht so aus: https://chat.whatsapp.com/AbCdEf123…\nFeld leeren = Link entfernen.`, t.whatsapp_link || "");
  if (wa === null) return;
  const link = wa.trim();
  if (link && !/^https:\/\/chat\.whatsapp\.com\/[A-Za-z0-9]{10,40}$/.test(link)) return notice("Das ist kein WhatsApp-Gruppenlink. Er muss mit https://chat.whatsapp.com/ beginnen.");
  teamApi("/api/mannschaften/" + t.id, "PUT", { name: t.name, sortierung: t.sortierung, aktiv: !!t.aktiv, whatsapp_link: link }, link ? `WhatsApp-Link für ${t.name} gespeichert.` : `WhatsApp-Link für ${t.name} entfernt.`);
}

function renderMembers() {
  $("view").innerHTML = `<div class="sectionhead"><h2>Mitglieder</h2><div class="actions" style="margin:0">
      <button class="quiet" data-act="importPeople" data-kind="mitglieder">CSV/Excel-Datei hochladen</button>
      <button class="quiet" data-act="membersCsv">Als CSV exportieren</button></div></div>
    ${teamsCard()}
    <div class="filters">
      <input id="msearch" type="search" placeholder="Name, E-Mail, Telefon …" aria-label="Mitglieder durchsuchen" value="${esc(mFilter.q)}">
      <select id="mteam" aria-label="Mannschaft filtern"><option value="">Alle Mannschaften</option>${teams.map(t => `<option value="${esc(t.id)}"${mFilter.team === t.id ? " selected" : ""}>${esc(t.name)}</option>`).join("")}<option value="__ohne"${mFilter.team === "__ohne" ? " selected" : ""}>ohne / nicht zugeordnet</option></select>
      <select id="mstatus" aria-label="Status filtern"><option value="">Alle Status</option>${options(MEMBER_STATUSES, mFilter.status)}</select>
    </div><div id="mtable"></div>`;
  $("msearch").oninput = e => { mFilter.q = e.target.value; renderMemberTable(); };
  $("mteam").onchange = e => { mFilter.team = e.target.value; renderMemberTable(); };
  $("mstatus").onchange = e => { mFilter.status = e.target.value; renderMemberTable(); };
  renderMemberTable();
}
function filteredMembers() {
  const q = mFilter.q.trim().toLocaleLowerCase("de");
  return members.filter(m => (!mFilter.team || (mFilter.team === "__ohne" ? !m.mannschaft_id : m.mannschaft_id === mFilter.team)) && (!mFilter.status || m.status === mFilter.status)
    && (!q || [m.vorname, m.nachname, m.email, m.telefon, m.mannschaft, m.notiz].join(" ").toLocaleLowerCase("de").includes(q)));
}
function renderMemberTable() {
  const list = filteredMembers();
  if (!members.length) {
    $("mtable").innerHTML = `<section class="card"><h3>Noch keine Mitglieder</h3><p class="muted" style="margin-top:6px">Klicke oben auf <b>＋ Mitglied</b>, um jemanden von Hand einzutragen,
      oder auf <b>CSV/Excel-Datei hochladen</b>, um eine ganze Liste zu übernehmen. Die Spalten (Vorname, Nachname, Geburtsdatum, Mannschaft, E-Mail, Telefon …) werden automatisch erkannt.</p></section>`;
    return;
  }
  $("mtable").innerHTML = `<p class="muted small" style="margin-bottom:8px">${list.length} von ${members.length} Mitgliedern · ${members.filter(m => m.status === "Aktiv").length} aktiv</p>
    <div class="tablewrap"><table class="table"><thead><tr><th>Name</th><th>Geburtsdatum</th><th>Mannschaft</th><th>E-Mail</th><th>Telefon</th><th>Status</th><th></th></tr></thead><tbody>
    ${list.map(m => `<tr><td><b>${esc(memberName(m))}</b></td><td>${m.geburtsdatum ? `${esc(dateText(m.geburtsdatum))} <span class="lock">(${age(m.geburtsdatum)})</span>` : ""}</td>
      <td>${teamCell(m)}</td><td class="wrap">${m.email ? `<a class="link" href="mailto:${esc(m.email)}">${esc(m.email)}</a>` : ""}</td><td>${esc(m.telefon)}</td>
      <td>${m.status === "Aktiv" ? "aktiv" : `<span class="lock">${esc(m.status.toLowerCase())}</span>`}</td>
      <td><button class="quiet" data-memberedit="${esc(m.id)}">Bearbeiten</button></td></tr>`).join("") || '<tr><td colspan="7" class="muted">Keine Treffer.</td></tr>'}
    </tbody></table></div>`;
}
function exportMembersCsv() {
  const cols = [["vorname","Vorname"],["nachname","Nachname"],["geburtsdatum","Geburtsdatum"],["mannschaft","Mannschaft"],["email","E-Mail"],["telefon","Telefon"],["eintritt","Mitglied seit"],["status","Status"],["notiz","Notiz"]];
  const cell = v => `"${String(v ?? "").replace(/"/g,'""')}"`;
  const rows = filteredMembers().map(m => cols.map(([k]) => cell(/datum|eintritt/.test(k) ? dateText(m[k]) : m[k])).join(";"));
  download(new Blob(["﻿" + [cols.map(c => c[1]).join(";"), ...rows].join("\r\n")], {type:"text/csv;charset=utf-8"}), `mitglieder_${today()}.csv`);
}

/* ---------------- Eltern-Verteiler ---------------- */
function parentsPanel() {
  // WhatsApp-Gruppen der Mannschaften (kostenlos über Einladungslink) – für alle, die Elternkommunikation sehen;
  // wer die Mannschaftsliste pflegt, trägt hier direkt die Links ein
  const edit = !!D().mannschaften_pflegen, active = teams.filter(t => t.aktiv), wa = active.filter(t => t.whatsapp_link);
  const waCard = edit ? `<section class="card parentsbox"><h3>WhatsApp-Gruppen der Mannschaften</h3>
      <p class="muted small" style="margin:4px 0 8px">Pro Mannschaft den Einladungslink der WhatsApp-Gruppe eintragen. Danach gibt es hier und bei „Meine Mannschaft“ den Knopf zum Öffnen der Gruppe.</p>
      ${active.length ? `<div class="walist">${active.map(t => `<div class="warow"><b>${esc(t.name)}</b>
        <div class="actions" style="margin:0">${t.whatsapp_link ? waButton(t) : '<span class="lock">noch kein Link</span>'}
        <button class="quiet" data-walink="${esc(t.id)}">${t.whatsapp_link ? "Link ändern" : "＋ WhatsApp-Link eintragen"}</button></div></div>`).join("")}</div>`
        : `<p class="muted">Noch keine Mannschaften. Lege sie zuerst unter <b>Mitglieder → Mannschaftsliste</b> an.</p>`}</section>`
    : wa.length ? `<section class="card parentsbox"><h3>WhatsApp-Gruppen der Mannschaften</h3>
      <p class="muted small" style="margin:4px 0 8px">Öffnet die Gruppe in WhatsApp. Eine Nachricht unten mit „Per WhatsApp teilen“ an die Gruppe weiterleiten.</p>
      <div class="actions">${wa.map(waButton).join("")}</div></section>` : "";
  if (!D().eltern_alle && !D().eltern_team) return waCard;
  const ro = !D().eltern_alle, ok = parents.filter(p => p.einwilligung).length;
  const rows = parents.map(p => `<tr><td>${esc(p.name)}</td><td>${esc(p.kind)}</td><td>${ro ? esc(teamName(p.mannschaft_id) || p.mannschaft) : teamCell(p)}</td><td class="wrap">${esc(p.email)}</td>
    <td>${p.einwilligung ? `✓ ${esc(dateText(p.einwilligung_datum))}` : '<span class="unassigned">⚠ fehlt</span>'}</td>
    <td>${ro ? "" : `<button class="quiet" data-parentedit="${esc(p.id)}">Bearbeiten</button>`}</td></tr>`).join("");
  return waCard + `<section class="card parentsbox"><div class="cardtop"><h3>Eltern-Verteiler${ro ? " meiner Mannschaft" + (myTeams().length > 1 ? "en" : "") : ""} <span class="muted small">${parents.length} ${parents.length === 1 ? "Adresse" : "Adressen"}${ro ? "" : ` · ${ok} mit Einwilligung`}</span></h3>
      <div class="actions" style="margin:0">${ro ? "" : `<button class="quiet" data-act="addParent">＋ Eltern</button>
      <button class="quiet" data-act="importPeople" data-kind="eltern">CSV/Excel-Datei hochladen</button>`}
      ${ok ? '<button class="quiet" data-act="mailAll">✉ E-Mail an Eltern</button>' : ""}</div></div>
    <p class="muted small" style="margin-top:6px">E-Mails gehen nur an Eltern mit Einwilligung, immer im BCC. Sichtbar nur für Admins, Jugendleitung und Trainer der jeweiligen Mannschaft.</p>
    ${parents.length ? `<details${parents.length <= 8 ? " open" : ""}><summary>Liste anzeigen</summary><div class="tablewrap" style="margin-top:8px"><table class="table">
      <thead><tr><th>Name</th><th>Kind</th><th>Mannschaft</th><th>E-Mail</th><th>Einwilligung</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></details>`
      : `<p class="muted small" style="margin-top:8px">${ro ? "Für deine Mannschaft sind noch keine Eltern-Adressen (mit Einwilligung) hinterlegt." : "Noch keine Eltern eingetragen. Am besten nur WhatsApp-Gruppenlinks nutzen – Adressen nur mit Einwilligung."}</p>`}
  </section>`;
}

function renderDocs() {
  $("view").innerHTML = `<div class="sectionhead"><h2>Dokumente</h2></div>
    <p class="muted" style="margin-bottom:18px;max-width:78ch">Sichtbar für: ${esc([...(me.sichtbar?.Dokumente || []), "Admins"].join(", "))}. Dateien werden in der Vereinsdatenbank gespeichert (max. 10 MB pro Datei).</p>
    ${docs.map(d => `<article class="card"><div class="cardtop"><h3>${esc(d.titel)}</h3>${badge(d.status)}</div>
      <div class="meta">${esc([dateText(d.datum), d.groesse ? d.dateiname + " · " + fmtBytes(d.groesse) : "Noch keine Datei hinterlegt"].filter(Boolean).join(" · "))}</div>
      ${d.beschreibung ? `<p class="body">${esc(d.beschreibung)}</p>` : ""}
      <div class="actions">
        ${d.groesse ? `<button data-docopen="${esc(d.id)}">Öffnen</button><button class="quiet" data-docdl="${esc(d.id)}">Herunterladen</button>` : ""}
        ${canW("Dokumente") ? `<button class="quiet" data-docedit="${esc(d.id)}">${d.groesse ? "Bearbeiten" : "Datei hochladen"}</button>` : ""}
      </div></article>`).join("") || '<p class="muted">Noch keine Dokumente.</p>'}`;
}

async function renderLog() {
  $("view").innerHTML = '<div class="sectionhead"><h2>Änderungsprotokoll</h2></div><p class="muted">Lädt …</p>';
  try {
    const { protokoll } = await api("/api/protokoll");
    $("view").innerHTML = `<div class="sectionhead"><h2>Änderungsprotokoll</h2><span class="muted small">${protokoll.length} Einträge (neueste zuerst)</span></div>` +
      (protokoll.map(l => `<article class="card"><h3>${esc(l.aktion)} · ${esc(l.titel)}</h3><div class="meta">${esc(fmtTime(l.zeit))} · ${esc(l.benutzer)}</div>${l.details ? `<p class="body">${esc(l.details)}</p>` : ""}</article>`).join("") || '<p class="muted">Noch keine Änderungen.</p>');
  } catch (e) { $("view").innerHTML = `<p class="muted">${esc(e.message)}</p>`; }
}

/* ---------------- Benutzer (Admin): Konten · Funktionen · Rechte ---------------- */
let uTab = "konten", matrix = null;
const funcBadges = ids => (ids || []).map(id => funktionen.find(f => f.id === id)).filter(Boolean)
  .map(f => `<span class="rolebadge fn${f.schluessel === "schatzmeister" ? " sch" : f.gruppe === "Fest" ? " fest" : f.gruppe === "Sport" ? " tr" : ""}${f.aktiv ? "" : " off"}">${esc(f.name)}</span>`).join(" ");
function renderUsers() {
  const tabs = [["konten", `Konten (${users.length})`], ["funktionen", `Funktionen (${funktionen.length})`], ["rechte", "Rechte"]];
  $("view").innerHTML = `<div class="sectionhead"><h2>Benutzer</h2><div class="tabs">${tabs.map(([k, l]) => `<button class="quiet${uTab === k ? " on" : ""}" data-utab="${k}">${l}</button>`).join("")}</div></div><div id="utab"></div>`;
  $("add").hidden = uTab !== "konten";
  if (uTab === "konten") renderUserList(); else if (uTab === "funktionen") renderFuncList(); else renderMatrix();
}
function renderUserList() {
  const roleBadge = u => `<span class="rolebadge${u.rolle === "ausschuss" ? " aus" : u.rolle === "trainer" ? " tr" : u.rolle === "helfer" ? " hlf" : ""}">${ROLE[u.rolle]}</span>${u.ist_admin ? ' <span class="rolebadge adm">Admin</span>' : ""}`;
  $("utab").innerHTML = `<p class="muted" style="margin-bottom:14px;max-width:85ch">Jedes Konto hat eine <b>Grundrolle</b> (Vorstand, Ausschuss, Trainer, Helfer) und beliebig viele <b>Funktionen</b>.
      Was jemand sieht und darf, steht unter <b>Rechte</b>. Rechnungen und Kasse gibt es nur für Admins und Schatzmeister/in.</p>
    <div class="tablewrap"><table class="table"><thead><tr><th>Name</th><th>Grundrolle</th><th>Funktionen</th><th>Letzter Login</th><th>Status</th><th></th></tr></thead><tbody>
    ${users.map(u => `<tr><td><b>${esc(u.anzeigename)}</b><div class="lock">${esc(u.benutzername)}</div></td><td>${roleBadge(u)}</td>
      <td>${funcBadges(u.funktionen) || '<span class="lock">–</span>'}${(u.mannschaften || []).length ? `<div class="lock">Mannschaften: ${esc(u.mannschaften.map(teamName).filter(Boolean).join(", "))}</div>` : ""}</td>
      <td class="lock">${esc(u.letzter_login ? fmtTime(u.letzter_login) : "noch nie")}</td>
      <td>${u.aktiv ? (u.pw_aendern ? '<span class="lock">wartet auf 1. Login</span>' : "aktiv") : '<span class="lock">deaktiviert</span>'}</td>
      <td><button class="quiet" data-useredit="${esc(u.id)}">Bearbeiten</button></td></tr>`).join("")}
    </tbody></table></div>`;
}
function renderFuncList() {
  const groups = ["Vorstand", "Ausschuss", "Sport", "Fest", "Sonstige"];
  const count = id => users.filter(u => (u.funktionen || []).includes(id)).length;
  $("utab").innerHTML = `<p class="muted" style="margin-bottom:12px;max-width:85ch">Funktionen kann man umbenennen und deaktivieren (deaktiviert = gibt keine Rechte mehr, bleibt aber erhalten).
      Sonderfunktionen (🔑) haben feste Regeln, z. B. Schatzmeister/in für Rechnungen und Kasse – das gilt auch nach dem Umbenennen.</p>
    <div class="actions" style="margin-bottom:12px"><button data-act="addFunc">＋ Funktion</button></div>
    ${groups.map(g => { const list = funktionen.filter(f => f.gruppe === g); return list.length ? `<h3 class="teamhead">${g}</h3><div class="tablewrap"><table class="table"><tbody>
      ${list.map(f => `<tr><td><b>${esc(f.name)}</b>${f.schluessel ? ' <span title="Sonderfunktion mit festen Regeln">🔑</span>' : ""}</td><td class="lock">${count(f.id)} Konten</td>
        <td>${f.aktiv ? "aktiv" : '<span class="lock">deaktiviert</span>'}</td>
        <td style="white-space:nowrap"><button class="quiet" data-funcren="${esc(f.id)}">Umbenennen</button> <button class="quiet" data-functog="${esc(f.id)}">${f.aktiv ? "Deaktivieren" : "Aktivieren"}</button></td></tr>`).join("")}
      </tbody></table></div>` : ""; }).join("")}`;
}
async function renderMatrix() {
  $("utab").innerHTML = '<p class="muted">Lädt …</p>';
  try { matrix = await api("/api/rechte"); } catch (e) { $("utab").innerHTML = `<p class="muted">${esc(e.message)}</p>`; return; }
  const M = matrix, short = a => ({ "Satzung & Beschlüsse": "Satzung", "Vorstand & Ausschuss": "Vorstand", "Beiträge & Ehrenamt": "Beiträge", "Elternkommunikation": "Eltern­komm.", "Offene Entscheidungen": "Entschei­dungen", "Änderungsprotokoll": "Protokoll", "Festwirtschaft": "Fest­wirtschaft" }[a] || a);
  let lastGroup = "";
  $("utab").innerHTML = `<div class="card" style="margin-bottom:12px"><b>Feste Regeln</b> (nicht änderbar):
      <ul class="rules"><li>Rechnungen und Kasse: nur Admins und Schatzmeister/in. <label class="check" style="display:inline-flex;margin:0"><input type="checkbox" data-act="kpToggle"${M.kassenpruefer_lesen ? " checked" : ""}> Kassenprüfer/in darf lesen</label></li>
      <li>Benutzer, Funktionen und Rechte: nur Admins. Admins haben überall alle Rechte (Chat-Nachrichten aber nur als Raum-Mitglied).</li>
      <li>Trainer, Co-Trainer, Betreuer, Festwirt-Team und Helfer bekommen keine Vorstandsbereiche (graue Felder).</li>
      <li>Eltern-Kontakte: nur Admins, Jugendleitung und Trainer der jeweiligen Mannschaft.</li></ul>
      <p class="muted small">Stufen: – keine (unsichtbar) · L lesen · B bearbeiten · X löschen. Wer mehrere Funktionen hat, bekommt die höchste Stufe. Änderungen wirken sofort.</p></div>
    <div class="tablewrap matrix"><table class="table"><thead><tr><th>Rolle / Funktion</th>${M.bereiche.map(a => `<th title="${esc(a)}">${short(a)}</th>`).join("")}</tr></thead><tbody>
    ${M.subjekte.map(s => {
      const head = s.gruppe !== lastGroup ? `<tr class="mgroup"><td colspan="${M.bereiche.length + 1}">${esc(lastGroup = s.gruppe)}</td></tr>` : "";
      return head + `<tr${s.aktiv ? "" : ' class="off"'}><td><b>${esc(s.label)}</b>${s.aktiv ? "" : ' <span class="lock">(deaktiviert)</span>'}</td>${M.bereiche.map(a => {
        const v = M.werte[s.key]?.[a] || 0, locked = s.gesperrt && M.vorstand_bereiche.includes(a);
        return `<td><select class="mcell s${v}" data-msubj="${esc(s.key)}" data-marea="${esc(a)}"${locked ? ' disabled title="Feste Regel: kein Vorstandsbereich"' : ""} aria-label="${esc(s.label)} – ${esc(a)}">${["–", "L", "B", "X"].map((l, i) => `<option value="${i}"${i === v ? " selected" : ""}>${l}</option>`).join("")}</select></td>`;
      }).join("")}</tr>`;
    }).join("")}</tbody></table></div>`;
}
async function setMatrix(sel) {
  sel.disabled = true;
  try { matrix = await api("/api/rechte", { method: "PUT", data: { subjekt: sel.dataset.msubj, bereich: sel.dataset.marea, stufe: Number(sel.value) } });
    sel.className = "mcell s" + sel.value; notice("Recht gespeichert.", true); me = (await api("/api/ich")).benutzer; }
  catch (e) { notice(e.message); renderMatrix(); }
  finally { sel.disabled = false; }
}

/* ---------------- Mein Team (Festwirt/in): nur Festwirt-Team-Konten ---------------- */
function renderTeam() {
  $("view").innerHTML = `<div class="sectionhead"><h2>Mein Festwirt-Team</h2><span class="muted small">${teamUsers.length} Konten</span></div>
    <p class="muted" style="margin-bottom:12px;max-width:80ch">Du kannst Konten für dein Festwirt-Team anlegen, deaktivieren und Passwörter zurücksetzen.
      Diese Konten haben nur die Funktion <b>Festwirt-Team</b> und sehen nur die Festwirtschaft, ihre Termine und eure Chat-Räume.</p>
    <div class="tablewrap"><table class="table"><thead><tr><th>Name</th><th>Benutzername</th><th>Letzter Login</th><th>Status</th><th></th></tr></thead><tbody>
    ${teamUsers.map(u => `<tr><td><b>${esc(u.anzeigename)}</b></td><td>${esc(u.benutzername)}</td><td class="lock">${esc(u.letzter_login ? fmtTime(u.letzter_login) : "noch nie")}</td>
      <td>${u.aktiv ? (u.pw_aendern ? '<span class="lock">wartet auf 1. Login</span>' : "aktiv") : '<span class="lock">deaktiviert</span>'}</td>
      <td style="white-space:nowrap"><button class="quiet" data-teamtog="${esc(u.id)}">${u.aktiv ? "Deaktivieren" : "Aktivieren"}</button> <button class="quiet" data-teampw="${esc(u.id)}">Passwort zurücksetzen</button></td></tr>`).join("")
      || '<tr><td colspan="5" class="muted">Noch keine Team-Konten. Oben auf „＋ Team-Konto“ klicken.</td></tr>'}
    </tbody></table></div>`;
}
async function newTeamAccount() {
  const anzeige = prompt("Name des Helfers (z. B. Anna Beispiel):"); if (!anzeige?.trim()) return;
  const name = prompt("Benutzername zum Anmelden (3–40 Zeichen, a–z, 0–9, Punkt, Minus):", anzeige.trim().toLowerCase().replace(/\s+/g, ".").replace(/[^a-z0-9._-]/g, "")); if (!name?.trim()) return;
  const pw = genPassword(), user = name.trim().toLowerCase();
  try {
    teamUsers = (await api("/api/team", { method: "POST", data: { benutzername: user, anzeigename: anzeige.trim(), passwort: await clientHash(user, pw) } })).benutzer;
    alert(`Team-Konto angelegt.\n\nBenutzername: ${user}\nStartpasswort: ${pw}\n\nBitte persönlich oder per Telefon weitergeben. Beim ersten Login muss ein eigenes Passwort gesetzt werden.`);
    render(); notice("Team-Konto angelegt.", true);
  } catch (e) { notice(e.message); }
}
async function teamToggle(id) {
  const u = teamUsers.find(x => x.id === id); if (!u || !confirm(`${u.anzeigename} ${u.aktiv ? "deaktivieren" : "wieder aktivieren"}?`)) return;
  try { teamUsers = (await api("/api/team/" + id, { method: "PUT", data: { aktiv: !u.aktiv } })).benutzer; render(); notice("Gespeichert.", true); } catch (e) { notice(e.message); }
}
async function teamPassword(id) {
  const u = teamUsers.find(x => x.id === id); if (!u || !confirm(`Passwort von ${u.anzeigename} zurücksetzen?`)) return;
  const pw = genPassword();
  try { await api(`/api/team/${id}/passwort`, { method: "POST", data: { passwort: await clientHash(u.benutzername, pw) } });
    alert(`Neues Startpasswort für ${u.benutzername}:\n\n${pw}\n\nBeim nächsten Login muss ein eigenes Passwort gesetzt werden.`); } catch (e) { notice(e.message); }
}

function renderAccount() {
  const areas = Object.entries(me.rechte || {}).filter(([, v]) => v > 0).map(([a, v]) => `${a} (${["", "lesen", "bearbeiten", "löschen"][v]})`);
  $("view").innerHTML = `<div class="sectionhead"><h2>Mein Konto</h2></div>
    <div class="optgrid">
      <section class="card"><h2>${esc(me.anzeigename)}</h2>
        <dl class="kv"><dt>Benutzername</dt><dd>${esc(me.benutzername)}</dd><dt>Rolle</dt><dd>${esc(rightsLabel(me))}</dd>
        ${myTeams().length ? `<dt>Mannschaften</dt><dd>${esc(myTeams().map(t => t.name).join(", "))}</dd>` : ""}
        <dt>Bereiche</dt><dd>${esc(areas.join(", ") || "keine eigenen Bereiche")}${D().geld_lesen ? esc(", Rechnungen und Kasse" + (D().geld_schreiben ? "" : " (lesen)")) : ""}</dd>
        <dt>Angemeldet</dt><dd>${store() === localStorage ? "dauerhaft auf diesem Gerät" : `bis zum Schließen des Browsers (Abmeldung nach ${IDLE_MINUTES} Min. Inaktivität)`}</dd></dl>
        <div class="actions"><button class="quiet" data-act="changepw">Passwort ändern</button><button class="quiet" data-act="logout">Abmelden</button></div></section>
      <section class="card"><h2>Export</h2>
        <p>Termine für den Handy-Kalender${readable().length ? " und Einträge als Excel-Tabelle" : ""}${D().export ? ", dazu eine komplette Sicherung als JSON" : ""}.</p>
        <div class="actions"><button class="quiet" data-act="ics">Termine (.ics)</button>${readable().length ? '<button class="quiet" data-act="csv">Einträge (CSV)</button>' : ""}
        ${D().export ? '<button class="quiet" data-act="exportJson">Sicherung (JSON)</button><button class="quiet" data-act="importJson">JSON importieren</button>' : ""}</div></section>
    </div>`;
}

/* ---------------- Export ---------------- */
function download(blob, name) {
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}
function exportCsv() {
  const cols = ["titel","bereich","status","datum","uhrzeit","ort","zustaendig","inhalt","quelle"];
  const cell = v => `"${String(v ?? "").replace(/"/g,'""')}"`;
  download(new Blob(["\uFEFF" + [cols.join(";"), ...entries.map(r => cols.map(c => cell(r[c])).join(";"))].join("\r\n")], {type:"text/csv;charset=utf-8"}), `vereinszentrale_${today()}.csv`);
}
function exportIcs() {
  const e = s => String(s ?? "").replace(/\\/g,"\\\\").replace(/;/g,"\\;").replace(/,/g,"\\,").replace(/\r?\n/g,"\\n");
  const L = ["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//FC Sender Kickers United//Vereinszentrale//DE","CALSCALE:GREGORIAN","X-WR-CALNAME:FC Sender Kickers United"];
  for (const r of entries.filter(r => r.datum)) {
    const d = r.datum.replace(/-/g,"");
    L.push("BEGIN:VEVENT", `UID:${r.id}@sender-kickers`, `DTSTAMP:${new Date().toISOString().replace(/[-:]/g,"").slice(0,15)}Z`);
    if (r.uhrzeit) { const [h,m] = r.uhrzeit.split(":").map(Number); L.push(`DTSTART;TZID=Europe/Berlin:${d}T${r.uhrzeit.replace(":","")}00`, `DTEND;TZID=Europe/Berlin:${d}T${String((h+1)%24).padStart(2,"0")}${String(m).padStart(2,"0")}00`); }
    else { const n = new Date(r.datum+"T12:00:00Z"); n.setUTCDate(n.getUTCDate()+1); L.push(`DTSTART;VALUE=DATE:${d}`, `DTEND;VALUE=DATE:${n.toISOString().slice(0,10).replace(/-/g,"")}`); }
    L.push(`SUMMARY:${e(r.titel)}`, `DESCRIPTION:${e([r.status, r.zustaendig, r.inhalt].filter(Boolean).join("\n"))}`);
    if (r.ort) L.push(`LOCATION:${e(r.ort)}`);
    L.push("END:VEVENT");
  }
  L.push("END:VCALENDAR");
  download(new Blob([L.join("\r\n")], {type:"text/calendar"}), "sender-kickers-termine.ics");
}
async function exportJson() {
  try { const data = await api("/api/export"); download(new Blob([JSON.stringify(data, null, 2)], {type:"application/json"}), `vereinszentrale_sicherung_${today()}.json`); }
  catch (e) { notice(e.message); }
}
async function importJsonFile(file) {
  let data; try { data = JSON.parse(await file.text()); } catch { return notice("JSON-Datei konnte nicht gelesen werden."); }
  const list = data.eintraege || data.records || (Array.isArray(data) ? data : null);
  if (!Array.isArray(list)) return notice("Keine Einträge in der Datei gefunden.");
  const arr = k => Array.isArray(data[k]) ? data[k] : [];
  const extra = [["mitglieder", "Mitglieder"], ["eltern", "Eltern-Adressen"], ["mannschaften", "Mannschaften"]].filter(([k]) => arr(k).length);
  const restore = isSchatz() ? [["rechnungen", "Rechnungen", invoices.length], ["kassenbuchungen", "Kassenbuchungen", kasse.buchungen.length]].filter(([k]) => arr(k).length) : [];
  if (!confirm(`${list.length} Einträge als neue Einträge importieren?${extra.map(([k, l]) => `\nDazu ${arr(k).length} ${l} (Doppelte werden übersprungen).`).join("")}`
    + restore.map(([k, l, have]) => `\n${arr(k).length} ${l}: ${have ? "werden übersprungen (feste Nummern, die Liste ist nicht leer)" : "werden wiederhergestellt (mit ihren Nummern)"}.`).join("")
    + (arr("downloads").length || arr("anhaenge").length ? "\nDateien (Downloads, Anhänge, Belege) sind nicht in der Sicherung und werden nicht übernommen." : "")
    + (arr("benutzer").length ? "\nKonten werden nicht angelegt (Passwörter sind nicht in der Sicherung)." : ""))) return;
  const msgs = [];
  // 1. Mannschaften zuerst, damit Einträge/Mitglieder/Eltern zugeordnet werden können (alte ID → neue ID über den Namen)
  const oldTeams = {};
  for (const t of arr("mannschaften")) oldTeams[t.id] = t.name;
  if (arr("mannschaften").length && D().mannschaften_pflegen)
    try { const r = await api("/api/mannschaften/import", { method: "POST", data: { liste: arr("mannschaften").map(t => ({ name: t.name, sortierung: t.sortierung, aktiv: !!t.aktiv })) } }); teams = r.mannschaften; msgs.push(`${r.neu} Mannschaften`); } catch (e) { msgs.push(e.message); }
  const mapTeam = id => findTeam(oldTeams[id])?.id || "";
  for (const k of ["mitglieder", "eltern"]) {
    const keys = k === "mitglieder" ? MEMBER_KEYS : PARENT_KEYS;
    for (let i = 0; i < arr(k).length; i += MAX_IMPORT)
      try { await api(`/api/${k}/import`, { method: "POST", data: { liste: arr(k).slice(i, i + MAX_IMPORT).map(x => ({ ...Object.fromEntries(keys.map(f => [f, x[f] ?? ""])), mannschaft_id: mapTeam(x.mannschaft_id) })), datei: file.name } }); } catch (e) { msgs.push(e.message); }
  }
  for (const [k, , have] of restore) {
    if (have) continue;
    try { const r = await api(k === "rechnungen" ? "/api/rechnungen/wiederherstellen" : "/api/kasse/wiederherstellen", { method: "POST", data: { liste: arr(k), datei: file.name } }); msgs.push(`${r.anzahl} ${k === "rechnungen" ? "Rechnungen" : "Kassenbuchungen"}`); }
    catch (e) { msgs.push(e.message); }
  }
  if (isSchatz() && data.kasse_einstellungen && !kasse.buchungen.length)
    try { await api("/api/kasse/einstellungen", { method: "PUT", data: data.kasse_einstellungen }); } catch (e) { msgs.push(e.message); }
  let n = 0;
  for (const r of list) {
    const v = { titel: r.titel ?? r.title, bereich: GROUPS.includes(r.bereich ?? r.group) ? (r.bereich ?? r.group) : "Offene Entscheidungen",
      status: STATUSES.includes(r.status) ? r.status : "Offen", datum: r.datum ?? r.date ?? "", uhrzeit: r.uhrzeit ?? "", ort: r.ort ?? "",
      zustaendig: r.zustaendig ?? r.owner ?? "", inhalt: r.inhalt ?? r.body ?? "", quelle: r.quelle ?? r.source ?? "Import",
      rueckmeldung: !!r.rueckmeldung, fuer_trainer: !!r.fuer_trainer, mannschaft_id: mapTeam(r.mannschaft_id) };
    if (!v.titel) continue;
    try { await api("/api/eintraege", { method: "POST", data: v }); n++; } catch {}
  }
  notice(`${n} Einträge importiert${msgs.length ? " · " + msgs.join(" · ") : ""}.`, true); reload();
}

/* ---------------- Tabellen lesen (CSV + Excel .xlsx, ohne fremde Bibliothek) ---------------- */
const SHEET_RE = /\.(csv|tsv|xlsx|xlsm|xls)$/i;
async function readTable(file) {
  const buf = await file.arrayBuffer();
  if (/\.xls$/i.test(file.name)) throw new Error("Alte .xls-Dateien kann die Seite nicht lesen. Bitte in Excel „Speichern unter“ → .xlsx oder .csv wählen.");
  if (/\.(xlsx|xlsm)$/i.test(file.name)) return readXlsx(buf);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(buf); } catch { text = new TextDecoder("windows-1252").decode(buf); }
  return parseCsv(text);
}
function parseCsv(text) {
  text = text.replace(/^﻿/, "");
  const first = text.split(/\r?\n/, 1)[0] || "";
  const delim = [";", ",", "\t"].map(d => [d, first.split(d).length]).sort((a, b) => b[1] - a[1])[0][0];
  const rows = []; let row = [], cell = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; }
    else if (c === '"' && cell === "") q = true;
    else if (c === delim) { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(cell); rows.push(row); row = []; cell = ""; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}
async function unzip(buf) {
  const dv = new DataView(buf), u8 = new Uint8Array(buf), dec = new TextDecoder();
  let eocd = -1;
  for (let i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error("Die Datei ist keine gültige Excel-Datei (.xlsx).");
  const files = {}; let p = dv.getUint32(eocd + 16, true);
  for (let n = dv.getUint16(eocd + 10, true); n > 0 && dv.getUint32(p, true) === 0x02014b50; n--) {
    const nlen = dv.getUint16(p + 28, true), elen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
    files[dec.decode(u8.subarray(p + 46, p + 46 + nlen))] = { method: dv.getUint16(p + 10, true), size: dv.getUint32(p + 20, true), off: dv.getUint32(p + 42, true) };
    p += 46 + nlen + elen + clen;
  }
  return async name => {
    const f = files[name]; if (!f) return null;
    const start = f.off + 30 + dv.getUint16(f.off + 26, true) + dv.getUint16(f.off + 28, true);
    const data = u8.subarray(start, start + f.size);
    if (f.method === 0) return dec.decode(data);
    if (f.method !== 8 || typeof DecompressionStream === "undefined") throw new Error("Dieser Browser kann die Excel-Datei nicht lesen. Bitte als CSV speichern oder einen aktuellen Browser verwenden.");
    return new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).text();
  };
}
async function readXlsx(buf) {
  const get = await unzip(buf);
  const xml = s => new DOMParser().parseFromString(s, "application/xml");
  const all = (el, tag) => [...el.getElementsByTagNameNS("*", tag)];
  const text = el => all(el, "t").map(t => t.textContent).join("");
  let sheetPath = "xl/worksheets/sheet1.xml";
  const wb = await get("xl/workbook.xml"), rels = await get("xl/_rels/workbook.xml.rels");
  if (wb && rels) {
    const first = all(xml(wb), "sheet")[0];
    const rid = first && (first.getAttributeNS("http://schemas.openxmlformats.org/officeDocument/2006/relationships", "id") || first.getAttribute("r:id"));
    const rel = all(xml(rels), "Relationship").find(r => r.getAttribute("Id") === rid);
    if (rel) { const t = rel.getAttribute("Target"); sheetPath = t.startsWith("/") ? t.slice(1) : "xl/" + t.replace(/^\.\//, ""); }
  }
  const ss = await get("xl/sharedStrings.xml");
  const shared = ss ? all(xml(ss), "si").map(text) : [];
  const sheet = await get(sheetPath);
  if (!sheet) throw new Error("In der Excel-Datei wurde keine Tabelle gefunden.");
  const colIndex = ref => { let n = 0; for (const ch of ref.replace(/\d+$/, "").toUpperCase()) n = n * 26 + ch.charCodeAt(0) - 64; return n - 1; };
  const rows = [];
  for (const row of all(xml(sheet), "row")) {
    const r = row.getAttribute("r"), ri = r ? Number(r) - 1 : rows.length, cells = [];
    let ci = 0;
    for (const c of all(row, "c")) {
      const ref = c.getAttribute("r"); if (ref) ci = colIndex(ref);
      const t = c.getAttribute("t"), v = all(c, "v")[0]?.textContent ?? "";
      cells[ci++] = t === "s" ? (shared[Number(v)] ?? "") : t === "inlineStr" ? text(c) : t === "b" ? (v === "1" ? "WAHR" : "FALSCH") : v;
    }
    rows[ri] = Array.from(cells, x => x ?? "");
  }
  return Array.from(rows, r => r || []);
}
// Erste nicht-leere Zeile = Überschriften, danach die Datenzeilen
function toRecords(table) {
  const filled = r => r.some(c => String(c ?? "").trim());
  const h = table.findIndex(filled);
  if (h < 0) throw new Error("Die Datei ist leer.");
  return { headers: table[h].map(c => String(c ?? "").trim()), rows: table.slice(h + 1).filter(filled) };
}
const norm = s => String(s ?? "").toLowerCase().replace(/ä/g,"ae").replace(/ö/g,"oe").replace(/ü/g,"ue").replace(/ß/g,"ss").replace(/[^a-z0-9]/g,"");
// Spalten anhand der Überschrift zuordnen: erst exakte Treffer, dann „beginnt mit“
function mapColumns(headers, aliases) {
  const keys = headers.map(norm), used = new Set(), map = {};
  for (const exact of [true, false]) for (const [field, names] of Object.entries(aliases)) {
    if (map[field] !== undefined) continue;
    const i = keys.findIndex((k, j) => k && !used.has(j) && names.some(a => exact ? k === a : a.length >= 4 && k.startsWith(a)));
    if (i >= 0) { map[field] = i; used.add(i); }
  }
  return { map, extra: headers.map((h, i) => i).filter(i => !used.has(i) && headers[i]) };
}
const cellOf = (row, i) => i === undefined ? "" : String(row[i] ?? "").trim();
const extraText = (row, headers, extra) => extra.map(i => cellOf(row, i) && `${headers[i]}: ${cellOf(row, i)}`).filter(Boolean).join("\n");
function isoDate(y, m, d) {
  const dt = new Date(Date.UTC(+y, +m - 1, +d));
  return dt.getUTCFullYear() === +y && dt.getUTCMonth() === +m - 1 && dt.getUTCDate() === +d ? dt.toISOString().slice(0, 10) : null;
}
// "" = leer, null = nicht erkennbar
function parseDate(v) {
  v = String(v ?? "").trim(); if (!v) return "";
  if (/^\d+(\.\d+)?$/.test(v) && +v > 1000 && +v < 80000) return new Date(Date.UTC(1899, 11, 30) + Math.floor(+v) * 864e5).toISOString().slice(0, 10);
  let m = v.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/); if (m) return isoDate(m[1], m[2], m[3]);
  m = v.match(/^(\d{1,2})[./-](\d{1,2})[./-](\d{2}|\d{4})$/);
  if (m) { let y = +m[3]; if (y < 100) y += y > (new Date().getFullYear() % 100) + 1 ? 1900 : 2000; return isoDate(y, m[2], m[1]); }
  return null;
}
function parseTime(v) {
  v = String(v ?? "").trim(); if (!v) return "";
  if (/^0?\.\d+$/.test(v) || v === "0") { const mins = Math.round(+v * 1440) % 1440; return `${String(Math.floor(mins / 60)).padStart(2, "0")}:${String(mins % 60).padStart(2, "0")}`; }
  const m = v.match(/^(\d{1,2})(?:[:.](\d{2}))?(?::\d{2})?\s*(?:uhr)?$/i);
  return m && +m[1] < 24 && +(m[2] || 0) < 60 ? `${m[1].padStart(2, "0")}:${m[2] || "00"}` : null;
}

const ENTRY_ALIASES = {
  titel: ["titel","title","bezeichnung","name","mannschaft","team","sponsor","firma","unternehmen","aufgabe","betreff","thema","schritt","veranstaltung","termin"],
  status: ["status","stand"],
  datum: ["datum","date","tag","frist","faellig","faelligam","deadline","spieltag"],
  uhrzeit: ["uhrzeit","zeit","time","beginn","anstoss","start"],
  ort: ["ort","platz","sportplatz","spielort","adresse","location"],
  zustaendig: ["zustaendig","verantwortlich","trainer","ansprechpartner","kontakt","betreuer","owner"],
  inhalt: ["inhalt","beschreibung","notiz","notizen","bemerkung","bemerkungen","text","details","info"],
  quelle: ["quelle","source"],
};
function sheetToEntries(t, bereich) {
  const { map, extra } = mapColumns(t.headers, ENTRY_ALIASES);
  if (map.titel === undefined) { map.titel = extra.shift() ?? 0; }
  const defStatus = bereich === "Kalender" ? "Geplant" : "Offen";
  return t.rows.map(r => {
    const notes = [], d = parseDate(cellOf(r, map.datum)), z = parseTime(cellOf(r, map.uhrzeit));
    if (d === null) notes.push(`Datum: ${cellOf(r, map.datum)}`);
    if (z === null) notes.push(`Uhrzeit: ${cellOf(r, map.uhrzeit)}`);
    const st = STATUSES.find(s => s.toLowerCase() === cellOf(r, map.status).toLowerCase());
    if (!st && cellOf(r, map.status)) notes.push(`Status: ${cellOf(r, map.status)}`);
    return { titel: cellOf(r, map.titel).slice(0, 160), bereich, status: st || defStatus, datum: d || "", uhrzeit: z || "",
      ort: cellOf(r, map.ort).slice(0, 120), zustaendig: cellOf(r, map.zustaendig).slice(0, 120),
      inhalt: [cellOf(r, map.inhalt), extraText(r, t.headers, extra), ...notes].filter(Boolean).join("\n"), quelle: cellOf(r, map.quelle).slice(0, 200) };
  }).filter(v => v.titel);
}
const columnInfo = (headers, map, labels) => Object.entries(map).map(([f, i]) => `${labels[f] || f} ← „${esc(headers[i])}“`).join(", ");

const MEMBER_ALIASES = {
  vorname: ["vorname","firstname","rufname"],
  nachname: ["nachname","familienname","lastname","surname","zuname"],
  voll: ["name","vollername","spieler","spielerin","mitglied","kind","kindname","spielername"],
  geburtsdatum: ["geburtsdatum","geboren","gebdatum","geburtstag","geb","gebam","birthday","geburt"],
  mannschaft: ["mannschaft","team","jahrgang","altersklasse","gruppe","klasse"],
  email: ["email","mail","emailadresse","emaileltern","elternemail"],
  telefon: ["telefon","tel","handy","mobil","mobilnummer","telefonnummer","phone","handynummer"],
  eintritt: ["eintritt","eintrittsdatum","mitgliedseit","beitritt","aufnahme","eintrittam"],
  status: ["status"],
  notiz: ["notiz","notizen","bemerkung","bemerkungen","info","hinweis","kommentar"],
};
const MEMBER_LABELS = { vorname: "Vorname", nachname: "Nachname", voll: "Name", geburtsdatum: "Geburtsdatum", mannschaft: "Mannschaft", email: "E-Mail", telefon: "Telefon", eintritt: "Mitglied seit", status: "Status", notiz: "Notiz" };
function sheetToMembers(t) {
  const { map, extra } = mapColumns(t.headers, MEMBER_ALIASES), skipped = [];
  const list = t.rows.map((r, n) => {
    let vorname = cellOf(r, map.vorname), nachname = cellOf(r, map.nachname);
    const voll = cellOf(r, map.voll);
    if (voll && !vorname && !nachname) {
      if (voll.includes(",")) [nachname, vorname] = voll.split(",").map(s => s.trim());
      else { const parts = voll.split(/\s+/); nachname = parts.pop(); vorname = parts.join(" "); }
    } else if (voll && !nachname) nachname = voll; else if (voll && !vorname) vorname = voll;
    const notes = [cellOf(r, map.notiz), extraText(r, t.headers, extra)];
    const geb = parseDate(cellOf(r, map.geburtsdatum)), ein = parseDate(cellOf(r, map.eintritt));
    if (geb === null) notes.push(`Geburtsdatum: ${cellOf(r, map.geburtsdatum)}`);
    if (ein === null) notes.push(`Mitglied seit: ${cellOf(r, map.eintritt)}`);
    const mails = cellOf(r, map.email).split(/[;,\s]+/).filter(Boolean);
    const email = mails.find(m => EMAIL_RE.test(m)) || "";
    if (mails.some(m => m !== email)) notes.push(`E-Mail: ${mails.filter(m => m !== email).join(", ")}`);
    const st = MEMBER_STATUSES.find(s => s.toLowerCase() === cellOf(r, map.status).toLowerCase());
    if (!st && cellOf(r, map.status)) notes.push(`Status: ${cellOf(r, map.status)}`);
    if (!vorname && !nachname) { skipped.push(`Zeile ${n + 2}: kein Name`); return null; }
    return { vorname: vorname.slice(0, 80), nachname: nachname.slice(0, 80), geburtsdatum: geb || "", mannschaft: cellOf(r, map.mannschaft).slice(0, 80),
      email: email.slice(0, 160), telefon: cellOf(r, map.telefon).slice(0, 60), eintritt: ein || "", status: st || "Aktiv",
      notiz: notes.filter(Boolean).join("\n").slice(0, 2000) };
  }).filter(Boolean);
  return withTeams({ list, skipped, info: columnInfo(t.headers, map, MEMBER_LABELS), extra: extra.map(i => t.headers[i]),
    cols: [["Name", m => memberName(m)], ["Geburtsdatum", m => dateText(m.geburtsdatum)], ["Mannschaft", teamPreview], ["E-Mail", m => m.email], ["Telefon", m => m.telefon]] });
}
// Mannschaft über den Namen zuordnen (ohne Groß/klein, Leerzeichen, Bindestriche); Unbekanntes markieren
const teamPreview = x => x.mannschaft_id ? teamName(x.mannschaft_id) : x.mannschaft ? `${x.mannschaft} ⚠ unbekannt` : "";
function withTeams(res) {
  for (const x of res.list) { const t = findTeam(x.mannschaft); x.mannschaft_id = t?.id || ""; if (t) x.mannschaft = t.name; }
  res.unknownTeams = distinct(res.list.filter(x => x.mannschaft && !x.mannschaft_id).map(x => x.mannschaft));
  return res;
}

const PARENT_ALIASES = {
  email: ["email","mail","emailadresse","emaileltern","elternemail","emailadresseeltern","kontaktemail"],
  kind: ["kind","kinder","spieler","spielerin","sohn","tochter","kindname","namekind","namedeskindes","mitglied","spielername"],
  name: ["name","eltern","elternteil","erziehungsberechtigter","erziehungsberechtigte","vater","mutter","ansprechpartner","kontakt","elternname","nameeltern"],
  mannschaft: ["mannschaft","team","jahrgang","altersklasse","gruppe","klasse"],
  notiz: ["notiz","notizen","bemerkung","bemerkungen","info","hinweis","telefon","tel","handy"],
};
const PARENT_LABELS = { email: "E-Mail", kind: "Kind", name: "Name", mannschaft: "Mannschaft", notiz: "Notiz" };
function sheetToParents(t) {
  const { map, extra } = mapColumns(t.headers, PARENT_ALIASES), skipped = [], list = [];
  if (map.email === undefined) {
    // keine E-Mail-Spalte erkannt: Spalte suchen, in der E-Mail-Adressen stehen
    const i = t.headers.findIndex((h, j) => t.rows.some(r => EMAIL_RE.test(cellOf(r, j))));
    if (i >= 0) { map.email = i; extra.splice(extra.indexOf(i), 1); }
  }
  t.rows.forEach((r, n) => {
    const mails = cellOf(r, map.email).split(/[;,\s]+/).filter(Boolean);
    const ok = mails.filter(m => EMAIL_RE.test(m));
    if (!ok.length) { skipped.push(`Zeile ${n + 2}: keine gültige E-Mail${mails.length ? ` („${mails.join(", ")}“)` : ""}`); return; }
    const notiz = [cellOf(r, map.notiz), extraText(r, t.headers, extra)].filter(Boolean).join("\n").slice(0, 1000);
    for (const email of ok) list.push({ name: cellOf(r, map.name).slice(0, 120), email: email.toLowerCase().slice(0, 160), kind: cellOf(r, map.kind).slice(0, 120), mannschaft: cellOf(r, map.mannschaft).slice(0, 80), notiz });
  });
  return withTeams({ list, skipped, info: columnInfo(t.headers, map, PARENT_LABELS), extra: extra.map(i => t.headers[i]),
    cols: [["Name", p => p.name], ["E-Mail", p => p.email], ["Kind", p => p.kind], ["Mannschaft", teamPreview]] });
}

/* ---------------- Mitglieder/Eltern importieren ---------------- */
let peopleKind = "mitglieder";
function pickPeopleFile(kind) { peopleKind = kind; $("peopleFile").click(); }
$("peopleFile").onchange = async e => {
  const file = e.target.files[0]; e.target.value = ""; if (!file) return;
  try {
    if (file.size > MAX_FILE) throw new Error("Datei zu groß (max. 10 MB).");
    const res = (peopleKind === "mitglieder" ? sheetToMembers : sheetToParents)(toRecords(await readTable(file)));
    pendingPeople = { kind: peopleKind, list: res.list, datei: file.name };
    const label = peopleKind === "mitglieder" ? "Mitglieder" : "Eltern-Adressen";
    $("importTitle").textContent = `${label} importieren`;
    $("importError").textContent = "";
    $("importGo").hidden = !res.list.length;
    $("importGo").textContent = `${res.list.length} ${label} übernehmen`;
    $("importInfo").innerHTML = `<p>Datei „${esc(file.name)}“: <b>${res.list.length} ${label}</b> erkannt.</p>
      <ul><li>Erkannte Spalten: ${res.info || "keine"}</li>
      ${res.extra.length ? `<li>Weitere Spalten kommen in die Notiz: ${res.extra.map(h => `„${esc(h)}“`).join(", ")}</li>` : ""}
      ${res.skipped.length ? `<li>Übersprungen: ${res.skipped.length} Zeilen (${esc(res.skipped.slice(0, 4).join("; "))}${res.skipped.length > 4 ? " …" : ""})</li>` : ""}
      ${res.unknownTeams.length ? `<li class="unassigned">⚠ Unbekannte Mannschaft${res.unknownTeams.length > 1 ? "en" : ""}: ${res.unknownTeams.map(x => `„${esc(x)}“`).join(", ")} – werden übernommen, aber als „nicht zugeordnet“ markiert. ${D().mannschaften_pflegen ? "Du kannst sie danach in der Mannschaftsliste zuordnen." : "Sie können später in der Mannschaftsliste zugeordnet werden."}</li>` : ""}
      <li>Wer schon in der Liste steht, wird nicht doppelt angelegt.</li></ul>
      ${res.list.length ? `<div class="tablewrap"><table class="table"><thead><tr>${res.cols.map(c => `<th>${c[0]}</th>`).join("")}</tr></thead><tbody>
        ${res.list.slice(0, 8).map(x => `<tr>${res.cols.map(c => `<td>${esc(c[1](x))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
        ${res.list.length > 8 ? `<p class="muted small" style="margin-top:6px">… und ${res.list.length - 8} weitere</p>` : ""}` : ""}`;
    $("memberEditor").close(); $("parentEditor").close();
    $("importDialog").showModal();
  } catch (err) { notice(err.message); }
};
$("importForm").onsubmit = async e => {
  e.preventDefault(); if (!pendingPeople) return;
  const { kind, list, datei } = pendingPeople;
  $("importGo").disabled = true; $("importError").textContent = "";
  try {
    let neu = 0, doppelt = 0, r;
    for (let i = 0; i < list.length; i += MAX_IMPORT) {
      r = await api(`/api/${kind}/import`, { method: "POST", data: { liste: list.slice(i, i + MAX_IMPORT), datei } });
      neu += r.neu; doppelt += r.doppelt;
    }
    if (kind === "mitglieder") members = r.liste; else parents = r.liste;
    $("importDialog").close(); pendingPeople = null; render();
    notice(`${neu} neu übernommen${doppelt ? `, ${doppelt} waren schon vorhanden` : ""}.`, true);
  } catch (err) { $("importError").textContent = err.message; }
  finally { $("importGo").disabled = false; }
};

/* ---------------- Einträge ---------------- */
const form = $("form"), editor = $("editor"), field = n => form.elements.namedItem(n);
const FIELDS = ["titel","bereich","status","datum","uhrzeit","ort","zustaendig","inhalt","quelle"];
function edit(rec, preset = {}) {
  if (!rec && !writable().length) return;   // keine Schreibrechte → nichts anlegen
  const ro = !!rec && !canW(rec.bereich);     // nur lesen: ansehen
  activeId = rec?.id || null;
  $("formTitle").textContent = ro ? "Eintrag" : activeId ? "Eintrag bearbeiten" : "Eintrag anlegen";
  $("remove").hidden = ro || !activeId || !canD(rec.bereich); $("duplicate").hidden = ro || !activeId; $("save").hidden = ro;
  $("error").textContent = "";
  const cur = sections[section], allowed = ro ? [rec.bereich] : writable();
  field("bereich").innerHTML = options(allowed, rec?.bereich || preset.bereich || (allowed.includes(cur) ? cur : allowed[0]));
  field("status").innerHTML = options(STATUSES, rec?.status || preset.status || (cur === "Kalender" ? "Geplant" : "Offen"));
  for (const k of ["titel","datum","uhrzeit","ort","zustaendig","inhalt","quelle"]) field(k).value = rec?.[k] ?? preset[k] ?? "";
  field("rueckmeldung").checked = rec ? !!rec.rueckmeldung : preset.rueckmeldung !== undefined ? !!preset.rueckmeldung : field("bereich").value === "Kalender";
  field("fuer_trainer").checked = !!(rec ? rec.fuer_trainer : preset.fuer_trainer);
  const tid = (rec ? rec.mannschaft_id : preset.mannschaft_id) || "";
  field("mannschaft_id").innerHTML = `<option value="">Alle Trainer</option>` + teams.filter(t => t.aktiv || t.id === tid).map(t => `<option value="${esc(t.id)}"${t.id === tid ? " selected" : ""}>Nur Trainer von ${esc(t.name)}</option>`).join("");
  for (const el of form.elements) if (el.name && el.type !== "button") el.disabled = ro;
  updateVisHint();
  $("formMeta").textContent = rec ? `Zuletzt geändert ${fmtTime(rec.geaendert)} von ${rec.geaendert_von}` : "";
  field("datei").value = ""; pendingSheet = null; $("importBox").hidden = true; $("importBox").innerHTML = "";
  field("datei").closest("fieldset").hidden = ro && !(rec?.anhaenge || []).length;
  renderAttachList(rec);
  editor.showModal(); if (!ro) field("titel").focus();
}
function updateVisHint() {
  const h = $("visHint"), b = field("bereich").value, ro = $("save").hidden;
  // Trainer-Häkchen nur in Bereichen, in denen es erlaubt ist (nie in Vorstands- oder Fest-Bereichen)
  const trOk = AUSSCHUSS_GROUPS.includes(b);
  if (!trOk) field("fuer_trainer").checked = false;
  field("fuer_trainer").disabled = !trOk || ro;
  field("mannschaft_id").disabled = !field("fuer_trainer").checked || ro;
  $("trainerWrap").hidden = ro || !trOk;
  if (ro) { h.textContent = ""; return; }
  // Wer sieht den Eintrag? Laut Rechte-Matrix (vom Server) + Admins + ggf. Trainer
  const who = [...(me.sichtbar?.[b] || []), "Admins"];
  const tr = field("fuer_trainer").checked ? ` 🏃 ${field("mannschaft_id").value ? "Trainer von " + teamName(field("mannschaft_id").value) : "Alle Trainer"} sehen ihn auch.` : "";
  h.className = "vishint" + (vorstandOnly(b) ? " vorstand" : "");
  h.textContent = (vorstandOnly(b) ? "🔒 Nur der Vorstand (und Admins) sieht diesen Eintrag." : `👥 Sichtbar für: ${who.join(", ")}.`) + tr;
}
field("bereich").addEventListener("change", updateVisHint);
field("fuer_trainer").addEventListener("change", updateVisHint);
field("mannschaft_id").addEventListener("change", updateVisHint);
function renderAttachList(rec) {
  $("attachList").innerHTML = (rec?.anhaenge || []).map(a => `<span><button type="button" class="quiet chip" data-att="${esc(a.id)}">📎 ${esc(a.dateiname)} <small>(${fmtBytes(a.groesse)})</small></button>${rec && canD(rec.bereich) ? `<button type="button" class="quiet danger chip" data-attdel="${esc(a.id)}" aria-label="${esc(a.dateiname)} löschen">✕</button>` : ""}</span>`).join("");
}
field("datei").onchange = async () => {
  const f = field("datei").files[0], box = $("importBox");
  pendingSheet = null; box.hidden = true; box.innerHTML = ""; $("error").textContent = "";
  if (!f) return;
  if (f.size > MAX_FILE) { $("error").textContent = "Datei zu groß (max. 10 MB)."; field("datei").value = ""; return; }
  if (!field("titel").value.trim()) field("titel").value = f.name.replace(/\.[^.]+$/, "").slice(0, 160);
  box.hidden = false;
  const attachNote = `„${esc(f.name)}“ wird beim <b>Speichern</b> an diesen Eintrag angehängt.`;
  if (!SHEET_RE.test(f.name)) { box.innerHTML = `<p>${attachNote}</p>`; return; }
  box.innerHTML = '<p class="muted">Datei wird gelesen …</p>';
  try {
    const t = toRecords(await readTable(f));
    const { map } = mapColumns(t.headers, ENTRY_ALIASES);
    const preview = sheetToEntries(t, field("bereich").value);
    if (!preview.length) throw new Error("In der Datei wurden keine Zeilen gefunden.");
    pendingSheet = { t, datei: f.name };
    box.innerHTML = `<p>In „${esc(f.name)}“ stehen <b>${preview.length} Zeilen</b>. Was soll passieren?</p>
      <ul><li>Erkannte Spalten: ${columnInfo(t.headers, map, { titel: "Titel", status: "Status", datum: "Datum", uhrzeit: "Uhrzeit", ort: "Ort", zustaendig: "Zuständig", inhalt: "Inhalt", quelle: "Quelle" }) || `Titel ← erste Spalte`}</li>
      <li>Beispiele: ${preview.slice(0, 3).map(v => `„${esc(v.titel)}“`).join(", ")}${preview.length > 3 ? " …" : ""}</li></ul>
      <div class="actions"><button type="button" data-act="sheetImport">Jede Zeile als eigenen Eintrag übernehmen (${preview.length})</button>
      <button type="button" class="quiet" data-act="sheetAttach">Nur als Datei anhängen</button></div>`;
  } catch (err) {
    box.innerHTML = `<p class="err" style="margin:0 0 6px">${esc(err.message)}</p><p>${attachNote}</p>`;
  }
};
async function importSheetEntries() {
  if (!pendingSheet) return;
  const bereich = field("bereich").value, list = sheetToEntries(pendingSheet.t, bereich);
  const btn = $("importBox").querySelector("[data-act=sheetImport]"); btn.disabled = true; btn.textContent = "Wird übernommen …";
  try {
    let n = 0;
    for (let i = 0; i < list.length; i += MAX_IMPORT) n += (await api("/api/eintraege/import", { method: "POST", data: { eintraege: list.slice(i, i + MAX_IMPORT), datei: pendingSheet.datei } })).anzahl;
    editor.close(); notice(`${n} Einträge in „${bereich}“ übernommen.`, true); await reload();
  } catch (err) { $("error").textContent = err.message; btn.disabled = false; btn.textContent = "Erneut versuchen"; }
}
async function uploadAttachment(entryId, file) {
  await api(`/api/eintraege/${entryId}/anhaenge`, { method: "POST", raw: file, headers: { "Content-Type": file.type || "application/octet-stream", "X-Dateiname": encodeURIComponent(file.name) } });
}
function findAttachment(id) { for (const r of entries) for (const a of r.anhaenge || []) if (a.id === id) return a; }
async function openAttachment(id) {
  const a = findAttachment(id); if (!a) return;
  const win = window.open("", "_blank");
  try {
    const blob = new Blob([await api(`/api/anhaenge/${id}`, { blob: true })], { type: a.mime || "application/octet-stream" });
    const viewable = /^(application\/pdf|image\/|text\/plain)/.test(a.mime);
    if (win && viewable) { const url = URL.createObjectURL(blob); win.location = url; setTimeout(() => URL.revokeObjectURL(url), 120000); }
    else { if (win) win.close(); download(blob, a.dateiname); }
  } catch (e) { if (win) win.close(); notice(e.message); }
}
async function deleteAttachment(id) {
  const a = findAttachment(id); if (!a || !confirm(`Datei „${a.dateiname}“ wirklich löschen?`)) return;
  try { await api(`/api/anhaenge/${id}`, { method: "DELETE" }); await reload(); renderAttachList(entries.find(r => r.id === activeId)); notice("Datei gelöscht.", true); }
  catch (e) { $("error").textContent = e.message; }
}
form.onsubmit = async e => {
  e.preventDefault();
  const v = Object.fromEntries(FIELDS.map(k => [k, String(field(k).value || "").trim()]));
  v.rueckmeldung = field("rueckmeldung").checked;
  v.fuer_trainer = field("fuer_trainer").checked; v.mannschaft_id = v.fuer_trainer ? field("mannschaft_id").value : "";
  const file = field("datei").files[0];
  $("save").disabled = true; $("error").textContent = "";
  try {
    const r = activeId ? await api("/api/eintraege/" + activeId, { method: "PUT", data: { ...v, geaendert: entries.find(x => x.id === activeId)?.geaendert } })
                       : await api("/api/eintraege", { method: "POST", data: v });
    if (file) { $("save").textContent = "Lädt hoch …"; activeId = r.eintrag.id; await uploadAttachment(r.eintrag.id, file); }
    editor.close(); notice(file ? "Eintrag mit Datei gespeichert." : activeId ? "Eintrag gespeichert." : "Eintrag angelegt.", true); await reload();
  } catch (err) { $("error").textContent = err.message; await reload(); }
  finally { $("save").disabled = false; $("save").textContent = "Speichern"; }
};
$("remove").onclick = async () => {
  const r = entries.find(x => x.id === activeId);
  if (!r || !confirm(`„${r.titel}“ wirklich löschen?`)) return;
  try { await api("/api/eintraege/" + activeId, { method: "DELETE" }); editor.close(); notice("Eintrag gelöscht.", true); await reload(); }
  catch (err) { $("error").textContent = err.message; }
};
$("duplicate").onclick = () => { const r = entries.find(x => x.id === activeId); editor.close(); edit(null, { ...r, titel: r.titel + " (Kopie)" }); };
async function markDone(id) {
  const r = entries.find(x => x.id === id); if (!r) return;
  try { await api("/api/eintraege/" + id, { method: "PUT", data: { ...r, status: "Erledigt" } }); notice("Als erledigt markiert.", true); await reload(); }
  catch (e) { notice(e.message); }
}

/* ---------------- Dokumente ---------------- */
const docForm = $("docForm"), docEditor = $("docEditor"), dfield = n => docForm.elements.namedItem(n);
function editDoc(id) {
  activeDocId = id || null; const d = docs.find(x => x.id === id);
  $("docFormTitle").textContent = d ? "Dokument bearbeiten" : "Dokument hinzufügen";
  $("docRemove").hidden = !d || !canD("Dokumente"); $("docError").textContent = "";
  dfield("titel").value = d?.titel || ""; dfield("beschreibung").value = d?.beschreibung || "";
  dfield("status").value = d?.status || "Entwurf"; dfield("datum").value = d?.datum || today(); dfield("datei").value = "";
  $("docFileInfo").textContent = d?.groesse ? `Aktuell: ${d.dateiname} (${fmtBytes(d.groesse)}) – neue Datei wählen, um sie zu ersetzen.` : "Noch keine Datei hinterlegt.";
  docEditor.showModal();
}
docForm.onsubmit = async e => {
  e.preventDefault();
  const file = dfield("datei").files[0];
  if (file && file.size > 10 * 1024 * 1024) { $("docError").textContent = "Datei zu groß (max. 10 MB)."; return; }
  $("docSave").disabled = true; $("docError").textContent = "";
  try {
    const v = { titel: dfield("titel").value, beschreibung: dfield("beschreibung").value, status: dfield("status").value, datum: dfield("datum").value };
    const r = await api(activeDocId ? "/api/dokumente/" + activeDocId : "/api/dokumente", { method: activeDocId ? "PUT" : "POST", data: v });
    if (file) { $("docSave").textContent = "Lädt hoch …"; await api(`/api/dokumente/${r.dokument.id}/datei`, { method: "PUT", raw: file, headers: { "Content-Type": file.type || "application/octet-stream", "X-Dateiname": encodeURIComponent(file.name) } }); }
    docEditor.close(); notice("Dokument gespeichert.", true); await reload();
  } catch (err) { $("docError").textContent = err.message; }
  finally { $("docSave").disabled = false; $("docSave").textContent = "Speichern"; }
};
$("docRemove").onclick = async () => {
  const d = docs.find(x => x.id === activeDocId);
  if (!d || !confirm(`Dokument „${d.titel}“ inklusive Datei löschen?`)) return;
  try { await api("/api/dokumente/" + activeDocId, { method: "DELETE" }); docEditor.close(); notice("Dokument gelöscht.", true); await reload(); }
  catch (err) { $("docError").textContent = err.message; }
};
async function openDoc(id, save) {
  const d = docs.find(x => x.id === id);
  try {
    const win = save ? null : window.open("", "_blank");
    const blob = await api(`/api/dokumente/${id}/datei`, { blob: true });
    const typed = new Blob([blob], { type: d.mime || blob.type });
    if (save) return download(typed, d.dateiname);
    const url = URL.createObjectURL(typed);
    if (win) win.location = url; else download(typed, d.dateiname);
    setTimeout(() => URL.revokeObjectURL(url), 120000);
  } catch (e) { notice(e.message); }
}

/* ---------------- Benutzer ---------------- */
const userForm = $("userForm"), userEditor = $("userEditor"), ufield = n => userForm.elements.namedItem(n);
function editUser(id) {
  activeUserId = id || null; const u = users.find(x => x.id === id);
  $("userFormTitle").textContent = u ? "Benutzer bearbeiten" : "Benutzer anlegen";
  ufield("benutzername").value = u?.benutzername || ""; ufield("benutzername").disabled = !!u;
  ufield("anzeigename").value = u?.anzeigename || ""; ufield("rolle").value = u?.rolle || "ausschuss";
  ufield("ist_admin").checked = !!u?.ist_admin; ufield("aktiv").checked = u ? u.aktiv : true;
  ufield("passwort").value = u ? "" : genPassword(); ufield("passwort").required = !u;
  $("pwWrap").hidden = $("pwGen").hidden = !!u; $("activeWrap").hidden = !u;
  $("userRemove").hidden = $("userReset").hidden = !u || u.id === me.id;
  const mine = u?.mannschaften || [], myF = u?.funktionen || [];
  // Funktionen nach Gruppe, Mehrfachauswahl
  $("funcChecks").innerHTML = ["Vorstand", "Ausschuss", "Sport", "Fest", "Sonstige"].map(g => {
    const list = funktionen.filter(f => f.gruppe === g && (f.aktiv || myF.includes(f.id)));
    return list.length ? `<div class="fgroup"><b>${g}</b>${list.map(f => `<label class="check"><input type="checkbox" data-func="${esc(f.id)}" data-key="${esc(f.schluessel)}"${myF.includes(f.id) ? " checked" : ""}> ${esc(f.name)}${f.aktiv ? "" : " (deaktiviert)"}</label>`).join("")}</div>` : "";
  }).join("");
  $("teamChecks").innerHTML = teams.filter(t => t.aktiv || mine.includes(t.id)).map(t => `<label class="check"><input type="checkbox" data-team="${esc(t.id)}"${mine.includes(t.id) ? " checked" : ""}> ${esc(t.name)}</label>`).join("")
    || '<p class="muted small">Noch keine Mannschaften angelegt (Mitglieder → Mannschaftsliste).</p>';
  $("userError").textContent = ""; syncAdminBox();
  userEditor.showModal();
}
// Admin und Schatzmeister/in nur mit Grundrolle Vorstand; Mannschaften nur für Trainer/Co-Trainer/Betreuer
function syncAdminBox() {
  const r = ufield("rolle").value, v = r === "vorstand";
  ufield("ist_admin").disabled = !v; if (!v) ufield("ist_admin").checked = false; $("adminWrap").hidden = !v;
  for (const c of $("funcChecks").querySelectorAll('[data-key="schatzmeister"]')) { c.disabled = !v; if (!v) c.checked = false; }
  const teamFn = [...$("funcChecks").querySelectorAll("[data-func]:checked")].some(c => ["trainer", "co_trainer", "betreuer"].includes(c.dataset.key));
  $("teamWrap").hidden = !(r === "trainer" || teamFn);
}
ufield("rolle").onchange = syncAdminBox;
$("funcChecks").addEventListener("change", syncAdminBox);
userForm.onsubmit = async e => {
  e.preventDefault(); $("userError").textContent = "";
  const data = { anzeigename: ufield("anzeigename").value.trim(), rolle: ufield("rolle").value, ist_admin: ufield("ist_admin").checked, aktiv: ufield("aktiv").checked,
    funktionen: [...$("funcChecks").querySelectorAll("[data-func]:checked")].map(x => x.dataset.func),
    mannschaften: $("teamWrap").hidden ? [] : [...$("teamChecks").querySelectorAll("[data-team]:checked")].map(x => x.dataset.team) };
  if (!$("teamWrap").hidden && !data.mannschaften.length && !confirm("Keine Mannschaft zugeordnet. Die Person sieht dann keine Mitglieder und Eltern. Trotzdem speichern?")) return;
  try {
    if (activeUserId) users = (await api("/api/benutzer/" + activeUserId, { method: "PUT", data })).benutzer;
    else {
      const name = ufield("benutzername").value.trim().toLowerCase(), pw = ufield("passwort").value;
      if (pw.length < 10) throw new Error("Startpasswort: mindestens 10 Zeichen.");
      users = (await api("/api/benutzer", { method: "POST", data: { ...data, benutzername: name, passwort: await clientHash(name, pw) } })).benutzer;
      alert(`Konto angelegt.\n\nBenutzername: ${name}\nStartpasswort: ${pw}\n\nBitte persönlich oder per Telefon weitergeben – nicht per E-Mail. Beim ersten Login muss ein eigenes Passwort gesetzt werden.`);
    }
    userEditor.close(); notice("Benutzer gespeichert.", true);
    if (activeUserId === me.id) { me = (await api("/api/ich")).benutzer; $("userRole").textContent = rightsLabel(me); buildSections(); await reload(); } else render();
  } catch (err) { $("userError").textContent = err.message; }
};
$("userReset").onclick = async () => {
  const u = users.find(x => x.id === activeUserId); if (!u) return;
  const pw = genPassword();
  if (!confirm(`Passwort von ${u.anzeigename} zurücksetzen? Alle Sitzungen werden beendet.`)) return;
  try { await api(`/api/benutzer/${u.id}/passwort`, { method: "POST", data: { passwort: await clientHash(u.benutzername, pw) } });
    alert(`Neues Startpasswort für ${u.benutzername}:\n\n${pw}\n\nBeim nächsten Login muss ein eigenes Passwort gesetzt werden.`); userEditor.close(); await reload(); }
  catch (err) { $("userError").textContent = err.message; }
};
$("userRemove").onclick = async () => {
  const u = users.find(x => x.id === activeUserId);
  if (!u || !confirm(`Konto von ${u.anzeigename} endgültig löschen? (Alternative: deaktivieren)`)) return;
  try { users = (await api("/api/benutzer/" + u.id, { method: "DELETE" })).benutzer; userEditor.close(); notice("Benutzer gelöscht.", true); render(); }
  catch (err) { $("userError").textContent = err.message; }
};

/* ---------------- Mitglied / Eltern bearbeiten ---------------- */
// Mannschafts-Auswahl → {mannschaft_id, mannschaft}; „__alt“ = alten, nicht zugeordneten Text behalten
function teamFromSelect(sel, old) {
  const v = sel.value;
  if (v === "__alt") return { mannschaft_id: "", mannschaft: old?.mannschaft || "" };
  return { mannschaft_id: v, mannschaft: teamName(v) };
}
const memberForm = $("memberForm"), mfield = n => memberForm.elements.namedItem(n);
const MEMBER_KEYS = ["vorname","nachname","geburtsdatum","mannschaft","mannschaft_id","email","telefon","eintritt","status","notiz"];
const MEMBER_INPUTS = ["vorname","nachname","geburtsdatum","email","telefon","eintritt","notiz"];
function editMember(id) {
  activeMemberId = id || null; const m = members.find(x => x.id === id);
  $("memberFormTitle").textContent = m ? memberName(m) : "Mitglied anlegen";
  $("memberHint").hidden = !!m; $("memberRemove").hidden = !m || !canD("Mitglieder"); $("memberError").textContent = "";
  mfield("status").innerHTML = options(MEMBER_STATUSES, m?.status || "Aktiv");
  for (const k of MEMBER_INPUTS) mfield(k).value = m?.[k] ?? "";
  mfield("mannschaft_id").innerHTML = teamOptions(m?.mannschaft_id || "", m?.mannschaft_id ? "" : m?.mannschaft);
  $("memberMeta").textContent = m ? `Zuletzt geändert ${fmtTime(m.geaendert)} von ${m.geaendert_von}` : "";
  $("memberEditor").showModal(); mfield("vorname").focus();
}
memberForm.onsubmit = async e => {
  e.preventDefault(); $("memberError").textContent = "";
  const data = { ...Object.fromEntries([...MEMBER_INPUTS, "status"].map(k => [k, String(mfield(k).value || "").trim()])),
    ...teamFromSelect(mfield("mannschaft_id"), members.find(x => x.id === activeMemberId)) };
  if (!data.vorname && !data.nachname) { $("memberError").textContent = "Bitte Vor- oder Nachnamen eingeben."; return; }
  try {
    const old = members.find(x => x.id === activeMemberId);
    members = (await api(activeMemberId ? "/api/mitglieder/" + activeMemberId : "/api/mitglieder", { method: activeMemberId ? "PUT" : "POST", data: { ...data, geaendert: old?.geaendert } })).liste;
    $("memberEditor").close(); notice("Mitglied gespeichert.", true); render();
  } catch (err) { $("memberError").textContent = err.message; }
};
$("memberRemove").onclick = async () => {
  const m = members.find(x => x.id === activeMemberId);
  if (!m || !confirm(`${memberName(m)} wirklich aus der Mitgliederliste löschen?\n\nTipp: Bei Austritt lieber Status „Ausgetreten“ wählen.`)) return;
  try { members = (await api("/api/mitglieder/" + m.id, { method: "DELETE" })).liste; $("memberEditor").close(); notice("Mitglied gelöscht.", true); render(); }
  catch (err) { $("memberError").textContent = err.message; }
};

const parentForm = $("parentForm"), pfield = n => parentForm.elements.namedItem(n);
const PARENT_KEYS = ["name","email","kind","mannschaft","mannschaft_id","notiz","einwilligung","einwilligung_datum"];
const PARENT_INPUTS = ["name","email","kind","notiz"];
function editParent(id) {
  if (!D().eltern_alle) return;
  activeParentId = id || null; const p = parents.find(x => x.id === id);
  $("parentFormTitle").textContent = p ? "Eltern bearbeiten" : "Eltern hinzufügen";
  $("parentHint").hidden = !!p; $("parentRemove").hidden = !p; $("parentError").textContent = "";
  for (const k of PARENT_INPUTS) pfield(k).value = p?.[k] ?? "";
  pfield("einwilligung").checked = !!p?.einwilligung; pfield("einwilligung_datum").value = p?.einwilligung_datum || "";
  pfield("mannschaft_id").innerHTML = teamOptions(p?.mannschaft_id || "", p?.mannschaft_id ? "" : p?.mannschaft);
  $("parentEditor").showModal(); pfield("name").focus();
}
pfield("einwilligung").onchange = () => { if (pfield("einwilligung").checked && !pfield("einwilligung_datum").value) pfield("einwilligung_datum").value = today(); };
parentForm.onsubmit = async e => {
  e.preventDefault(); $("parentError").textContent = "";
  const data = { ...Object.fromEntries(PARENT_INPUTS.map(k => [k, String(pfield(k).value || "").trim()])),
    einwilligung: pfield("einwilligung").checked, einwilligung_datum: pfield("einwilligung").checked ? pfield("einwilligung_datum").value : "",
    ...teamFromSelect(pfield("mannschaft_id"), parents.find(x => x.id === activeParentId)) };
  if (!EMAIL_RE.test(data.email)) { $("parentError").textContent = "Bitte eine gültige E-Mail-Adresse eingeben."; return; }
  if (!activeParentId && parents.some(p => p.email.toLowerCase() === data.email.toLowerCase()) && !confirm(`${data.email} steht schon im Verteiler. Trotzdem noch einmal eintragen?`)) return;
  try {
    const old = parents.find(x => x.id === activeParentId);
    parents = (await api(activeParentId ? "/api/eltern/" + activeParentId : "/api/eltern", { method: activeParentId ? "PUT" : "POST", data: { ...data, geaendert: old?.geaendert } })).liste;
    $("parentEditor").close(); notice("Eltern-Adresse gespeichert.", true); render();
  } catch (err) { $("parentError").textContent = err.message; }
};
$("parentRemove").onclick = async () => {
  const p = parents.find(x => x.id === activeParentId);
  if (!p || !confirm(`${p.email} aus dem Eltern-Verteiler löschen?`)) return;
  try { parents = (await api("/api/eltern/" + p.id, { method: "DELETE" })).liste; $("parentEditor").close(); notice("Adresse gelöscht.", true); render(); }
  catch (err) { $("parentError").textContent = err.message; }
};

/* ---------------- E-Mail an Eltern (über das eigene E-Mail-Programm, alle im BCC) ---------------- */
const mailForm = $("mailForm"), xfield = n => mailForm.elements.namedItem(n);
// Gruppen-Schlüssel: Mannschaft aus der Liste, sonst der alte Freitext
const mailKey = p => p.mannschaft_id || (p.mannschaft ? "txt:" + p.mannschaft : "");
// Nur Eltern mit Einwilligung bekommen E-Mails
const consented = () => parents.filter(p => p.einwilligung);
const recipients = () => { const t = xfield("mannschaft").value; return [...new Set(consented().filter(p => !t || mailKey(p) === t).map(p => p.email.toLowerCase()))]; };
function updateMailCount() { const n = recipients().length; $("mailCount").textContent = n ? `${n} Empfänger (alle im BCC)` : "Keine Empfänger für diese Auswahl."; }
function openMail(entryId) {
  if (!consented().length) return notice(D().eltern_alle ? "Es gibt noch keine Eltern-Adressen mit Einwilligung." : "Für deine Mannschaft sind noch keine Eltern-Adressen (mit Einwilligung) hinterlegt.");
  const r = entries.find(x => x.id === entryId), list = consented();
  const groups = [...new Set(list.map(mailKey).filter(Boolean))].map(k => [k, k.startsWith("txt:") ? k.slice(4) + " (nicht zugeordnet)" : teamName(k)]).sort((a, b) => a[1].localeCompare(b[1], "de"));
  const count = k => new Set(list.filter(p => mailKey(p) === k).map(p => p.email.toLowerCase())).size;
  xfield("mannschaft").innerHTML = `<option value="">${D().eltern_alle ? "Alle Eltern" : "Alle meine Eltern"} (${new Set(list.map(p => p.email.toLowerCase())).size})</option>` +
    groups.map(([k, label]) => `<option value="${esc(k)}">Nur ${esc(label)} (${count(k)})</option>`).join("");
  xfield("betreff").value = r ? r.titel : ""; xfield("text").value = r ? r.inhalt : "";
  $("mailError").textContent = ""; updateMailCount(); $("mailDialog").showModal();
}
xfield("mannschaft").onchange = updateMailCount;
async function copyMails() {
  const list = recipients(); if (!list.length) return;
  try { await navigator.clipboard.writeText(list.join("; ")); notice(`${list.length} Adressen kopiert.`, true); } catch { $("mailError").textContent = "Kopieren fehlgeschlagen."; }
}
mailForm.onsubmit = async e => {
  e.preventDefault();
  const list = recipients();
  if (!list.length) { $("mailError").textContent = "Keine Empfänger für diese Auswahl."; return; }
  const q = `subject=${encodeURIComponent(xfield("betreff").value)}&body=${encodeURIComponent(xfield("text").value.replace(/\r?\n/g, "\r\n"))}`;
  let url = `mailto:?bcc=${list.map(encodeURIComponent).join(",")}&${q}`;
  if (url.length > 1900) {
    // Sehr lange Adresslisten passen nicht in einen mailto-Link: Adressen in die Zwischenablage
    try { await navigator.clipboard.writeText(list.join("; ")); } catch { $("mailError").textContent = "Adressen konnten nicht kopiert werden. Bitte „Adressen kopieren“ versuchen."; return; }
    alert(`Es sind ${list.length} Empfänger – zu viele für einen direkten Link.\n\nDie Adressen sind jetzt kopiert. Im E-Mail-Programm bei „BCC“ klicken und mit Strg+V einfügen.`);
    url = `mailto:?${q}`;
  }
  location.href = url;
  $("mailDialog").close();
};

/* ---------------- Drucken (Rechnung, Mitgliedsantrag) ---------------- */
function printPaper(html, title) {
  const old = document.title;
  $("printArea").innerHTML = html; document.body.classList.add("printmode"); if (title) document.title = title;
  const done = () => { document.body.classList.remove("printmode"); document.title = old; window.removeEventListener("afterprint", done); };
  window.addEventListener("afterprint", done);
  // Bilder (Logo) erst laden, dann drucken
  const imgs = [...$("printArea").querySelectorAll("img")].filter(i => !i.complete);
  Promise.all(imgs.map(i => new Promise(r => { i.onload = i.onerror = r; }))).then(() => { window.print(); setTimeout(done, 500); });
}
const fmtEur = c => (c / 100).toLocaleString("de-DE", { style: "currency", currency: "EUR" });
const fmtNum = n => Number(n).toLocaleString("de-DE", { maximumFractionDigits: 3 });
const lines = s => esc(s).replace(/\n/g, "<br>");
function paperHead() {
  return `<div class="p-head"><div><div class="p-club">${CLUB.toUpperCase()}</div><div class="p-sub">MÜHLACKER · JUGENDFUSSBALL</div></div><img class="p-logo" src="logo.png" alt="Logo ${CLUB}"></div>`;
}
function paperFoot(a) {
  const c1 = [CLUB, a.adresse, a.vorsitz && "Vertreten durch: " + a.vorsitz, a.register].filter(Boolean).join("\n");
  const c2 = [a.telefon && "Tel. " + a.telefon, a.email, a.web, a.fusszeile].filter(Boolean).join("\n");
  const c3 = [a.bank, a.iban && "IBAN " + a.iban, a.bic && "BIC " + a.bic, a.steuernummer && "St.-Nr. " + a.steuernummer, a.ustid && "USt-IdNr. " + a.ustid].filter(Boolean).join("\n");
  return `<div class="p-foot"><div>${esc(c1)}</div><div>${esc(c2)}</div><div>${esc(c3)}</div></div>`;
}

/* ---------------- Downloads ---------------- */
const DL_HINTS = {
  "Formulare": "z. B. Mitgliedsantrag als PDF, Austrittserklärung, Einverständnis für Fotos, Spielerpass-Antrag",
  "Sponsoren": "z. B. Sponsoring-Mappe, Preisliste Bandenwerbung/Trikotwerbung, Sponsorenvertrag, Spendenbescheinigung-Vorlage",
  "Logos & Werbematerial": "z. B. Logo als SVG/PDF/EPS für Druckereien, Logo in Weiß/Schwarz, Flyer, Plakate, Vereinsfarben",
  "Sonstiges": "alles andere, was ihr öfter braucht",
};
function renderDownloads() {
  const card = d => `<article class="card"><div class="cardtop"><h3>${esc(d.titel)}</h3></div>
    <div class="meta">${esc(d.groesse ? `${d.dateiname} · ${fmtBytes(d.groesse)}` : "Noch keine Datei hochgeladen")} · ${esc(fmtTime(d.geaendert))}</div>
    ${d.beschreibung ? `<p class="body">${esc(d.beschreibung)}</p>` : ""}
    <div class="actions">${d.groesse ? `<button data-dlopen="${esc(d.id)}">Öffnen</button><button class="quiet" data-dldl="${esc(d.id)}">Herunterladen</button>` : ""}
      <button class="quiet" data-dledit="${esc(d.id)}">${d.groesse ? "Bearbeiten" : "Datei hochladen"}</button></div></article>`;
  $("view").innerHTML = `<div class="sectionhead"><h2>Downloads</h2><span class="muted small">Nur für Vorstand und Ausschuss</span></div>
    <h3 class="dlcat">Von der Vereinszentrale erstellt</h3>
    <div class="dlgrid">
      <article class="card"><h3>Mitgliedsantrag (Aufnahmeantrag)</h3>
        <p class="body muted">Mit Vereinslogo, Angaben zum Mitglied, Erziehungsberechtigten, Beitrag, SEPA-Lastschriftmandat, Einwilligungen und Unterschrift. Adresse, Gläubiger-ID und Beitragstext kommen aus den <a class="link" href="#" data-act="settings">Vereinsdaten</a>.</p>
        <p class="muted small">Bitte vor dem ersten Einsatz vom Vorstand prüfen lassen.</p>
        <div class="actions"><button data-act="printMembership">Drucken / als PDF speichern</button></div></article>
      <article class="card"><h3>Logo-Paket</h3>
        <p class="body muted">Vereinswappen für Bildschirm, Webseite, Social Media und Word/PowerPoint.</p>
        <p class="muted small">⚠ Das vorhandene Logo hat nur 400 × 400 Pixel und einen dunklen Hintergrund. <b>Für Druck</b> (Trikots, Banner, Flyer) braucht die Druckerei eine Vektordatei (SVG, PDF oder EPS) mit transparentem Hintergrund. Die bekommt ihr vom Designer. Ladet sie dann unten bei „Logos &amp; Werbematerial“ hoch.</p>
        <div class="actions"><button class="quiet" data-act="logoPng">PNG (400 × 400)</button><button class="quiet" data-act="logoJpg">JPG (für Office)</button><button class="quiet" data-act="logoIcon">App-Symbol (180 × 180)</button></div></article>
    </div>
    ${DL_CATS.map(c => {
      const list = downloads.filter(d => d.kategorie === c);
      return `<div class="sectionhead"><h3 class="dlcat" style="margin:0">${esc(c)} <span class="muted small">(${list.length})</span></h3><button class="quiet" data-dlnew="${esc(c)}">＋ Hochladen</button></div>
        <div class="dlgrid">${list.map(card).join("") || `<article class="card hintcard"><p class="muted small">Noch nichts hochgeladen – ${esc(DL_HINTS[c])}.</p></article>`}</div>`;
    }).join("")}`;
}
const dlForm = $("dlForm"), dlfield = n => dlForm.elements.namedItem(n);
function editDownload(id, cat) {
  activeDlId = id || null; const d = downloads.find(x => x.id === id);
  $("dlFormTitle").textContent = d ? "Download bearbeiten" : "Datei hochladen";
  dlfield("kategorie").innerHTML = options(DL_CATS, d?.kategorie || cat || DL_CATS[0]);
  dlfield("titel").value = d?.titel || ""; dlfield("beschreibung").value = d?.beschreibung || ""; dlfield("datei").value = "";
  $("dlFileInfo").textContent = d?.groesse ? `Aktuell: ${d.dateiname} (${fmtBytes(d.groesse)}) – neue Datei wählen, um sie zu ersetzen.` : "";
  $("dlRemove").hidden = !d || !canD("Downloads"); $("dlError").textContent = "";
  $("dlEditor").showModal();
}
dlfield("datei").onchange = () => { const f = dlfield("datei").files[0]; if (f && !dlfield("titel").value.trim()) dlfield("titel").value = f.name.replace(/\.[^.]+$/, "").slice(0, 160); };
dlForm.onsubmit = async e => {
  e.preventDefault();
  const file = dlfield("datei").files[0];
  if (file && file.size > MAX_FILE) { $("dlError").textContent = "Datei zu groß (max. 10 MB)."; return; }
  if (!activeDlId && !file) { $("dlError").textContent = "Bitte eine Datei auswählen."; return; }
  $("dlSave").disabled = true; $("dlError").textContent = "";
  try {
    const r = await api(activeDlId ? "/api/downloads/" + activeDlId : "/api/downloads", { method: activeDlId ? "PUT" : "POST",
      data: { titel: dlfield("titel").value, kategorie: dlfield("kategorie").value, beschreibung: dlfield("beschreibung").value } });
    activeDlId = r.download.id;
    if (file) { $("dlSave").textContent = "Lädt hoch …"; await api(`/api/downloads/${r.download.id}/datei`, { method: "PUT", raw: file, headers: { "Content-Type": file.type || "application/octet-stream", "X-Dateiname": encodeURIComponent(file.name) } }); }
    $("dlEditor").close(); notice("Download gespeichert.", true); await reload();
  } catch (err) { $("dlError").textContent = err.message; await reload(); }
  finally { $("dlSave").disabled = false; $("dlSave").textContent = "Speichern"; }
};
$("dlRemove").onclick = async () => {
  const d = downloads.find(x => x.id === activeDlId);
  if (!d || !confirm(`„${d.titel}“ wirklich löschen?`)) return;
  try { await api("/api/downloads/" + d.id, { method: "DELETE" }); $("dlEditor").close(); notice("Download gelöscht.", true); await reload(); }
  catch (err) { $("dlError").textContent = err.message; }
};
async function openDownload(id, save) {
  const d = downloads.find(x => x.id === id); if (!d) return;
  const win = save ? null : window.open("", "_blank");
  try {
    const blob = new Blob([await api(`/api/downloads/${id}/datei`, { blob: true })], { type: d.mime || "application/octet-stream" });
    if (win && /^(application\/pdf|image\/|text\/plain)/.test(d.mime)) { const url = URL.createObjectURL(blob); win.location = url; setTimeout(() => URL.revokeObjectURL(url), 120000); }
    else { if (win) win.close(); download(blob, d.dateiname); }
  } catch (e) { if (win) win.close(); notice(e.message); }
}
async function logoFile(kind) {
  try {
    if (kind === "png") return download(await (await fetch("logo.png")).blob(), "FC-Sender-Kickers-United_Logo_400.png");
    if (kind === "icon") return download(await (await fetch("apple-touch-icon.png")).blob(), "FC-Sender-Kickers-United_Symbol_180.png");
    const img = new Image(); img.src = "logo.png"; await img.decode();
    const c = document.createElement("canvas"); c.width = img.naturalWidth; c.height = img.naturalHeight;
    const g = c.getContext("2d"); g.fillStyle = "#fff"; g.fillRect(0, 0, c.width, c.height); g.drawImage(img, 0, 0);
    c.toBlob(b => download(b, "FC-Sender-Kickers-United_Logo_400.jpg"), "image/jpeg", 0.95);
  } catch { notice("Logo konnte nicht erstellt werden."); }
}
function membershipHtml() {
  const a = settings.verein || {};
  const f = label => `<div class="p-field">${esc(label)}</div>`;
  return `<div class="paper">${paperHead()}
    <h1>Aufnahmeantrag</h1>
    <p>Hiermit beantrage ich die Mitgliedschaft im <b>${CLUB}</b>${a.adresse ? ` (${esc(a.adresse.replace(/\n/g, ", "))})` : ""}.</p>
    <div class="p-box"><h3>Angaben zum Mitglied</h3><div class="p-fields">
      ${f("Vorname")}${f("Nachname")}${f("Geburtsdatum")}${f("Mannschaft / Jahrgang")}${f("Straße, Hausnummer")}${f("PLZ, Ort")}${f("Telefon")}${f("E-Mail")}${f("Mitglied ab (Datum)")}${f("Staatsangehörigkeit (für Spielerpass)")}
    </div></div>
    <div class="p-box"><h3>Bei Minderjährigen: Erziehungsberechtigte</h3><div class="p-fields">
      ${f("Name Erziehungsberechtigte/r 1")}${f("Name Erziehungsberechtigte/r 2")}${f("Telefon")}${f("E-Mail")}
    </div></div>
    <div class="p-box"><h3>Mitgliedsbeitrag</h3><p class="p-text">${a.beitrag_text ? esc(a.beitrag_text) : "Der Beitrag richtet sich nach der aktuellen Beitragsordnung des Vereins."}</p></div>
    <div class="p-box"><h3>SEPA-Lastschriftmandat</h3>
      <p style="font-size:11px">Gläubiger-ID: <b>${esc(a.glaeubiger_id || "______________________")}</b> · Mandatsreferenz: wird separat mitgeteilt</p>
      <p style="font-size:10.5px">Ich ermächtige den ${CLUB}, Zahlungen von meinem Konto mittels Lastschrift einzuziehen. Zugleich weise ich mein Kreditinstitut an, die vom ${CLUB} auf mein Konto gezogenen Lastschriften einzulösen. Hinweis: Ich kann innerhalb von acht Wochen, beginnend mit dem Belastungsdatum, die Erstattung des belasteten Betrages verlangen. Es gelten dabei die mit meinem Kreditinstitut vereinbarten Bedingungen.</p>
      <div class="p-fields">${f("Kontoinhaber/in")}${f("Kreditinstitut")}${f("IBAN")}${f("BIC")}</div>
    </div>
    <div class="p-box"><h3>Erklärungen</h3>
      <div class="p-check">Ich erkenne die Satzung des Vereins an.</div>
      <div class="p-check">Ich willige ein, dass meine Daten (bzw. die meines Kindes) zur Mitgliederverwaltung, Beitragsabrechnung und Teilnahme am Spielbetrieb verarbeitet werden. Die Datenschutzhinweise des Vereins habe ich erhalten.</div>
      <div class="p-check">Freiwillig: Ich bin einverstanden, dass Fotos von Vereinsveranstaltungen, auf denen ich bzw. mein Kind zu sehen bin/ist, auf der Webseite und in sozialen Medien des Vereins veröffentlicht werden. Die Einwilligung kann jederzeit widerrufen werden.</div>
    </div>
    <div class="p-sign"><div>Ort, Datum</div><div>Unterschrift Mitglied bzw. Erziehungsberechtigte/r</div></div>
    ${paperFoot(a)}</div>`;
}

/* ---------------- Vereinsdaten / Vorlage ---------------- */
const settingsForm = $("settingsForm"), sfield = n => settingsForm.elements.namedItem(n);
const VEREIN_KEYS = ["adresse","telefon","email","web","vorsitz","register","steuernummer","ustid","bank","iban","bic","glaeubiger_id","ersteller","mwst","zahlungsziel","einleitung","schlusstext","fusszeile","beitrag_text"];
function openSettings() {
  const v = settings.verein || {};
  for (const k of VEREIN_KEYS) sfield(k).value = v[k] ?? "";
  $("settingsMeta").textContent = settings.geaendert ? `Zuletzt geändert ${fmtTime(settings.geaendert)} von ${settings.geaendert_von}` : "";
  $("settingsError").textContent = ""; $("settingsEditor").showModal();
}
settingsForm.onsubmit = async e => {
  e.preventDefault(); $("settingsError").textContent = "";
  try {
    settings = await api("/api/einstellungen/verein", { method: "PUT", data: Object.fromEntries(VEREIN_KEYS.map(k => [k, sfield(k).value.trim()])) });
    $("settingsEditor").close(); notice("Vereinsdaten gespeichert. Sie gelten für neue Rechnungen.", true); render();
  } catch (err) { $("settingsError").textContent = err.message; }
};

/* ---------------- Rechnungen ---------------- */
const parseDe = s => { s = String(s ?? "").trim().replace(/\s|€/g, ""); if (!s) return NaN; if (s.includes(",")) s = s.replace(/\./g, "").replace(",", "."); return Number(s); };
const numDe = n => n === "" || n === null || n === undefined || Number.isNaN(n) ? "" : String(n).replace(".", ",");
const addDays = (iso, n) => { const d = new Date(iso + "T12:00:00Z"); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };
function calcTotals(pos) {
  const byRate = new Map();
  for (const p of pos) byRate.set(p.mwst, (byRate.get(p.mwst) || 0) + Math.round(p.menge * p.preis));
  const rates = [...byRate.entries()].sort((a, b) => a[0] - b[0]).map(([r, net]) => [r, net, Math.round(net * r / 100)]);
  const netto = rates.reduce((a, x) => a + x[1], 0), steuer = rates.reduce((a, x) => a + x[2], 0);
  return { rates, netto, steuer, brutto: netto + steuer };
}
const parseInv = r => ({ ...r, positionen: JSON.parse(r.positionen || "[]"), absender: JSON.parse(r.absender || "{}") });
function invoiceHtml(inv) {
  const a = inv.absender || {}, t = calcTotals(inv.positionen);
  const fill = s => String(s || "").replace(/\{nummer\}/g, inv.nummer).replace(/\{faellig\}/g, dateText(inv.faellig) || "–")
    .replace(/\{betrag\}/g, fmtEur(t.brutto)).replace(/\{ersteller\}/g, a.ersteller || "").replace(/\{datum\}/g, dateText(inv.datum));
  const zero = t.rates.every(r => r[0] === 0);
  const meta = [["Rechnungsnr.", inv.nummer], ["Rechnungsdatum", dateText(inv.datum)], ["Leistungsdatum", dateText(inv.leistungsdatum)],
    ["Zahlbar bis", dateText(inv.faellig)], ["Ansprechpartner", a.ersteller]].filter(x => x[1]);
  return `<div class="paper">${inv.status === "Storniert" ? '<div class="p-stamp">STORNIERT</div>' : ""}${paperHead()}
    <div class="p-row"><div><div class="p-sender">${esc([CLUB, ...String(a.adresse || "").split("\n")].filter(Boolean).join(" · "))}</div>
      <div class="p-to">${esc(inv.empfaenger)}</div></div>
      <dl class="p-meta">${meta.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl></div>
    <h1>Rechnung ${esc(inv.nummer)}</h1>${inv.betreff ? `<p><b>${esc(inv.betreff)}</b></p>` : ""}
    ${inv.einleitung ? `<p class="p-text">${esc(fill(inv.einleitung))}</p>` : ""}
    <table><thead><tr><th>Pos.</th><th>Beschreibung</th><th class="r">Menge</th><th class="r">Einzelpreis</th>${zero ? "" : '<th class="r">MwSt.</th>'}<th class="r">Gesamt</th></tr></thead><tbody>
      ${inv.positionen.map((p, i) => `<tr><td>${i + 1}</td><td>${lines(p.beschreibung)}</td><td class="r">${esc(fmtNum(p.menge))}${p.einheit ? " " + esc(p.einheit) : ""}</td>
        <td class="r">${fmtEur(p.preis)}</td>${zero ? "" : `<td class="r">${esc(fmtNum(p.mwst))} %</td>`}<td class="r">${fmtEur(Math.round(p.menge * p.preis))}</td></tr>`).join("")}
    </tbody></table>
    <table class="p-totals">${zero ? "" : `<tr><td>Summe netto</td><td class="r">${fmtEur(t.netto)}</td></tr>` +
      t.rates.filter(r => r[0] > 0).map(r => `<tr><td>zzgl. ${esc(fmtNum(r[0]))} % MwSt. auf ${fmtEur(r[1])}</td><td class="r">${fmtEur(r[2])}</td></tr>`).join("")}
      <tr class="grand"><td>Gesamtbetrag</td><td class="r">${fmtEur(t.brutto)}</td></tr></table>
    ${inv.schlusstext ? `<p class="p-text" style="margin-top:14px">${esc(fill(inv.schlusstext))}</p>` : ""}
    ${paperFoot(a)}</div>`;
}
const nextNumber = jahr => `SKU-${jahr}-${String(Math.max(0, ...invoices.filter(i => i.jahr === Number(jahr)).map(i => i.lfd)) + 1).padStart(4, "0")}`;
const isOverdue = i => i.status === "Offen" && i.faellig && i.faellig < today();
function renderInvoices() {
  const years = distinct(invoices.map(i => String(i.jahr))).reverse();
  const y = today().slice(0, 4);
  const open = invoices.filter(i => i.status === "Offen"), paidYear = invoices.filter(i => i.status === "Bezahlt" && String(i.jahr) === y);
  const q = iFilter.q.trim().toLocaleLowerCase("de");
  const list = invoices.filter(i => (!iFilter.status || i.status === iFilter.status) && (!iFilter.jahr || String(i.jahr) === iFilter.jahr)
    && (!q || [i.nummer, i.empfaenger, i.betreff].join(" ").toLocaleLowerCase("de").includes(q)));
  $("view").innerHTML = `<div class="sectionhead"><h2>Rechnungen</h2><div class="actions" style="margin:0"><button class="quiet" data-act="settings">Vereinsdaten &amp; Vorlage</button></div></div>
    <div class="stats">
      <div class="stat"><strong>${open.length}</strong>offen · ${fmtEur(open.reduce((a, i) => a + i.brutto, 0))}</div>
      <div class="stat"><strong>${open.filter(isOverdue).length}</strong>überfällig</div>
      <div class="stat"><strong>${paidYear.length}</strong>bezahlt ${y} · ${fmtEur(paidYear.reduce((a, i) => a + i.brutto, 0))}</div>
      <div class="stat"><strong>${invoices.length}</strong>Rechnungen gesamt</div>
    </div>
    ${invoices.length ? `<div class="filters">
      <input id="isearch" type="search" placeholder="Nummer, Empfänger, Betreff …" aria-label="Rechnungen durchsuchen" value="${esc(iFilter.q)}">
      <select id="istatus" aria-label="Status filtern"><option value="">Alle Status</option>${options(["Offen","Bezahlt","Storniert"], iFilter.status)}</select>
      <select id="ijahr" aria-label="Jahr filtern"><option value="">Alle Jahre</option>${options(years, iFilter.jahr)}</select></div>
    <div class="tablewrap"><table class="table"><thead><tr><th>Nummer</th><th>Datum</th><th>Empfänger</th><th>Betreff</th><th class="money">Betrag</th><th>Status</th><th>Fällig</th><th></th></tr></thead><tbody>
    ${list.map(i => `<tr><td style="white-space:nowrap"><b>${esc(i.nummer)}</b></td><td>${esc(dateText(i.datum))}</td><td>${esc(i.empfaenger.split("\n")[0])}</td><td>${esc(i.betreff)}</td>
      <td class="money">${fmtEur(i.brutto)}</td><td>${badge(i.status)}${i.status === "Bezahlt" && i.bezahlt_am ? `<div class="lock">${esc(dateText(i.bezahlt_am))}</div>` : ""}</td>
      <td class="${isOverdue(i) ? "overdue" : "lock"}">${esc(dateText(i.faellig))}${isOverdue(i) ? " ⚠" : ""}</td>
      <td><button class="quiet" data-invview="${esc(i.id)}">Ansehen</button></td></tr>`).join("") || '<tr><td colspan="8" class="muted">Keine Treffer.</td></tr>'}
    </tbody></table></div>` : `<section class="card"><h3>Noch keine Rechnungen</h3><p class="muted" style="margin-top:6px">Klicke auf <b>＋ Rechnung erstellen</b>. Trage vorher am besten einmal die <a class="link" href="#" data-act="settings">Vereinsdaten</a> ein (Anschrift, Bank, Steuernummer), dann sind sie in jeder Rechnung schon ausgefüllt.</p></section>`}`;
  if (!invoices.length) return;
  $("isearch").oninput = e => { iFilter.q = e.target.value; renderInvoices(); $("isearch").focus(); $("isearch").setSelectionRange(9999, 9999); };
  $("istatus").onchange = e => { iFilter.status = e.target.value; renderInvoices(); };
  $("ijahr").onchange = e => { iFilter.jahr = e.target.value; renderInvoices(); };
}
function viewInvoice(id) {
  const raw = invoices.find(i => i.id === id); if (!raw) return;
  viewInvoiceId = id;
  $("invoiceViewBody").innerHTML = `<div class="previewwrap" style="margin:0">${invoiceHtml(parseInv(raw))}</div>
    <p class="muted small" style="margin-top:8px">Erstellt ${esc(fmtTime(raw.erstellt))} von ${esc(raw.erstellt_von)}${raw.geaendert !== raw.erstellt ? ` · zuletzt geändert ${esc(fmtTime(raw.geaendert))} von ${esc(raw.geaendert_von)}` : ""}</p>`;
  $("invStorno").hidden = !D().stornieren || raw.status === "Storniert";
  $("invPaid").hidden = !isSchatz() || raw.status !== "Offen"; $("invOpen").hidden = !isSchatz() || raw.status !== "Bezahlt"; $("invEdit").hidden = !isSchatz() || raw.status === "Storniert";
  $("invoiceError").textContent = "";
  if (!$("invoiceView").open) $("invoiceView").showModal();
}
async function setInvoiceStatus(status) {
  const raw = invoices.find(i => i.id === viewInvoiceId); if (!raw) return;
  let bezahlt_am = "";
  if (status === "Storniert" && !confirm(`Rechnung ${raw.nummer} wirklich stornieren?\n\nDie Rechnung bleibt mit ihrer Nummer erhalten (Pflicht für die Buchhaltung), wird aber als STORNIERT markiert und kann nicht mehr geändert werden.`)) return;
  if (status === "Bezahlt") { bezahlt_am = prompt("Bezahlt am (TT.MM.JJJJ):", dateText(today())); if (bezahlt_am === null) return; bezahlt_am = parseDate(bezahlt_am); if (!bezahlt_am) { $("invoiceError").textContent = "Datum nicht erkannt."; return; } }
  try {
    await api(`/api/rechnungen/${raw.id}/status`, { method: "POST", data: { status, bezahlt_am } });
    await reload(); viewInvoice(raw.id); notice(`Rechnung ${raw.nummer}: ${status}.`, true);
    // Schatzmeister: nachfragen, ob die Zahlung in die Kasse gebucht werden soll (nie automatisch)
    if (status === "Bezahlt" && isSchatz() && confirm(`Rechnung ${raw.nummer} ist bezahlt.\n\nSoll dafür jetzt eine Einnahme in der Kasse gebucht werden (${fmtEur(raw.brutto)}, Bank)?`)) {
      $("invoiceView").close();
      newBooking({ art: "einnahme", betrag: raw.brutto, datum: bezahlt_am, zahlungsweg: "bank", rechnung_id: raw.id,
        kategorie: KS().kategorien.includes("Sponsoring") ? "Sponsoring" : undefined, beschreibung: `Zahlung Rechnung ${raw.nummer} · ${raw.empfaenger.split("\n")[0]}` });
    }
  } catch (e) { $("invoiceError").textContent = e.message; }
}
$("invPrint").onclick = () => { const raw = invoices.find(i => i.id === viewInvoiceId); if (raw) printPaper(invoiceHtml(parseInv(raw)), `Rechnung ${raw.nummer}`); };
$("invPaid").onclick = () => setInvoiceStatus("Bezahlt");
$("invOpen").onclick = () => setInvoiceStatus("Offen");
$("invStorno").onclick = () => setInvoiceStatus("Storniert");
$("invEdit").onclick = () => { $("invoiceView").close(); editInvoice(viewInvoiceId); };

// Rechnung erstellen / bearbeiten
let invDraft = null;
const ABS_FIELDS = [["ersteller","Rechnungsersteller / Ansprechpartner"],["adresse","Anschrift des Vereins",1],["telefon","Telefon"],["email","E-Mail"],["web","Webseite"],
  ["vorsitz","Vertreten durch"],["register","Vereinsregister"],["steuernummer","Steuernummer"],["ustid","USt-IdNr."],["bank","Bank"],["iban","IBAN"],["bic","BIC"],["fusszeile","Zusätzliche Fußzeile",1]];
function goInvoiceForm() { const h = route(IDX("Rechnung erstellen")); if (location.hash === h) render(); else location.hash = h; }
function newInvoice() { editingInvoiceId = null; invDraft = null; goInvoiceForm(); }
function editInvoice(id) { editingInvoiceId = id; invDraft = null; goInvoiceForm(); }
function makeDraft() {
  const v = settings.verein || {}, raw = invoices.find(i => i.id === editingInvoiceId);
  if (raw) {
    const r = parseInv(raw);
    return { _for: raw.id, nummer: raw.nummer, geaendert: raw.geaendert, datum: r.datum, leistungsdatum: r.leistungsdatum, faellig: r.faellig, faelligManual: true,
      empfaenger: r.empfaenger, betreff: r.betreff, einleitung: r.einleitung, schlusstext: r.schlusstext, absender: { ...r.absender },
      positionen: r.positionen.map(p => ({ beschreibung: p.beschreibung, menge: numDe(p.menge), einheit: p.einheit, preis: numDe((p.preis / 100).toFixed(2)), mwst: numDe(p.mwst) })) };
  }
  const d = today(), ziel = Number(v.zahlungsziel) || 0;
  return { _for: "new", datum: d, leistungsdatum: d, faellig: ziel ? addDays(d, ziel) : "", faelligManual: false, empfaenger: "", betreff: "",
    einleitung: v.einleitung || "", schlusstext: v.schlusstext || "", absender: Object.fromEntries(ABS_FIELDS.map(([k]) => [k, v[k] || ""])),
    positionen: [{ beschreibung: "", menge: "1", einheit: "", preis: "", mwst: numDe(v.mwst ?? "19") }] };
}
function draftPositions(strict) {
  return invDraft.positionen.map((p, i) => {
    const x = { beschreibung: p.beschreibung.trim(), menge: parseDe(p.menge), einheit: p.einheit.trim(), preis: Math.round(parseDe(p.preis) * 100), mwst: parseDe(p.mwst) };
    if (strict) {
      if (!x.beschreibung) throw new Error(`Position ${i + 1}: Bitte eine Beschreibung eingeben.`);
      if (!Number.isFinite(x.menge)) throw new Error(`Position ${i + 1}: Menge ist keine Zahl.`);
      if (!Number.isFinite(x.preis)) throw new Error(`Position ${i + 1}: Preis ist keine Zahl (z. B. 250,00).`);
      if (!Number.isFinite(x.mwst) || x.mwst < 0 || x.mwst > 100) throw new Error(`Position ${i + 1}: MwSt. zwischen 0 und 100 %.`);
    }
    return { ...x, menge: Number.isFinite(x.menge) ? x.menge : 0, preis: Number.isFinite(x.preis) ? x.preis : 0, mwst: Number.isFinite(x.mwst) ? x.mwst : 0 };
  });
}
function renderInvoiceForm() {
  const raw = editingInvoiceId && invoices.find(i => i.id === editingInvoiceId);
  if (editingInvoiceId && (!raw || raw.status === "Storniert")) { editingInvoiceId = null; invDraft = null; }
  if (!invDraft || invDraft._for !== (editingInvoiceId || "new")) invDraft = makeDraft();
  const D = invDraft, editing = !!editingInvoiceId;
  const ta = (k, rows, ph = "") => `<textarea data-f="${k}" rows="${rows}" placeholder="${esc(ph)}">${esc(D[k])}</textarea>`;
  $("view").innerHTML = `<form id="invForm" class="invform" novalidate>
    <div class="sectionhead"><h2>${editing ? `Rechnung ${esc(D.nummer)} bearbeiten` : "Neue Rechnung"}</h2><div class="actions" style="margin:0">
      <button type="button" class="quiet" data-act="settings">Vereinsdaten &amp; Vorlage</button>${editing ? '<button type="button" class="quiet" data-act="newInvoice">Neue Rechnung</button>' : ""}</div></div>
    <section class="card"><p class="muted small">Rechnungsnummer: <b id="invNo">${esc(editing ? D.nummer : nextNumber(D.datum.slice(0, 4)))}</b> ${editing ? "(fest)" : "(wird beim Erstellen automatisch vergeben)"} · Absender: <b>${CLUB}</b> mit Logo</p>
      <div class="fields">
        <label>Rechnungsempfänger (Name und Anschrift)${ta("empfaenger", 5, "Firma Muster GmbH\nz. Hd. Frau Beispiel\nHauptstraße 1\n75417 Mühlacker")}</label>
        <div><label>Rechnungsdatum<input type="date" data-f="datum" value="${esc(D.datum)}" required></label>
          <label>Leistungsdatum / -zeitraum<input type="date" data-f="leistungsdatum" value="${esc(D.leistungsdatum)}"></label>
          <label>Zahlbar bis<input type="date" data-f="faellig" value="${esc(D.faellig)}"></label></div>
      </div>
      <label>Betreff<input data-f="betreff" maxlength="200" value="${esc(D.betreff)}" placeholder="z. B. Bandenwerbung Saison 2026/27"></label>
      <label>Einleitung${ta("einleitung", 2)}</label>
    </section>
    <section class="card"><h3>Positionen</h3>
      <div class="tablewrap" style="margin-top:8px"><table class="table postable"><thead><tr><th>Beschreibung</th><th>Menge</th><th>Einheit</th><th>Einzelpreis netto €</th><th>MwSt. %</th><th class="money">Gesamt netto</th><th></th></tr></thead>
      <tbody id="posBody"></tbody></table></div>
      <div class="actions"><button type="button" class="quiet" data-act="addPos">＋ Position</button></div>
      <div class="invtotals" id="invTotals"></div>
    </section>
    <section class="card"><label>Schlusstext${ta("schlusstext", 4)}</label>
      <p class="muted small">Platzhalter: <code>{nummer}</code> <code>{faellig}</code> <code>{betrag}</code> <code>{ersteller}</code></p>
      <details style="margin-top:12px"><summary>Absender, Bank und Ersteller für diese Rechnung ändern</summary>
        <div class="fields">${ABS_FIELDS.map(([k, l, multi]) => `<label>${esc(l)}${multi ? `<textarea data-a="${k}" rows="2">${esc(D.absender[k] || "")}</textarea>` : `<input data-a="${k}" value="${esc(D.absender[k] || "")}">`}</label>`).join("")}</div>
        <label class="check"><input type="checkbox" id="invSaveDefault"> Diese Angaben auch als Standard für künftige Rechnungen speichern</label>
      </details>
    </section>
    <div id="invFormError" class="err" role="alert"></div>
    <div class="actions"><button id="invSave">${editing ? "Änderungen speichern" : "Rechnung erstellen"}</button><button type="button" class="quiet" data-act="cancelInvoice">Abbrechen</button></div>
  </form>
  <h3 style="margin:24px 0 0">Vorschau</h3><div class="previewwrap" id="invPreview"></div>`;
  renderPositions();
  const f = $("invForm");
  f.oninput = e => {
    const t = e.target, ds = t.dataset;
    if (ds.f) {
      D[ds.f] = t.value;
      if (ds.f === "faellig") D.faelligManual = true;
      if (ds.f === "datum" && !D.faelligManual && /^\d{4}-/.test(t.value)) {
        const ziel = Number(settings.verein?.zahlungsziel) || 0;
        if (ziel) { D.faellig = addDays(t.value, ziel); f.querySelector('[data-f="faellig"]').value = D.faellig; }
      }
      if (ds.f === "datum" && !editing && /^\d{4}-/.test(t.value)) $("invNo").textContent = nextNumber(t.value.slice(0, 4));
    } else if (ds.a) D.absender[ds.a] = t.value;
    else if (ds.p) { const [i, k] = ds.p.split(":"); D.positionen[i][k] = t.value; }
    updateInvPreview();
  };
  f.onsubmit = e => { e.preventDefault(); saveInvoice(); };
}
function renderPositions() {
  $("posBody").innerHTML = invDraft.positionen.map((p, i) => `<tr>
    <td><textarea data-p="${i}:beschreibung" rows="1" placeholder="z. B. Bandenwerbung 3 × 1 m, Saison 2026/27">${esc(p.beschreibung)}</textarea></td>
    <td><input class="num" data-p="${i}:menge" inputmode="decimal" value="${esc(p.menge)}"></td>
    <td><input class="small" data-p="${i}:einheit" value="${esc(p.einheit)}" placeholder="Stk."></td>
    <td><input class="num" data-p="${i}:preis" inputmode="decimal" value="${esc(p.preis)}" placeholder="0,00"></td>
    <td><input class="small" data-p="${i}:mwst" inputmode="decimal" value="${esc(p.mwst)}"></td>
    <td class="money" id="posSum${i}"></td>
    <td>${invDraft.positionen.length > 1 ? `<button type="button" class="quiet danger" data-delpos="${i}" aria-label="Position ${i + 1} entfernen">✕</button>` : ""}</td></tr>`).join("");
  updateInvPreview();
}
function draftInvoice() {
  const D = invDraft;
  return { nummer: D.nummer || nextNumber((D.datum || today()).slice(0, 4)) + " (vorläufig)", datum: D.datum, leistungsdatum: D.leistungsdatum, faellig: D.faellig,
    empfaenger: D.empfaenger, betreff: D.betreff, einleitung: D.einleitung, schlusstext: D.schlusstext, absender: D.absender, positionen: draftPositions(false), status: "Offen" };
}
function updateInvPreview() {
  if (!$("invPreview")) return;
  const inv = draftInvoice(), t = calcTotals(inv.positionen);
  inv.positionen.forEach((p, i) => { const c = $("posSum" + i); if (c) c.textContent = fmtEur(Math.round(p.menge * p.preis)); });
  $("invTotals").innerHTML = `<span>Summe netto</span><span class="money">${fmtEur(t.netto)}</span>` +
    t.rates.filter(r => r[0] > 0).map(r => `<span>MwSt. ${esc(fmtNum(r[0]))} %</span><span class="money">${fmtEur(r[2])}</span>`).join("") +
    `<span class="grand">Gesamtbetrag</span><span class="money grand">${fmtEur(t.brutto)}</span>`;
  $("invPreview").innerHTML = invoiceHtml(inv);
}
async function saveInvoice() {
  const D = invDraft, err = $("invFormError"); err.textContent = "";
  try {
    if (!D.empfaenger.trim()) throw new Error("Bitte den Rechnungsempfänger eingeben.");
    if (!D.datum) throw new Error("Bitte ein Rechnungsdatum eingeben.");
    const data = { datum: D.datum, leistungsdatum: D.leistungsdatum, faellig: D.faellig, empfaenger: D.empfaenger.trim(), betreff: D.betreff.trim(),
      einleitung: D.einleitung.trim(), schlusstext: D.schlusstext.trim(), positionen: draftPositions(true), absender: D.absender, geaendert: D.geaendert };
    if (!editingInvoiceId && !confirm(`Rechnung jetzt erstellen?\n\nSie bekommt die feste Nummer ${nextNumber(D.datum.slice(0, 4))} (oder die nächste freie).`)) return;
    $("invSave").disabled = true;
    const r = await api(editingInvoiceId ? "/api/rechnungen/" + editingInvoiceId : "/api/rechnungen", { method: editingInvoiceId ? "PUT" : "POST", data });
    if ($("invSaveDefault").checked) settings = await api("/api/einstellungen/verein", { method: "PUT", data: { ...(settings.verein || {}), ...D.absender } });
    invDraft = null; editingInvoiceId = null;
    await reload();
    location.hash = route(IDX("Rechnungen"));
    viewInvoice(r.rechnung.id);
    notice(`Rechnung ${r.rechnung.nummer} gespeichert.`, true);
  } catch (e) { err.textContent = e.message; if ($("invSave")) $("invSave").disabled = false; }
}

/* ---------------- Kasse (Vorstand liest, nur Schatzmeister schreibt) ---------------- */
const KS = () => kasse.einstellungen || { kategorien: [] };
const signed = b => (b.art === "einnahme" ? 1 : -1) * b.betrag;
function kasseStand() {
  const s = KS(), from = s.stichtag || "";
  const live = kasse.buchungen.filter(b => !b.storniert && b.datum >= from);
  const sum = weg => live.filter(b => b.zahlungsweg === weg).reduce((a, b) => a + signed(b), 0);
  return { bar: (s.anfang_bar || 0) + sum("bar"), bank: (s.anfang_bank || 0) + sum("bank") };
}
function filteredBookings() {
  const q = kFilter.q.trim().toLocaleLowerCase("de");
  return kasse.buchungen.filter(b => (!kFilter.jahr || b.datum.startsWith(kFilter.jahr)) && (!kFilter.monat || b.datum.slice(5, 7) === kFilter.monat)
    && (!kFilter.kategorie || b.kategorie === kFilter.kategorie) && (!kFilter.art || b.art === kFilter.art)
    && (!q || [b.belegnr, b.beschreibung, b.kategorie, b.rechnung_nr, b.storno_grund].join(" ").toLocaleLowerCase("de").includes(q)));
}
function renderKasse() {
  const y = today().slice(0, 4), st = kasseStand();
  const yearLive = kasse.buchungen.filter(b => !b.storniert && b.datum.startsWith(y));
  const ein = yearLive.filter(b => b.art === "einnahme").reduce((a, b) => a + b.betrag, 0), aus = yearLive.filter(b => b.art === "ausgabe").reduce((a, b) => a + b.betrag, 0);
  const years = distinct([y, ...kasse.buchungen.map(b => b.datum.slice(0, 4))]).reverse();
  const months = ["01","02","03","04","05","06","07","08","09","10","11","12"], mName = m => new Intl.DateTimeFormat("de-DE", { month: "long", timeZone: "UTC" }).format(new Date(Date.UTC(2000, Number(m) - 1, 1)));
  $("view").innerHTML = `<div class="sectionhead"><h2>Kasse</h2><div class="actions" style="margin:0">
      ${isSchatz() ? '<button class="quiet" data-act="kasseSettings">Einstellungen</button>' : ""}<button class="quiet" data-act="kasseCsv">CSV ${esc(kFilter.jahr || "alle Jahre")}</button></div></div>
    ${isSchatz() ? "" : '<p class="muted small" style="margin-bottom:12px">Nur lesen (Kassenprüfung) – buchen dürfen Admins und Schatzmeister/in, stornieren nur Schatzmeister/in.</p>'}
    <div class="stats">
      <div class="stat"><strong>${fmtEur(st.bar)}</strong>Kassenstand Bar</div>
      <div class="stat"><strong>${fmtEur(st.bank)}</strong>Kontostand Bank</div>
      <div class="stat"><strong class="k-in">${fmtEur(ein)}</strong>Einnahmen ${y}</div>
      <div class="stat"><strong class="k-out">${fmtEur(aus)}</strong>Ausgaben ${y}</div>
    </div>
    <div class="filters">
      <input id="ksearch" type="search" placeholder="Belegnr., Beschreibung, Rechnung …" aria-label="Buchungen durchsuchen" value="${esc(kFilter.q)}">
      <select id="kjahr" aria-label="Jahr"><option value="">Alle Jahre</option>${options(years, kFilter.jahr)}</select>
      <select id="kmonat" aria-label="Monat"><option value="">Alle Monate</option>${months.map(m => `<option value="${m}"${kFilter.monat === m ? " selected" : ""}>${mName(m)}</option>`).join("")}</select>
      <select id="kkat" aria-label="Kategorie"><option value="">Alle Kategorien</option>${options(distinct([...KS().kategorien, ...kasse.buchungen.map(b => b.kategorie)]), kFilter.kategorie)}</select>
      <select id="kart" aria-label="Art"><option value="">Einnahmen und Ausgaben</option><option value="einnahme"${kFilter.art === "einnahme" ? " selected" : ""}>Nur Einnahmen</option><option value="ausgabe"${kFilter.art === "ausgabe" ? " selected" : ""}>Nur Ausgaben</option></select>
    </div><div id="ktable"></div>`;
  for (const [id, k] of [["kjahr","jahr"],["kmonat","monat"],["kkat","kategorie"],["kart","art"]]) $(id).onchange = e => { kFilter[k] = e.target.value; renderKasseTable(); };
  $("ksearch").oninput = e => { kFilter.q = e.target.value; renderKasseTable(); };
  renderKasseTable();
}
function renderKasseTable() {
  const list = filteredBookings();
  const live = list.filter(b => !b.storniert), saldo = live.reduce((a, b) => a + signed(b), 0);
  $("ktable").innerHTML = !kasse.buchungen.length
    ? `<section class="card"><h3>Noch keine Buchungen</h3><p class="muted" style="margin-top:6px">${isSchatz() ? "Trage zuerst unter <b>Einstellungen</b> die Anfangsbestände ein, dann über <b>＋ Buchung</b> die erste Einnahme oder Ausgabe." : "Der Schatzmeister hat noch nichts gebucht."}</p></section>`
    : `<p class="muted small" style="margin-bottom:8px">${list.length} Buchungen · Saldo der Auswahl (ohne Stornos): <b>${fmtEur(saldo)}</b></p>
    <div class="tablewrap"><table class="table"><thead><tr><th>Beleg</th><th>Datum</th><th>Beschreibung</th><th>Kategorie</th><th>Weg</th><th class="money">Betrag</th><th></th></tr></thead><tbody>
    ${list.map(b => `<tr class="${b.storniert ? "storno" : ""}"><td style="white-space:nowrap"><b>${esc(b.belegnr)}</b></td><td>${esc(dateText(b.datum))}</td>
      <td>${esc(b.beschreibung)}${b.rechnung_nr ? `<div class="lock">Rechnung ${esc(b.rechnung_nr)}</div>` : ""}${b.storniert ? `<div class="lock">Storniert ${esc(fmtTime(b.storno_am))} von ${esc(b.storno_von)}: ${esc(b.storno_grund)}</div>` : ""}
        ${(b.belege || []).map(x => `<button class="quiet chip" data-beleg="${esc(x.id)}">📎 ${esc(x.dateiname)}</button>`).join(" ")}</td>
      <td>${esc(b.kategorie)}</td><td>${b.zahlungsweg === "bar" ? "Bar" : "Bank"}</td>
      <td class="money ${b.art === "einnahme" ? "k-in" : "k-out"}">${b.art === "einnahme" ? "+" : "−"} ${fmtEur(b.betrag)}</td>
      <td style="white-space:nowrap">${isSchatz() ? `<button class="quiet" data-kbeleg="${esc(b.id)}" title="Beleg anhängen">📎</button>${b.storniert || !D().stornieren ? "" : ` <button class="quiet danger" data-kstorno="${esc(b.id)}">Storno</button>`}` : ""}</td></tr>`).join("")
      || '<tr><td colspan="7" class="muted">Keine Treffer.</td></tr>'}
    </tbody></table></div>`;
}
const kasseForm = $("kasseForm"), kfield = n => kasseForm.elements.namedItem(n);
function newBooking(preset = {}) {
  if (!isSchatz()) return;
  kasseFromInvoice = preset.rechnung_id || null;
  kfield("datum").value = preset.datum || today(); kfield("art").value = preset.art || "einnahme";
  kfield("betrag").value = preset.betrag ? numDe((preset.betrag / 100).toFixed(2)) : ""; kfield("zahlungsweg").value = preset.zahlungsweg || "bank";
  const kats = KS().kategorien;
  kfield("kategorie").innerHTML = options(kats, preset.kategorie && kats.includes(preset.kategorie) ? preset.kategorie : kats[0]);
  kfield("rechnung_id").innerHTML = `<option value="">– keine –</option>` + invoices.filter(i => i.status !== "Storniert").map(i => `<option value="${esc(i.id)}"${i.id === preset.rechnung_id ? " selected" : ""}>${esc(i.nummer)} · ${esc(i.empfaenger.split("\n")[0])} · ${fmtEur(i.brutto)}</option>`).join("");
  kfield("beschreibung").value = preset.beschreibung || ""; kfield("beleg").value = ""; $("kasseError").textContent = "";
  $("kasseEditor").showModal();
}
kasseForm.onsubmit = async e => {
  e.preventDefault(); $("kasseError").textContent = "";
  const betrag = Math.round(parseDe(kfield("betrag").value) * 100), file = kfield("beleg").files[0];
  if (!Number.isFinite(betrag) || betrag <= 0) { $("kasseError").textContent = "Bitte einen Betrag größer als 0 eingeben (z. B. 49,90)."; return; }
  if (file && file.size > MAX_FILE) { $("kasseError").textContent = "Beleg zu groß (max. 10 MB)."; return; }
  const data = { datum: kfield("datum").value, art: kfield("art").value, betrag, zahlungsweg: kfield("zahlungsweg").value, kategorie: kfield("kategorie").value,
    rechnung_id: kfield("rechnung_id").value, beschreibung: kfield("beschreibung").value.trim() };
  $("kasseSave").disabled = true;
  try {
    let r;
    try { r = await api("/api/kasse", { method: "POST", data }); }
    catch (err) {
      if (!/gibt es schon die Buchung/.test(err.message) || !confirm(err.message + "\n\nTrotzdem noch einmal buchen?")) throw err;
      r = await api("/api/kasse", { method: "POST", data: { ...data, trotzdem: true } });
    }
    if (file) await api(`/api/kasse/${r.buchung.id}/belege`, { method: "POST", raw: file, headers: { "Content-Type": file.type || "application/octet-stream", "X-Dateiname": encodeURIComponent(file.name) } });
    $("kasseEditor").close(); kasseFromInvoice = null; await reload(); notice(`Gebucht: ${r.buchung.belegnr}.`, true);
  } catch (err) { $("kasseError").textContent = err.message; }
  finally { $("kasseSave").disabled = false; }
};
async function stornoBooking(id) {
  const b = kasse.buchungen.find(x => x.id === id); if (!b) return;
  const grund = prompt(`Buchung ${b.belegnr} (${fmtEur(b.betrag)}) stornieren?\n\nDie Buchung bleibt mit ihrer Nummer sichtbar, zählt aber nicht mehr mit. Bitte den Grund eingeben:`);
  if (grund === null) return;
  if (!grund.trim()) return notice("Ohne Grund kann nicht storniert werden.");
  try { kasse = await api(`/api/kasse/${id}/storno`, { method: "POST", data: { grund: grund.trim() } }); render(); notice(`${b.belegnr} storniert.`, true); }
  catch (e) { notice(e.message); }
}
let belegFor = null;
$("kasseBelegFile").onchange = async e => {
  const f = e.target.files[0]; e.target.value = ""; if (!f || !belegFor) return;
  if (f.size > MAX_FILE) return notice("Beleg zu groß (max. 10 MB).");
  try { await api(`/api/kasse/${belegFor}/belege`, { method: "POST", raw: f, headers: { "Content-Type": f.type || "application/octet-stream", "X-Dateiname": encodeURIComponent(f.name) } }); await reload(); notice("Beleg angehängt.", true); }
  catch (err) { notice(err.message); }
};
async function openBeleg(id) {
  const x = kasse.buchungen.flatMap(b => b.belege || []).find(b => b.id === id); if (!x) return;
  const win = window.open("", "_blank");
  try {
    const blob = new Blob([await api(`/api/kasse/belege/${id}`, { blob: true })], { type: x.mime || "application/octet-stream" });
    if (win && /^(application\/pdf|image\/)/.test(x.mime)) { const url = URL.createObjectURL(blob); win.location = url; setTimeout(() => URL.revokeObjectURL(url), 120000); }
    else { if (win) win.close(); download(blob, x.dateiname); }
  } catch (e) { if (win) win.close(); notice(e.message); }
}
function exportKasseCsv() {
  const list = [...filteredBookings()].sort((a, b) => (a.datum + a.belegnr).localeCompare(b.datum + b.belegnr));
  const cell = v => `"${String(v ?? "").replace(/"/g, '""')}"`, eur = c => (c / 100).toFixed(2).replace(".", ",");
  const head = ["Belegnr.","Datum","Art","Betrag","Einnahme","Ausgabe","Kategorie","Zahlungsweg","Beschreibung","Rechnung","Storniert","Storno-Grund","Beleg-Dateien","Erstellt von"];
  const rows = list.map(b => [b.belegnr, dateText(b.datum), b.art === "einnahme" ? "Einnahme" : "Ausgabe", eur(signed(b)), b.art === "einnahme" ? eur(b.betrag) : "", b.art === "ausgabe" ? eur(b.betrag) : "",
    b.kategorie, b.zahlungsweg === "bar" ? "Bar" : "Bank", b.beschreibung, b.rechnung_nr, b.storniert ? "ja" : "", b.storno_grund, (b.belege || []).map(x => x.dateiname).join(", "), b.erstellt_von].map(cell).join(";"));
  download(new Blob(["﻿" + [head.join(";"), ...rows].join("\r\n")], { type: "text/csv;charset=utf-8" }), `kassenbuch_${kFilter.jahr || "alle"}_${today()}.csv`);
}
const ksForm = $("kasseSettingsForm"), ksfield = n => ksForm.elements.namedItem(n);
function openKasseSettings() {
  const s = KS();
  ksfield("anfang_bar").value = numDe(((s.anfang_bar || 0) / 100).toFixed(2)); ksfield("anfang_bank").value = numDe(((s.anfang_bank || 0) / 100).toFixed(2));
  ksfield("stichtag").value = s.stichtag || ""; ksfield("kategorien").value = (s.kategorien || []).join("\n");
  $("kasseSettingsMeta").textContent = s.geaendert ? `Zuletzt geändert ${fmtTime(s.geaendert)} von ${s.geaendert_von}` : "";
  $("kasseSettingsError").textContent = ""; $("kasseSettings").showModal();
}
ksForm.onsubmit = async e => {
  e.preventDefault();
  const c = v => { const n = parseDe(v || "0"); return Math.round((Number.isFinite(n) ? n : NaN) * 100); };
  const data = { anfang_bar: c(ksfield("anfang_bar").value), anfang_bank: c(ksfield("anfang_bank").value), stichtag: ksfield("stichtag").value,
    kategorien: ksfield("kategorien").value.split("\n").map(s => s.trim()).filter(Boolean) };
  if (!Number.isFinite(data.anfang_bar) || !Number.isFinite(data.anfang_bank)) { $("kasseSettingsError").textContent = "Anfangsbestand ist keine Zahl (z. B. 150,00)."; return; }
  try { kasse = await api("/api/kasse/einstellungen", { method: "PUT", data }); $("kasseSettings").close(); render(); notice("Kasse: Einstellungen gespeichert.", true); }
  catch (err) { $("kasseSettingsError").textContent = err.message; }
};

/* ---------------- Funktionen (Admin) ---------------- */
async function funcApi(path, method, data, msg) {
  try { funktionen = (await api(path, { method, data })).funktionen; users = (await api("/api/benutzer")).benutzer; renderUsers(); notice(msg, true); }
  catch (e) { notice(e.message); }
}
function addFunc() {
  const name = prompt("Name der neuen Funktion (z. B. Kioskdienst):"); if (!name?.trim()) return;
  const g = prompt("Gruppe: 1 = Vorstand, 2 = Ausschuss, 3 = Sport, 4 = Fest, 5 = Sonstige", "5"); if (g === null) return;
  funcApi("/api/funktionen", "POST", { name: name.trim(), gruppe: ["Vorstand", "Ausschuss", "Sport", "Fest", "Sonstige"][Number(g) - 1] || "Sonstige" }, "Funktion angelegt. Rechte dafür unter „Rechte“ einstellen.");
}
function renameFunc(id) {
  const f = funktionen.find(x => x.id === id); if (!f) return;
  const name = prompt("Neuer Name:", f.name); if (!name?.trim() || name.trim() === f.name) return;
  funcApi("/api/funktionen/" + id, "PUT", { name: name.trim() }, "Funktion umbenannt.");
}
function toggleFunc(id) {
  const f = funktionen.find(x => x.id === id); if (!f) return;
  if (!confirm(f.aktiv ? `„${f.name}“ deaktivieren?\n\nAlle Konten mit dieser Funktion verlieren sofort die Rechte daraus.` : `„${f.name}“ wieder aktivieren?`)) return;
  funcApi("/api/funktionen/" + id, "PUT", { name: f.name, aktiv: !f.aktiv }, f.aktiv ? "Funktion deaktiviert." : "Funktion aktiviert.");
}
async function setKp(on) {
  try { matrix = await api("/api/rechte/kassenpruefer", { method: "PUT", data: { an: on } }); notice(on ? "Kassenprüfer/in darf Rechnungen und Kasse lesen." : "Kassenprüfer/in hat keinen Zugriff mehr auf Rechnungen und Kasse.", true); }
  catch (e) { notice(e.message); }
}
document.addEventListener("change", e => {
  if (e.target.matches(".mcell")) return setMatrix(e.target);
  if (e.target.dataset.act === "kpToggle") return setKp(e.target.checked);
});

/* ---------------- Chat (Polling: 5 s im offenen Raum, 30 s für die Zähler) ---------------- */
let chatOpen = null, chatMsgs = [], chatLast = 0, chatT = "", chatMod = false, chatTimer = null, lastListPoll = 0, lastMsgPoll = 0, chatBusy = false;
const roomById = id => chatRooms.find(r => r.id === id);
function chatHomeCard(always) {
  const unread = chatRooms.filter(r => r.mitglied && r.ungelesen);
  if (!unread.length && !always) return "";
  return `<section class="card"><div class="cardtop"><h2>Chat</h2><a class="link" href="${route(IDX("Chat"))}">öffnen</a></div>
    ${unread.length ? unread.map(r => `<button class="mini" data-room="${esc(r.id)}">${esc(r.name)}<small>${r.ungelesen} neue Nachricht${r.ungelesen === 1 ? "" : "en"}${r.erwaehnt ? " · du wurdest erwähnt" : ""}</small></button>`).join("") : '<p class="muted">Keine neuen Nachrichten.</p>'}</section>`;
}
function renderChat() {
  if (pendingRoom) { const id = pendingRoom; pendingRoom = null; return openRoom(id); }
  window.scrollTo(0, 0);
  const mine = chatRooms.filter(r => r.mitglied), manage = chatRooms.filter(r => !r.mitglied && r.verwalten);
  const item = r => `<button class="roomitem${chatOpen === r.id ? " on" : ""}" data-room="${esc(r.id)}"><span><b>${esc(r.name)}</b><small>${esc(r.beschreibung || (r.alle ? "Alle angemeldeten" : ""))}</small></span>
    <span class="roombadges">${r.erwaehnt ? '<span class="count at">@</span>' : ""}${r.ungelesen ? `<span class="count unread">${r.ungelesen}</span>` : ""}</span></button>`;
  $("view").innerHTML = `<div class="chat${chatOpen ? " open" : ""}">
    <div class="roomlist"><div class="sectionhead" style="margin:0 0 8px"><h2>Chat</h2></div>
      ${mine.map(item).join("") || '<p class="muted small">Du bist in keinem Raum Mitglied.</p>'}
      ${manage.length ? `<p class="muted small" style="margin:14px 0 4px">Von dir verwaltet, du bist kein Mitglied (Nachrichten nicht lesbar):</p>
        ${manage.map(r => `<div class="roomitem off"><span><b>${esc(r.name)}</b></span><button class="quiet" data-roomedit="${esc(r.id)}">Verwalten</button></div>`).join("")}` : ""}
    </div>
    <section class="room" id="room">${chatOpen ? "" : '<p class="muted" style="padding:20px">Wähle links einen Raum.</p>'}</section></div>`;
  sizeChat();
  if (chatOpen) renderRoom();
}
// Chat passt sich dem Platz an: schmal (Handy, iPad hochkant mit Seitenleiste) = eine Spalte mit ‹ zurück;
// Höhe so, dass Menü/Reiter oben und das Eingabefeld unten immer sichtbar bleiben – ohne die Seite zu verschieben
function sizeChat() {
  const c = document.querySelector(".chat"); if (!c) return;
  c.classList.toggle("narrow", c.clientWidth < 700);
  c.style.height = Math.max(340, window.innerHeight - c.getBoundingClientRect().top - 12) + "px";
}
window.addEventListener("resize", () => { if (document.querySelector(".chat")) { const box = $("msgs"), bottom = box && box.scrollHeight - box.scrollTop - box.clientHeight < 80; sizeChat(); if (bottom) box.scrollTop = box.scrollHeight; } });
function msgHtml(m) {
  const own = m.benutzer_id === me.id;
  const text = esc(m.text).replace(/(^|\s)(@[\wÄÖÜäöüß.\-]+(?: [\wÄÖÜäöüß.\-]+)?)/g, (all, sp, at) => `${sp}<mark class="${me.anzeigename && at.slice(1).toLowerCase().startsWith(me.anzeigename.toLowerCase().split(" ")[0]) ? "me" : ""}">${at}</mark>`).replace(/\n/g, "<br>");
  return `<div class="msg${own ? " own" : ""}" id="m${m.id}"><div class="mhead"><b>${esc(m.autor)}</b> <span class="lock">${esc(fmtTime(m.erstellt))}${m.bearbeitet && !m.geloescht ? " · bearbeitet" : ""}</span>
    ${!m.geloescht && (own || chatMod) ? `<span class="mtools">${own ? `<button class="linkbtn" data-msgedit="${m.id}">bearbeiten</button>` : ""}<button class="linkbtn" data-msgdel="${m.id}">löschen</button></span>` : ""}</div>
    <div class="mtext">${m.geloescht ? '<i class="lock">Nachricht gelöscht</i>' : text}</div></div>`;
}
function renderRoom() {
  const r = roomById(chatOpen), el = $("room"); if (!r || !el) return;
  el.innerHTML = `<div class="roomhead"><button class="quiet back" data-act="chatBack" aria-label="Zurück zur Raumliste">‹</button>
      <div><b>${esc(r.name)}</b><div class="lock">${esc(r.beschreibung)}</div></div>${r.verwalten ? `<button class="quiet" data-roomedit="${esc(r.id)}">Verwalten</button>` : ""}</div>
    <div class="msgs" id="msgs">${chatMsgs.map(msgHtml).join("") || '<p class="muted" style="padding:12px">Noch keine Nachrichten. Schreib die erste!</p>'}</div>
    <form class="composer" id="composer"><textarea id="chatText" rows="2" maxlength="4000" placeholder="Nachricht schreiben … (@Name erwähnt jemanden)" aria-label="Nachricht"></textarea>
      <button id="chatSend">Senden</button></form>`;
  sizeChat();
  const box = $("msgs"); box.scrollTop = box.scrollHeight;
  $("composer").onsubmit = e => { e.preventDefault(); sendMsg(); };
  $("chatText").onkeydown = e => { if (e.key === "Enter" && !e.shiftKey && !matchMedia("(pointer: coarse)").matches) { e.preventDefault(); sendMsg(); } };
}
function updateMsgs() {
  const box = $("msgs"); if (!box) return;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  box.innerHTML = chatMsgs.map(msgHtml).join("") || '<p class="muted" style="padding:12px">Noch keine Nachrichten. Schreib die erste!</p>';
  if (atBottom) box.scrollTop = box.scrollHeight;
}
function mergeMsgs(list) {
  for (const m of list) { const i = chatMsgs.findIndex(x => x.id === m.id); if (i >= 0) chatMsgs[i] = m; else chatMsgs.push(m); chatLast = Math.max(chatLast, m.id); }
  chatMsgs.sort((a, b) => a.id - b.id);
}
let pendingRoom = null;
async function openRoom(id) {
  if (IDX("Chat") !== section) { pendingRoom = id; location.hash = route(IDX("Chat")); return; }
  chatOpen = id; chatMsgs = []; chatLast = 0;
  renderChat();
  try { const r = await api(`/api/chat/${id}`); chatMod = r.moderieren; chatT = r.jetzt; mergeMsgs(r.nachrichten); updateMsgs(); await markRead(); }
  catch (e) { notice(e.message); }
}
async function pollMsgs() {
  if (!chatOpen || chatBusy) return;
  chatBusy = true;
  try {
    const r = await api(`/api/chat/${chatOpen}?seit=${chatLast}&t=${encodeURIComponent(chatT)}`);
    chatT = r.jetzt; chatMod = r.moderieren;
    if (r.nachrichten.length) { mergeMsgs(r.nachrichten); updateMsgs(); await markRead(); }
  } catch {} finally { chatBusy = false; }
}
async function markRead() {
  if (!chatOpen || !chatLast) return;
  try { await api(`/api/chat/${chatOpen}/gelesen`, { method: "POST", data: { bis: chatLast } }); } catch {}
  const r = roomById(chatOpen); if (r) { r.ungelesen = 0; r.erwaehnt = 0; }
  renderNav(); for (const b of document.querySelectorAll(`.roomitem[data-room="${chatOpen}"] .roombadges`)) b.innerHTML = "";
}
async function sendMsg() {
  const ta = $("chatText"), text = ta.value.trim(); if (!text || !chatOpen) return;
  if (text.length > 4000) return notice("Höchstens 4000 Zeichen.");
  $("chatSend").disabled = true;
  try { const r = await api(`/api/chat/${chatOpen}`, { method: "POST", data: { text } }); ta.value = ""; mergeMsgs([r.nachricht]); updateMsgs(); $("msgs").scrollTop = $("msgs").scrollHeight; }
  catch (e) { notice(e.message); }
  finally { $("chatSend").disabled = false; ta.focus(); }
}
async function editMsg(id) {
  const m = chatMsgs.find(x => x.id === id); if (!m) return;
  const text = prompt("Nachricht bearbeiten:", m.text); if (text === null || !text.trim() || text === m.text) return;
  try { await api(`/api/chat/nachricht/${id}`, { method: "PUT", data: { text: text.trim() } }); m.text = text.trim(); m.bearbeitet = new Date().toISOString(); updateMsgs(); }
  catch (e) { notice(e.message); }
}
async function deleteMsg(id) {
  const m = chatMsgs.find(x => x.id === id); if (!m || !confirm(m.benutzer_id === me.id ? "Deine Nachricht löschen?" : `Nachricht von ${m.autor} als Raum-Admin entfernen?`)) return;
  try { await api(`/api/chat/nachricht/${id}`, { method: "DELETE" }); m.geloescht = true; m.text = ""; updateMsgs(); }
  catch (e) { notice(e.message); }
}
async function refreshRooms() {
  try {
    chatRooms = (await api("/api/chat")).raeume; renderNav();
    if (sections[section] === "Chat" && !chatOpen) renderChat();
    else if (sections[section] === "Chat") for (const r of chatRooms) { const b = document.querySelector(`.roomitem[data-room="${r.id}"] .roombadges`); if (b && r.id !== chatOpen) b.innerHTML = `${r.erwaehnt ? '<span class="count at">@</span>' : ""}${r.ungelesen ? `<span class="count unread">${r.ungelesen}</span>` : ""}`; }
  } catch {}
}
// Ein Takt alle 5 s: offener Raum bei sichtbarem Tab alle 5 s, Zähler alle 30 s (auch im Hintergrund)
function startChatPolling() {
  clearInterval(chatTimer); lastListPoll = Date.now();
  chatTimer = setInterval(() => {
    if (!me) return clearInterval(chatTimer);
    const now = Date.now(), visible = document.visibilityState === "visible";
    if (visible && chatOpen && sections[section] === "Chat" && now - lastMsgPoll >= 5000) { lastMsgPoll = now; pollMsgs(); }
    if (now - lastListPoll >= 30000) { lastListPoll = now; refreshRooms(); }
  }, 5000);
}
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && me) { refreshRooms(); if (chatOpen) pollMsgs(); } });

// Räume anlegen/verwalten (Admin: alle; Festwirt/in: nur für sein Festwirt-Team)
const roomForm = $("roomForm"), rfield = n => roomForm.elements.namedItem(n);
let activeRoomId = null;
function editRoom(id) {
  const r = id ? roomById(id) : null, rules = r?.regeln || [], has = (t, v) => rules.some(x => x.typ === t && x.wert === v);
  const admin = !!me.ist_admin;
  activeRoomId = id || null;
  $("roomFormTitle").textContent = r ? "Raum verwalten" : "Neuer Raum";
  rfield("name").value = r?.name || ""; rfield("beschreibung").value = r?.beschreibung || "";
  rfield("alle").checked = !!r?.alle; rfield("aktiv").checked = r ? r.aktiv : true;
  $("roomAlleWrap").hidden = !admin;
  const check = (t, v, label) => `<label class="check"><input type="checkbox" data-rt="${t}" data-rv="${esc(v)}"${has(t, v) ? " checked" : ""}> ${esc(label)}</label>`;
  const ft = funktionen.find(f => f.schluessel === "festwirt_team");
  const people = admin ? users.filter(u => u.aktiv) : teamUsers.filter(u => u.aktiv);
  $("roomRules").innerHTML = (admin ? `<div class="fgroup"><b>Grundrollen</b>${Object.entries(ROLE).map(([k, l]) => check("rolle", k, l)).join("")}</div>
      <div class="fgroup"><b>Funktionen</b>${funktionen.filter(f => f.aktiv).map(f => check("funktion", f.id, f.name)).join("")}</div>`
    : `<div class="fgroup"><b>Funktion</b>${ft ? check("funktion", ft.id, ft.name + " (alle)") : ""}</div>`)
    + `<div class="fgroup"><b>Einzelne Personen</b>${people.map(u => check("person", u.id, u.anzeigename)).join("") || '<span class="lock">keine</span>'}</div>`;
  $("roomHint").textContent = admin ? "Admins verwalten Räume, lesen die Nachrichten aber nur, wenn sie selbst Mitglied sind." : "Als Festwirt/in kannst du Räume nur für dein Festwirt-Team anlegen. Du bist automatisch Mitglied.";
  $("roomError").textContent = ""; $("roomEditor").showModal(); rfield("name").focus();
}
roomForm.onsubmit = async e => {
  e.preventDefault(); $("roomError").textContent = "";
  const data = { name: rfield("name").value.trim(), beschreibung: rfield("beschreibung").value.trim(), alle: rfield("alle").checked, aktiv: rfield("aktiv").checked,
    regeln: [...$("roomRules").querySelectorAll("[data-rt]:checked")].map(x => ({ typ: x.dataset.rt, wert: x.dataset.rv })) };
  if (!data.alle && !data.regeln.length && me.ist_admin) { $("roomError").textContent = "Bitte „Alle angemeldeten“ oder mindestens eine Rolle, Funktion oder Person wählen."; return; }
  try { chatRooms = (await api(activeRoomId ? "/api/chat/raeume/" + activeRoomId : "/api/chat/raeume", { method: activeRoomId ? "PUT" : "POST", data })).raeume;
    $("roomEditor").close(); notice("Raum gespeichert.", true); renderNav(); if (sections[section] === "Chat") renderChat(); }
  catch (err) { $("roomError").textContent = err.message; }
};

/* ---------------- Ereignisse ---------------- */
$("add").onclick = () => {
  const n = sections[section];
  if (n === "Chat") return editRoom(null);
  if (n === "Mein Team") return newTeamAccount();
  if (n === "Kasse") newBooking();
  else if (n === "Dokumente") editDoc(); else if (n === "Benutzer") editUser(); else if (n === "Mitglieder") editMember();
  else if (n === "Downloads") editDownload(); else if (n === "Rechnungen") newInvoice(); else edit();
};
document.querySelectorAll("[data-close]").forEach(b => b.onclick = () => b.closest("dialog").close());
$("importJson").onchange = e => { const f = e.target.files[0]; e.target.value = ""; if (f) importJsonFile(f); };
$("globalSearch").addEventListener("keydown", e => {
  if (e.key !== "Enter" || !e.target.value.trim()) return;
  const term = e.target.value.trim(), hits = entries.filter(r => matches(r, term));
  history.replaceState(null, "", "#start"); section = 0; $("hero").hidden = true; $("crumb").textContent = "Suche"; renderNav();
  $("view").innerHTML = `<div class="sectionhead"><h2>Suche: „${esc(term)}“</h2><span class="muted small">${hits.length} Treffer</span></div>` + (hits.map(r => card(r, true)).join("") || '<p class="muted">Keine Treffer.</p>');
});
document.addEventListener("click", async e => {
  const b = e.target.closest("button, .day, a[data-act]"); if (!b) return;
  const ds = b.dataset;
  if (b.matches("a[data-act]")) e.preventDefault();
  if (ds.dlopen) return openDownload(ds.dlopen, false);
  if (ds.dldl) return openDownload(ds.dldl, true);
  if (ds.dledit) return editDownload(ds.dledit);
  if (ds.dlnew) return editDownload(null, ds.dlnew);
  if (ds.invview) return viewInvoice(ds.invview);
  if (ds.utab) { uTab = ds.utab; return renderUsers(); }
  if (ds.funcren) return renameFunc(ds.funcren);
  if (ds.functog) return toggleFunc(ds.functog);
  if (ds.teamtog) return teamToggle(ds.teamtog);
  if (ds.teampw) return teamPassword(ds.teampw);
  if (ds.room) return openRoom(ds.room);
  if (ds.roomedit) return editRoom(ds.roomedit);
  if (ds.msgedit) return editMsg(Number(ds.msgedit));
  if (ds.msgdel) return deleteMsg(Number(ds.msgdel));
  if (ds.walink) return editWaLink(ds.walink);
  if (ds.teamedit) return editTeam(ds.teamedit);
  if (ds.beleg) return openBeleg(ds.beleg);
  if (ds.kbeleg) { belegFor = ds.kbeleg; return $("kasseBelegFile").click(); }
  if (ds.kstorno) return stornoBooking(ds.kstorno);
  if (ds.assign !== undefined || ds.assignnew !== undefined) {
    const u = teamsUnassigned[Number(ds.assign ?? ds.assignnew)]; if (!u) return;
    if (ds.assignnew !== undefined) {
      if (!confirm(`„${u.name}“ als neue Mannschaft anlegen und alle ${u.mitglieder + u.eltern} Einträge zuordnen?`)) return;
      try { const r = await api("/api/mannschaften", { method: "POST", data: { name: u.name, sortierung: teams.length + 1, aktiv: true } });
        const t = r.mannschaften.find(x => normTeam(x.name) === normTeam(u.name));
        return teamApi("/api/mannschaften/zuordnen", "POST", { text: u.name, mannschaft_id: t.id }, `„${u.name}“ angelegt und zugeordnet.`); }
      catch (e) { return notice(e.message); }
    }
    const sel = document.querySelector(`[data-assignsel="${ds.assign}"]`);
    if (!sel?.value) return notice("Bitte zuerst eine Mannschaft auswählen.");
    return teamApi("/api/mannschaften/zuordnen", "POST", { text: u.name, mannschaft_id: sel.value }, `„${u.name}“ → ${teamName(sel.value)} zugeordnet.`);
  }
  if (ds.delpos !== undefined) { invDraft.positionen.splice(Number(ds.delpos), 1); return renderPositions(); }
  if (ds.edit) { e.stopPropagation(); return edit(entries.find(r => r.id === ds.edit)); }
  if (ds.day) return edit(null, { datum: ds.day, bereich: "Kalender", status: "Geplant" });
  if (ds.done) return markDone(ds.done);
  if (ds.copy) { const r = entries.find(x => x.id === ds.copy); try { await navigator.clipboard.writeText(r.inhalt); notice("Text kopiert.", true); } catch { notice("Kopieren fehlgeschlagen."); } return; }
  if (ds.docopen) return openDoc(ds.docopen, false);
  if (ds.docdl) return openDoc(ds.docdl, true);
  if (ds.docedit) return editDoc(ds.docedit);
  if (ds.useredit) return editUser(ds.useredit);
  if (ds.att) return openAttachment(ds.att);
  if (ds.attdel) return deleteAttachment(ds.attdel);
  if (ds.memberedit) return editMember(ds.memberedit);
  if (ds.parentedit) return editParent(ds.parentedit);
  if (ds.mail) return openMail(ds.mail);
  if (ds.rsvp) return answer(ds.rsvp, ds.a);
  switch (ds.act) {
    case "settings": return openSettings();
    case "addFunc": return addFunc();
    case "chatBack": chatOpen = null; return renderChat();
    case "addTeam": return editTeam(null);
    case "kasseSettings": return openKasseSettings();
    case "kasseCsv": return exportKasseCsv();
    case "printMembership": return printPaper(membershipHtml(), "Aufnahmeantrag FC Sender Kickers United");
    case "logoPng": return logoFile("png");
    case "logoJpg": return logoFile("jpg");
    case "logoIcon": return logoFile("icon");
    case "newInvoice": return newInvoice();
    case "cancelInvoice": invDraft = null; editingInvoiceId = null; location.hash = route(IDX("Rechnungen")); return;
    case "addPos": invDraft.positionen.push({ beschreibung: "", menge: "1", einheit: "", preis: "", mwst: numDe(settings.verein?.mwst ?? "19") }); return renderPositions();
    case "importPeople": return pickPeopleFile(ds.kind);
    case "membersCsv": return exportMembersCsv();
    case "addParent": return editParent();
    case "mailAll": return openMail(null);
    case "copyMails": return copyMails();
    case "sheetImport": return importSheetEntries();
    case "sheetAttach": pendingSheet = null; $("importBox").innerHTML = `<p>„${esc(field("datei").files[0]?.name || "")}“ wird beim <b>Speichern</b> an diesen Eintrag angehängt.</p>`; return;
    case "logout": return logout();
    case "changepw": return showPwChange();
    case "genpw": ufield("passwort").value = genPassword(); return;
    case "ics": return exportIcs();
    case "csv": return exportCsv();
    case "exportJson": return exportJson();
    case "importJson": return $("importJson").click();
    case "calView": calView = ds.v; return render();
    case "calPrev": return shiftMonth(-1);
    case "calNext": return shiftMonth(1);
    case "calToday": calMonth = today().slice(0,7); if ($("month")) $("month").value = calMonth; renderCalendar(); return renderCards();
  }
});
window.addEventListener("hashchange", () => { $("notice").textContent = ""; render(true); });

/* ---------------- Start ---------------- */
(async function init() {
  if (!API || API.includes("DEIN-NAME")) {
    authMode("loginForm", "Noch nicht verbunden", "In config.js fehlt die Adresse des Servers (API_URL). Siehe ANLEITUNG.md.");
    $("loginForm").hidden = true; return;
  }
  try {
    if (getToken()) {
      me = (await api("/api/ich")).benutzer;
      return me.pw_aendern ? showPwChange() : startApp();
    }
    const s = await api("/api/einrichtung");
    s.einrichtung_noetig ? showSetup() : showLogin();
  } catch (e) {
    if (!me) { authMode("loginForm", "Vereinszentrale", e.message); }
  }
})();
