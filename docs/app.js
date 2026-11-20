/* Vereinszentrale · FC Sender Kickers United – Frontend (GitHub Pages)
 * Alle Daten liegen in der SQLite-Datenbank (Cloudflare D1) hinter dem Worker.
 * Der Server prüft bei jeder Anfrage Anmeldung und Rolle – die Oberfläche blendet nur zusätzlich aus.
 */
"use strict";

const API = String(window.VZ_CONFIG?.API_URL || "").replace(/\/+$/, "");
const GROUPS = ["Satzung & Beschlüsse","Vorstand & Ausschuss","Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender","Gründungsplan","Offene Entscheidungen"];
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
const ROLE = { vorstand: "Vorstand", ausschuss: "Ausschuss" };

const MEMBER_STATUSES = ["Aktiv","Passiv","Ausgetreten"];
const MAX_FILE = 10 * 1024 * 1024, MAX_IMPORT = 1000;
const EMAIL_RE = /^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/;

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
  clearToken(); me = null; entries = docs = users = members = parents = []; showLogin("Du wurdest abgemeldet.");
}
let idleTimer;
function resetIdle() {
  clearTimeout(idleTimer);
  if (me && store() === sessionStorage) idleTimer = setTimeout(() => { logout().then(() => showLogin("Wegen Inaktivität abgemeldet.")); }, IDLE_MINUTES * 60000);
}
["click","keydown"].forEach(ev => document.addEventListener(ev, resetIdle, { passive: true }));

/* ---------------- App-Aufbau ---------------- */
const isVorstand = () => me?.rolle === "vorstand";
function buildSections() {
  sections = ["Übersicht", ...GROUPS.filter(g => me.bereiche.includes(g)), "Mitglieder"];
  if (isVorstand()) sections.push("Dokumente", "Änderungsprotokoll");
  if (me.ist_admin) sections.push("Benutzer");
  sections.push("Mein Konto");
}
const IDX = name => sections.indexOf(name);
const route = i => i ? "#bereich-" + i : "#start";

async function startApp() {
  $("authScreen").hidden = true; $("appScreen").hidden = false;
  buildSections();
  $("userName").textContent = me.anzeigename;
  $("userRole").textContent = ROLE[me.rolle] + (me.ist_admin ? " · Admin" : "");
  $("heroText").textContent = isVorstand() ? "Gründung, Aufgaben und Termine an einem Ort." : "Mannschaften, Termine und Elternkommunikation an einem Ort.";
  resetIdle();
  await reload();
}
async function reload() {
  try {
    const jobs = [api("/api/eintraege").then(r => entries = r.eintraege),
      api("/api/mitglieder").then(r => members = r.liste), api("/api/eltern").then(r => parents = r.liste)];
    if (isVorstand()) jobs.push(api("/api/dokumente").then(r => docs = r.dokumente));
    if (me.ist_admin) jobs.push(api("/api/benutzer").then(r => users = r.benutzer));
    await Promise.all(jobs);
    render();
  } catch (e) { $("view").innerHTML = `<p class="muted">${esc(e.message)}</p>`; }
}

function notice(text, ok = false) { const n = $("notice"); n.textContent = text; n.className = ok ? "ok" : ""; clearTimeout(notice.t); notice.t = setTimeout(() => n.textContent = "", 6000); }

function renderNav() {
  const c = {}; for (const r of entries) if (r.status !== "Erledigt") c[r.bereich] = (c[r.bereich] || 0) + 1;
  $("nav").innerHTML = sections.map((s, i) => {
    const sep = ["Mitglieder","Dokumente","Benutzer","Mein Konto"].includes(s) && !["Mitglieder","Dokumente","Benutzer"].includes(sections[i-1]) ? '<div class="navsep"></div>' : "";
    const n = c[s] ? `<span class="count">${c[s]}</span>` : "";
    return `${sep}<a href="${route(i)}"${i===section?' aria-current="page"':""}>${esc(s)}${n}</a>`;
  }).join("");
}

function card(r, showGroup = false) {
  const meta = [dateText(r.datum) + (r.uhrzeit ? " · " + r.uhrzeit + " Uhr" : ""), r.ort, r.zustaendig, r.quelle].filter(Boolean).map(esc).join(" · ");
  const body = r.inhalt ? `<p class="body">${esc(r.inhalt)}</p>` : "";
  const parent = r.bereich === "Elternkommunikation";
  const files = (r.anhaenge || []).map(a => `<button class="quiet chip" data-att="${esc(a.id)}" title="${esc(a.dateiname)} öffnen">📎 ${esc(a.dateiname)} <small>(${fmtBytes(a.groesse)})</small></button>`).join("");
  return `<article class="card">${showGroup ? `<div class="meta">${esc(r.bereich)}</div>` : ""}<div class="cardtop"><h3>${esc(r.titel)}</h3>${badge(r.status)}</div>
    ${meta ? `<div class="meta">${meta}</div>` : ""}
    ${r.inhalt.length > 1700 ? `<details><summary>Volltext anzeigen</summary>${body}</details>` : body}
    ${files ? `<div class="attachments">${files}</div>` : ""}
    <div class="actions">
      <button class="quiet" data-edit="${esc(r.id)}">Bearbeiten</button>
      ${!["Erledigt","Bestätigt"].includes(r.status) ? `<button class="quiet" data-done="${esc(r.id)}">✓ Erledigt</button>` : ""}
      ${parent ? `<button class="quiet" data-mail="${esc(r.id)}">✉ Per E-Mail an Eltern</button><button class="quiet" data-copy="${esc(r.id)}">Text kopieren</button><a class="btnlink quiet" target="_blank" rel="noopener noreferrer" href="https://wa.me/?text=${encodeURIComponent(r.inhalt)}">Per WhatsApp teilen</a>` : ""}
    </div></article>`;
}
function mini(items, empty) {
  return items.length ? items.map(r => `<button class="mini" data-edit="${esc(r.id)}">${esc(r.titel)}<small>${esc([dateText(r.datum), r.zustaendig, r.status].filter(Boolean).join(" · "))}</small></button>`).join("")
    : `<p class="muted">${empty}</p>`;
}

function render(reset = false) {
  if (!me) return;
  const next = Number(location.hash.match(/^#bereich-(\d+)$/)?.[1]) || 0;
  if (reset || next !== section) { filter = ""; search = ""; mFilter = { q: "", team: "", status: "" }; }
  section = next < sections.length ? next : 0;
  const name = sections[section];
  $("hero").hidden = section !== 0;
  $("crumb").textContent = section ? name : "Vereinszentrale";
  $("add").hidden = ["Änderungsprotokoll","Mein Konto"].includes(name);
  $("add").textContent = name === "Dokumente" ? "＋ Dokument" : name === "Benutzer" ? "＋ Benutzer" : name === "Mitglieder" ? "＋ Mitglied" : "＋ Eintrag";
  renderNav();
  if (!section) renderHome();
  else if (name === "Mitglieder") renderMembers();
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
  let extra = "";
  if (isVorstand()) {
    const plan = entries.filter(r => r.bereich === "Gründungsplan"), done = plan.filter(r => ["Erledigt","Bestätigt"].includes(r.status)).length;
    const pct = plan.length ? Math.round(done / plan.length * 100) : 0;
    extra = `<section class="card"><div class="cardtop"><h2>Gründungsfortschritt</h2><a class="link" href="${route(IDX("Gründungsplan"))}">Gründungsplan</a></div>
        <div class="progress" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><span style="width:${pct}%"></span></div>
        <p class="muted">${done} von ${plan.length} Schritten erledigt (${pct} %)</p></section>
      <section class="card"><div class="cardtop"><h2>Unterlagen</h2><a class="link" href="${route(IDX("Dokumente"))}">Dokumente</a></div>
        <p class="muted" style="margin-top:8px">${docs.length} Dokumente erfasst, ${docs.filter(d => d.groesse).length} mit hinterlegter Datei.</p></section>`;
  }
  $("view").innerHTML = `
    <div class="stats">
      ${stat(by("Offen").length, "Offen", isVorstand() ? route(IDX("Offene Entscheidungen")) : cal)}
      ${stat(by("Geplant").length, "Geplant", cal)}
      ${stat(by("Bestätigt").length, "Bestätigt", isVorstand() ? route(IDX("Satzung & Beschlüsse")) : cal)}
      ${stat(by("Schätzung").length, "Schätzungen", route(IDX("Beiträge & Ehrenamt")))}
    </div>
    <div class="homegrid">${extra}
      <section class="card"><div class="cardtop"><h2>Nächste Termine</h2><a class="link" href="${cal}">Kalender</a></div>${mini(upcoming, "Keine anstehenden Termine.")}</section>
      <section class="card"><h2>Offene Punkte</h2>${mini(open, "Keine offenen Punkte.")}</section>
      <section class="card"><h2>Zuletzt geändert</h2>${recent.map(r => `<button class="mini" data-edit="${esc(r.id)}">${esc(r.titel)}<small>${esc(fmtTime(r.geaendert))} · ${esc(r.geaendert_von)}</small></button>`).join("") || '<p class="muted">Noch nichts.</p>'}</section>
    </div>`;
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
    const ev = (byDay[iso] || []).sort((a,b) => a.uhrzeit.localeCompare(b.uhrzeit)).map(r => `<button class="ev" data-s="${esc(r.status)}" data-edit="${esc(r.id)}" title="${esc(r.titel)}">${r.uhrzeit ? esc(r.uhrzeit)+" " : ""}${esc(r.titel)}</button>`).join("");
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
function renderMembers() {
  const teams = distinct(members.map(m => m.mannschaft));
  $("view").innerHTML = `<div class="sectionhead"><h2>Mitglieder</h2><div class="actions" style="margin:0">
      <button class="quiet" data-act="importPeople" data-kind="mitglieder">CSV/Excel-Datei hochladen</button>
      <button class="quiet" data-act="membersCsv">Als CSV exportieren</button></div></div>
    <div class="filters">
      <input id="msearch" type="search" placeholder="Name, E-Mail, Telefon …" aria-label="Mitglieder durchsuchen" value="${esc(mFilter.q)}">
      <select id="mteam" aria-label="Mannschaft filtern"><option value="">Alle Mannschaften</option>${options(teams, mFilter.team)}</select>
      <select id="mstatus" aria-label="Status filtern"><option value="">Alle Status</option>${options(MEMBER_STATUSES, mFilter.status)}</select>
    </div><div id="mtable"></div>`;
  $("msearch").oninput = e => { mFilter.q = e.target.value; renderMemberTable(); };
  $("mteam").onchange = e => { mFilter.team = e.target.value; renderMemberTable(); };
  $("mstatus").onchange = e => { mFilter.status = e.target.value; renderMemberTable(); };
  renderMemberTable();
}
function filteredMembers() {
  const q = mFilter.q.trim().toLocaleLowerCase("de");
  return members.filter(m => (!mFilter.team || m.mannschaft === mFilter.team) && (!mFilter.status || m.status === mFilter.status)
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
      <td>${esc(m.mannschaft)}</td><td class="wrap">${m.email ? `<a class="link" href="mailto:${esc(m.email)}">${esc(m.email)}</a>` : ""}</td><td>${esc(m.telefon)}</td>
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
  const rows = parents.map(p => `<tr><td>${esc(p.name)}</td><td>${esc(p.kind)}</td><td>${esc(p.mannschaft)}</td><td class="wrap">${esc(p.email)}</td>
    <td><button class="quiet" data-parentedit="${esc(p.id)}">Bearbeiten</button></td></tr>`).join("");
  return `<section class="card parentsbox"><div class="cardtop"><h3>Eltern-Verteiler <span class="muted small">${parents.length} ${parents.length === 1 ? "Adresse" : "Adressen"}</span></h3>
      <div class="actions" style="margin:0"><button class="quiet" data-act="addParent">＋ Eltern</button>
      <button class="quiet" data-act="importPeople" data-kind="eltern">CSV/Excel-Datei hochladen</button>
      ${parents.length ? '<button class="quiet" data-act="mailAll">✉ E-Mail an Eltern</button>' : ""}</div></div>
    ${parents.length ? `<details${parents.length <= 8 ? " open" : ""}><summary>Liste anzeigen</summary><div class="tablewrap" style="margin-top:8px"><table class="table">
      <thead><tr><th>Name</th><th>Kind</th><th>Mannschaft</th><th>E-Mail</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></details>`
      : '<p class="muted small" style="margin-top:8px">Noch keine Eltern eingetragen. Füge Adressen einzeln hinzu oder lade eine CSV/Excel-Liste hoch.</p>'}
  </section>`;
}

function renderDocs() {
  $("view").innerHTML = `<div class="sectionhead"><h2>Dokumente</h2></div>
    <p class="muted" style="margin-bottom:18px;max-width:78ch">Nur für den Vorstand sichtbar. Dateien werden in der Vereinsdatenbank gespeichert (max. 10 MB pro Datei).</p>
    ${docs.map(d => `<article class="card"><div class="cardtop"><h3>${esc(d.titel)}</h3>${badge(d.status)}</div>
      <div class="meta">${esc([dateText(d.datum), d.groesse ? d.dateiname + " · " + fmtBytes(d.groesse) : "Noch keine Datei hinterlegt"].filter(Boolean).join(" · "))}</div>
      ${d.beschreibung ? `<p class="body">${esc(d.beschreibung)}</p>` : ""}
      <div class="actions">
        ${d.groesse ? `<button data-docopen="${esc(d.id)}">Öffnen</button><button class="quiet" data-docdl="${esc(d.id)}">Herunterladen</button>` : ""}
        <button class="quiet" data-docedit="${esc(d.id)}">${d.groesse ? "Bearbeiten" : "Datei hochladen"}</button>
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

function renderUsers() {
  const roleBadge = u => `<span class="rolebadge${u.rolle === "ausschuss" ? " aus" : ""}">${ROLE[u.rolle]}</span>${u.ist_admin ? ' <span class="rolebadge adm">Admin</span>' : ""}`;
  $("view").innerHTML = `<div class="sectionhead"><h2>Benutzer</h2><span class="muted small">${users.length} Konten</span></div>
    <p class="muted" style="margin-bottom:14px;max-width:80ch"><b>Vorstand</b> sieht und bearbeitet alles. <b>Ausschuss</b> sieht und bearbeitet nur ${esc(["Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender","Mitglieder"].join(", "))} und darf nichts löschen. <b>Admin</b> verwaltet zusätzlich die Benutzer.</p>
    <div class="tablewrap"><table class="table"><thead><tr><th>Name</th><th>Benutzername</th><th>Rolle</th><th>Letzter Login</th><th>Status</th><th></th></tr></thead><tbody>
    ${users.map(u => `<tr><td><b>${esc(u.anzeigename)}</b></td><td>${esc(u.benutzername)}</td><td>${roleBadge(u)}</td><td class="lock">${esc(u.letzter_login ? fmtTime(u.letzter_login) : "noch nie")}</td>
      <td>${u.aktiv ? (u.pw_aendern ? '<span class="lock">wartet auf 1. Login</span>' : "aktiv") : '<span class="lock">deaktiviert</span>'}</td>
      <td><button class="quiet" data-useredit="${esc(u.id)}">Bearbeiten</button></td></tr>`).join("")}
    </tbody></table></div>`;
}

function renderAccount() {
  $("view").innerHTML = `<div class="sectionhead"><h2>Mein Konto</h2></div>
    <div class="optgrid">
      <section class="card"><h2>${esc(me.anzeigename)}</h2>
        <dl class="kv"><dt>Benutzername</dt><dd>${esc(me.benutzername)}</dd><dt>Rolle</dt><dd>${ROLE[me.rolle]}${me.ist_admin ? " · Admin" : ""}</dd>
        <dt>Bereiche</dt><dd>${esc(me.bereiche.join(", "))}</dd><dt>Angemeldet</dt><dd>${store() === localStorage ? "dauerhaft auf diesem Gerät" : `bis zum Schließen des Browsers (Abmeldung nach ${IDLE_MINUTES} Min. Inaktivität)`}</dd></dl>
        <div class="actions"><button class="quiet" data-act="changepw">Passwort ändern</button><button class="quiet" data-act="logout">Abmelden</button></div></section>
      <section class="card"><h2>Export</h2>
        <p>Termine für den Handy-Kalender${isVorstand() ? ", Einträge als Excel-Tabelle und eine komplette Sicherung als JSON" : " und Einträge als Excel-Tabelle"}.</p>
        <div class="actions"><button class="quiet" data-act="ics">Termine (.ics)</button><button class="quiet" data-act="csv">Einträge (CSV)</button>
        ${isVorstand() ? '<button class="quiet" data-act="exportJson">Sicherung (JSON)</button><button class="quiet" data-act="importJson">JSON importieren</button>' : ""}</div></section>
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
  const extra = [["mitglieder", "Mitglieder"], ["eltern", "Eltern-Adressen"]].filter(([k]) => Array.isArray(data[k]) && data[k].length);
  if (!confirm(`${list.length} Einträge als neue Einträge importieren?${extra.map(([k, l]) => `\nDazu ${data[k].length} ${l} (Doppelte werden übersprungen).`).join("")}`)) return;
  for (const [k] of extra) {
    const keys = k === "mitglieder" ? MEMBER_KEYS : PARENT_KEYS;
    for (let i = 0; i < data[k].length; i += MAX_IMPORT)
      try { await api(`/api/${k}/import`, { method: "POST", data: { liste: data[k].slice(i, i + MAX_IMPORT).map(x => Object.fromEntries(keys.map(f => [f, x[f] ?? ""]))), datei: file.name } }); } catch (e) { notice(e.message); }
  }
  let n = 0;
  for (const r of list) {
    const v = { titel: r.titel ?? r.title, bereich: GROUPS.includes(r.bereich ?? r.group) ? (r.bereich ?? r.group) : "Offene Entscheidungen",
      status: STATUSES.includes(r.status) ? r.status : "Offen", datum: r.datum ?? r.date ?? "", uhrzeit: r.uhrzeit ?? "", ort: r.ort ?? "",
      zustaendig: r.zustaendig ?? r.owner ?? "", inhalt: r.inhalt ?? r.body ?? "", quelle: r.quelle ?? r.source ?? "Import" };
    if (!v.titel) continue;
    try { await api("/api/eintraege", { method: "POST", data: v }); n++; } catch {}
  }
  notice(`${n} Einträge importiert.`, true); reload();
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
  return { list, skipped, info: columnInfo(t.headers, map, MEMBER_LABELS), extra: extra.map(i => t.headers[i]),
    cols: [["Name", m => memberName(m)], ["Geburtsdatum", m => dateText(m.geburtsdatum)], ["Mannschaft", m => m.mannschaft], ["E-Mail", m => m.email], ["Telefon", m => m.telefon]] };
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
  return { list, skipped, info: columnInfo(t.headers, map, PARENT_LABELS), extra: extra.map(i => t.headers[i]),
    cols: [["Name", p => p.name], ["E-Mail", p => p.email], ["Kind", p => p.kind], ["Mannschaft", p => p.mannschaft]] };
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
  activeId = rec?.id || null;
  $("formTitle").textContent = activeId ? "Eintrag bearbeiten" : "Eintrag anlegen";
  $("remove").hidden = !activeId || !me.darf_loeschen; $("duplicate").hidden = !activeId;
  $("error").textContent = "";
  const cur = sections[section];
  field("bereich").innerHTML = options(me.bereiche, rec?.bereich || preset.bereich || (me.bereiche.includes(cur) ? cur : me.bereiche[0]));
  field("status").innerHTML = options(STATUSES, rec?.status || preset.status || (cur === "Kalender" ? "Geplant" : "Offen"));
  for (const k of ["titel","datum","uhrzeit","ort","zustaendig","inhalt","quelle"]) field(k).value = rec?.[k] ?? preset[k] ?? "";
  $("formMeta").textContent = rec ? `Zuletzt geändert ${fmtTime(rec.geaendert)} von ${rec.geaendert_von}` : "";
  field("datei").value = ""; pendingSheet = null; $("importBox").hidden = true; $("importBox").innerHTML = "";
  renderAttachList(rec);
  editor.showModal(); field("titel").focus();
}
function renderAttachList(rec) {
  $("attachList").innerHTML = (rec?.anhaenge || []).map(a => `<span><button type="button" class="quiet chip" data-att="${esc(a.id)}">📎 ${esc(a.dateiname)} <small>(${fmtBytes(a.groesse)})</small></button>${me.darf_loeschen ? `<button type="button" class="quiet danger chip" data-attdel="${esc(a.id)}" aria-label="${esc(a.dateiname)} löschen">✕</button>` : ""}</span>`).join("");
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
  $("docRemove").hidden = !d; $("docError").textContent = "";
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
  $("userError").textContent = ""; syncAdminBox();
  userEditor.showModal();
}
function syncAdminBox() { const v = ufield("rolle").value === "vorstand"; ufield("ist_admin").disabled = !v; if (!v) ufield("ist_admin").checked = false; }
ufield("rolle").onchange = syncAdminBox;
userForm.onsubmit = async e => {
  e.preventDefault(); $("userError").textContent = "";
  const data = { anzeigename: ufield("anzeigename").value.trim(), rolle: ufield("rolle").value, ist_admin: ufield("ist_admin").checked, aktiv: ufield("aktiv").checked };
  try {
    if (activeUserId) users = (await api("/api/benutzer/" + activeUserId, { method: "PUT", data })).benutzer;
    else {
      const name = ufield("benutzername").value.trim().toLowerCase(), pw = ufield("passwort").value;
      if (pw.length < 10) throw new Error("Startpasswort: mindestens 10 Zeichen.");
      users = (await api("/api/benutzer", { method: "POST", data: { ...data, benutzername: name, passwort: await clientHash(name, pw) } })).benutzer;
      alert(`Konto angelegt.\n\nBenutzername: ${name}\nStartpasswort: ${pw}\n\nBitte persönlich oder per Telefon weitergeben – nicht per E-Mail. Beim ersten Login muss ein eigenes Passwort gesetzt werden.`);
    }
    userEditor.close(); notice("Benutzer gespeichert.", true); render();
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
function fillTeams() { $("teamList").innerHTML = distinct([...members.map(m => m.mannschaft), ...parents.map(p => p.mannschaft)]).map(t => `<option value="${esc(t)}">`).join(""); }
const memberForm = $("memberForm"), mfield = n => memberForm.elements.namedItem(n);
const MEMBER_KEYS = ["vorname","nachname","geburtsdatum","mannschaft","email","telefon","eintritt","status","notiz"];
function editMember(id) {
  activeMemberId = id || null; const m = members.find(x => x.id === id);
  $("memberFormTitle").textContent = m ? memberName(m) : "Mitglied anlegen";
  $("memberHint").hidden = !!m; $("memberRemove").hidden = !m || !me.darf_loeschen; $("memberError").textContent = "";
  mfield("status").innerHTML = options(MEMBER_STATUSES, m?.status || "Aktiv");
  for (const k of MEMBER_KEYS) if (k !== "status") mfield(k).value = m?.[k] ?? "";
  $("memberMeta").textContent = m ? `Zuletzt geändert ${fmtTime(m.geaendert)} von ${m.geaendert_von}` : "";
  fillTeams(); $("memberEditor").showModal(); mfield("vorname").focus();
}
memberForm.onsubmit = async e => {
  e.preventDefault(); $("memberError").textContent = "";
  const data = Object.fromEntries(MEMBER_KEYS.map(k => [k, String(mfield(k).value || "").trim()]));
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
const PARENT_KEYS = ["name","email","kind","mannschaft","notiz"];
function editParent(id) {
  activeParentId = id || null; const p = parents.find(x => x.id === id);
  $("parentFormTitle").textContent = p ? "Eltern bearbeiten" : "Eltern hinzufügen";
  $("parentHint").hidden = !!p; $("parentRemove").hidden = !p || !me.darf_loeschen; $("parentError").textContent = "";
  for (const k of PARENT_KEYS) pfield(k).value = p?.[k] ?? "";
  fillTeams(); $("parentEditor").showModal(); pfield("name").focus();
}
parentForm.onsubmit = async e => {
  e.preventDefault(); $("parentError").textContent = "";
  const data = Object.fromEntries(PARENT_KEYS.map(k => [k, String(pfield(k).value || "").trim()]));
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
const recipients = () => { const t = xfield("mannschaft").value; return [...new Set(parents.filter(p => !t || p.mannschaft === t).map(p => p.email.toLowerCase()))]; };
function updateMailCount() { const n = recipients().length; $("mailCount").textContent = n ? `${n} Empfänger` : "Keine Empfänger für diese Auswahl."; }
function openMail(entryId) {
  if (!parents.length) return notice("Im Eltern-Verteiler stehen noch keine Adressen. Füge sie oben bei „Eltern-Verteiler“ hinzu.");
  const r = entries.find(x => x.id === entryId);
  const teams = distinct(parents.map(p => p.mannschaft));
  xfield("mannschaft").innerHTML = `<option value="">Alle Eltern (${new Set(parents.map(p => p.email.toLowerCase())).size})</option>` +
    teams.map(t => `<option value="${esc(t)}">Nur ${esc(t)} (${new Set(parents.filter(p => p.mannschaft === t).map(p => p.email.toLowerCase())).size})</option>`).join("");
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

/* ---------------- Ereignisse ---------------- */
$("add").onclick = () => { const n = sections[section]; n === "Dokumente" ? editDoc() : n === "Benutzer" ? editUser() : n === "Mitglieder" ? editMember() : edit(); };
document.querySelectorAll("[data-close]").forEach(b => b.onclick = () => b.closest("dialog").close());
$("importJson").onchange = e => { const f = e.target.files[0]; e.target.value = ""; if (f) importJsonFile(f); };
$("globalSearch").addEventListener("keydown", e => {
  if (e.key !== "Enter" || !e.target.value.trim()) return;
  const term = e.target.value.trim(), hits = entries.filter(r => matches(r, term));
  history.replaceState(null, "", "#start"); section = 0; $("hero").hidden = true; $("crumb").textContent = "Suche"; renderNav();
  $("view").innerHTML = `<div class="sectionhead"><h2>Suche: „${esc(term)}“</h2><span class="muted small">${hits.length} Treffer</span></div>` + (hits.map(r => card(r, true)).join("") || '<p class="muted">Keine Treffer.</p>');
});
document.addEventListener("click", async e => {
  const b = e.target.closest("button, .day"); if (!b) return;
  const ds = b.dataset;
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
  switch (ds.act) {
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
