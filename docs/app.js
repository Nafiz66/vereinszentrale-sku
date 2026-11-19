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

let me = null, entries = [], docs = [], users = [];
let sections = [], section = 0, filter = "", search = "", calMonth = today().slice(0,7), calView = "monat";
let activeId = null, activeDocId = null, activeUserId = null;

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
  clearToken(); me = null; entries = docs = users = []; showLogin("Du wurdest abgemeldet.");
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
  sections = ["Übersicht", ...GROUPS.filter(g => me.bereiche.includes(g))];
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
    const jobs = [api("/api/eintraege").then(r => entries = r.eintraege)];
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
    const sep = ["Dokumente","Benutzer","Mein Konto"].includes(s) && !["Dokumente","Benutzer"].includes(sections[i-1]) ? '<div class="navsep"></div>' : "";
    const n = c[s] ? `<span class="count">${c[s]}</span>` : "";
    return `${sep}<a href="${route(i)}"${i===section?' aria-current="page"':""}>${esc(s)}${n}</a>`;
  }).join("");
}

function card(r, showGroup = false) {
  const meta = [dateText(r.datum) + (r.uhrzeit ? " · " + r.uhrzeit + " Uhr" : ""), r.ort, r.zustaendig, r.quelle].filter(Boolean).map(esc).join(" · ");
  const body = r.inhalt ? `<p class="body">${esc(r.inhalt)}</p>` : "";
  const parent = r.bereich === "Elternkommunikation";
  return `<article class="card">${showGroup ? `<div class="meta">${esc(r.bereich)}</div>` : ""}<div class="cardtop"><h3>${esc(r.titel)}</h3>${badge(r.status)}</div>
    ${meta ? `<div class="meta">${meta}</div>` : ""}
    ${r.inhalt.length > 1700 ? `<details><summary>Volltext anzeigen</summary>${body}</details>` : body}
    <div class="actions">
      <button class="quiet" data-edit="${esc(r.id)}">Bearbeiten</button>
      ${!["Erledigt","Bestätigt"].includes(r.status) ? `<button class="quiet" data-done="${esc(r.id)}">✓ Erledigt</button>` : ""}
      ${parent ? `<button class="quiet" data-copy="${esc(r.id)}">Text kopieren</button><a class="btnlink quiet" target="_blank" rel="noopener noreferrer" href="https://wa.me/?text=${encodeURIComponent(r.inhalt)}">Per WhatsApp teilen</a>` : ""}
    </div></article>`;
}
function mini(items, empty) {
  return items.length ? items.map(r => `<button class="mini" data-edit="${esc(r.id)}">${esc(r.titel)}<small>${esc([dateText(r.datum), r.zustaendig, r.status].filter(Boolean).join(" · "))}</small></button>`).join("")
    : `<p class="muted">${empty}</p>`;
}

function render(reset = false) {
  if (!me) return;
  const next = Number(location.hash.match(/^#bereich-(\d+)$/)?.[1]) || 0;
  if (reset || next !== section) { filter = ""; search = ""; }
  section = next < sections.length ? next : 0;
  const name = sections[section];
  $("hero").hidden = section !== 0;
  $("crumb").textContent = section ? name : "Vereinszentrale";
  $("add").hidden = ["Änderungsprotokoll","Mein Konto"].includes(name);
  $("add").textContent = name === "Dokumente" ? "＋ Dokument" : name === "Benutzer" ? "＋ Benutzer" : "＋ Eintrag";
  renderNav();
  if (!section) renderHome();
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
    <p class="muted" style="margin-bottom:14px;max-width:80ch"><b>Vorstand</b> sieht und bearbeitet alles. <b>Ausschuss</b> sieht und bearbeitet nur ${esc(["Beiträge & Ehrenamt","Mannschaften","Elternkommunikation","Sponsoren","Kalender"].join(", "))} und darf nichts löschen. <b>Admin</b> verwaltet zusätzlich die Benutzer.</p>
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
  if (!confirm(`${list.length} Einträge als neue Einträge importieren?`)) return;
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
  editor.showModal(); field("titel").focus();
}
form.onsubmit = async e => {
  e.preventDefault();
  const v = Object.fromEntries(FIELDS.map(k => [k, String(field(k).value || "").trim()]));
  $("save").disabled = true; $("error").textContent = "";
  try {
    if (activeId) await api("/api/eintraege/" + activeId, { method: "PUT", data: { ...v, geaendert: entries.find(r => r.id === activeId)?.geaendert } });
    else await api("/api/eintraege", { method: "POST", data: v });
    editor.close(); notice(activeId ? "Eintrag gespeichert." : "Eintrag angelegt.", true); await reload();
  } catch (err) { $("error").textContent = err.message; }
  finally { $("save").disabled = false; }
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

/* ---------------- Ereignisse ---------------- */
$("add").onclick = () => { const n = sections[section]; n === "Dokumente" ? editDoc() : n === "Benutzer" ? editUser() : edit(); };
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
  switch (ds.act) {
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
