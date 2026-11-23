// Bringt eine Sicherung aus `wrangler d1 export` in eine Reihenfolge, die sich wieder einspielen lässt.
//
// Problem: Der Export legt die Tabellen in der Reihenfolge an, in der sie in der Datenbank stehen.
// Seit Tabellen neu aufgebaut wurden (z. B. benutzer), kommt eine Tabelle evtl. VOR der Tabelle, auf die sie
// verweist (sitzungen → benutzer). Beim Einspielen meldet SQLite dann „no such table: main.benutzer“.
// Lösung: Tabellen so sortieren, dass jede Tabelle nach den Tabellen kommt, auf die sie verweist.
//
// Aufruf (im Ordner worker):   node tools/sicherung-sortieren.mjs backup.sql backup_sortiert.sql
import fs from "node:fs";

const [, , inFile, outFile] = process.argv;
if (!inFile || !outFile) { console.error("Aufruf: node tools/sicherung-sortieren.mjs <eingabe.sql> <ausgabe.sql>"); process.exit(1); }
const src = fs.readFileSync(inFile, "utf8");

// In Anweisungen zerlegen – Semikolons in Texten ('…') und Bezeichnern ("…") nicht beachten
const stmts = []; let cur = "", q = null;
for (let i = 0; i < src.length; i++) {
  const c = src[i]; cur += c;
  if (q) { if (c === q) { if (src[i + 1] === q) { cur += src[++i]; } else q = null; } }
  else if (c === "'" || c === '"') q = c;
  else if (c === ";") { if (cur.trim() !== ";") stmts.push(cur.trim()); cur = ""; }
}
if (cur.trim()) stmts.push(cur.trim());

const tableOf = s => { const m = s.match(/^(?:CREATE TABLE(?: IF NOT EXISTS)?|INSERT INTO)\s+"?([\w]+)"?/i); return m ? m[1] : null; };
const head = [], tail = [], tables = new Map();   // name → { create, inserts[], refs[] }
for (const s of stmts) {
  if (/^PRAGMA/i.test(s) || /^BEGIN|^COMMIT/i.test(s)) { head.push(s); continue; }
  const t = tableOf(s);
  if (!t || t === "sqlite_sequence") { tail.push(s); continue; }
  if (!tables.has(t)) tables.set(t, { create: null, inserts: [], refs: [] });
  const e = tables.get(t);
  if (/^CREATE TABLE/i.test(s)) { e.create = s; e.refs = [...s.matchAll(/REFERENCES\s+"?(\w+)"?/gi)].map(m => m[1]).filter(r => r !== t); }
  else e.inserts.push(s);
}
// Topologisch sortieren (stabil: ursprüngliche Reihenfolge, wo möglich)
const order = [], done = new Set(), busy = new Set();
const visit = n => {
  if (done.has(n) || !tables.has(n)) return;
  if (busy.has(n)) throw new Error("Zyklische Verweise bei Tabelle " + n);
  busy.add(n); for (const r of tables.get(n).refs) visit(r); busy.delete(n);
  done.add(n); order.push(n);
};
for (const n of tables.keys()) visit(n);

// D1 nimmt höchstens 100 KB pro Anweisung an. Große Dateien (X'…' am Ende der Werte) in Stücke teilen:
// erst mit dem ersten Stück einfügen, dann Stück für Stück anhängen (CAST … AS BLOB hält die Bytes unverändert).
const MAX = 90000, CHUNK_HEX = 80000;
let split = 0;
function splitValues(s) {           // Werte-Liste an Kommas außerhalb von Anführungszeichen trennen
  const parts = []; let c = "", qq = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (qq) { c += ch; if (ch === qq) { if (s[i + 1] === qq) c += s[++i]; else qq = null; } }
    else if (ch === "'" || ch === '"') { qq = ch; c += ch; }
    else if (ch === ",") { parts.push(c.trim()); c = ""; }
    else c += ch;
  }
  parts.push(c.trim()); return parts;
}
function chunkInsert(s) {
  if (s.length <= MAX) return [s];
  const m = s.match(/^INSERT INTO\s+("?\w+"?)\s*\(([^)]*)\)\s*VALUES\s*\(([\s\S]*)\);?$/i);
  if (!m) return [s];
  const cols = m[2].split(",").map(x => x.trim()), vals = splitValues(m[3]);
  const bi = vals.findIndex(v => /^X'[0-9a-f]*'$/i.test(v));
  if (bi < 0 || cols.length !== vals.length) return [s];
  const hex = vals[bi].slice(2, -1), where = cols.map((c, i) => i === bi ? null : `${c}=${vals[i]}`).filter(Boolean).join(" AND ");
  const res = [];
  for (let i = 0; i < hex.length; i += CHUNK_HEX) {
    const part = `X'${hex.slice(i, i + CHUNK_HEX)}'`;
    if (i === 0) { const v = [...vals]; v[bi] = part; res.push(`INSERT INTO ${m[1]} (${m[2]}) VALUES(${v.join(",")})`); }
    else res.push(`UPDATE ${m[1]} SET ${cols[bi]} = CAST(${cols[bi]} || ${part} AS BLOB) WHERE ${where}`);
  }
  split++; return res;
}

const out = [...head];
if (!head.some(s => /defer_foreign_keys/i.test(s))) out.unshift("PRAGMA defer_foreign_keys=TRUE");
for (const n of order) { const e = tables.get(n); if (e.create) out.push(e.create); for (const s of e.inserts) out.push(...chunkInsert(s)); }
out.push(...tail);
fs.writeFileSync(outFile, out.map(s => s.endsWith(";") ? s : s + ";").join("\n") + "\n");
console.log(`${stmts.length} Anweisungen, ${order.length} Tabellen sortiert → ${outFile}`);
console.log("Reihenfolge: " + order.join(", "));
if (split) console.log(`${split} große Datei(en) in Stücke geteilt (D1-Grenze 100 KB pro Anweisung).`);
