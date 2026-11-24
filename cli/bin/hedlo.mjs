#!/usr/bin/env node
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { basename, join, resolve } from "node:path";
import { collect, pack, validate } from "../src/pack.mjs";
import { day, discountBody, listingPatch, money, table, toMinor } from "../src/commands.mjs";

const VERSION = "0.1.0";
const DEFAULT_URL = "https://marketplace.hedlo.io";

function fail(message, code = 1) {
  process.stderr.write(`hedlo: ${message}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2);
      if (v !== undefined) out.flags[k] = v;
      else if (argv[i + 1] && !argv[i + 1].startsWith("-")) out.flags[k] = argv[++i];
      else out.flags[k] = true;
    } else if (a === "-o" || a === "-d") out.flags[a === "-o" ? "out" : "dir"] = argv[++i];
    else out._.push(a);
  }
  return out;
}

function baseUrl(flags) {
  const raw = String(flags.url ?? process.env.HEDLO_MARKET_URL ?? DEFAULT_URL).replace(/\/+$/, "");
  let u;
  try {
    u = new URL(raw);
  } catch {
    fail(`not a URL: ${raw}`);
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) fail("the marketplace URL must use https");
  return u.origin;
}

function configDir() {
  if (process.env.HEDLO_CONFIG_DIR) return process.env.HEDLO_CONFIG_DIR;
  if (process.platform === "win32") return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "hedlo");
  return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "hedlo");
}

function credentialsFile() {
  return join(configDir(), "credentials.json");
}

function readCredentials() {
  try {
    const v = JSON.parse(readFileSync(credentialsFile(), "utf8"));
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}

function writeCredentials(all) {
  const dir = configDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = credentialsFile();
  writeFileSync(file, JSON.stringify(all, null, 2) + "\n", { mode: 0o600 });
  try {
    chmodSync(file, 0o600);
  } catch {}
}

function session(url) {
  if (process.env.HEDLO_TOKEN) return { token: process.env.HEDLO_TOKEN, publisher: process.env.HEDLO_PUBLISHER ?? "" };
  const s = readCredentials()[url];
  if (!s || !s.token) fail("not signed in; run hedlo login (or set HEDLO_TOKEN in CI)");
  if (s.expiresAt && Date.now() >= s.expiresAt) fail("the stored token expired; run hedlo login");
  return s;
}

async function call(url, path, init = {}) {
  let res;
  try {
    res = await fetch(url + path, { ...init, headers: { "user-agent": `hedlo-cli/${VERSION}`, accept: "application/json", ...(init.headers ?? {}) }, redirect: "error" });
  } catch (e) {
    fail(`cannot reach ${url}: ${e instanceof Error ? e.message : e}`);
  }
  const text = await res.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

async function authed(url, path, init = {}) {
  const s = session(url);
  const r = await call(url, path, { ...init, headers: { authorization: `Bearer ${s.token}`, ...(init.headers ?? {}) } });
  if (r.status === 401) fail(`${r.body?.message ?? "unauthorized"}; run hedlo login`);
  if (r.status >= 400 && r.status !== 422) fail(r.body?.message ?? `request failed with ${r.status}`);
  return r.body;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function login(flags) {
  const url = baseUrl(flags);
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const scope = flags["read-only"] ? "read" : flags.finance ? "publish read finance" : "publish read";
  const start = await call(url, "/api/v1/device/code", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code_challenge: challenge, code_challenge_method: "S256", client_name: `hedlo CLI on ${hostname()}`.slice(0, 60), scope }) });
  if (start.status !== 200 || !start.body?.device_code) fail(start.body?.message ?? "could not start sign-in");
  const d = start.body;
  process.stdout.write(`\nOpen ${d.verification_uri_complete}\nand confirm the code ${d.user_code}\n\nWaiting for approval…\n`);
  let interval = Math.max(5, Number(d.interval) || 5) * 1000;
  const until = Date.now() + Number(d.expires_in) * 1000;
  while (Date.now() < until) {
    await sleep(interval);
    const r = await call(url, "/api/v1/device/token", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_code: d.device_code, code_verifier: verifier }) });
    if (r.status === 200 && r.body?.access_token) {
      const all = readCredentials();
      all[url] = { token: r.body.access_token, publisher: r.body.publisher, scope: r.body.scope, expiresAt: Date.now() + Number(r.body.expires_in) * 1000 };
      writeCredentials(all);
      process.stdout.write(`Signed in as publisher ${r.body.publisher}. Token stored in ${credentialsFile()}\n`);
      return;
    }
    const err = r.body?.error;
    if (err === "authorization_pending") continue;
    if (err === "slow_down") {
      interval += 5000;
      continue;
    }
    if (err === "access_denied") fail("the request was denied in the browser");
    if (err === "expired_token") fail("the code expired; run hedlo login again");
    fail(r.body?.message ?? err ?? `sign-in failed with ${r.status}`);
  }
  fail("the code expired; run hedlo login again");
}

function logout(flags) {
  const url = baseUrl(flags);
  const all = readCredentials();
  if (!all[url]) {
    process.stdout.write("Not signed in.\n");
    return;
  }
  delete all[url];
  if (Object.keys(all).length) writeCredentials(all);
  else rmSync(credentialsFile(), { force: true });
  process.stdout.write(`Signed out of ${url}. Revoke the token under Tokens in the dashboard if it may have leaked.\n`);
}

async function whoami(flags) {
  const url = baseUrl(flags);
  const me = await authed(url, "/api/v1/whoami");
  process.stdout.write(`${me.email}\npublisher  ${me.publisher.name} (${me.publisher.slug}), ${me.publisher.standing}\ntoken      ${me.token.name} ${me.token.prefix}… [${me.token.scopes.join(", ")}] until ${new Date(me.token.expiresAt).toISOString().slice(0, 10)}\n`);
}

function init(flags) {
  const dir = resolve(String(flags.dir ?? "."));
  const file = join(dir, "hedlo.json");
  if (existsSync(file) && !flags.force) fail("hedlo.json already exists (use --force to overwrite)");
  const publisher = String(flags.publisher ?? readCredentials()[baseUrl(flags)]?.publisher ?? "your-handle");
  const slug = basename(dir).toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "") || "item";
  const product = String(flags.product ?? "loom");
  const kind = String(flags.kind ?? "plugin");
  const manifest = { id: `${publisher}.${slug}`, kind, product, version: "0.1.0", name: slug, summary: "", categories: ["utilities"], readme: "README.md", changelog: "CHANGELOG.md" };
  writeFileSync(file, JSON.stringify(manifest, null, 2) + "\n");
  if (!existsSync(join(dir, "README.md"))) writeFileSync(join(dir, "README.md"), `# ${slug}\n`);
  if (!existsSync(join(dir, "CHANGELOG.md"))) writeFileSync(join(dir, "CHANGELOG.md"), `## 0.1.0\n`);
  process.stdout.write(`Wrote ${file}. Fill in name, summary and categories, then run hedlo validate.\n`);
}

function check(flags) {
  const dir = resolve(String(flags.dir ?? "."));
  const files = collect(dir);
  const stored = readCredentials()[baseUrl(flags)];
  const r = validate(files, stored?.publisher ?? process.env.HEDLO_PUBLISHER ?? "");
  for (const w of r.warnings) process.stdout.write(`warning  ${w}\n`);
  for (const e of r.errors) process.stdout.write(`error    ${e}\n`);
  return { dir, files, r };
}

function validateCmd(flags) {
  const { r } = check(flags);
  if (r.errors.length) fail(`${r.errors.length} problem(s) found`, 2);
  process.stdout.write(`OK  ${r.manifest.id} ${r.manifest.version}  ${r.files} files, ${(r.bytes / 1024).toFixed(1)} KB\n`);
}

function packCmd(flags) {
  const { files, r } = check(flags);
  if (r.errors.length) fail(`${r.errors.length} problem(s) found`, 2);
  const out = resolve(String(flags.out ?? `${r.manifest.id}-${r.manifest.version}.hpkg`));
  writeFileSync(out, pack(files));
  process.stdout.write(`Wrote ${out}\n`);
}

async function publish(flags) {
  const url = baseUrl(flags);
  const { files, r } = check(flags);
  if (r.errors.length) fail(`${r.errors.length} problem(s) found; fix them before publishing`, 2);
  const bytes = pack(files);
  const notes = String(flags.notes ?? "").slice(0, 2000);
  const res = await authed(url, "/api/v1/publish", { method: "POST", headers: { "content-type": "application/octet-stream", "x-hedlo-notes": encodeURIComponent(notes) }, body: bytes });
  for (const f of res.findings ?? []) process.stdout.write(`${f.severity.padEnd(8)} ${f.rule}${f.path ? " " + f.path : ""}: ${f.detail}\n`);
  if (res.status === "failed") fail("the automatic checks failed; nothing was queued", 2);
  process.stdout.write(`Submitted ${res.item} ${res.version} for review (${res.status}). Track it with hedlo status or in the dashboard.\n`);
}

function out(flags, data, text) {
  process.stdout.write(flags.json ? JSON.stringify(data, null, 2) + "\n" : text);
}

function send(url, path, method, body) {
  return authed(url, path, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body ?? {}) });
}

const enc = encodeURIComponent;

function need(value, usage) {
  if (!value) fail(`usage: ${usage}`);
  return value;
}

function showItem(flags, r) {
  const i = r.item;
  let text = `${i.name} (${i.id})  ${i.status}  ${i.product} ${i.kind}\n`;
  text += `price      ${i.price ? money(i.price, i.currency) + (i.billing !== "once" ? " per " + i.billing : "") : "free"}${i.trialDays ? `, ${i.trialDays}-day trial` : ""}, updates ${i.updates}\n`;
  text += `summary    ${i.summary}\ncategories ${i.categories.join(", ") || "-"}\ntags       ${i.tags.join(", ") || "-"}\n`;
  text += `sales      ${i.sales}${i.rating !== null ? `, rated ${i.rating}/5 by ${i.ratings}` : ""}\n\n`;
  text += table(r.versions.map((v) => [v.version, v.status, day(v.submittedAt), day(v.decidedAt), v.decision ? v.decision.slice(0, 60) : ""]), ["VERSION", "STATUS", "SUBMITTED", "DECIDED", "REVIEWER"]);
  const pending = r.versions.find((v) => v.status === "queued" || v.status === "changes" || v.status === "failed");
  for (const f of pending?.findings ?? []) text += `    ${f.severity} ${f.rule}${f.path ? " " + f.path : ""}: ${f.detail}\n`;
  out(flags, r, text);
}

async function item(flags, args) {
  const url = baseUrl(flags);
  if (args[0] === "set") {
    const id = need(args[1], "hedlo item set <item-id> [--price 4.99] [--summary text] [--listed|--unlisted] ...");
    const { patch, error } = listingPatch(flags);
    if (error) fail(error);
    if (patch.descriptionFile) {
      patch.description = readFileSync(resolve(patch.descriptionFile), "utf8");
      delete patch.descriptionFile;
    }
    if (Object.keys(patch).length === 0) fail("nothing to change; pass at least one listing option (see hedlo help)");
    showItem(flags, await send(url, `/api/v1/items/${enc(id)}`, "PATCH", patch));
    return;
  }
  showItem(flags, await authed(url, `/api/v1/items/${enc(need(args[0], "hedlo item <item-id>"))}`));
}

async function versions(flags, args) {
  const url = baseUrl(flags);
  if (args[0] === "withdraw") {
    const id = need(args[1], "hedlo versions withdraw <item-id> <version>");
    const version = need(args[2], "hedlo versions withdraw <item-id> <version>");
    const r = await send(url, `/api/v1/items/${enc(id)}/versions/${enc(version)}/withdraw`, "POST");
    out(flags, r, `Withdrew ${id} ${version}.\n`);
    return;
  }
  showItem(flags, await authed(url, `/api/v1/items/${enc(need(args[0], "hedlo versions <item-id>"))}`));
}

async function advisory(flags, args) {
  const url = baseUrl(flags);
  const id = need(args[0], "hedlo advisory <item-id> --severity high --title text --affected '<1.2.3' [--fixed 1.2.3] [--body text]");
  const r = await send(url, `/api/v1/items/${enc(id)}/advisories`, "POST", { severity: String(flags.severity ?? ""), title: String(flags.title ?? ""), body: String(flags.body ?? ""), affected: String(flags.affected ?? ""), fixed: flags.fixed && flags.fixed !== true ? String(flags.fixed) : "" });
  out(flags, r, `Published advisory ${r.id} (${r.severity}): ${r.title}. Holders of affected versions are notified.\n`);
}

async function reviews(flags, args) {
  const url = baseUrl(flags);
  if (args[0] === "reply") {
    const usage = "hedlo reviews reply <review-id> <text>";
    const id = need(args[1], usage);
    const text = need(args.slice(2).join(" ") || (flags.text !== true ? flags.text : ""), usage);
    out(flags, await send(url, `/api/v1/reviews/${enc(id)}/reply`, "POST", { text }), `Replied to ${id}.\n`);
    return;
  }
  const r = await authed(url, `/api/v1/items/${enc(need(args[0], "hedlo reviews <item-id>"))}/reviews`);
  let text = r.reviews.length ? "" : "No reviews yet.\n";
  for (const x of r.reviews) text += `${"★".repeat(x.stars)}${"☆".repeat(5 - x.stars)}  ${x.title || "(no title)"}  by ${x.author}, ${day(x.created)}  [${x.id}]\n  ${x.body.replace(/\s+/g, " ").slice(0, 200)}\n${x.reply ? "  ↳ " + x.reply.replace(/\s+/g, " ").slice(0, 200) + "\n" : ""}\n`;
  out(flags, r, text);
}

async function discounts(flags, args) {
  const url = baseUrl(flags);
  if (args[0] === "add") {
    const { body, error } = discountBody(flags);
    if (error) fail(error);
    const r = await send(url, "/api/v1/discounts", "POST", body);
    out(flags, r, `Created ${body.code ? "code " + body.code.toUpperCase() : "a sale"}.\n`);
    return;
  }
  if (args[0] === "end") {
    const id = need(args[1], "hedlo discounts end <discount-id>");
    out(flags, await authed(url, `/api/v1/discounts/${enc(id)}`, { method: "DELETE" }), `Ended ${id}.\n`);
    return;
  }
  const r = await authed(url, "/api/v1/discounts");
  const rows = r.discounts.map((d) => [d.id, d.code ?? "(sale)", d.kind === "percent" ? `${d.value} %` : money(d.value, ""), d.items?.length ? d.items.join(",") : "all items", `${d.uses}${d.maxUses ? "/" + d.maxUses : ""}`, day(d.endsAt), d.active ? "active" : "ended"]);
  out(flags, r, rows.length ? table(rows, ["ID", "CODE", "OFF", "ITEMS", "USES", "ENDS", "STATE"]) : "No discounts.\n");
}

async function sales(flags) {
  const url = baseUrl(flags);
  const r = await authed(url, "/api/v1/sales");
  let text = table(r.balances.map((b) => [b.currency.toUpperCase(), money(b.available, b.currency), money(b.pending, b.currency), money(b.total, b.currency)]), ["CURRENCY", "AVAILABLE", "PENDING", "TOTAL"]) || "No balance yet.\n";
  const limit = Math.max(1, Math.min(100, Number(flags.limit) || 20));
  if (r.sales.length) text += "\n" + table(r.sales.slice(0, limit).map((o) => [day(o.paidAt), o.item, o.status, money(o.paid, o.currency), money(o.fee + o.affiliate, o.currency), money(o.share, o.currency), o.country ?? ""]), ["DATE", "ITEM", "STATUS", "PAID", "FEES", "YOURS", "COUNTRY"]);
  if (r.withdrawals.length) text += "\n" + table(r.withdrawals.slice(0, 10).map((w) => [w.id, day(w.created), money(w.amount, w.currency), w.status, w.failure ?? ""]), ["WITHDRAWAL", "DATE", "AMOUNT", "STATUS", "NOTE"]);
  out(flags, r, text);
}

async function payouts(flags, args) {
  const url = baseUrl(flags);
  if (args[0] === "withdraw") {
    const usage = "hedlo payouts withdraw <amount> <currency>   (needs a token with the finance scope: hedlo login --finance)";
    const amount = toMinor(need(args[1], usage));
    const currency = need(args[2], usage).toLowerCase();
    if (amount === null || amount <= 0) fail("the amount must look like 125.00");
    const r = await send(url, "/api/v1/withdrawals", "POST", { amount, currency });
    out(flags, r, `Requested ${money(r.amount, r.currency)} (${r.id}, ${r.status}).\n`);
    return;
  }
  if (args[0] === "cancel") {
    const id = need(args[1], "hedlo payouts cancel <withdrawal-id>");
    out(flags, await authed(url, `/api/v1/withdrawals/${enc(id)}`, { method: "DELETE" }), `Cancelled ${id}.\n`);
    return;
  }
  await sales(flags);
}

async function analytics(flags) {
  const url = baseUrl(flags);
  const days = String(flags.days ?? "30");
  const r = await authed(url, `/api/v1/analytics?days=${enc(days)}`);
  const pct = (x) => (x === null || x === undefined ? "-" : `${(x * 100).toFixed(1)} %`);
  let text = `last ${r.range} days  views ${r.views}  sales ${r.sales}  trials ${r.trials}  conversion ${pct(r.conversion)}  installs ${r.installs}\n`;
  if (r.finance) text += `revenue ${money(r.revenue, r.currency)}  refunds ${r.refunds} (${pct(r.refundRate)})\n`;
  text += "\n" + table(r.items.map((i) => [i.id, i.views, i.sales, i.trials, pct(i.conversion), r.finance ? money(i.revenue, r.currency) : "-"]), ["ITEM", "VIEWS", "SALES", "TRIALS", "CONV", "REVENUE"]);
  if (r.countries.length) text += "\n" + table(r.countries.slice(0, 10).map((c) => [c.country, c.sales, pct(c.share)]), ["COUNTRY", "SALES", "SHARE"]);
  out(flags, r, text);
}

async function compat(flags) {
  const url = baseUrl(flags);
  const r = await authed(url, "/api/v1/compatibility");
  let text = r.releases.length ? "" : "No Loom or Bolt release recorded yet, or no approved Loom/Bolt items.\n";
  let failing = 0;
  for (const rel of r.releases) {
    text += `\n${rel.product} ${rel.version} (${rel.channel}, ${day(rel.recordedAt)})\n`;
    text += table(rel.items.map((x) => [x.item, x.version, x.status, x.reasons.join(", ")]), ["ITEM", "VERSION", "RESULT", "REASONS"]);
    failing += rel.items.filter((x) => x.status === "fail").length;
  }
  out(flags, r, text.replace(/^\n/, ""));
  if (flags.strict && failing) process.exit(3);
}

async function sandbox(flags, args) {
  const url = baseUrl(flags);
  if (args[0] === "install") {
    const usage = "hedlo sandbox install <item-id> <version> --site <domain-or-id>";
    const body = { item: need(args[1], usage), version: need(args[2], usage), site: need(flags.site !== true ? flags.site : "", usage) };
    const r = await send(url, "/api/v1/sandbox", "POST", body);
    out(flags, r, `Sandbox licence issued for ${body.item} ${body.version} on ${body.site}. Install it from the site's marketplace page.\n`);
    return;
  }
  if (args[0] === "end") {
    const id = need(args[1], "hedlo sandbox end <run-id>");
    out(flags, await authed(url, `/api/v1/sandbox/${enc(id)}`, { method: "DELETE" }), `Ended ${id}.\n`);
    return;
  }
  const r = await authed(url, "/api/v1/sandbox");
  let text = table(r.runs.map((x) => [x.id, x.item, x.version, x.site, x.mode, x.status, day(x.until)]), ["RUN", "ITEM", "VERSION", "SITE", "MODE", "STATUS", "UNTIL"]) || "No sandbox runs.\n";
  text += `\nsites: ${r.sites.map((s) => `${s.domain} (${s.product})`).join(", ") || "none linked"}\n`;
  text += `testable: ${r.testable.map((t) => `${t.item} ${t.versions.map((v) => v.version).join("/")}`).join(", ") || "none"}\n`;
  out(flags, r, text);
}

async function support(flags) {
  const url = baseUrl(flags);
  const filter = String(flags.filter ?? "waiting");
  const r = await authed(url, `/api/v1/support?filter=${enc(filter)}`);
  const text = table(r.threads.map((t) => [t.id, t.status, t.item, t.buyer, day(t.updated), t.subject.slice(0, 60)]), ["THREAD", "STATUS", "ITEM", "BUYER", "UPDATED", "SUBJECT"]) || `No ${r.filter} threads.\n`;
  out(flags, r, text + `\n${r.waiting} waiting for a reply. Answer in the dashboard under Support.\n`);
}

async function status(flags, filter) {
  const url = baseUrl(flags);
  const r = await authed(url, "/api/v1/items");
  const rows = (r.items ?? []).filter((i) => !filter || i.id === filter);
  if (rows.length === 0) {
    process.stdout.write(filter ? `No item ${filter}.\n` : "No items yet. Run hedlo publish.\n");
    return;
  }
  for (const i of rows) {
    const pending = i.pending ? `  ${i.pending.version} ${i.pending.status}` : "";
    process.stdout.write(`${i.id.padEnd(40)} ${String(i.status).padEnd(9)} ${i.latest ?? "-"}${pending}\n`);
    if (filter && i.pending) {
      for (const f of i.pending.findings ?? []) process.stdout.write(`    ${f.severity} ${f.rule}${f.path ? " " + f.path : ""}: ${f.detail}\n`);
      if (i.pending.decision) process.stdout.write(`    reviewer: ${i.pending.decision}\n`);
    }
  }
}

const HELP = `hedlo ${VERSION} — publish to the Hedlo Marketplace

  hedlo login [--read-only|--finance]  sign in through the browser (device code + PKCE)
  hedlo logout                  forget the stored token
  hedlo whoami                  show the account, publisher and token
  hedlo init [--product loom|bolt|shuttle] [--kind plugin|theme|email-template|invoice-template]
  hedlo validate                check hedlo.json, file names, size and secrets
  hedlo pack [-o file.hpkg]     write the package file
  hedlo publish [--notes text]  upload a new version for review
  hedlo status                  list your items and pending reviews

Listings and versions
  hedlo item <item-id>          listing, versions and review findings
  hedlo item set <item-id> [--name] [--summary] [--description-file README.md] [--price 4.99]
        [--currency eur] [--billing once|month|year] [--trial-days 7] [--updates lifetime|12m|24m]
        [--categories a,b] [--tags a,b] [--homepage url] [--support url] [--video url] [--listed|--unlisted]
  hedlo versions <item-id>      same as hedlo item
  hedlo versions withdraw <item-id> <version>
  hedlo advisory <item-id> --severity low|medium|high|critical --title text --affected range [--fixed version] [--body text]
  hedlo compat [--strict]       compatibility with the current Loom/Bolt releases (exit 3 on failures with --strict)
  hedlo sandbox                 sandbox runs, linked sites and testable versions
  hedlo sandbox install <item-id> <version> --site <domain>
  hedlo sandbox end <run-id>

Selling
  hedlo discounts               list sales and codes
  hedlo discounts add (--percent 20 | --amount 2.50) [--code SPRING] [--items a,b] [--starts date] [--ends date] [--max-uses n]
  hedlo discounts end <discount-id>
  hedlo sales [--limit 20]      balances, recent sales and withdrawals
  hedlo payouts withdraw <amount> <currency>   needs hedlo login --finance
  hedlo payouts cancel <withdrawal-id>
  hedlo analytics [--days 7|30|90|365]
  hedlo reviews <item-id>       ratings with your replies
  hedlo reviews reply <review-id> <text>
  hedlo support [--filter waiting|answered|closed|all]

Options: --url <marketplace>, -d/--dir <folder>, --json (machine-readable output)
CI: set HEDLO_TOKEN (and HEDLO_PUBLISHER) instead of hedlo login.
`;

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];
if (args.flags.version) {
  process.stdout.write(VERSION + "\n");
  process.exit(0);
}
switch (cmd) {
  case "login":
    await login(args.flags);
    break;
  case "logout":
    logout(args.flags);
    break;
  case "whoami":
    await whoami(args.flags);
    break;
  case "init":
    init(args.flags);
    break;
  case "validate":
    validateCmd(args.flags);
    break;
  case "pack":
    packCmd(args.flags);
    break;
  case "publish":
    await publish(args.flags);
    break;
  case "status":
    await status(args.flags, "");
    break;
  case "versions":
    await versions(args.flags, args._.slice(1));
    break;
  case "item":
    await item(args.flags, args._.slice(1));
    break;
  case "advisory":
    await advisory(args.flags, args._.slice(1));
    break;
  case "reviews":
    await reviews(args.flags, args._.slice(1));
    break;
  case "discounts":
    await discounts(args.flags, args._.slice(1));
    break;
  case "sales":
    await sales(args.flags);
    break;
  case "payouts":
    await payouts(args.flags, args._.slice(1));
    break;
  case "analytics":
    await analytics(args.flags);
    break;
  case "compat":
    await compat(args.flags);
    break;
  case "sandbox":
    await sandbox(args.flags, args._.slice(1));
    break;
  case "support":
    await support(args.flags);
    break;
  case undefined:
  case "help":
    process.stdout.write(HELP);
    break;
  default:
    fail(`unknown command ${cmd}; run hedlo help`);
}
