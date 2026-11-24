import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { verifyPackage } from "../../../../kit/packages/platform/src/plugins.ts";
import { unpackPlugin } from "../../../../kit/packages/platform/src/registry.ts";
import {
  autoReview, balances, b64url, canSellPaid, checkCertificate, checkDiscount, checkLinkRequest, checkWithdrawal, proofChallenge, proofMatches, proofMessage,
  ed25519Pair, encodeForm, issueCertificate, issuePackage, linkRequestMessage, MarketError, normaliseDomain, normaliseUserCode, openPackage, pack,
  pollDecision, quote, rank, readMark, reversalEntry, saleEntry, signBytes, signWebhook, startDeviceGrant, stripe, subscriptionSessionForm, unpack, unwrapWith, verifyWebhook,
  withdrawalEntry, wrapTo, x25519Pair, type Discount, type LinkRequest, type PackFile, type RankStats,
} from "../src/index.ts";

const enc = (s: string) => new TextEncoder().encode(s);
const DAY = 86_400_000;
const now = Date.UTC(2026, 10, 22);

test("archives are byte-compatible with the kit format", () => {
  const files: PackFile[] = [{ path: "src/b.js", body: enc("b") }, { path: "a.json", body: enc("{}") }, { path: ".hedlo/licence.json", body: enc("{}") }];
  const bytes = pack(files);
  assert.deepEqual(unpackPlugin(bytes).map((f) => f.path), [".hedlo/licence.json", "a.json", "src/b.js"]);
  assert.deepEqual(unpack(bytes).map((f) => f.path), [".hedlo/licence.json", "a.json", "src/b.js"]);
  assert.throws(() => pack([{ path: "../x", body: enc("") }]), MarketError);
  assert.throws(() => pack([{ path: "A", body: enc("") }, { path: "a", body: enc("") }]), MarketError);
});

test("wrapped keys open only with the right installation key and context", () => {
  const site = x25519Pair();
  const other = x25519Pair();
  const secret = randomBytes(32);
  const w = wrapTo(site.publicKey, secret, "ctx");
  assert.deepEqual(unwrapWith(site.privateKey, w, "ctx"), secret);
  assert.throws(() => unwrapWith(other.privateKey, w, "ctx"), MarketError);
  assert.throws(() => unwrapWith(site.privateKey, w, "other"), MarketError);
});

function setup() {
  const market = ed25519Pair();
  const signer = ed25519Pair();
  const site = ed25519Pair();
  const box = x25519Pair();
  const input = { licence: "lic_1", item: "acme.backups", site: "site_1", installKey: site.publicKey, domain: "Admin.Example.com" };
  return { market, signer, site, box, input };
}

test("activation certificates are bound to key, domain and item", () => {
  const { market, site, input } = setup();
  const raw = issueCertificate(input, now, market.privateKey);
  const ok = checkCertificate(raw, [market.publicKey], { installKey: site.publicKey, domain: "admin.example.com", item: "acme.backups" }, now + DAY);
  assert.equal(ok.ok, true);
  assert.equal(ok.ok && ok.renewDue, false);
  assert.equal(checkCertificate(raw, [market.publicKey], { installKey: site.publicKey, domain: "admin.example.com", item: "acme.backups" }, now + 4 * DAY).ok && true, true);
  assert.deepEqual(checkCertificate(raw, [market.publicKey], { installKey: site.publicKey, domain: "admin.example.com", item: "acme.backups" }, now + 31 * DAY), { ok: false, reason: "expired" });
  assert.deepEqual(checkCertificate(raw, [market.publicKey], { installKey: ed25519Pair().publicKey, domain: "admin.example.com", item: "acme.backups" }, now), { ok: false, reason: "site" });
  assert.deepEqual(checkCertificate(raw, [market.publicKey], { installKey: site.publicKey, domain: "other.example.com", item: "acme.backups" }, now), { ok: false, reason: "site" });
  assert.deepEqual(checkCertificate(raw, [market.publicKey], { installKey: site.publicKey, domain: "admin.example.com", item: "acme.other" }, now), { ok: false, reason: "item" });
  assert.deepEqual(checkCertificate(raw, [ed25519Pair().publicKey], { installKey: site.publicKey, domain: "admin.example.com", item: "acme.backups" }, now), { ok: false, reason: "signature" });
  const [body, sig] = raw.split(".");
  const forged = JSON.parse(Buffer.from(body!, "base64url").toString());
  forged.exp = now + 999 * DAY;
  assert.deepEqual(checkCertificate(`${b64url(Buffer.from(JSON.stringify(forged)))}.${sig}`, [market.publicKey], { installKey: site.publicKey, domain: "admin.example.com", item: "acme.backups" }, now), { ok: false, reason: "signature" });
  const trial = issueCertificate({ ...input, trialUntil: now + 7 * DAY }, now, market.privateKey);
  assert.deepEqual(checkCertificate(trial, [market.publicKey], { installKey: site.publicKey, domain: "admin.example.com", item: "acme.backups" }, now + 8 * DAY), { ok: false, reason: "expired" });
});

test("issued packages are sealed to the site, signed, watermarked and kit-verifiable", () => {
  const { market, signer, site, box, input } = setup();
  const cert = checkCertificate(issueCertificate(input, now, market.privateKey), [market.publicKey], { installKey: site.publicKey, domain: input.domain, item: input.item }, now);
  assert.ok(cert.ok);
  const base: PackFile[] = [{ path: "hedlo.json", body: enc("{}") }, { path: "index.js", body: enc("export default 1") }];
  const mark = { licence: "lic_1", item: "acme.backups", version: "1.0.0", buyer: "b1", site: "site_1", issued: now };
  const p = issuePackage(base, mark, signer.privateKey, box.publicKey);
  const opened = openPackage(p, box.privateKey, [signer.publicKey], cert.cert);
  assert.deepEqual(readMark(opened.files), mark);
  assert.ok(verifyPackage(opened.bytes, p.signature, [signer.publicKey]));
  assert.throws(() => openPackage(p, x25519Pair().privateKey, [signer.publicKey], cert.cert), MarketError);
  assert.throws(() => openPackage(p, box.privateKey, [ed25519Pair().publicKey], cert.cert), /not signed/);
  assert.throws(() => openPackage({ ...p, licence: "lic_2" }, box.privateKey, [signer.publicKey], cert.cert), /another licence/);
  const body = Buffer.from(p.body, "base64url");
  body[body.length - 1] ^= 1;
  assert.throws(() => openPackage({ ...p, body: b64url(body) }, box.privateKey, [signer.publicKey], cert.cert), MarketError);
  const stripped = pack(opened.files.filter((f) => f.path !== ".hedlo/licence.json"));
  assert.equal(verifyPackage(stripped, p.signature, [signer.publicKey]), null);
  assert.throws(() => issuePackage([...base, { path: ".hedlo/licence.json", body: enc("x") }], mark, signer.privateKey, box.publicKey), /reserved/);
});

test("site link requests are signed by the installation and prove the domain", () => {
  const site = ed25519Pair();
  const box = x25519Pair();
  const req: LinkRequest = { domain: "admin.example.com", product: "loom", version: "1.0.0", signKey: site.publicKey, boxKey: box.publicKey, nonce: b64url(randomBytes(18)), iat: now };
  const sig = signBytes(linkRequestMessage(req), site.privateKey);
  assert.equal(checkLinkRequest(req, sig, now).domain, "admin.example.com");
  assert.throws(() => checkLinkRequest({ ...req, domain: "evil.example.com" }, sig, now), /signature/);
  assert.throws(() => checkLinkRequest(req, sig, now + 11 * 60_000), /too old/);
  const ch = proofChallenge();
  const answer = signBytes(proofMessage("admin.example.com", ch), site.privateKey);
  assert.ok(proofMatches(`${answer}\n`, site.publicKey, "admin.example.com", ch));
  assert.equal(proofMatches(answer, site.publicKey, "admin.example.com", proofChallenge()), false);
  assert.equal(proofMatches(answer, site.publicKey, "evil.example.com", ch), false);
  assert.equal(proofMatches(signBytes(proofMessage("admin.example.com", ch), ed25519Pair().privateKey), site.publicKey, "admin.example.com", ch), false);
  for (const bad of ["localhost", "10.0.0.1", "a..b", "-a.com", "x", "a.localhost", "exa mple.com"]) assert.throws(() => normaliseDomain(bad), MarketError, bad);
  assert.equal(normaliseUserCode("bcdf ghjk"), "BCDF-GHJK");
  assert.equal(normaliseUserCode("abc"), "");
});

const disc = (o: Partial<Discount>): Discount => ({ id: "d", kind: "percent", value: 20, code: null, items: null, startsAt: null, endsAt: null, maxUses: null, uses: 0, active: true, ...o });

test("quotes apply the best valid discount and fee on the paid price", () => {
  assert.deepEqual(quote(2000, "eur", 1500, [], "a.b", now, null), { list: 2000, discount: 0, paid: 2000, fee: 300, publisher: 1700, currency: "eur", discountId: null });
  const q = quote(2000, "eur", 1500, [disc({ id: "p", value: 25 }), disc({ id: "f", kind: "fixed", value: 300 })], "a.b", now, null);
  assert.equal(q.discountId, "p");
  assert.equal(q.paid, 1500);
  assert.equal(q.fee, 225);
  assert.equal(q.publisher, 1275);
  assert.equal(quote(2000, "eur", 1500, [disc({ code: "LAUNCH" })], "a.b", now, null).discount, 0);
  assert.equal(quote(2000, "eur", 1500, [disc({ code: "LAUNCH" })], "a.b", now, "launch").discount, 400);
  assert.equal(quote(2000, "eur", 1500, [disc({ endsAt: now })], "a.b", now, null).discount, 0);
  assert.equal(quote(2000, "eur", 1500, [disc({ maxUses: 3, uses: 3 })], "a.b", now, null).discount, 0);
  assert.equal(quote(2000, "eur", 1500, [disc({ items: ["x.y"] })], "a.b", now, null).discount, 0);
  assert.equal(quote(250, "eur", 1500, [disc({ kind: "fixed", value: 500 })], "a.b", now, null).paid, 199);
  assert.throws(() => checkDiscount({ kind: "percent", value: 95, code: null, startsAt: null, endsAt: null, maxUses: null }), MarketError);
  assert.deepEqual(canSellPaid(1, true), { ok: false, free: 1, kyc: true });
  assert.equal(canSellPaid(2, true).ok, true);
  assert.equal(canSellPaid(5, false).ok, false);
});

test("ledger keeps sales pending through the refund window and nets refunds", () => {
  const s1 = saleEntry("e1", "p", "eur", 1700, "o1", now);
  const s2 = saleEntry("e2", "p", "eur", 1000, "o2", now - 20 * DAY);
  let b = balances([s1, s2], now)[0]!;
  assert.deepEqual([b.pending, b.available, b.total], [1700, 1000, 2700]);
  const r1 = reversalEntry("e3", s1, "refund", now + DAY);
  b = balances([s1, s2, r1], now + DAY)[0]!;
  assert.deepEqual([b.pending, b.available], [0, 1000]);
  assert.deepEqual(checkWithdrawal(1000, "eur", b, true, 0), { ok: true, hold: false });
  assert.deepEqual(checkWithdrawal(1001, "eur", b, true, 0), { ok: false, reason: "insufficient" });
  assert.deepEqual(checkWithdrawal(500, "eur", b, true, 0), { ok: false, reason: "minimum" });
  assert.deepEqual(checkWithdrawal(1000, "eur", b, false, 0), { ok: false, reason: "kyc" });
  assert.deepEqual(checkWithdrawal(1000, "eur", b, true, 1), { ok: false, reason: "open" });
  b = balances([s1, s2, r1, withdrawalEntry("e4", "p", "eur", 1000, "w1", now + DAY)], now + DAY)[0]!;
  assert.equal(b.available, 0);
});

test("Stripe webhooks need a fresh, valid signature", () => {
  const payload = JSON.stringify({ id: "evt_1", type: "checkout.session.completed", created: 1, livemode: false, data: { object: { id: "cs_1" } } });
  const t = Math.floor(now / 1000);
  const h = signWebhook(payload, "whsec_test", t);
  assert.equal(verifyWebhook(payload, h, "whsec_test", t).id, "evt_1");
  assert.throws(() => verifyWebhook(payload, h, "whsec_other", t), /does not match/);
  assert.throws(() => verifyWebhook(payload + " ", h, "whsec_test", t), /does not match/);
  assert.throws(() => verifyWebhook(payload, h, "whsec_test", t + 301), /tolerance/);
  assert.throws(() => verifyWebhook(payload, null, "whsec_test", t), /missing/);
  assert.equal(encodeForm({ a: 1, b: { c: "x y" }, d: [{ e: 2 }] }), "a=1&b%5Bc%5D=x%20y&d%5B0%5D%5Be%5D=2");
});

test("automatic review catches unsafe packages", () => {
  const manifest = { id: "acme.backups", kind: "plugin", product: "loom", version: "1.1.0", name: "Backups", summary: "Backups", categories: ["backups"] };
  const good: PackFile[] = [
    { path: "hedlo.json", body: enc(JSON.stringify(manifest)) },
    { path: "loom-plugin.json", body: enc(JSON.stringify({ id: "acme.backups", version: "1.1.0" })) },
    { path: "README.md", body: enc("# Backups") },
    { path: "CHANGELOG.md", body: enc("# 1.1.0") },
    { path: "index.js", body: enc("export default {}") },
  ];
  assert.equal(autoReview({ files: good, publisherSlug: "acme", previousVersion: "1.0.0" }).passed, true);
  const rules = (files: PackFile[], o: Partial<{ slug: string; prev: string | null }> = {}) => autoReview({ files, publisherSlug: o.slug ?? "acme", previousVersion: o.prev ?? null }).findings.map((f) => f.rule);
  assert.ok(rules(good, { slug: "other" }).includes("manifest-namespace"));
  assert.ok(rules(good, { prev: "1.1.0" }).includes("version-order"));
  assert.ok(rules([...good, { path: "config.js", body: enc("const k = 'sk_live_abcdefghijklmnop1234'") }]).includes("stripe-live-key"));
  assert.ok(rules([...good, { path: "id.pem.txt", body: enc("-----BEGIN PRIVATE KEY-----") }]).includes("private-key"));
  assert.ok(rules([...good, { path: "bin/run.exe", body: enc("MZ") }]).includes("executable"));
  assert.ok(rules([...good, { path: ".env", body: enc("A=1") }]).includes("sensitive-file"));
  assert.ok(rules([...good, { path: "x.js", body: enc("eval(atob(x))") }]).includes("dynamic-code"));
  assert.ok(rules(good.filter((f) => f.path !== "loom-plugin.json")).includes("native-manifest"));
  assert.ok(rules(good.filter((f) => f.path !== "hedlo.json")).includes("manifest-missing"));
  const pkg = (o: object) => [...good, { path: "package.json", body: enc(JSON.stringify(o)) }];
  assert.ok(rules(pkg({ scripts: { postinstall: "node x" } })).includes("install-script"));
  assert.ok(rules(pkg({ dependencies: { left: "^1.0.0" } })).includes("dependencies"));
  assert.ok(rules(pkg({ dependencies: { left: "github:evil/left" } })).includes("dependency-source"));
  assert.equal(autoReview({ files: pkg({ dependencies: { left: "^1.0.0" } }), publisherSlug: "acme", previousVersion: null }).passed, true);
  const native = good.map((f) => (f.path === "loom-plugin.json" ? { path: f.path, body: enc(JSON.stringify({ id: "acme.backups", version: "1.1.0", capabilities: ["db"], permissions: [{ id: "backups.run" }] })) } : f));
  assert.ok(rules(native).includes("capabilities") && rules(native).includes("permissions"));
});

test("ranking caps sponsored slots, penalises refunds and explores new items", () => {
  const base = (id: string, o: Partial<RankStats> = {}): RankStats => ({ id, sales30: 20, views30: 400, ratingSum: 40, ratingCount: 10, refunds90: 0, sales90: 50, updatedAt: now - 10 * DAY, publishedAt: now - 400 * DAY, compatible: true, promoted: false, advisoryOpen: false, ...o });
  const items = [
    ...Array.from({ length: 10 }, (_, i) => base(`top${i}`, { sales30: 50 - i })),
    base("refundy", { sales30: 80, refunds90: 30, sales90: 60 }),
    base("p1", { promoted: true }), base("p2", { promoted: true }), base("p3", { promoted: true }),
    base("newbie", { sales30: 0, views30: 5, ratingCount: 0, ratingSum: 0, publishedAt: now - 3 * DAY, updatedAt: now - 3 * DAY }),
  ];
  const r = rank(items, now);
  assert.equal(r.filter((x) => x.sponsored).length, 2);
  assert.ok(r.findIndex((x) => x.id === "newbie") < 8);
  assert.ok(r.findIndex((x) => x.id === "refundy") > r.findIndex((x) => x.id === "top9"));
  assert.equal(new Set(r.map((x) => x.id)).size, items.length);
});

test("device grants require PKCE and respect polling rules", () => {
  const verifier = b64url(randomBytes(40));
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const g = startDeviceGrant(challenge, "S256", now)!;
  assert.match(g.userCode, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  assert.equal(startDeviceGrant(challenge, "plain", now), null);
  const st = { state: "pending" as const, expiresAt: g.expiresAt, challenge, lastPoll: null, interval: 5 };
  assert.deepEqual(pollDecision(st, verifier, now), { ok: false, error: "authorization_pending" });
  assert.deepEqual(pollDecision({ ...st, lastPoll: now - 1000 }, verifier, now), { ok: false, error: "slow_down" });
  assert.deepEqual(pollDecision({ ...st, state: "approved" }, b64url(randomBytes(40)), now), { ok: false, error: "invalid_grant" });
  assert.deepEqual(pollDecision({ ...st, state: "approved" }, verifier, now), { ok: true });
  assert.deepEqual(pollDecision({ ...st, state: "used" }, verifier, now), { ok: false, error: "invalid_grant" });
  assert.deepEqual(pollDecision(st, verifier, g.expiresAt), { ok: false, error: "expired_token" });
});

test("site API requests are signed, fresh and bound to method, path and body", async () => {
  const { checkSiteRequest, siteRequestMessage } = await import("../src/index.ts");
  const site = ed25519Pair();
  const sig = signBytes(siteRequestMessage("POST", "/api/v1/site/certificates", now, "{}"), site.privateKey);
  const h = { key: site.publicKey, time: String(now), signature: sig };
  assert.equal(checkSiteRequest(h, "POST", "/api/v1/site/certificates", "{}", now), site.publicKey);
  assert.equal(checkSiteRequest(h, "POST", "/api/v1/site/certificates", "{\"x\":1}", now), null);
  assert.equal(checkSiteRequest(h, "GET", "/api/v1/site/certificates", "{}", now), null);
  assert.equal(checkSiteRequest(h, "POST", "/api/v1/site/other", "{}", now), null);
  assert.equal(checkSiteRequest(h, "POST", "/api/v1/site/certificates", "{}", now + 6 * 60_000), null);
  assert.equal(checkSiteRequest({ ...h, key: ed25519Pair().publicKey }, "POST", "/api/v1/site/certificates", "{}", now), null);
});

test("subscription checkout sessions recur and carry the order", () => {
  const body = decodeURIComponent(encodeForm(subscriptionSessionForm({ order: "ord_1", line: { name: "Pro (licence for a.example)", amount: 990, currency: "eur" }, interval: "month", email: "b@example.com", success: "https://m/o", cancel: "https://m/c" })));
  assert.match(body, /mode=subscription/);
  assert.ok(body.includes("line_items[0][price_data][recurring][interval]=month"));
  assert.ok(body.includes("subscription_data[metadata][order]=ord_1"));
  assert.doesNotMatch(body, /payment_intent_data|invoice_creation/);
});

test("the Stripe client sends DELETE for subscription cancellation", async () => {
  const seen: string[] = [];
  const client = stripe({ secretKey: "sk_test_" + "a".repeat(24), fetcher: (async (url: string, init: RequestInit) => {
    seen.push(String(init.method) + " " + url);
    return new Response(JSON.stringify({ id: "sub_1", status: "canceled" }), { status: 200 });
  }) as never });
  const r = await client.del<{ status: string }>("/subscriptions/sub_1");
  assert.equal(r.status, "canceled");
  assert.deepEqual(seen, ["DELETE https://api.stripe.com/v1/subscriptions/sub_1"]);
});

test("bundle split is proportional, exact to the cent and applies each publisher's fee", async () => {
  const { splitBundle, bundleSaving } = await import("../src/index.ts");
  const parts = [
    { item: "a", publisher: "p1", list: 1000, feeBps: 1500 },
    { item: "b", publisher: "p2", list: 2000, feeBps: 1000 },
    { item: "c", publisher: "p1", list: 333, feeBps: 1500 },
  ];
  const s = splitBundle(2501, "eur", parts);
  assert.equal(s.reduce((n, x) => n + x.paid, 0), 2501);
  for (const x of s) {
    assert.equal(x.paid + x.discount, x.list);
    assert.equal(x.fee + x.share, x.paid);
  }
  assert.ok(s[1]!.paid > s[0]!.paid && s[0]!.paid > s[2]!.paid);
  assert.equal(s[1]!.fee, Math.round((s[1]!.paid * 1000) / 10_000));
  assert.equal(bundleSaving(2501, parts), 25);
  assert.throws(() => splitBundle(3333, "eur", parts), /less than its items/);
  assert.throws(() => splitBundle(1000, "eur", [parts[0]!]), /2 to 10/);
  assert.throws(() => splitBundle(1000, "eur", [parts[0]!, parts[0]!]), /once/);
  assert.throws(() => splitBundle(100, "eur", parts), /too low/);
});
