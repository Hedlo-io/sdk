import { test } from "node:test";
import assert from "node:assert/strict";
import { pack as serverPack, unpack, autoReview } from "../../packages/market/src/index.ts";
import { pack, validate } from "../src/pack.mjs";

const enc = (s) => new TextEncoder().encode(s);
const files = [
  { path: "hedlo.json", body: enc(JSON.stringify({ id: "acme.hello", kind: "plugin", product: "loom", version: "1.0.0", name: "Hello", summary: "Says hello", categories: ["utilities"] })) },
  { path: "loom-plugin.json", body: enc(JSON.stringify({ id: "acme.hello", version: "1.0.0" })) },
  { path: "README.md", body: enc("# Hello\n") },
  { path: "CHANGELOG.md", body: enc("## 1.0.0\n") },
  { path: "src/index.js", body: enc("export default 1;\n") },
];

test("CLI pack matches the marketplace format byte for byte", () => {
  const a = pack(files);
  assert.deepEqual(Buffer.from(a), Buffer.from(serverPack(files)));
  assert.deepEqual(unpack(a).map((f) => f.path), ["CHANGELOG.md", "README.md", "hedlo.json", "loom-plugin.json", "src/index.js"]);
});

test("CLI validate agrees with the server review on a good package", () => {
  const r = validate(files, "acme");
  assert.deepEqual(r.errors, []);
  assert.equal(autoReview({ files, publisherSlug: "acme", previousVersion: null }).passed, true);
});

test("CLI validate catches the namespace, secrets and binaries", () => {
  const bad = [...files, { path: "run.sh", body: enc("echo") }, { path: "config.json", body: enc('{"k":"sk_live_abcdefghijklmnop1234"}') }];
  const r = validate(bad, "other");
  assert.ok(r.errors.some((e) => e.includes("must start with other.")));
  assert.ok(r.errors.some((e) => e.includes("run.sh")));
  assert.ok(r.errors.some((e) => e.includes("config.json")));
});

test("pack refuses unsafe paths", () => {
  assert.throws(() => pack([{ path: "../x", body: enc("") }]));
});
