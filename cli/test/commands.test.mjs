import { test } from "node:test";
import assert from "node:assert/strict";
import { discountBody, listingPatch, money, table, toMinor } from "../src/commands.mjs";

test("toMinor parses prices into minor units", () => {
  assert.equal(toMinor("4.99"), 499);
  assert.equal(toMinor("4,5"), 450);
  assert.equal(toMinor("12"), 1200);
  assert.equal(toMinor("0"), 0);
  assert.equal(toMinor("4.999"), null);
  assert.equal(toMinor("-1"), null);
  assert.equal(toMinor("abc"), null);
});

test("money formats minor units", () => {
  assert.equal(money(1999, "eur"), "19.99 EUR");
  assert.equal(money(0, "usd"), "0.00 USD");
});

test("listingPatch maps flags to the listing API", () => {
  assert.deepEqual(listingPatch({ price: "9.50", "trial-days": "7", categories: "billing, themes", unlisted: true }).patch, { price: 950, trialDays: 7, categories: ["billing", "themes"], listed: false });
  assert.deepEqual(listingPatch({ listed: true, summary: "A short summary" }).patch, { summary: "A short summary", listed: true });
  assert.ok(listingPatch({ price: "free" }).error);
  assert.deepEqual(listingPatch({ name: true }).patch, {});
});

test("discountBody validates kind and value", () => {
  assert.deepEqual(discountBody({ percent: "20", code: "spring", items: "a.b,c.d", ends: "2026-12-31" }).body, { kind: "percent", value: 20, code: "spring", items: ["a.b", "c.d"], startsAt: null, endsAt: "2026-12-31", maxUses: null });
  assert.deepEqual(discountBody({ amount: "2.50", "max-uses": "100" }).body.value, 250);
  assert.ok(discountBody({ percent: "95" }).error);
  assert.ok(discountBody({ amount: "0" }).error);
  assert.ok(discountBody({ kind: "bogus" }).error);
});

test("table aligns columns", () => {
  assert.equal(table([["a", "1"], ["bbb", "22"]], ["K", "V"]), "K    V\na    1\nbbb  22\n");
  assert.equal(table([], ["K"]), "");
});
