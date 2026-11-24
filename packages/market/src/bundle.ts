import { MarketError } from "./crypto.ts";
import { MIN_PRICE, type Currency } from "./pricing.ts";

export const BUNDLE_MIN_ITEMS = 2;
export const BUNDLE_MAX_ITEMS = 10;

export interface BundlePart {
  item: string;
  publisher: string;
  list: number;
  feeBps: number;
}

export interface BundleShare {
  item: string;
  publisher: string;
  list: number;
  discount: number;
  paid: number;
  fee: number;
  share: number;
}

export function splitBundle(price: number, currency: Currency, parts: readonly BundlePart[]): BundleShare[] {
  if (parts.length < BUNDLE_MIN_ITEMS || parts.length > BUNDLE_MAX_ITEMS) throw new MarketError("bundle", `a bundle holds ${BUNDLE_MIN_ITEMS} to ${BUNDLE_MAX_ITEMS} items`);
  if (new Set(parts.map((p) => p.item)).size !== parts.length) throw new MarketError("bundle", "each item can be in a bundle once");
  const total = parts.reduce((n, p) => n + p.list, 0);
  if (parts.some((p) => !Number.isInteger(p.list) || p.list <= 0)) throw new MarketError("bundle", "bundles hold paid items only");
  if (!Number.isInteger(price) || price < MIN_PRICE[currency]) throw new MarketError("bundle", "the bundle price is too low");
  if (price >= total) throw new MarketError("bundle", "the bundle must cost less than its items bought separately");
  const raw = parts.map((p) => (price * p.list) / total);
  const paid = raw.map(Math.floor);
  let left = price - paid.reduce((n, x) => n + x, 0);
  const order = raw.map((x, i) => ({ i, r: x - Math.floor(x), list: parts[i]!.list })).sort((a, b) => b.r - a.r || b.list - a.list || a.i - b.i);
  for (let k = 0; left > 0; k = (k + 1) % order.length, left--) paid[order[k]!.i]! += 1;
  return parts.map((p, i) => {
    if (!Number.isInteger(p.feeBps) || p.feeBps < 0 || p.feeBps > 5000) throw new MarketError("fee", "the platform fee is out of range");
    const amount = paid[i]!;
    const fee = Math.round((amount * p.feeBps) / 10_000);
    return { item: p.item, publisher: p.publisher, list: p.list, discount: p.list - amount, paid: amount, fee, share: amount - fee };
  });
}

export function bundleSaving(price: number, parts: readonly { list: number }[]): number {
  const total = parts.reduce((n, p) => n + p.list, 0);
  return total > 0 ? Math.max(0, Math.round(((total - price) / total) * 100)) : 0;
}
