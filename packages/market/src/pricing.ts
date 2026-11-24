import { MarketError } from "./crypto.ts";

export const CURRENCIES = ["eur", "usd", "gbp"] as const;
export type Currency = (typeof CURRENCIES)[number];

export const MIN_PRICE: Record<Currency, number> = { eur: 199, usd: 199, gbp: 199 };
export const MAX_PRICE = 999_900;
export const FREE_BEFORE_PAID = 2;

export interface Discount {
  id: string;
  kind: "percent" | "fixed";
  value: number;
  code: string | null;
  items: string[] | null;
  startsAt: number | null;
  endsAt: number | null;
  maxUses: number | null;
  uses: number;
  active: boolean;
}

export function validPrice(amount: number, currency: Currency): boolean {
  return amount === 0 || (Number.isInteger(amount) && amount >= MIN_PRICE[currency] && amount <= MAX_PRICE);
}

export function checkDiscount(d: Pick<Discount, "kind" | "value" | "code" | "startsAt" | "endsAt" | "maxUses">): void {
  if (d.kind === "percent" && (!Number.isInteger(d.value) || d.value < 1 || d.value > 90)) throw new MarketError("discount", "a percentage discount is between 1 and 90");
  if (d.kind === "fixed" && (!Number.isInteger(d.value) || d.value < 1)) throw new MarketError("discount", "a fixed discount is a positive amount");
  if (d.code !== null && !/^[A-Z0-9-]{3,32}$/.test(d.code)) throw new MarketError("discount", "codes use 3 to 32 letters, digits or dashes");
  if (d.startsAt !== null && d.endsAt !== null && d.endsAt <= d.startsAt) throw new MarketError("discount", "the end date is before the start date");
  if (d.maxUses !== null && (!Number.isInteger(d.maxUses) || d.maxUses < 1)) throw new MarketError("discount", "the usage limit is a positive number");
}

export function discountApplies(d: Discount, item: string, now: number, code: string | null): boolean {
  if (!d.active) return false;
  if (d.items && !d.items.includes(item)) return false;
  if (d.startsAt !== null && now < d.startsAt) return false;
  if (d.endsAt !== null && now >= d.endsAt) return false;
  if (d.maxUses !== null && d.uses >= d.maxUses) return false;
  if (d.code !== null) return code !== null && code.toUpperCase() === d.code;
  return true;
}

export interface Quote {
  list: number;
  discount: number;
  paid: number;
  fee: number;
  publisher: number;
  currency: Currency;
  discountId: string | null;
}

export function quote(list: number, currency: Currency, feeBps: number, discounts: readonly Discount[], item: string, now: number, code: string | null): Quote {
  if (!Number.isInteger(feeBps) || feeBps < 0 || feeBps > 5000) throw new MarketError("fee", "the platform fee is out of range");
  let best: { d: Discount; off: number } | null = null;
  if (list > 0) {
    for (const d of discounts) {
      if (!discountApplies(d, item, now, code)) continue;
      const raw = d.kind === "percent" ? Math.floor((list * d.value) / 100) : d.value;
      const off = Math.min(raw, list - MIN_PRICE[currency]);
      if (off > 0 && (!best || off > best.off)) best = { d, off };
    }
  }
  const discount = best?.off ?? 0;
  const paid = list - discount;
  const fee = Math.round((paid * feeBps) / 10_000);
  return { list, discount, paid, fee, publisher: paid - fee, currency, discountId: best?.d.id ?? null };
}

export function canSellPaid(approvedFreeItems: number, kycVerified: boolean): { ok: boolean; free: number; kyc: boolean } {
  return { ok: approvedFreeItems >= FREE_BEFORE_PAID && kycVerified, free: Math.max(0, FREE_BEFORE_PAID - approvedFreeItems), kyc: kycVerified };
}

export function formatMoney(amount: number, currency: Currency, locale: string): string {
  return new Intl.NumberFormat(locale, { style: "currency", currency: currency.toUpperCase() }).format(amount / 100);
}
