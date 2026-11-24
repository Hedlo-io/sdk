import { MarketError } from "./crypto.ts";
import type { Currency } from "./pricing.ts";

export const REFUND_WINDOW = 14 * 86_400_000;
export const MIN_WITHDRAWAL: Record<Currency, number> = { eur: 1000, usd: 1000, gbp: 1000 };
export const REVIEW_WITHDRAWAL: Record<Currency, number> = { eur: 500_000, usd: 500_000, gbp: 500_000 };

export type EntryKind = "sale" | "refund" | "chargeback" | "withdrawal" | "withdrawal_reversal" | "adjustment";

export interface Entry {
  id: string;
  publisher: string;
  currency: Currency;
  amount: number;
  kind: EntryKind;
  ref: string;
  availableAt: number;
  createdAt: number;
}

export interface Balance {
  currency: Currency;
  pending: number;
  available: number;
  total: number;
}

export function balances(entries: readonly Entry[], now: number): Balance[] {
  const by = new Map<Currency, Balance>();
  for (const e of entries) {
    if (!Number.isInteger(e.amount)) throw new MarketError("ledger", "ledger amounts are integers");
    const b = by.get(e.currency) ?? { currency: e.currency, pending: 0, available: 0, total: 0 };
    if (e.availableAt > now) b.pending += e.amount;
    else b.available += e.amount;
    b.total += e.amount;
    by.set(e.currency, b);
  }
  return [...by.values()].sort((a, b) => a.currency.localeCompare(b.currency));
}

export function saleEntry(id: string, publisher: string, currency: Currency, publisherShare: number, order: string, now: number, window = REFUND_WINDOW): Entry {
  if (!Number.isInteger(publisherShare) || publisherShare < 0) throw new MarketError("ledger", "a sale credits a non-negative amount");
  return { id, publisher, currency, amount: publisherShare, kind: "sale", ref: order, availableAt: now + window, createdAt: now };
}

export function reversalEntry(id: string, sale: Entry, kind: "refund" | "chargeback", now: number): Entry {
  if (sale.kind !== "sale") throw new MarketError("ledger", "only sales can be reversed");
  return { id, publisher: sale.publisher, currency: sale.currency, amount: -sale.amount, kind, ref: sale.ref, availableAt: Math.max(now, sale.availableAt), createdAt: now };
}

export type WithdrawalCheck = { ok: true; hold: boolean } | { ok: false; reason: "minimum" | "insufficient" | "kyc" | "open" };

export function checkWithdrawal(amount: number, currency: Currency, balance: Balance | undefined, kycVerified: boolean, openWithdrawals: number): WithdrawalCheck {
  if (!kycVerified) return { ok: false, reason: "kyc" };
  if (openWithdrawals > 0) return { ok: false, reason: "open" };
  if (!Number.isInteger(amount) || amount < MIN_WITHDRAWAL[currency]) return { ok: false, reason: "minimum" };
  if (!balance || amount > balance.available) return { ok: false, reason: "insufficient" };
  return { ok: true, hold: amount >= REVIEW_WITHDRAWAL[currency] };
}

export function withdrawalEntry(id: string, publisher: string, currency: Currency, amount: number, withdrawal: string, now: number): Entry {
  return { id, publisher, currency, amount: -amount, kind: "withdrawal", ref: withdrawal, availableAt: now, createdAt: now };
}
