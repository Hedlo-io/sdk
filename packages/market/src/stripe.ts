import { createHmac, timingSafeEqual } from "node:crypto";
import { MarketError } from "./crypto.ts";

export type Form = { [k: string]: string | number | boolean | null | undefined | Form | Form[] | string[] };

export function encodeForm(data: Form, prefix = ""): string {
  const out: string[] = [];
  for (const [k, v] of Object.entries(data)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (Array.isArray(v)) v.forEach((x, i) => out.push(typeof x === "object" ? encodeForm(x as Form, `${key}[${i}]`) : `${encodeURIComponent(`${key}[${i}]`)}=${encodeURIComponent(String(x))}`));
    else if (typeof v === "object") out.push(encodeForm(v, key));
    else out.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(v))}`);
  }
  return out.filter(Boolean).join("&");
}

export interface StripeOptions {
  secretKey: string;
  fetcher?: typeof fetch;
  apiBase?: string;
}

export class StripeError extends MarketError {
  status: number;
  type: string;
  constructor(status: number, type: string, message: string) {
    super("stripe", message);
    this.status = status;
    this.type = type;
  }
}

export interface Stripe {
  post<T = Record<string, unknown>>(path: string, body: Form, o?: { idempotencyKey?: string; account?: string }): Promise<T>;
  get<T = Record<string, unknown>>(path: string, o?: { account?: string }): Promise<T>;
  del<T = Record<string, unknown>>(path: string, o?: { idempotencyKey?: string }): Promise<T>;
  testMode: boolean;
}

export function stripe(o: StripeOptions): Stripe {
  if (!/^(sk|rk)_(test|live)_[A-Za-z0-9]{10,}$/.test(o.secretKey)) throw new MarketError("stripe", "STRIPE_SECRET_KEY is not a Stripe secret or restricted key");
  const f = o.fetcher ?? fetch;
  const base = o.apiBase ?? "https://api.stripe.com/v1";
  async function call<T>(method: "GET" | "POST" | "DELETE", path: string, body: string | null, extra: Record<string, string>): Promise<T> {
    if (!/^\/[a-z_]+(\/[A-Za-z0-9_]+)*$/.test(path)) throw new MarketError("stripe", "bad Stripe path");
    const res = await f(base + path, {
      method,
      headers: { authorization: `Bearer ${o.secretKey}`, "content-type": "application/x-www-form-urlencoded", "stripe-version": "2024-06-20", ...extra },
      body,
      signal: AbortSignal.timeout(30_000),
      redirect: "error",
    });
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const err = (json.error ?? {}) as Record<string, unknown>;
      throw new StripeError(res.status, String(err.type ?? "api_error"), String(err.message ?? `Stripe answered ${res.status}`).slice(0, 300));
    }
    return json as T;
  }
  return {
    testMode: o.secretKey.includes("_test_"),
    post: (path, body, x = {}) => call("POST", path, encodeForm(body), { ...(x.idempotencyKey ? { "idempotency-key": x.idempotencyKey } : {}), ...(x.account ? { "stripe-account": x.account } : {}) }),
    get: (path, x = {}) => call("GET", path, null, x.account ? { "stripe-account": x.account } : {}),
    del: (path, x = {}) => call("DELETE", path, null, x.idempotencyKey ? { "idempotency-key": x.idempotencyKey } : {}),
  };
}

export interface StripeEvent {
  id: string;
  type: string;
  created: number;
  livemode: boolean;
  data: { object: Record<string, unknown> };
}

export function verifyWebhook(payload: string, header: string | null, secret: string, nowSeconds: number, tolerance = 300): StripeEvent {
  if (!header || header.length > 2000) throw new MarketError("webhook", "missing Stripe-Signature");
  let t = 0;
  const sigs: string[] = [];
  for (const part of header.split(",")) {
    const [k, v] = part.split("=", 2);
    if (k === "t") t = Number(v);
    else if (k === "v1" && v && /^[0-9a-f]{64}$/.test(v)) sigs.push(v);
  }
  if (!Number.isInteger(t) || t <= 0 || sigs.length === 0) throw new MarketError("webhook", "malformed Stripe-Signature");
  if (Math.abs(nowSeconds - t) > tolerance) throw new MarketError("webhook", "the webhook timestamp is outside the tolerance");
  const expected = createHmac("sha256", secret).update(`${t}.${payload}`).digest();
  if (!sigs.some((s) => timingSafeEqual(Buffer.from(s, "hex"), expected))) throw new MarketError("webhook", "the webhook signature does not match");
  const ev = JSON.parse(payload) as StripeEvent;
  if (!ev || typeof ev.id !== "string" || typeof ev.type !== "string" || !ev.data?.object) throw new MarketError("webhook", "malformed event");
  return ev;
}

export function signWebhook(payload: string, secret: string, t: number): string {
  return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex")}`;
}

export interface CheckoutLine {
  name: string;
  amount: number;
  currency: string;
}

export type BillingInterval = "month" | "year";

export function subscriptionSessionForm(o: { order: string; line: CheckoutLine; interval: BillingInterval; email: string; success: string; cancel: string; customer?: string | null }): Form {
  return {
    mode: "subscription",
    client_reference_id: o.order,
    customer: o.customer ?? undefined,
    customer_email: o.customer ? undefined : o.email,
    success_url: o.success,
    cancel_url: o.cancel,
    "automatic_tax[enabled]": true,
    "tax_id_collection[enabled]": true,
    billing_address_collection: "required",
    line_items: [{ quantity: 1, price_data: { currency: o.line.currency, unit_amount: o.line.amount, tax_behavior: "exclusive", recurring: { interval: o.interval }, product_data: { name: o.line.name.slice(0, 250) } } }],
    subscription_data: { metadata: { order: o.order } },
    metadata: { order: o.order },
  };
}

export function checkoutSessionForm(o: { order: string; line: CheckoutLine; email: string; success: string; cancel: string; customer?: string | null }): Form {
  return {
    mode: "payment",
    client_reference_id: o.order,
    customer: o.customer ?? undefined,
    customer_email: o.customer ? undefined : o.email,
    success_url: o.success,
    cancel_url: o.cancel,
    "automatic_tax[enabled]": true,
    "invoice_creation[enabled]": true,
    "tax_id_collection[enabled]": true,
    billing_address_collection: "required",
    line_items: [{ quantity: 1, price_data: { currency: o.line.currency, unit_amount: o.line.amount, tax_behavior: "exclusive", product_data: { name: o.line.name.slice(0, 250) } } }],
    payment_intent_data: { transfer_group: o.order, metadata: { order: o.order } },
    metadata: { order: o.order },
  };
}
