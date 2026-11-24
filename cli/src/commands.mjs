export function money(minor, currency) {
  const n = Number(minor) || 0;
  return `${(n / 100).toFixed(2)} ${String(currency ?? "").toUpperCase()}`;
}

export function toMinor(raw) {
  const s = String(raw ?? "").trim().replace(",", ".");
  if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  const [a, b = ""] = s.split(".");
  return Number(a) * 100 + Number((b + "00").slice(0, 2));
}

export function day(ms) {
  return ms ? new Date(ms).toISOString().slice(0, 10) : "-";
}

export function table(rows, cols) {
  if (rows.length === 0) return "";
  const widths = cols.map((c, i) => Math.max(c.length, ...rows.map((r) => String(r[i] ?? "").length)));
  const line = (r) => r.map((v, i) => (i === r.length - 1 ? String(v ?? "") : String(v ?? "").padEnd(widths[i]))).join("  ").trimEnd();
  return [line(cols), ...rows.map(line)].join("\n") + "\n";
}

const LISTING_FLAGS = {
  name: (v) => String(v),
  summary: (v) => String(v),
  description: (v) => String(v),
  currency: (v) => String(v).toLowerCase(),
  billing: (v) => String(v),
  updates: (v) => String(v),
  homepage: (v) => String(v),
  support: (v) => String(v),
  video: (v) => String(v),
  tags: (v) => String(v).split(",").map((x) => x.trim()).filter(Boolean),
  categories: (v) => String(v).split(",").map((x) => x.trim()).filter(Boolean),
  "trial-days": (v) => Number(v),
};

export function listingPatch(flags) {
  const out = {};
  for (const [k, conv] of Object.entries(LISTING_FLAGS)) if (flags[k] !== undefined && flags[k] !== true) out[k === "trial-days" ? "trialDays" : k] = conv(flags[k]);
  if (flags.price !== undefined) {
    const p = toMinor(flags.price);
    if (p === null) return { error: "--price must look like 4.99 (0 for free)" };
    out.price = p;
  }
  if (flags.listed !== undefined) out.listed = flags.listed === true || flags.listed === "true" || flags.listed === "yes";
  if (flags.unlisted) out.listed = false;
  if (flags["description-file"]) out.descriptionFile = String(flags["description-file"]);
  return { patch: out };
}

export function discountBody(flags) {
  const kind = String(flags.kind ?? (flags.percent !== undefined ? "percent" : "fixed"));
  if (kind !== "percent" && kind !== "fixed") return { error: "--kind must be percent or fixed" };
  let value;
  if (kind === "percent") {
    value = Number(flags.percent ?? flags.value);
    if (!Number.isInteger(value) || value < 1 || value > 90) return { error: "--percent must be a whole number from 1 to 90" };
  } else {
    value = toMinor(flags.amount ?? flags.value);
    if (value === null || value <= 0) return { error: "--amount must look like 2.50" };
  }
  const items = flags.items && flags.items !== true ? String(flags.items).split(",").map((x) => x.trim()).filter(Boolean) : [];
  const date = (k) => (flags[k] && flags[k] !== true ? String(flags[k]) : null);
  return { body: { kind, value, code: flags.code && flags.code !== true ? String(flags.code) : "", items, startsAt: date("starts"), endsAt: date("ends"), maxUses: flags["max-uses"] ? Number(flags["max-uses"]) : null } };
}
