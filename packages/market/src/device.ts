import { createHash } from "node:crypto";
import { sha256hex, token } from "./crypto.ts";
import { userCode } from "./licence.ts";

export const DEVICE_TTL = 15 * 60_000;
export const DEVICE_INTERVAL = 5;
export const TOKEN_TTL = 90 * 86_400_000;
export const SCOPES = ["publish", "read", "finance"] as const;
export type Scope = (typeof SCOPES)[number];

export interface DeviceGrant {
  deviceCode: string;
  deviceHash: string;
  userCode: string;
  challenge: string;
  expiresAt: number;
  interval: number;
}

export function startDeviceGrant(challenge: string, method: string, now: number): DeviceGrant | null {
  if (method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return null;
  const deviceCode = token("hdc_", 32);
  return { deviceCode, deviceHash: sha256hex(deviceCode), userCode: userCode(), challenge, expiresAt: now + DEVICE_TTL, interval: DEVICE_INTERVAL };
}

export function pkceMatches(verifier: string, challenge: string): boolean {
  if (typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  return createHash("sha256").update(verifier).digest("base64url") === challenge;
}

export type DeviceState = "pending" | "approved" | "denied" | "used";

export type TokenAnswer =
  | { ok: true }
  | { ok: false; error: "authorization_pending" | "slow_down" | "access_denied" | "expired_token" | "invalid_grant" };

export function pollDecision(g: { state: DeviceState; expiresAt: number; challenge: string; lastPoll: number | null; interval: number }, verifier: string, now: number): TokenAnswer {
  if (now >= g.expiresAt) return { ok: false, error: "expired_token" };
  if (!pkceMatches(verifier, g.challenge)) return { ok: false, error: "invalid_grant" };
  if (g.state === "used") return { ok: false, error: "invalid_grant" };
  if (g.state === "denied") return { ok: false, error: "access_denied" };
  if (g.lastPoll !== null && now - g.lastPoll < g.interval * 1000) return { ok: false, error: "slow_down" };
  if (g.state === "pending") return { ok: false, error: "authorization_pending" };
  return { ok: true };
}

export function newApiToken(): { token: string; hash: string; prefix: string } {
  const t = token("hdl_", 32);
  return { token: t, hash: sha256hex(t), prefix: t.slice(0, 10) };
}

export function tokenHash(raw: string): string | null {
  return typeof raw === "string" && /^hdl_[A-Za-z0-9_-]{43}$/.test(raw) ? sha256hex(raw) : null;
}

export function parseScopes(raw: unknown): Scope[] {
  const list = typeof raw === "string" ? raw.split(/\s+/) : [];
  const out = SCOPES.filter((s) => list.includes(s));
  return out.length ? out : ["read"];
}
