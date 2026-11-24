import { createHash, randomBytes, verify } from "node:crypto";
import { b64url, canonicalJson, edPublic, fingerprint, fromB64url, MarketError, open, readToken, seal, sha256hex, signToken, unwrapWith, verifyBytes, wrapTo, type WrappedKey } from "./crypto.ts";
import { pack, packageSignature, unpack, type PackFile } from "./archive.ts";

export const DAY = 86_400_000;
export const CERT_VALID = 30 * DAY;
export const CERT_RENEW = 3 * DAY;
export const MARK_PATH = ".hedlo/licence.json";

export interface Certificate {
  typ: "activation";
  v: 1;
  licence: string;
  item: string;
  site: string;
  key: string;
  domain: string;
  updatesUntil: number | null;
  trialUntil: number | null;
  iat: number;
  renew: number;
  exp: number;
}

export interface CertificateInput {
  licence: string;
  item: string;
  site: string;
  installKey: string;
  domain: string;
  updatesUntil?: number | null;
  trialUntil?: number | null;
}

export function issueCertificate(i: CertificateInput, now: number, licencePem: string): string {
  const exp = i.trialUntil ? Math.min(now + CERT_VALID, i.trialUntil) : now + CERT_VALID;
  return signToken("activation", { v: 1, licence: i.licence, item: i.item, site: i.site, key: fingerprint(i.installKey), domain: normaliseDomain(i.domain), updatesUntil: i.updatesUntil ?? null, trialUntil: i.trialUntil ?? null, iat: now, renew: Math.min(now + CERT_RENEW, exp), exp }, licencePem);
}

export type CertCheck = { ok: true; cert: Certificate; renewDue: boolean } | { ok: false; reason: "signature" | "expired" | "site" | "item" | "future" };

export function checkCertificate(raw: string, marketKeys: readonly string[], expect: { installKey: string; domain: string; item: string }, now: number): CertCheck {
  const cert = readToken<Certificate>("activation", raw, marketKeys);
  if (!cert || cert.v !== 1) return { ok: false, reason: "signature" };
  if (cert.iat > now + 5 * 60_000) return { ok: false, reason: "future" };
  if (now >= cert.exp) return { ok: false, reason: "expired" };
  if (cert.key !== fingerprint(expect.installKey) || cert.domain !== normaliseDomain(expect.domain)) return { ok: false, reason: "site" };
  if (cert.item !== expect.item) return { ok: false, reason: "item" };
  return { ok: true, cert, renewDue: now >= cert.renew };
}

export function updatesCover(cert: Certificate, releasedAt: number): boolean {
  return cert.updatesUntil === null || releasedAt <= cert.updatesUntil;
}

const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

export function normaliseDomain(raw: string): string {
  const d = String(raw ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!DOMAIN.test(d) || /^\d+(\.\d+){3}$/.test(d) || d.endsWith(".localhost") || d === "localhost") throw new MarketError("domain", "enter the public address of your installation, like admin.example.com");
  return d;
}

export interface LinkRequest {
  domain: string;
  product: "loom" | "bolt";
  version: string;
  signKey: string;
  boxKey: string;
  nonce: string;
  iat: number;
}

export function linkRequestMessage(r: LinkRequest): Buffer {
  return Buffer.from(`hedlo:link:${canonicalJson(r)}`);
}

export function checkLinkRequest(raw: unknown, signature: string, now: number): LinkRequest {
  const r = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const req: LinkRequest = {
    domain: normaliseDomain(String(r.domain ?? "")),
    product: r.product === "bolt" ? "bolt" : r.product === "loom" ? "loom" : (() => { throw new MarketError("link", "unknown product"); })(),
    version: String(r.version ?? "").slice(0, 40),
    signKey: String(r.signKey ?? ""),
    boxKey: String(r.boxKey ?? ""),
    nonce: String(r.nonce ?? ""),
    iat: Number(r.iat),
  };
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(req.nonce)) throw new MarketError("link", "bad nonce");
  if (!Number.isFinite(req.iat) || Math.abs(now - req.iat) > 10 * 60_000) throw new MarketError("link", "the link request is too old; check the server clock");
  edPublic(req.signKey);
  if (fromB64url(req.boxKey, 64).length !== 32) throw new MarketError("key", "bad box key");
  if (!verifyBytes(linkRequestMessage(req), signature, req.signKey)) throw new MarketError("link", "the link request signature is wrong");
  return req;
}

export const LINK_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ23456789";

export function userCode(groups = 2, size = 4): string {
  const out: string[] = [];
  for (let g = 0; g < groups; g++) {
    let s = "";
    while (s.length < size) {
      const b = randomBytes(1)[0]!;
      if (b < 252) s += LINK_ALPHABET[b % LINK_ALPHABET.length];
    }
    out.push(s);
  }
  return out.join("-");
}

export function normaliseUserCode(raw: string): string {
  const s = String(raw ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  return s.length === 8 ? `${s.slice(0, 4)}-${s.slice(4)}` : "";
}

export const PROOF_PATH = "/api/hedlo/site-proof";

export function proofChallenge(): string {
  return b64url(randomBytes(24));
}

export function proofMessage(domain: string, challenge: string): Buffer {
  return Buffer.from(`hedlo:proof:${normaliseDomain(domain)}:${challenge}`);
}

export function proofMatches(body: string, signKey: string, domain: string, challenge: string): boolean {
  const sig = String(body ?? "").trim();
  return /^[A-Za-z0-9_-]{86}$/.test(sig) && verifyBytes(proofMessage(domain, challenge), sig, signKey);
}

export interface Mark {
  licence: string;
  item: string;
  version: string;
  buyer: string;
  site: string;
  issued: number;
}

export function buyerTag(userId: string, secret: string): string {
  return createHash("sha256").update(`${secret}:${userId}`).digest("hex").slice(0, 24);
}

export function watermark(files: readonly PackFile[], mark: Mark): PackFile[] {
  if (files.some((f) => f.path.toLowerCase() === MARK_PATH)) throw new MarketError("archive", `${MARK_PATH} is reserved`);
  return [...files, { path: MARK_PATH, body: new TextEncoder().encode(canonicalJson(mark)) }];
}

export function readMark(files: readonly PackFile[]): Mark | null {
  const f = files.find((x) => x.path === MARK_PATH);
  if (!f) return null;
  try {
    return JSON.parse(new TextDecoder().decode(f.body)) as Mark;
  } catch {
    return null;
  }
}

export interface IssuedPackage {
  format: "hedlo-sealed-v1";
  licence: string;
  item: string;
  version: string;
  key: WrappedKey;
  sha256: string;
  signature: string;
  body: string;
}

const AAD = (licence: string, item: string, version: string) => `hedlo-package-v1|${licence}|${item}|${version}`;

export function issuePackage(base: readonly PackFile[], mark: Mark, signingPem: string, installBoxKey: string): IssuedPackage {
  const plain = pack(watermark(base, mark));
  const key = randomBytes(32);
  const aad = AAD(mark.licence, mark.item, mark.version);
  return {
    format: "hedlo-sealed-v1",
    licence: mark.licence,
    item: mark.item,
    version: mark.version,
    key: wrapTo(installBoxKey, key, aad),
    sha256: sha256hex(plain),
    signature: packageSignature(plain, signingPem),
    body: b64url(seal(key, plain, aad)),
  };
}

export function openPackage(p: IssuedPackage, installBoxPem: string, marketSignKeys: readonly string[], cert: Certificate): { bytes: Uint8Array; files: PackFile[] } {
  if (p.format !== "hedlo-sealed-v1") throw new MarketError("package", "unknown package format");
  if (p.licence !== cert.licence || p.item !== cert.item) throw new MarketError("package", "this package was issued for another licence");
  const aad = AAD(p.licence, p.item, p.version);
  const key = unwrapWith(installBoxPem, p.key, aad);
  const bytes = open(key, fromB64url(p.body, 64 << 20), aad);
  if (sha256hex(bytes) !== p.sha256) throw new MarketError("package", "the package checksum does not match");
  const digest = createHash("sha256").update(bytes).digest();
  const sig = Buffer.from(p.signature, "base64");
  const signed = sig.length === 64 && marketSignKeys.some((k) => {
    try {
      return verify(null, digest, edPublic(k), sig);
    } catch {
      return false;
    }
  });
  if (!signed) throw new MarketError("package", "the package is not signed by the marketplace");
  const files = unpack(bytes, { maxBytes: 64 << 20, maxFiles: 5001 });
  const mark = readMark(files);
  if (!mark || mark.licence !== cert.licence || mark.item !== cert.item || mark.site !== cert.site) throw new MarketError("package", "the package mark does not match the licence");
  return { bytes, files };
}

export function siteRequestMessage(method: string, path: string, time: number, body: Uint8Array | string): Buffer {
  return Buffer.from(`hedlo:api:${method.toUpperCase()}:${path}:${time}:${sha256hex(body)}`);
}

export function checkSiteRequest(h: { key: string | null; time: string | null; signature: string | null }, method: string, path: string, body: Uint8Array | string, now: number): string | null {
  if (!h.key || !h.time || !h.signature || !/^\d{10,16}$/.test(h.time)) return null;
  const time = Number(h.time);
  if (Math.abs(now - time) > 5 * 60_000) return null;
  return verifyBytes(siteRequestMessage(method, path, time, body), h.signature, h.key) ? h.key : null;
}
