import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, sign, timingSafeEqual, verify, type KeyObject } from "node:crypto";

export class MarketError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "MarketError";
  }
}

const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");

export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function fromB64url(s: string, max = 1 << 20): Buffer {
  if (typeof s !== "string" || s.length > max || !/^[A-Za-z0-9_-]*$/.test(s)) throw new MarketError("encoding", "not base64url");
  return Buffer.from(s, "base64url");
}

export function sha256(data: Uint8Array | string): Buffer {
  return createHash("sha256").update(data).digest();
}

export function sha256hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function token(prefix: string, bytes = 32): string {
  return prefix + randomBytes(bytes).toString("base64url");
}

export function sameSecret(a: string, b: string): boolean {
  const x = sha256(a);
  const y = sha256(b);
  return timingSafeEqual(x, y) && a.length === b.length;
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export function ed25519Pair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { publicKey: rawPublic(publicKey), privateKey: privateKey.export({ format: "pem", type: "pkcs8" }).toString() };
}

export function x25519Pair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return { publicKey: rawPublic(publicKey), privateKey: privateKey.export({ format: "pem", type: "pkcs8" }).toString() };
}

function rawPublic(k: KeyObject): string {
  return b64url(k.export({ format: "der", type: "spki" }).subarray(12));
}

export function edPublic(raw: string): KeyObject {
  const b = fromB64url(raw, 64);
  if (b.length !== 32) throw new MarketError("key", "an Ed25519 public key is 32 bytes");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI, b]), format: "der", type: "spki" });
}

export function xPublic(raw: string): KeyObject {
  const b = fromB64url(raw, 64);
  if (b.length !== 32) throw new MarketError("key", "an X25519 public key is 32 bytes");
  return createPublicKey({ key: Buffer.concat([X25519_SPKI, b]), format: "der", type: "spki" });
}

export function privateKey(pem: string): KeyObject {
  return createPrivateKey(pem);
}

export function publicOf(pem: string): string {
  return rawPublic(createPublicKey(createPrivateKey(pem)));
}

export function fingerprint(rawPublicKey: string): string {
  return sha256hex(fromB64url(rawPublicKey, 64)).slice(0, 32);
}

export function signBytes(data: Uint8Array, pem: string): string {
  return b64url(sign(null, data, createPrivateKey(pem)));
}

export function verifyBytes(data: Uint8Array, signature: string, rawPublicKey: string): boolean {
  try {
    const sig = fromB64url(signature, 200);
    return sig.length === 64 && verify(null, data, edPublic(rawPublicKey), sig);
  } catch {
    return false;
  }
}

export function seal(key: Uint8Array, plain: Uint8Array, aad: string): Buffer {
  if (key.length !== 32) throw new MarketError("key", "AES-256 needs a 32-byte key");
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(aad));
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]);
}

export function open(key: Uint8Array, sealed: Uint8Array, aad: string): Buffer {
  if (key.length !== 32 || sealed.length < 28) throw new MarketError("decrypt", "cannot decrypt");
  const buf = Buffer.from(sealed);
  const d = createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(buf.subarray(12, 28));
  try {
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]);
  } catch {
    throw new MarketError("decrypt", "cannot decrypt");
  }
}

export interface WrappedKey {
  epk: string;
  box: string;
}

function wrapKey(shared: Buffer, epk: string, recipient: string, context: string): Buffer {
  return Buffer.from(hkdfSync("sha256", shared, Buffer.concat([fromB64url(epk), fromB64url(recipient)]), `hedlo-wrap-v1|${context}`, 32));
}

export function wrapTo(recipientX25519: string, secret: Uint8Array, context: string): WrappedKey {
  const eph = generateKeyPairSync("x25519");
  const epk = rawPublic(eph.publicKey);
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: xPublic(recipientX25519) });
  const k = wrapKey(shared, epk, recipientX25519, context);
  return { epk, box: b64url(seal(k, secret, context)) };
}

export function unwrapWith(recipientPrivatePem: string, w: WrappedKey, context: string): Buffer {
  const priv = createPrivateKey(recipientPrivatePem);
  const own = rawPublic(createPublicKey(priv));
  const shared = diffieHellman({ privateKey: priv, publicKey: xPublic(w.epk) });
  return open(wrapKey(shared, w.epk, own, context), fromB64url(w.box), context);
}

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}

export function signToken(kind: string, payload: Record<string, unknown>, pem: string): string {
  const body = b64url(Buffer.from(canonicalJson({ ...payload, typ: kind })));
  return `${body}.${signBytes(Buffer.from(`hedlo:${kind}:${body}`), pem)}`;
}

export function readToken<T>(kind: string, raw: string, rawPublicKeys: readonly string[]): T | null {
  if (typeof raw !== "string" || raw.length > 8192) return null;
  const [body, sig, extra] = raw.split(".");
  if (!body || !sig || extra !== undefined) return null;
  const msg = Buffer.from(`hedlo:${kind}:${body}`);
  if (!rawPublicKeys.some((k) => verifyBytes(msg, sig, k))) return null;
  try {
    const v = JSON.parse(fromB64url(body).toString("utf8")) as Record<string, unknown>;
    return v && v.typ === kind ? (v as T) : null;
  } catch {
    return null;
  }
}
