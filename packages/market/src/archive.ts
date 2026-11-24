import { createHash, createPrivateKey, sign } from "node:crypto";
import { MarketError } from "./crypto.ts";

export interface PackFile {
  path: string;
  body: Uint8Array;
}

export const MAX_UPLOAD = 25 * 1024 * 1024;
export const MAX_FILES = 2000;
const SAFE_PATH = /^(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._@+-]+(?:\/[A-Za-z0-9._@+-]+)*$/;

export function safePath(path: string): boolean {
  return typeof path === "string" && path.length <= 400 && SAFE_PATH.test(path);
}

export function pack(files: readonly PackFile[]): Uint8Array {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const seen = new Set<string>();
  const parts: Buffer[] = [];
  for (const f of sorted) {
    if (!safePath(f.path)) throw new MarketError("archive", `unsafe path ${f.path.slice(0, 80)}`);
    const low = f.path.toLowerCase();
    if (seen.has(low)) throw new MarketError("archive", `duplicate path ${f.path.slice(0, 80)}`);
    seen.add(low);
    parts.push(Buffer.from(f.path, "utf8"), Buffer.from([0]), Buffer.from(String(f.body.byteLength), "ascii"), Buffer.from([0]), Buffer.from(f.body));
  }
  return new Uint8Array(Buffer.concat(parts));
}

export function unpack(bytes: Uint8Array, limits: { maxBytes?: number; maxFiles?: number } = {}): PackFile[] {
  const maxBytes = limits.maxBytes ?? MAX_UPLOAD;
  const maxFiles = limits.maxFiles ?? MAX_FILES;
  if (bytes.byteLength > maxBytes) throw new MarketError("archive", "the package is too large");
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out: PackFile[] = [];
  const seen = new Set<string>();
  let i = 0;
  let last = "";
  while (i < buf.length) {
    const a = buf.indexOf(0, i);
    if (a < 0 || a - i > 512) throw new MarketError("archive", "the package is damaged");
    const path = buf.subarray(i, a).toString("utf8");
    const b = buf.indexOf(0, a + 1);
    if (b < 0 || b - a > 12) throw new MarketError("archive", "the package is damaged");
    const lenText = buf.subarray(a + 1, b).toString("ascii");
    const len = /^\d+$/.test(lenText) ? Number(lenText) : -1;
    if (len < 0 || b + 1 + len > buf.length) throw new MarketError("archive", "the package is damaged");
    if (!safePath(path)) throw new MarketError("archive", `unsafe path ${path.slice(0, 80)}`);
    if (seen.has(path.toLowerCase())) throw new MarketError("archive", `duplicate path ${path.slice(0, 80)}`);
    if (path <= last) throw new MarketError("archive", "the package is not in canonical order");
    seen.add(path.toLowerCase());
    last = path;
    out.push({ path, body: new Uint8Array(buf.subarray(b + 1, b + 1 + len)) });
    if (out.length > maxFiles) throw new MarketError("archive", `more than ${maxFiles} files`);
    i = b + 1 + len;
  }
  return out;
}

export function packageSignature(bytes: Uint8Array, signingPem: string): string {
  const digest = createHash("sha256").update(bytes).digest();
  return sign(null, digest, createPrivateKey(signingPem)).toString("base64");
}
