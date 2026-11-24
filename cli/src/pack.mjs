import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

export const MAX_UPLOAD = 25 * 1024 * 1024;
export const MAX_FILES = 2000;
const SAFE_PATH = /^(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._@+-]+(?:\/[A-Za-z0-9._@+-]+)*$/;
const ID = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/;
const KINDS = ["plugin", "theme", "email-template", "invoice-template"];
const PRODUCTS = ["loom", "bolt", "shuttle"];
const NATIVE = { loom: "loom-plugin.json", bolt: "bolt-plugin.json", shuttle: "plugin.toml" };
const ALWAYS_SKIP = [".git", "node_modules", ".hedlo", ".DS_Store", "Thumbs.db"];
const BLOCKED = /\.(exe|dll|so|dylib|bat|cmd|ps1|sh|jar|class|node|wasm|scr|msi|apk|dmg)$/i;
const SENSITIVE = /(^|\/)(\.env(\..+)?|id_rsa|id_ed25519|\.npmrc)$/i;
const SECRETS = [
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/,
  /\bgh[pousr]_[0-9A-Za-z]{36,}\b/,
  /\bxox[abpr]-[0-9A-Za-z-]{10,}\b/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
];
const TEXT = /\.(m?[jt]sx?|cjs|json|wx|css|html?|md|txt|toml|ya?ml|svg|hbs|mjml|xml|csv|po|ini|env)$/i;

export function safePath(path) {
  return typeof path === "string" && path.length <= 400 && SAFE_PATH.test(path);
}

function globToRegex(pattern) {
  let re = "";
  for (const ch of pattern) {
    if (ch === "*") re += "[^/]*";
    else if (ch === "?") re += "[^/]";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$");
}

export function readIgnore(dir) {
  let text = "";
  try {
    text = readFileSync(join(dir, ".hedloignore"), "utf8");
  } catch {
    return [];
  }
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => l.replace(/^\/+/, "").replace(/\/+$/, ""));
}

function ignored(path, rules) {
  const parts = path.split("/");
  if (parts.some((p) => ALWAYS_SKIP.includes(p))) return true;
  for (const r of rules) {
    if (!r.includes("/") && parts.some((p) => globToRegex(r).test(p))) return true;
    if (r.includes("/") && (path === r || path.startsWith(r + "/") || globToRegex(r).test(path))) return true;
  }
  return false;
}

export function collect(dir) {
  const rules = readIgnore(dir);
  const out = [];
  const walk = (abs) => {
    for (const name of readdirSync(abs).sort()) {
      const full = join(abs, name);
      const rel = relative(dir, full).split(sep).join("/");
      if (ignored(rel, rules)) continue;
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) {
        out.push({ path: rel, body: new Uint8Array(readFileSync(full)) });
        if (out.length > MAX_FILES) throw new Error(`more than ${MAX_FILES} files; add a .hedloignore`);
      }
    }
  };
  walk(dir);
  return out;
}

export function pack(files) {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const seen = new Set();
  const parts = [];
  for (const f of sorted) {
    if (!safePath(f.path)) throw new Error(`unsafe path ${f.path.slice(0, 80)}`);
    const low = f.path.toLowerCase();
    if (seen.has(low)) throw new Error(`duplicate path ${f.path.slice(0, 80)}`);
    seen.add(low);
    parts.push(Buffer.from(f.path, "utf8"), Buffer.from([0]), Buffer.from(String(f.body.byteLength), "ascii"), Buffer.from([0]), Buffer.from(f.body));
  }
  return new Uint8Array(Buffer.concat(parts));
}

export function parseManifest(raw) {
  const errors = [];
  const m = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  if (!m) return { manifest: null, errors: ["hedlo.json must be an object"] };
  const s = (k, max, req = true) => {
    const v = m[k];
    if (v === undefined && !req) return "";
    if (typeof v !== "string" || v.length > max || (req && !v.trim())) {
      errors.push(`${k} must be text up to ${max} characters`);
      return "";
    }
    return v.trim();
  };
  const id = s("id", 100);
  if (id && !ID.test(id)) errors.push("id looks like publisher.item, lowercase");
  const kind = s("kind", 40);
  if (kind && !KINDS.includes(kind)) errors.push(`kind is one of ${KINDS.join(", ")}`);
  const product = s("product", 20);
  if (product && !PRODUCTS.includes(product)) errors.push(`product is one of ${PRODUCTS.join(", ")}`);
  if (product === "shuttle" && kind && kind !== "plugin") errors.push("Shuttle only takes plugins");
  const version = s("version", 64);
  if (version && !SEMVER.test(version)) errors.push("version is a semantic version like 1.2.0");
  const cats = m.categories;
  if (!Array.isArray(cats) || cats.length === 0 || cats.length > 3 || cats.some((c) => typeof c !== "string" || !/^[a-z0-9-]{2,40}$/.test(c))) errors.push("categories lists 1 to 3 category slugs");
  const name = s("name", 80);
  const summary = s("summary", 200);
  const readme = s("readme", 200, false) || "README.md";
  const changelog = s("changelog", 200, false) || "CHANGELOG.md";
  return { manifest: errors.length ? null : { id, kind, product, version, name, summary, categories: cats, readme, changelog }, errors };
}

export function validate(files, publisher) {
  const errors = [];
  const warnings = [];
  const size = files.reduce((n, f) => n + f.body.byteLength, 0);
  if (size > MAX_UPLOAD) errors.push(`the package is ${(size / 1048576).toFixed(1)} MB; the limit is 25 MB`);
  const mf = files.find((f) => f.path === "hedlo.json");
  let manifest = null;
  if (!mf) errors.push("hedlo.json is missing; run hedlo init");
  else {
    try {
      const r = parseManifest(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(mf.body)));
      manifest = r.manifest;
      errors.push(...r.errors.map((e) => "hedlo.json: " + e));
    } catch {
      errors.push("hedlo.json is not valid JSON");
    }
  }
  if (manifest) {
    if (publisher && !manifest.id.startsWith(publisher + ".")) errors.push(`the id must start with ${publisher}.`);
    if (manifest.kind === "plugin" || manifest.kind === "theme") {
      const native = NATIVE[manifest.product];
      const nf = files.find((f) => f.path === native);
      if (!nf) errors.push(`a ${manifest.product} ${manifest.kind} needs ${native}`);
      else if (native.endsWith(".json")) {
        try {
          const n = JSON.parse(new TextDecoder().decode(nf.body));
          if (n.id !== manifest.id) errors.push(`${native}: the id differs from hedlo.json`);
          if (n.version !== manifest.version) errors.push(`${native}: the version differs from hedlo.json`);
        } catch {
          errors.push(`${native} is not valid JSON`);
        }
      }
    }
    if (!files.some((f) => f.path === manifest.readme)) errors.push(`${manifest.readme} is missing`);
    if (!files.some((f) => f.path === manifest.changelog)) warnings.push(`there is no ${manifest.changelog}`);
  }
  for (const f of files) {
    if (!safePath(f.path)) errors.push(`unsafe file name ${f.path}`);
    if (BLOCKED.test(f.path)) errors.push(`${f.path}: executables and native binaries are not accepted`);
    if (SENSITIVE.test(f.path)) errors.push(`${f.path}: this file should not be published`);
    if (TEXT.test(f.path) && f.body.byteLength <= 2 * 1024 * 1024) {
      const text = new TextDecoder().decode(f.body);
      if (SECRETS.some((re) => re.test(text))) errors.push(`${f.path}: looks like it contains a secret`);
    }
  }
  return { manifest, errors, warnings, files: files.length, bytes: size };
}
