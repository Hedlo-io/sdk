import { MarketError } from "./crypto.ts";
import { MARK_PATH } from "./licence.ts";
import type { PackFile } from "./archive.ts";

export const KINDS = ["plugin", "theme", "email-template", "invoice-template", "section-pack"] as const;
export type Kind = (typeof KINDS)[number];
export const PRODUCTS = ["loom", "bolt", "shuttle"] as const;
export type Product = (typeof PRODUCTS)[number];

export interface HedloManifest {
  id: string;
  kind: Kind;
  product: Product;
  version: string;
  name: string;
  summary: string;
  categories: string[];
  readme: string;
  changelog: string;
}

export type Severity = "error" | "warning";

export interface Finding {
  severity: Severity;
  rule: string;
  path: string;
  detail: string;
}

const ID = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/;
const NATIVE: Record<Product, string> = { loom: "loom-plugin.json", bolt: "bolt-plugin.json", shuttle: "plugin.toml" };

export function parseManifest(raw: unknown): HedloManifest {
  const m = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null;
  const fail = (f: string, why: string): never => {
    throw new MarketError("manifest", `hedlo.json: ${f} ${why}`);
  };
  if (!m) fail("", "must be an object");
  const s = (k: string, max: number, req = true) => {
    const v = m![k];
    if (v === undefined && !req) return "";
    if (typeof v !== "string" || v.length > max || (req && !v.trim())) fail(k, `must be text up to ${max} characters`);
    return (v as string).trim();
  };
  const id = s("id", 100);
  if (!ID.test(id)) fail("id", "looks like publisher.item, lowercase");
  const kind = s("kind", 40) as Kind;
  if (!KINDS.includes(kind)) fail("kind", `is one of ${KINDS.join(", ")}`);
  const product = s("product", 20) as Product;
  if (!PRODUCTS.includes(product)) fail("product", `is one of ${PRODUCTS.join(", ")}`);
  if (product === "shuttle" && kind !== "plugin") fail("kind", "Shuttle only takes plugins");
  const version = s("version", 64);
  if (!SEMVER.test(version)) fail("version", "is a semantic version like 1.2.0");
  const cats = m!.categories;
  if (!Array.isArray(cats) || cats.length === 0 || cats.length > 3 || cats.some((c) => typeof c !== "string" || !/^[a-z0-9-]{2,40}$/.test(c))) fail("categories", "lists 1 to 3 category slugs");
  const readme = s("readme", 200, false) || "README.md";
  const changelog = s("changelog", 200, false) || "CHANGELOG.md";
  return { id, kind, product, version, name: s("name", 80), summary: s("summary", 200), categories: cats as string[], readme, changelog };
}

const SECRETS: { rule: string; re: RegExp }[] = [
  { rule: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/ },
  { rule: "aws-key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { rule: "stripe-live-key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/ },
  { rule: "github-token", re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/ },
  { rule: "slack-token", re: /\bxox[abpr]-[0-9A-Za-z-]{10,}\b/ },
  { rule: "google-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { rule: "db-url-password", re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]{3,}@/ },
];

const RISKY: { rule: string; re: RegExp; detail: string }[] = [
  { rule: "dynamic-code", re: /\beval\s*\(|\bnew\s+Function\s*\(/, detail: "runs code built from strings" },
  { rule: "child-process", re: /\bchild_process\b|\bspawnSync?\s*\(|\bexecSync?\s*\(/, detail: "starts processes" },
  { rule: "obfuscation", re: /(?:\\x[0-9a-f]{2}){40,}|_0x[0-9a-f]{4,}\b.*_0x[0-9a-f]{4,}\b.*_0x[0-9a-f]{4,}\b/i, detail: "looks obfuscated" },
  { rule: "remote-code", re: /\bimport\s*\(\s*["'`]https?:|require\s*\(\s*["'`]https?:/, detail: "loads code from the network" },
  { rule: "crypto-miner", re: /\b(?:coinhive|cryptonight|stratum\+tcp|xmrig)\b/i, detail: "mentions crypto-mining" },
];

const TEXT = /\.(m?[jt]sx?|cjs|json|wx|css|html?|md|txt|toml|ya?ml|svg|hbs|mjml|xml|csv|po|ini|env)$/i;
const BLOCKED = /\.(exe|dll|so|dylib|bat|cmd|ps1|sh|jar|class|node|wasm|scr|msi|apk|dmg)$/i;
const MAX_TEXT_SCAN = 2 * 1024 * 1024;

export interface ReviewInput {
  files: readonly PackFile[];
  publisherSlug: string;
  previousVersion: string | null;
}

export interface AutoReview {
  manifest: HedloManifest | null;
  findings: Finding[];
  passed: boolean;
  files: number;
  bytes: number;
}

function cmp(a: string, b: string): number {
  const pa = a.split(/[.-]/);
  const pb = b.split(/[.-]/);
  for (let i = 0; i < 3; i++) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d) return d;
  }
  const ra = a.includes("-");
  const rb = b.includes("-");
  return ra === rb ? a.localeCompare(b) : ra ? -1 : 1;
}

export function autoReview(i: ReviewInput): AutoReview {
  const findings: Finding[] = [];
  const add = (severity: Severity, rule: string, path: string, detail: string) => findings.push({ severity, rule, path, detail });
  const bytes = i.files.reduce((n, f) => n + f.body.byteLength, 0);
  let manifest: HedloManifest | null = null;
  const mf = i.files.find((f) => f.path === "hedlo.json");
  if (!mf) add("error", "manifest-missing", "hedlo.json", "the package has no hedlo.json");
  else {
    try {
      manifest = parseManifest(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(mf.body)));
    } catch (e) {
      add("error", "manifest-invalid", "hedlo.json", e instanceof MarketError ? e.message : "hedlo.json is not valid JSON");
    }
  }
  if (manifest) {
    if (!manifest.id.startsWith(`${i.publisherSlug}.`)) add("error", "manifest-namespace", "hedlo.json", `the id must start with ${i.publisherSlug}.`);
    if (manifest.kind === "plugin" || manifest.kind === "theme") {
      const native = NATIVE[manifest.product];
      const nf = i.files.find((f) => f.path === native);
      if (!nf) add("error", "native-manifest", native, `a ${manifest.product} ${manifest.kind} needs ${native}`);
      else if (native.endsWith(".json")) {
        try {
          const n = JSON.parse(new TextDecoder().decode(nf.body)) as Record<string, unknown>;
          if (n.id !== manifest.id) add("error", "native-id", native, "the id differs from hedlo.json");
          if (n.version !== manifest.version) add("error", "native-version", native, "the version differs from hedlo.json");
          const caps = Array.isArray(n.capabilities) ? n.capabilities.filter((c): c is string => typeof c === "string") : [];
          if (caps.length) add("warning", "capabilities", native, `requests ${caps.join(", ")}; the reviewer checks each one is needed`);
          const perms = Array.isArray(n.permissions) ? n.permissions.map((p) => (p && typeof p === "object" ? String((p as { id?: unknown }).id ?? "") : "")).filter(Boolean) : [];
          if (perms.length) add("warning", "permissions", native, `adds permissions ${perms.join(", ")}`);
        } catch {
          add("error", "native-manifest", native, `${native} is not valid JSON`);
        }
      }
    }
    if (!i.files.some((f) => f.path === manifest!.readme)) add("error", "readme-missing", manifest.readme, "the readme file is missing");
    if (!i.files.some((f) => f.path === manifest!.changelog)) add("warning", "changelog-missing", manifest.changelog, "there is no changelog");
    if (i.previousVersion && cmp(manifest.version, i.previousVersion) <= 0) add("error", "version-order", "hedlo.json", `the version must be newer than ${i.previousVersion}`);
  }
  for (const f of i.files.filter((x) => /(^|\/)package\.json$/.test(x.path) && !/(^|\/)node_modules\//.test(x.path))) {
    let pkg: Record<string, unknown> = {};
    try {
      pkg = JSON.parse(new TextDecoder().decode(f.body)) as Record<string, unknown>;
    } catch {
      add("error", "package-json", f.path, "package.json is not valid JSON");
      continue;
    }
    const scripts = pkg.scripts && typeof pkg.scripts === "object" ? Object.keys(pkg.scripts as object) : [];
    const hooks = scripts.filter((k) => /^(pre|post)?install$|^prepare$/.test(k));
    if (hooks.length) add("error", "install-script", f.path, `install scripts are not accepted: ${hooks.join(", ")}`);
    const deps = ["dependencies", "optionalDependencies"].flatMap((k) => (pkg[k] && typeof pkg[k] === "object" ? Object.keys(pkg[k] as object) : []));
    if (deps.length) add("warning", "dependencies", f.path, `declares runtime dependencies (${deps.slice(0, 12).join(", ")}); bundle them so reviewers see the shipped code`);
    for (const [name, spec] of Object.entries((pkg.dependencies ?? {}) as Record<string, unknown>)) {
      if (typeof spec === "string" && /^(git\+|git:|https?:|file:|link:|github:|[\w-]+\/[\w.-]+(#.*)?$)/.test(spec)) add("error", "dependency-source", f.path, `${name} is not from the npm registry`);
    }
  }
  for (const f of i.files) {
    if (f.path.toLowerCase() === MARK_PATH || f.path.toLowerCase().startsWith(".hedlo/")) add("error", "reserved-path", f.path, ".hedlo/ is reserved for the marketplace");
    if (BLOCKED.test(f.path)) add("error", "executable", f.path, "executables and native binaries are not accepted");
    if (/(^|\/)(\.env(\..+)?|id_rsa|id_ed25519|\.npmrc|\.git\/.*)$/i.test(f.path)) add("error", "sensitive-file", f.path, "this file should not be published");
    if (/(^|\/)node_modules\//.test(f.path)) add("warning", "node-modules", f.path, "bundle dependencies instead of shipping node_modules");
    if (!TEXT.test(f.path) || f.body.byteLength > MAX_TEXT_SCAN) continue;
    const text = new TextDecoder().decode(f.body);
    for (const s of SECRETS) if (s.re.test(text)) add("error", s.rule, f.path, "looks like a secret; remove it and rotate it");
    if (/\.(m?[jt]sx?|cjs|wx)$/i.test(f.path)) for (const r of RISKY) if (r.re.test(text)) add("warning", r.rule, f.path, r.detail);
    if (/\.(m?js|cjs)$/i.test(f.path) && text.length > 2000 && text.split("\n").length < 3 && !f.path.includes(".min.")) add("warning", "minified", f.path, "reviewers need readable source; ship unminified code");
  }
  return { manifest, findings, passed: !findings.some((f) => f.severity === "error"), files: i.files.length, bytes };
}

export const CHECKLIST = ["matches-description", "permissions-justified", "no-tracking", "no-hidden-network", "licence-clear", "readme-usable"] as const;

export type Decision = "approved" | "changes" | "rejected";

export function canReview(reviewer: { id: string; publishers: readonly string[]; staff: boolean }, publisher: string): boolean {
  return reviewer.staff && !reviewer.publishers.includes(publisher);
}
