import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(REPO, "build", "npm");
const CONFIG = JSON.parse(readFileSync(join(REPO, "scripts", "npm-packages.json"), "utf8"));
const NPM_CLI = [join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"), join(dirname(process.execPath), "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")].find((p) => existsSync(p)) ?? null;
const NPM = "npm";

const HELP = `Build, pack and publish this repository's npm packages.

  node scripts/publish-npm.mjs [options] [package...]

Options
  --version <x.y.z>   set the version before building (written back to package.json)
  --tag <name>        publish under a dist-tag instead of latest
  --build-only        build, test-import and pack, but do not publish
  --dry-run           run everything and call npm publish --dry-run
  --offline           skip every npm registry check (implies --build-only)
  --help              show this text

Packages: ${CONFIG.packages.map((p) => p.name).join(", ")}
Run npm login first. npm asks for two-factor approval in the browser when it publishes.`;

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const option = (name) => {
  const i = args.indexOf(name);
  if (i === -1) return null;
  const v = args[i + 1];
  if (!v || v.startsWith("--")) fail(`${name} needs a value`);
  return v;
};
function fail(message) {
  console.error(`publish-npm: ${message}`);
  process.exit(1);
}

if (flag("--help") || flag("-h")) {
  console.log(HELP);
  process.exit(0);
}

const offline = flag("--offline");
const dry = flag("--dry-run");
const buildOnly = flag("--build-only") || offline;
const tag = option("--tag");
const setVersion = option("--version");
const valued = new Set(["--tag", "--version"]);
const wanted = args.filter((a, i) => !a.startsWith("--") && !valued.has(args[i - 1] ?? ""));

if (setVersion && !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(setVersion)) fail(`--version ${setVersion} is not a semver version`);
if (tag && /^v?\d/.test(tag)) fail(`--tag ${tag} looks like a version; npm refuses tags that parse as versions`);

const selected = wanted.length === 0 ? CONFIG.packages : wanted.map((w) => CONFIG.packages.find((p) => p.name === w || p.dir === w) ?? fail(`unknown package ${w}`));

function resolveCmd(cmd, argv) {
  if (cmd !== NPM) return [cmd, argv];
  if (NPM_CLI) return [process.execPath, [NPM_CLI, ...argv]];
  return [process.platform === "win32" ? "npm.cmd" : "npm", argv];
}

function run(cmd0, argv0, opts = {}) {
  const [cmd, argv] = resolveCmd(cmd0, argv0);
  const r = spawnSync(cmd, argv, { stdio: "inherit", windowsHide: true, ...opts });
  if (r.error) fail(`${cmd} failed to start: ${r.error.message}`);
  return r.status ?? 1;
}

function capture(cmd0, argv0, opts = {}) {
  const [cmd, argv] = resolveCmd(cmd0, argv0);
  const r = spawnSync(cmd, argv, { encoding: "utf8", windowsHide: true, ...opts });
  return { status: r.status ?? 1, out: String(r.stdout ?? ""), err: String(r.stderr ?? "") };
}

function findUp(start, rel) {
  for (let dir = start; ; dir = dirname(dir)) {
    const p = join(dir, rel);
    if (existsSync(p)) return p;
    if (dirname(dir) === dir) return null;
  }
}

const TSC = findUp(REPO, join("node_modules", "typescript", "bin", "tsc"));
if (!TSC) fail("TypeScript is not installed; run npm install in the workspace first");

function registryVersions(name) {
  const r = capture(NPM, ["view", name, "versions", "--json"]);
  if (r.status !== 0) {
    if (/E404|404 Not Found/.test(r.out + r.err)) return [];
    fail(`npm view ${name} failed:\n${(r.err || r.out).trim()}`);
  }
  const v = JSON.parse(r.out || "[]");
  return Array.isArray(v) ? v : [v];
}

function satisfiesCaret(range, versions) {
  const m = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(range);
  if (!m) return versions.length > 0;
  const [maj, min, pat] = m.slice(1).map(Number);
  return versions.some((v) => {
    const n = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
    if (!n) return false;
    const [a, b, c] = n.slice(1).map(Number);
    if (maj > 0) return a === maj && (b > min || (b === min && c >= pat));
    if (min > 0) return a === 0 && b === min && c >= pat;
    return a === 0 && b === 0 && c === pat;
  });
}

function exportTarget(src) {
  if (typeof src !== "string" || !src.startsWith("./src/") || !src.endsWith(".ts")) fail(`export ${src} must point at ./src/*.ts`);
  const base = src.slice("./src/".length, -".ts".length);
  return { types: `./dist/${base}.d.ts`, default: `./dist/${base}.js` };
}

function manifest(pkg, spec, version) {
  const exportsIn = typeof pkg.exports === "string" ? { ".": pkg.exports } : pkg.exports;
  if (!exportsIn || typeof exportsIn !== "object") fail(`${spec.dir} has no exports`);
  const exportsOut = Object.fromEntries(Object.entries(exportsIn).map(([k, v]) => [k, exportTarget(v)]));
  const root = exportsOut["."];
  const out = {
    name: spec.name,
    version,
    description: spec.description ?? pkg.description,
    license: pkg.license,
    type: "module",
    ...(root ? { main: root.default, types: root.types } : {}),
    exports: exportsOut,
    files: ["dist", "README.md", "LICENSE", "NOTICE"],
    engines: pkg.engines ?? { node: ">=22.6" },
    ...(spec.keywords ? { keywords: spec.keywords } : {}),
    ...(spec.homepage ? { homepage: spec.homepage } : {}),
    ...(spec.repository ? { repository: spec.repository } : {}),
    ...(pkg.dependencies ? { dependencies: pkg.dependencies } : {}),
    ...(pkg.peerDependencies ? { peerDependencies: pkg.peerDependencies } : {}),
    ...(pkg.peerDependenciesMeta ? { peerDependenciesMeta: pkg.peerDependenciesMeta } : {}),
    publishConfig: { access: "public" },
  };
  for (const [dep, range] of Object.entries(out.dependencies ?? {})) {
    if (/^(file:|link:|workspace:)/.test(range) || range === "*") fail(`${spec.name} depends on ${dep}@${range}, which cannot be published`);
  }
  return out;
}

function listFiles(dir, base = dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? listFiles(join(dir, e.name), base) : [relative(base, join(dir, e.name)).replaceAll("\\", "/")]));
}

function build(spec) {
  const src = join(REPO, spec.dir);
  const pkgPath = join(src, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  if (setVersion && pkg.version !== setVersion) {
    pkg.version = setVersion;
    writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
    console.log(`${spec.dir}: version set to ${setVersion}`);
  }
  const version = pkg.version;
  if (version === "0.0.0") fail(`${spec.dir} is still at 0.0.0; pass --version x.y.z`);
  const stage = join(OUT, spec.name.replace(/^@/, "").replace("/", "-"));
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });

  const tsconfig = {
    compilerOptions: {
      target: "ES2023",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      strict: true,
      noUncheckedIndexedAccess: true,
      verbatimModuleSyntax: true,
      erasableSyntaxOnly: true,
      rewriteRelativeImportExtensions: true,
      declaration: true,
      sourceMap: false,
      noEmitOnError: true,
      skipLibCheck: true,
      types: ["node"],
      rootDir: relative(stage, join(src, "src")).replaceAll("\\", "/"),
      outDir: "dist",
    },
    include: [relative(stage, join(src, "src")).replaceAll("\\", "/") + "/**/*.ts"],
  };
  writeFileSync(join(stage, "tsconfig.json"), JSON.stringify(tsconfig, null, 2));
  console.log(`\n${spec.name}@${version}: compiling`);
  if (run(process.execPath, [TSC, "-p", join(stage, "tsconfig.json")]) !== 0) fail(`${spec.name} does not compile`);
  rmSync(join(stage, "tsconfig.json"));

  const dist = join(stage, "dist");
  for (const f of listFiles(dist).filter((f) => f.endsWith(".d.ts"))) {
    const p = join(dist, f);
    const text = readFileSync(p, "utf8");
    const fixed = text.replace(/((?:from\s+|import\()["'])(\.{1,2}\/[^"']+)\.ts(["'])/g, "$1$2.js$3");
    if (fixed !== text) writeFileSync(p, fixed);
  }
  const leaked = listFiles(dist).filter((f) => /\.(js|d\.ts)$/.test(f)).filter((f) => /from\s+["']\.{1,2}\/[^"']+\.ts["']|import\(["']\.{1,2}\/[^"']+\.ts["']\)/.test(readFileSync(join(dist, f), "utf8")));
  if (leaked.length) fail(`${spec.name}: relative .ts imports left in ${leaked.join(", ")}`);

  const out = manifest(pkg, spec, version);
  writeFileSync(join(stage, "package.json"), JSON.stringify(out, null, 2) + "\n");
  for (const f of ["README.md", "LICENSE", "NOTICE"]) {
    const from = [join(src, f), join(REPO, f)].find((p) => existsSync(p));
    if (from) copyFileSync(from, join(stage, f));
    else if (f !== "NOTICE") fail(`${spec.name}: no ${f} in ${spec.dir} or the repository root`);
  }
  for (const [k, v] of Object.entries(out.exports)) {
    for (const file of [v.types, v.default]) if (!existsSync(join(stage, file))) fail(`${spec.name}: export ${k} points at missing ${file}`);
  }
  return { spec, stage, version, manifest: out };
}

async function smoke(b) {
  for (const [k, v] of Object.entries(b.manifest.exports)) {
    try {
      await import(pathToFileURL(join(b.stage, v.default)).href);
    } catch (e) {
      fail(`${b.spec.name}: importing export ${k} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  console.log(`${b.spec.name}: ${Object.keys(b.manifest.exports).length} export(s) import cleanly`);
}

function pack(b) {
  const r = capture(NPM, ["pack", "--json", "--pack-destination", OUT], { cwd: b.stage });
  if (r.status !== 0) fail(`npm pack failed for ${b.spec.name}:\n${r.err || r.out}`);
  const info = JSON.parse(r.out.slice(r.out.indexOf("[")))[0];
  const files = info.files.map((f) => f.path);
  const bad = files.filter((f) => (/\.ts$/.test(f) && !/\.d\.ts$/.test(f)) || /(^|\/)(test|tests|__tests__)\//.test(f) || /\.(map|tsbuildinfo)$/.test(f) || /(^|\/)\.env/.test(f));
  if (bad.length) fail(`${b.spec.name}: the tarball would include ${bad.join(", ")}`);
  const tgz = join(OUT, info.filename);
  console.log(`${b.spec.name}: packed ${files.length} files, ${(info.size / 1024).toFixed(1)} kB -> ${relative(REPO, tgz)}`);
  return tgz;
}

function checkRegistry(b) {
  const published = registryVersions(b.spec.name);
  if (published.includes(b.version)) fail(`${b.spec.name}@${b.version} is already on npm; pass --version with a higher version`);
  for (const [dep, range] of Object.entries(b.manifest.dependencies ?? {})) {
    if (!satisfiesCaret(range, registryVersions(dep))) fail(`${b.spec.name} needs ${dep}@${range}, which is not on npm yet; publish it first`);
  }
  console.log(`${b.spec.name}@${b.version}: not published yet, dependencies are on npm`);
}

mkdirSync(OUT, { recursive: true });
const built = selected.map(build);
for (const b of built) await smoke(b);
const tarballs = built.map((b) => ({ b, tgz: pack(b) }));

if (!offline) {
  for (const b of built) checkRegistry(b);
}

if (buildOnly) {
  console.log(`\nBuilt ${tarballs.length} package(s) in ${relative(REPO, OUT)}. Nothing was published.`);
  process.exit(0);
}

if (!dry) {
  const who = capture(NPM, ["whoami"]);
  if (who.status !== 0) fail("you are not logged in to npm; run npm login and try again");
  console.log(`\nPublishing as ${who.out.trim()}`);
}

for (const { b, tgz } of tarballs) {
  const argv = ["publish", tgz, "--access", "public", ...(tag ? ["--tag", tag] : []), ...(dry ? ["--dry-run"] : [])];
  console.log(`\nnpm ${argv.join(" ")}`);
  if (run(NPM, argv, { cwd: REPO }) !== 0) fail(`publishing ${b.spec.name} failed; packages before it in this run are already published`);
}
console.log(dry ? "\nDry run finished. Nothing was published." : `\nPublished ${tarballs.map(({ b }) => `${b.spec.name}@${b.version}`).join(", ")}.`);
