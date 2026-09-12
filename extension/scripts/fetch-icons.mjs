// Fetches the technology logos the fingerprint database references from the
// enthec/webappanalyzer repository (GPL-3.0 data, so they are generated, never committed).
// Icons above MAX_ICON_BYTES are skipped; the popup falls back to a letter tile for them.
import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TARBALL_URL = "https://codeload.github.com/enthec/webappanalyzer/tar.gz/main";
const CACHE_DIR = ".cache";
const CACHE_FILE = join(CACHE_DIR, "webappanalyzer-main.tar.gz");
const CACHE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const OUT_DIR = "src/generated/icons";
const MAX_ICON_BYTES = 16_000;

async function cachedTarball() {
  try {
    const info = await stat(CACHE_FILE);
    if (Date.now() - info.mtimeMs < CACHE_MAX_AGE_MS) {
      return CACHE_FILE;
    }
  } catch {}
  const response = await fetch(TARBALL_URL);
  if (!response.ok) {
    throw new Error(`download ${TARBALL_URL}: HTTP ${response.status}`);
  }
  await mkdir(CACHE_DIR, { recursive: true });
  await writeFile(CACHE_FILE, Buffer.from(await response.arrayBuffer()));
  return CACHE_FILE;
}

const technologies = JSON.parse(await readFile("src/generated/technologies.json", "utf8"));
const wanted = new Set(
  Object.values(technologies)
    .map((t) => t.icon)
    .filter(Boolean),
);

const tarball = await cachedTarball();
const extractDir = join(tmpdir(), `wappacvelyze-icons-${process.pid}`);
await mkdir(extractDir, { recursive: true });
execFileSync("tar", [
  "-xzf",
  tarball,
  "-C",
  extractDir,
  "--strip-components=4",
  "webappanalyzer-main/src/images/icons",
]);

await rm(OUT_DIR, { recursive: true, force: true });
await mkdir(OUT_DIR, { recursive: true });
let copied = 0;
let skipped = 0;
for (const name of await readdir(extractDir)) {
  if (!wanted.has(name)) {
    continue;
  }
  const info = await stat(join(extractDir, name));
  if (info.size > MAX_ICON_BYTES) {
    skipped++;
    continue;
  }
  await cp(join(extractDir, name), join(OUT_DIR, name));
  copied++;
}
await rm(extractDir, { recursive: true, force: true });
console.log(
  `icons: ${copied} copied, ${skipped} skipped (> ${MAX_ICON_BYTES} bytes), ${wanted.size - copied - skipped} missing upstream`,
);
