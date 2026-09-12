import { build } from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";

const entryPoints = ["background", "content", "page", "popup", "options"].map(
  (name) => `src/${name}.ts`,
);
const staticFiles = ["popup.html", "popup.css", "options.html"];

async function bundle(outdir, manifest) {
  await rm(outdir, { recursive: true, force: true });
  await mkdir(outdir, { recursive: true });
  await build({
    entryPoints,
    outdir,
    bundle: true,
    format: "iife",
    target: "chrome120",
    sourcemap: false,
    logLevel: "warning",
  });
  for (const file of staticFiles) {
    await cp(`src/${file}`, `${outdir}/${file}`);
  }
  await writeFile(`${outdir}/manifest.json`, JSON.stringify(manifest, null, 2) + "\n");
}

const manifest = JSON.parse(await readFile("manifest.json", "utf8"));

// Chrome runs the background script as a service worker; Firefox still expects an event
// page declared with "scripts", so each browser gets its own manifest.
await bundle("dist", manifest);
await bundle("dist-firefox", {
  ...manifest,
  background: { scripts: [manifest.background.service_worker] },
});
console.log("built dist/ (Chrome, Edge) and dist-firefox/ (Firefox)");
