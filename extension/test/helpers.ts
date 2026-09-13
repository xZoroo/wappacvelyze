import categoriesJson from "../src/generated/categories.json";
import technologiesJson from "../src/generated/technologies.json";
import type { Database } from "../src/lib/db.ts";
import {
  compileDatabase,
  type Category,
  type RawTechnology,
  type Technology,
} from "../src/lib/fingerprints.ts";

let database: Map<string, Technology> | null = null;

/** Compiles the generated fingerprint database once per test run (`npm run data` first). */
export function fingerprintDatabase(): Map<string, Technology> {
  database ??= compileDatabase(
    technologiesJson as Record<string, RawTechnology>,
    categoriesJson as Record<string, Category>,
  );
  return database;
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

/** Gzips text with the web CompressionStream, as the database is published. */
export async function gzipBytes(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function testDatabase(built = "v1"): Database {
  return {
    schema: 1,
    built,
    sources: { built },
    products: {
      "f5:nginx": {
        matches: {
          "CVE-2021-23017": [
            { version: "*", versionStartIncluding: "0.6.18", versionEndExcluding: "1.20.1" },
          ],
          "CVE-2019-20372": [{ version: "1.18.0" }],
          "CVE-FIXED": [{ version: "*", versionEndExcluding: "1.17.0" }],
          "CVE-UNSCOPED": [{ version: "*" }],
        },
        lifecycle: {
          product: "nginx",
          cycles: [
            { name: "1.18", latest: "1.18.0", eol: true, eolFrom: "2021-04-20", maintained: false },
            { name: "1.31", latest: "1.31.5", eol: false, maintained: true },
            { name: "1", latest: "1.31.5", eol: false, maintained: true },
          ],
        },
      },
    },
    vulnerabilities: {
      "CVE-2021-23017": {
        id: "CVE-2021-23017",
        score: 7.7,
        severity: "HIGH",
        epss: 0.9,
        exploits: ["nuclei"],
        kev: { name: "nginx off-by-one", dateAdded: "2021-11-03" },
      },
      "CVE-2019-20372": { id: "CVE-2019-20372", score: 5.3, severity: "MEDIUM" },
      "CVE-FIXED": { id: "CVE-FIXED" },
      "CVE-UNSCOPED": { id: "CVE-UNSCOPED" },
    },
    libraries: {
      jquery: {
        npm: "jquery",
        vulnerabilities: [
          { below: "1.6.3", severity: "MEDIUM", cves: ["CVE-2011-4969"], info: ["https://x/1"] },
          {
            atOrAbove: "1.2.0",
            below: "3.5.0",
            severity: "MEDIUM",
            ghsa: "GHSA-gxr4-xjj5-5px2",
            summary: "XSS",
          },
          {
            atOrAbove: "1.0.0",
            below: "4.0.0",
            severity: "LOW",
            summary: "EOL",
            info: ["https://x/eol"],
          },
        ],
      },
    },
    technology_libraries: { jQuery: "jquery" },
  };
}
