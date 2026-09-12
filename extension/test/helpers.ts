import categoriesJson from "../src/generated/categories.json";
import technologiesJson from "../src/generated/technologies.json";
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
