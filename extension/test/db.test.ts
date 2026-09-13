import { describe, expect, it, vi } from "vitest";
import {
  DatabaseClient,
  MemoryBlobStore,
  databaseVulnerabilities,
  libraryVulnerabilities,
  lifecycleFor,
  mergeVulnerabilities,
  parseDatabase,
  productFor,
  sha256Hex,
} from "../src/lib/db.ts";
import { productFromCpeName } from "../src/lib/cpe.ts";
import { MemoryStore } from "../src/lib/store.ts";
import { parseVersion } from "../src/lib/version.ts";
import { gzipBytes, jsonResponse, testDatabase } from "./helpers.ts";

const CPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*";

function version(raw: string) {
  const parsed = parseVersion(raw);
  if (!parsed) throw new Error(raw);
  return parsed;
}

describe("database lookups", () => {
  const db = testDatabase();

  it("evaluates stored applicability statements locally with enrichment", () => {
    const product = productFor(db, "cpe:2.3:a:F5:nginx:*:*:*:*:*:*:*:*");
    expect(product).not.toBeNull();
    const vulns = databaseVulnerabilities(db, product!, productFromCpeName(CPE));
    expect(vulns.map((v) => `${v.id} ${v.affected_range}`)).toEqual([
      "CVE-2019-20372 == 1.18.0",
      "CVE-2021-23017 >= 0.6.18, < 1.20.1",
    ]);
    expect(vulns[1]).toMatchObject({
      epss: 0.9,
      exploits: ["nuclei"],
      kev: { vulnerabilityName: "nginx off-by-one" },
    });
    expect(vulns[1]?.kev?.url).toContain("CVE-2021-23017");
    expect(productFor(db, "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*")).toBeNull();
  });

  it("places versions in release cycles", () => {
    const product = db.products["f5:nginx"]!;
    expect(lifecycleFor(product, version("1.18.0"), "1.18.0")).toMatchObject({
      cycle: "1.18",
      eol: true,
      behind: false,
    });
    expect(lifecycleFor(product, version("1.31.2"), "1.31.2")).toMatchObject({
      cycle: "1.31",
      behind: true,
      latest: "1.31.5",
    });
    expect(lifecycleFor(product, version("1.31.5"), "1.31.5")).toMatchObject({
      cycle: "1.31",
      behind: false,
    });
    expect(lifecycleFor(product, version("1.30.0"), "1.30.0")?.cycle).toBe("1");
    expect(lifecycleFor(product, version("2.0.0"), "2.0.0")).toBeNull();
    expect(lifecycleFor(null, version("1.0.0"), "1.0.0")).toBeNull();
  });

  it("matches Retire.js ranges and builds stable ids", () => {
    const vulns = libraryVulnerabilities(db, "jQuery", version("1.5.0"));
    expect(vulns.map((v) => v.id)).toEqual([
      "CVE-2011-4969",
      "GHSA-gxr4-xjj5-5px2",
      "RETIREJS-JQUERY-3",
    ]);
    expect(vulns[1]?.url).toBe("https://github.com/advisories/GHSA-gxr4-xjj5-5px2");
    expect(vulns[2]?.url).toBe("https://x/eol");
    expect(libraryVulnerabilities(db, "jQuery", version("3.7.1")).map((v) => v.id)).toEqual([
      "RETIREJS-JQUERY-3",
    ]);
    expect(libraryVulnerabilities(db, "Nope", version("1.0.0"))).toEqual([]);
    expect(libraryVulnerabilities(null, "jQuery", version("1.0.0"))).toEqual([]);
  });

  it("merges keeping the first occurrence", () => {
    const merged = mergeVulnerabilities(
      [{ id: "CVE-1", url: "", epss: 0.5 }],
      [
        { id: "CVE-1", url: "" },
        { id: "GHSA-x", url: "" },
      ],
    );
    expect(merged.map((v) => [v.id, v.epss])).toEqual([
      ["CVE-1", 0.5],
      ["GHSA-x", undefined],
    ]);
  });
});

describe("DatabaseClient", () => {
  async function publisher(built: string) {
    const bytes = await gzipBytes(JSON.stringify(testDatabase(built)));
    const manifest = {
      schema: 1,
      built,
      path: "wappacvelyze-db.json.gz",
      sha256: await sha256Hex(bytes),
      bytes: bytes.length,
    };
    return { bytes, manifest };
  }

  function client(handler: (url: string) => Response | Promise<Response>, now: () => number) {
    const fetchFn = vi.fn(async (input: string | URL | Request) => handler(String(input)));
    const meta = new MemoryStore();
    const blobs = new MemoryBlobStore();
    return {
      fetchFn,
      make: () =>
        new DatabaseClient(meta, blobs, {
          baseUrl: "https://db.test/",
          fetchFn,
          now,
          maxAgeMs: 1000,
        }),
    };
  }

  it("downloads once, serves from cache within maxAge, re-downloads only on a new checksum", async () => {
    let current = await publisher("v1");
    let clock = 0;
    const { fetchFn, make } = client(
      async (url) => {
        if (url.endsWith("latest.json")) return jsonResponse(current.manifest);
        return new Response(current.bytes as BodyInit);
      },
      () => clock,
    );
    const first = await make().load();
    expect(first.database?.sources["built"]).toBe("v1");
    expect(first.warning).toBeUndefined();
    expect(fetchFn).toHaveBeenCalledTimes(2);

    clock = 500;
    await make().load();
    expect(fetchFn).toHaveBeenCalledTimes(2);

    clock = 5000;
    await make().load();
    expect(fetchFn).toHaveBeenCalledTimes(3);

    current = await publisher("v2");
    clock = 10000;
    const third = await make().load();
    expect(third.database?.sources["built"]).toBe("v2");
    expect(fetchFn).toHaveBeenCalledTimes(5);
  });

  it("falls back to the cached copy with a warning and rejects bad checksums", async () => {
    const good = await publisher("v1");
    let healthy = true;
    let clock = 0;
    const { make } = client(
      async (url) => {
        if (!healthy) return new Response("", { status: 502 });
        if (url.endsWith("latest.json")) return jsonResponse(good.manifest);
        return new Response(good.bytes as BodyInit);
      },
      () => clock,
    );
    await make().load();
    healthy = false;
    clock = 5000;
    const stale = await make().load();
    expect(stale.database?.sources["built"]).toBe("v1");
    expect(stale.warning).toMatch(/502/);

    const tampered = { ...good.manifest, sha256: "0".repeat(64) };
    const bad = client(
      async (url) =>
        url.endsWith("latest.json") ? jsonResponse(tampered) : new Response(good.bytes as BodyInit),
      () => 0,
    );
    const result = await bad.make().load();
    expect(result.database).toBeNull();
    expect(result.warning).toMatch(/checksum/);
  });

  it("parses gzipped payloads and rejects other schemas", async () => {
    const bytes = await gzipBytes(JSON.stringify(testDatabase()));
    expect((await parseDatabase(bytes)).products["f5:nginx"]).toBeDefined();
    const wrong = await gzipBytes(JSON.stringify({ ...testDatabase(), schema: 99 }));
    await expect(parseDatabase(wrong)).rejects.toThrow(/schema/);
  });
});
