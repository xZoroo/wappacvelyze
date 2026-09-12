import { describe, expect, it, vi } from "vitest";
import { Cache } from "../src/lib/cache.ts";
import { Assessor, classify, lookupKey, rank } from "../src/lib/classify.ts";
import { fetchKev, type KevCatalog } from "../src/lib/kev.ts";
import { NvdClient } from "../src/lib/nvd.ts";
import { MemoryStore } from "../src/lib/store.ts";
import type { Technology, Vulnerability } from "../src/lib/types.ts";
import { jsonResponse } from "./helpers.ts";

const nginx: Technology = {
  name: "Nginx",
  version: "1.18.0",
  cpe: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
  categories: ["Web servers"],
};
const CPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*";
const { version: _version, ...noVersion } = nginx;
const { cpe: _cpe, ...noCpe } = nginx;

const kev: KevCatalog = {
  catalogVersion: "test",
  dateReleased: "",
  entries: {
    "CVE-2021-A": {
      cveID: "CVE-2021-A",
      vendorProject: "F5",
      product: "nginx",
      vulnerabilityName: "x",
      dateAdded: "",
      shortDescription: "",
      requiredAction: "",
      dueDate: "",
      knownRansomwareCampaignUse: "Unknown",
      url: "https://cisa.test/CVE-2021-A",
    },
  },
};

describe("lookupKey", () => {
  it("builds a versioned CPE or explains why it cannot", () => {
    expect(lookupKey(nginx)).toEqual({ cpeName: CPE });
    expect(lookupKey(noVersion)).toEqual({ reason: "version not disclosed" });
    expect(lookupKey(noCpe)).toMatchObject({ reason: /no CPE/ });
    expect(lookupKey({ ...nginx, version: "8" })).toMatchObject({ reason: /too coarse/ });
    expect(lookupKey({ ...nginx, version: "1.x" })).toMatchObject({ reason: /not comparable/ });
    expect(lookupKey({ ...nginx, cpe: "cpe:/a:x" })).toMatchObject({ reason: /malformed/ });
  });
});

describe("classify", () => {
  const vulns: Vulnerability[] = [
    { id: "CVE-2021-A", score: 5.3, url: "u" },
    { id: "CVE-2021-B", score: 9.8, url: "u" },
  ];

  it("is current without vulnerabilities", () => {
    expect(classify(nginx, CPE, [], kev)).toEqual({
      technology: nginx,
      status: "current",
      cpe_name: CPE,
    });
  });

  it("orders by score when nothing is exploited", () => {
    const result = classify(nginx, CPE, vulns, null);
    expect(result.status).toBe("vulnerable");
    expect(result.vulnerabilities?.map((v) => v.id)).toEqual(["CVE-2021-B", "CVE-2021-A"]);
  });

  it("promotes KEV hits to critical and lists them first without mutating input", () => {
    const result = classify(nginx, CPE, vulns, kev);
    expect(result.status).toBe("critical");
    expect(result.vulnerabilities?.[0]).toMatchObject({
      id: "CVE-2021-A",
      kev: { url: "https://cisa.test/CVE-2021-A" },
    });
    expect(vulns[0]?.kev).toBeUndefined();
  });

  it("ranks statuses strictly", () => {
    expect(rank("critical")).toBeGreaterThan(rank("vulnerable"));
    expect(rank("vulnerable")).toBeGreaterThan(rank("unknown"));
    expect(rank("unknown")).toBeGreaterThan(rank("current"));
  });
});

describe("Assessor", () => {
  const page = {
    totalResults: 1,
    vulnerabilities: [
      {
        cve: {
          id: "CVE-2021-A",
          configurations: [
            {
              nodes: [
                {
                  cpeMatch: [
                    { vulnerable: true, criteria: nginx.cpe, versionEndExcluding: "1.20.1" },
                  ],
                },
              ],
            },
          ],
        },
      },
    ],
  };

  it("serves repeat lookups from the cache", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(page));
    const nvd = new NvdClient({ baseUrl: "https://nvd.test", fetchFn });
    const assessor = new Assessor(nvd, kev, new Cache(new MemoryStore(), "nvd:", 60_000));
    for (let i = 0; i < 2; i++) {
      const result = await assessor.assess(nginx);
      expect(result.status).toBe("critical");
      expect(result.cpe_name).toBe(CPE);
    }
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("skips lookups it cannot make and reports failures as unknown", async () => {
    const failing = vi.fn(async () => new Response("", { status: 500 }));
    const assessor = new Assessor(
      new NvdClient({ baseUrl: "https://nvd.test", fetchFn: failing }),
      null,
      null,
    );
    expect(await assessor.assess(noVersion)).toMatchObject({
      status: "unknown",
      reason: "version not disclosed",
    });
    expect(failing).not.toHaveBeenCalled();
    expect(await assessor.assess(nginx)).toMatchObject({ status: "unknown", reason: /HTTP 500/ });
  });
});

describe("fetchKev", () => {
  it("indexes entries by upper-case ID with a catalog link", async () => {
    const feed = {
      catalogVersion: "2026.09.10",
      vulnerabilities: [{ cveID: "cve-2021-44228", vendorProject: "Apache", product: "Log4j2" }],
    };
    const catalog = await fetchKev(async () => jsonResponse(feed));
    expect(catalog.entries["CVE-2021-44228"]?.url).toContain("CVE-2021-44228");
  });

  it("rejects an empty catalog", async () => {
    await expect(fetchKev(async () => jsonResponse({ vulnerabilities: [] }))).rejects.toThrow(
      /empty/,
    );
  });
});
