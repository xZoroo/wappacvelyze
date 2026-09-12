import { describe, expect, it, vi } from "vitest";
import { NvdClient, NVD_DETAIL_URL } from "../src/lib/nvd.ts";
import { jsonResponse } from "./helpers.ts";

const CPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*";
const WILDCARD = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*";

function cve(id: string, cpeMatch: object[], extra: object = {}) {
  return { cve: { id, configurations: [{ nodes: [{ cpeMatch }] }], ...extra } };
}

const ranged = cve(
  "CVE-2021-23017",
  [
    {
      vulnerable: true,
      criteria: WILDCARD,
      versionStartIncluding: "0.6.18",
      versionEndExcluding: "1.20.1",
    },
  ],
  {
    published: "2021-05-25T13:15:00.000",
    descriptions: [
      { lang: "es", value: "no" },
      { lang: "en", value: "1-byte overwrite" },
    ],
    metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.7, baseSeverity: "High" } }] },
    references: [
      { url: "https://example.com/other", tags: ["Third Party Advisory"] },
      { url: "https://nginx.org/advisory", tags: ["Vendor Advisory"] },
    ],
  },
);

function client(handler: (url: string, init?: RequestInit) => Response, apiKey = "") {
  const fetchFn = vi.fn(async (input: string | URL | Request, init?: RequestInit) =>
    handler(String(input), init),
  );
  const nvd = new NvdClient({ apiKey, baseUrl: "https://nvd.test/cves", fetchFn, retryDelayMs: 1 });
  return { nvd, fetchFn };
}

describe("NvdClient.vulnerabilitiesFor", () => {
  it("paginates, parses fields and records the affected range", async () => {
    const { nvd, fetchFn } = client((url) => {
      const params = new URL(url).searchParams;
      expect(params.get("cpeName")).toBe(CPE);
      if (params.get("startIndex") === "0") {
        return jsonResponse({ totalResults: 2, vulnerabilities: [ranged] });
      }
      return jsonResponse({
        totalResults: 2,
        vulnerabilities: [
          cve("CVE-2019-20372", [
            { vulnerable: true, criteria: WILDCARD, versionEndIncluding: "1.18.0" },
          ]),
        ],
      });
    });
    const vulns = await nvd.vulnerabilitiesFor(CPE);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(vulns.map((v) => v.id)).toEqual(["CVE-2021-23017", "CVE-2019-20372"]);
    expect(vulns[0]).toMatchObject({
      severity: "HIGH",
      score: 7.7,
      description: "1-byte overwrite",
      advisory: "https://nginx.org/advisory",
      url: NVD_DETAIL_URL + "CVE-2021-23017",
      affected_range: ">= 0.6.18, < 1.20.1",
    });
    expect(vulns[1]?.affected_range).toBe("<= 1.18.0");
  });

  it("drops unscoped, fixed, exact-mismatch and other-product records", async () => {
    const { nvd } = client(() =>
      jsonResponse({
        totalResults: 5,
        vulnerabilities: [
          cve("CVE-UNSCOPED", [{ vulnerable: true, criteria: WILDCARD }]),
          cve("CVE-EXACT", [
            { vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*" },
          ]),
          cve("CVE-OTHER-EXACT", [
            { vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:1.18.1:*:*:*:*:*:*:*" },
          ]),
          cve("CVE-FIXED", [
            { vulnerable: true, criteria: WILDCARD, versionEndExcluding: "1.17.0" },
          ]),
          cve("CVE-PHP", [
            {
              vulnerable: true,
              criteria: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
              versionEndExcluding: "9",
            },
          ]),
        ],
      }),
    );
    const vulns = await nvd.vulnerabilitiesFor(CPE);
    expect(vulns.map((v) => [v.id, v.affected_range])).toEqual([["CVE-EXACT", "== 1.18.0"]]);
  });

  it("sends the API key header", async () => {
    const { nvd } = client((_, init) => {
      expect(new Headers(init?.headers).get("apiKey")).toBe("secret");
      return jsonResponse({ totalResults: 0, vulnerabilities: [] });
    }, "secret");
    await expect(nvd.vulnerabilitiesFor(CPE)).resolves.toEqual([]);
  });

  it("retries throttling then reports guidance", async () => {
    const { nvd, fetchFn } = client(() => new Response("", { status: 403 }));
    await expect(nvd.vulnerabilitiesFor(CPE)).rejects.toThrow(/API key/);
    expect(fetchFn).toHaveBeenCalledTimes(3);
  });

  it("does not retry rejected queries and surfaces NVD's message", async () => {
    const { nvd, fetchFn } = client(
      () => new Response("", { status: 404, headers: { message: "Invalid cpeName" } }),
    );
    await expect(nvd.vulnerabilitiesFor(CPE)).rejects.toThrow(/Invalid cpeName/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});
