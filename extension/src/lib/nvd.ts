// NVD CVE API 2.0 client with rate limiting and local applicability re-checking,
// mirroring the CLI's cve/nvd.go and cve/applies.go.

import { cpeParts, productFromCpeName, type Product } from "./cpe.ts";
import { Limiter, sleep } from "./limiter.ts";
import type { Vulnerability } from "./types.ts";
import { compareVersions, parseVersion } from "./version.ts";

export const DEFAULT_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/";

const PAGE_SIZE = 2000;
const WINDOW_MS = 30_000;
const PUBLIC_BUDGET = 5;
const KEYED_BUDGET = 50;
const MAX_ATTEMPTS = 3;
const THROTTLED_STATUSES = new Set([403, 429, 503]);

export interface NvdClientOptions {
  apiKey?: string;
  baseUrl?: string;
  fetchFn?: typeof fetch;
  retryDelayMs?: number;
}

interface NvdCpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

interface NvdMetric {
  baseSeverity?: string;
  cvssData?: { baseScore?: number; baseSeverity?: string };
}

interface NvdCve {
  id: string;
  published?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: {
    cvssMetricV40?: NvdMetric[];
    cvssMetricV31?: NvdMetric[];
    cvssMetricV30?: NvdMetric[];
    cvssMetricV2?: NvdMetric[];
  };
  references?: { url: string; tags?: string[] }[];
  configurations?: { nodes?: { cpeMatch?: NvdCpeMatch[] }[] }[];
}

interface NvdPage {
  totalResults?: number;
  vulnerabilities?: { cve: NvdCve }[];
}

class ThrottledError extends Error {}

export class NvdClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly retryDelayMs: number;
  private readonly limiter: Limiter;

  constructor(options: NvdClientOptions = {}) {
    this.apiKey = options.apiKey ?? "";
    this.baseUrl = options.baseUrl ?? DEFAULT_NVD_BASE_URL;
    // A bare `fetch` loses its receiver when stored as a property; bind it to the global.
    this.fetchFn = options.fetchFn ?? fetch.bind(globalThis);
    this.retryDelayMs = options.retryDelayMs ?? 6_000;
    this.limiter = new Limiter(this.apiKey ? KEYED_BUDGET : PUBLIC_BUDGET, WINDOW_MS);
  }

  /**
   * Returns every CVE that applies to the concrete version in cpeName. NVD pre-filters
   * by version server-side; each record is re-checked locally so unscoped wildcard
   * records do not flag every version.
   */
  async vulnerabilitiesFor(cpeName: string): Promise<Vulnerability[]> {
    const target = productFromCpeName(cpeName);
    const vulnerabilities: Vulnerability[] = [];
    let start = 0;
    for (;;) {
      const page = await this.fetchPage(cpeName, start);
      const items = page.vulnerabilities ?? [];
      for (const { cve } of items) {
        const affected = applicableRange(cve, target);
        if (affected !== null) {
          vulnerabilities.push({ ...toVulnerability(cve), affected_range: affected });
        }
      }
      start += items.length;
      if (items.length === 0 || start >= (page.totalResults ?? 0)) {
        return vulnerabilities;
      }
    }
  }

  private async fetchPage(cpeName: string, start: number): Promise<NvdPage> {
    const query = new URLSearchParams({
      cpeName,
      resultsPerPage: String(PAGE_SIZE),
      startIndex: String(start),
    });
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers["apiKey"] = this.apiKey;
    }
    for (let attempt = 1; ; attempt++) {
      await this.limiter.wait();
      const response = await this.fetchFn(`${this.baseUrl}?${query}`, { headers });
      try {
        return await decodePage(response, cpeName);
      } catch (error) {
        if (!(error instanceof ThrottledError) || attempt >= MAX_ATTEMPTS) {
          throw error;
        }
        await sleep(this.retryDelayMs);
      }
    }
  }
}

async function decodePage(response: Response, cpeName: string): Promise<NvdPage> {
  if (response.ok) {
    return (await response.json()) as NvdPage;
  }
  if (THROTTLED_STATUSES.has(response.status)) {
    throw new ThrottledError(
      `NVD rate limit reached (HTTP ${response.status}) querying ${cpeName}; add an NVD API key in the extension options`,
    );
  }
  const reason = response.headers.get("message") ?? `HTTP ${response.status}`;
  throw new Error(`NVD rejected query for ${cpeName}: ${reason}`);
}

function toVulnerability(cve: NvdCve): Vulnerability {
  const vulnerability: Vulnerability = { id: cve.id, url: NVD_DETAIL_URL + cve.id };
  const [score, severity] = cvss(cve);
  if (score !== undefined) {
    vulnerability.score = score;
  }
  if (severity) {
    vulnerability.severity = severity;
  }
  if (cve.published) {
    vulnerability.published = cve.published;
  }
  const description = cve.descriptions?.find((d) => d.lang === "en")?.value;
  if (description) {
    vulnerability.description = description;
  }
  const advisory = advisoryUrl(cve);
  if (advisory) {
    vulnerability.advisory = advisory;
  }
  return vulnerability;
}

/** Score and severity from the newest CVSS version NVD has recorded. */
function cvss(cve: NvdCve): [number | undefined, string] {
  const metrics = cve.metrics ?? {};
  for (const list of [
    metrics.cvssMetricV40,
    metrics.cvssMetricV31,
    metrics.cvssMetricV30,
    metrics.cvssMetricV2,
  ]) {
    const metric = list?.[0];
    if (!metric) {
      continue;
    }
    const severity = metric.cvssData?.baseSeverity ?? metric.baseSeverity ?? "";
    return [metric.cvssData?.baseScore, severity.toUpperCase()];
  }
  return [undefined, ""];
}

/** The most authoritative reference: a vendor advisory, then a patch, then any. */
function advisoryUrl(cve: NvdCve): string {
  const references = cve.references ?? [];
  for (const tag of ["Vendor Advisory", "Patch", ""]) {
    const reference = references.find((r) => tag === "" || (r.tags ?? []).includes(tag));
    if (reference) {
      return reference.url;
    }
  }
  return "";
}

/** Scans every applicability statement for one that covers the product. */
export function applicableRange(cve: NvdCve, target: Product): string | null {
  for (const configuration of cve.configurations ?? []) {
    for (const node of configuration.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        const affected = matchApplies(match, target);
        if (affected !== null) {
          return affected;
        }
      }
    }
  }
  return null;
}

/**
 * A wildcard criteria with no version bounds is ignored: NVD carries many old records
 * whose applicability was never scoped, and they would flag every version ever released.
 */
export function matchApplies(match: NvdCpeMatch, target: Product): string | null {
  if (!match.vulnerable || !match.criteria) {
    return null;
  }
  const criteria = cpeParts(match.criteria);
  if (criteria.vendor !== target.vendor || criteria.product !== target.product) {
    return null;
  }
  if (criteria.version !== "*") {
    const exact = parseVersion(criteria.version);
    if (!exact || compareVersions(exact, target.version) !== 0) {
      return null;
    }
    return `== ${criteria.version}`;
  }
  return rangeApplies(match, target);
}

function rangeApplies(match: NvdCpeMatch, target: Product): string | null {
  const bounds: [string | undefined, string, (cmp: number) => boolean][] = [
    [match.versionStartIncluding, ">=", (c) => c >= 0],
    [match.versionStartExcluding, ">", (c) => c > 0],
    [match.versionEndIncluding, "<=", (c) => c <= 0],
    [match.versionEndExcluding, "<", (c) => c < 0],
  ];
  const parts: string[] = [];
  for (const [raw, op, ok] of bounds) {
    if (!raw) {
      continue;
    }
    const limit = parseVersion(raw);
    if (!limit || !ok(compareVersions(target.version, limit))) {
      return null;
    }
    parts.push(`${op} ${raw}`);
  }
  return parts.length === 0 ? null : parts.join(", ");
}
