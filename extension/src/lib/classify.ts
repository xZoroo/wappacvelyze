// Status classification, mirroring the CLI's cve/classify.go.

import type { Cache } from "./cache.ts";
import { cpeWithVersion } from "./cpe.ts";
import { lookupKev, type KevCatalog } from "./kev.ts";
import type { NvdClient } from "./nvd.ts";
import type { Assessment, Status, Technology, Vulnerability } from "./types.ts";
import { parseVersion } from "./version.ts";

const RANK: Record<Status, number> = { current: 0, unknown: 1, vulnerable: 2, critical: 3 };

/** Orders statuses by urgency, from current (0) to critical (3). */
export function rank(status: Status): number {
  return RANK[status];
}

/**
 * Returns the versioned CPE to query, or the reason no lookup is possible. Single-segment
 * versions such as "8" match every 8.x advisory and would produce false alarms.
 */
export function lookupKey(technology: Technology): { cpeName: string } | { reason: string } {
  if (!technology.version) {
    return { reason: "version not disclosed" };
  }
  if (!technology.cpe) {
    return { reason: "no CPE mapping for this technology" };
  }
  if (!technology.version.includes(".")) {
    return { reason: `version "${technology.version}" is too coarse to match advisories` };
  }
  if (!parseVersion(technology.version)) {
    return { reason: `version "${technology.version}" is not comparable` };
  }
  try {
    return { cpeName: cpeWithVersion(technology.cpe, technology.version) };
  } catch (error) {
    return { reason: error instanceof Error ? error.message : String(error) };
  }
}

function moreUrgent(a: Vulnerability, b: Vulnerability): number {
  if ((a.kev !== undefined) !== (b.kev !== undefined)) {
    return a.kev ? -1 : 1;
  }
  const scoreDiff = (b.score ?? 0) - (a.score ?? 0);
  if (scoreDiff !== 0) {
    return scoreDiff;
  }
  return b.id.localeCompare(a.id);
}

/** Derives a status from NVD results and the KEV catalog; exploited CVEs sort first. */
export function classify(
  technology: Technology,
  cpeName: string,
  vulnerabilities: Vulnerability[],
  kev: KevCatalog | null,
): Assessment {
  if (vulnerabilities.length === 0) {
    return { technology, status: "current", cpe_name: cpeName };
  }
  let status: Status = "vulnerable";
  const enriched = vulnerabilities.map((vulnerability) => {
    const entry = lookupKev(kev, vulnerability.id);
    if (!entry) {
      return { ...vulnerability };
    }
    status = "critical";
    return { ...vulnerability, kev: entry };
  });
  enriched.sort(moreUrgent);
  return { technology, status, cpe_name: cpeName, vulnerabilities: enriched };
}

export class Assessor {
  constructor(
    private readonly nvd: NvdClient,
    private readonly kev: KevCatalog | null,
    private readonly cache: Cache | null,
  ) {}

  /** Looks up CVEs for a technology. Lookup failures yield "unknown" with the error as reason. */
  async assess(technology: Technology): Promise<Assessment> {
    const key = lookupKey(technology);
    if ("reason" in key) {
      return { technology, status: "unknown", reason: key.reason };
    }
    try {
      const vulnerabilities = await this.vulnerabilities(key.cpeName);
      return classify(technology, key.cpeName, vulnerabilities, this.kev);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return { technology, status: "unknown", reason, cpe_name: key.cpeName };
    }
  }

  private async vulnerabilities(cpeName: string): Promise<Vulnerability[]> {
    const cached = await this.cache?.get<Vulnerability[]>(cpeName);
    if (cached) {
      return cached;
    }
    const fresh = await this.nvd.vulnerabilitiesFor(cpeName);
    await this.cache?.set(cpeName, fresh);
    return fresh;
  }
}
