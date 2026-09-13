// Status classification, mirroring the CLI's cve/classify.go: database first, live NVD
// as fallback, Retire.js merged in, release cycles deciding between current/outdated/EOL.

import type { Cache } from "./cache.ts";
import { cpeWithVersion, productFromCpeName } from "./cpe.ts";
import {
  databaseVulnerabilities,
  libraryVulnerabilities,
  lifecycleFor,
  mergeVulnerabilities,
  productFor,
  type Database,
} from "./db.ts";
import { lookupKev, type KevCatalog } from "./kev.ts";
import type { NvdClient } from "./nvd.ts";
import type { Assessment, LifecycleInfo, Status, Technology, Vulnerability } from "./types.ts";
import { parseVersion, type Version } from "./version.ts";

const RANK: Record<Status, number> = {
  current: 0,
  outdated: 1,
  unknown: 2,
  unsupported: 3,
  vulnerable: 4,
  critical: 5,
};

/** Orders statuses by urgency, from current (0) to critical (5). */
export function rank(status: Status): number {
  return RANK[status];
}

/**
 * Returns the parsed version or the reason no verdict is possible. Single-segment
 * versions such as "8" match every 8.x advisory and would produce false alarms.
 */
export function comparableVersion(
  technology: Technology,
): { version: Version } | { reason: string } {
  if (!technology.version) {
    return { reason: "version not disclosed" };
  }
  if (!technology.version.includes(".")) {
    return { reason: `version "${technology.version}" is too coarse to match advisories` };
  }
  const version = parseVersion(technology.version);
  if (!version) {
    return { reason: `version "${technology.version}" is not comparable` };
  }
  return { version };
}

function moreUrgent(a: Vulnerability, b: Vulnerability): number {
  if ((a.kev !== undefined) !== (b.kev !== undefined)) {
    return a.kev ? -1 : 1;
  }
  const aExploit = (a.exploits?.length ?? 0) > 0;
  const bExploit = (b.exploits?.length ?? 0) > 0;
  if (aExploit !== bExploit) {
    return aExploit ? -1 : 1;
  }
  const epssDiff = (b.epss ?? 0) - (a.epss ?? 0);
  if (epssDiff !== 0) {
    return epssDiff;
  }
  const scoreDiff = (b.score ?? 0) - (a.score ?? 0);
  if (scoreDiff !== 0) {
    return scoreDiff;
  }
  return b.id.localeCompare(a.id);
}

/**
 * Derives a status from applicable vulnerabilities, the KEV catalog and release data.
 * Vulnerabilities are ordered exploited in the wild → public exploit → EPSS → CVSS.
 */
export function classify(
  technology: Technology,
  cpeName: string,
  vulnerabilities: Vulnerability[],
  kev: KevCatalog | null,
  lifecycle: LifecycleInfo | null = null,
): Assessment {
  const assessment: Assessment = { technology, status: "current" };
  if (cpeName) assessment.cpe_name = cpeName;
  if (lifecycle) assessment.lifecycle = lifecycle;
  if (vulnerabilities.length === 0) {
    if (lifecycle?.eol) {
      assessment.status = "unsupported";
    } else if (lifecycle?.behind) {
      assessment.status = "outdated";
    }
    return assessment;
  }
  assessment.status = "vulnerable";
  assessment.vulnerabilities = vulnerabilities.map((vulnerability) => {
    const entry = vulnerability.kev ?? lookupKev(kev, vulnerability.id);
    if (!entry) {
      return { ...vulnerability };
    }
    assessment.status = "critical";
    return { ...vulnerability, kev: entry };
  });
  assessment.vulnerabilities.sort(moreUrgent);
  return assessment;
}

export class Assessor {
  constructor(
    private readonly nvd: NvdClient | null,
    private readonly kev: KevCatalog | null,
    private readonly cache: Cache | null,
    private readonly database: Database | null = null,
  ) {}

  /** Looks up CVEs and release status for a technology; lookup failures yield "unknown". */
  async assess(technology: Technology): Promise<Assessment> {
    const parsed = comparableVersion(technology);
    if ("reason" in parsed) {
      return { technology, status: "unknown", reason: parsed.reason };
    }
    const record = productFor(this.database, technology.cpe);
    const libraryKey = this.database?.technology_libraries[technology.name];
    const hasLibrary =
      libraryKey !== undefined && this.database?.libraries[libraryKey] !== undefined;
    if (!technology.cpe && !hasLibrary) {
      return { technology, status: "unknown", reason: "no CPE mapping for this technology" };
    }
    let vulnerabilities: Vulnerability[] = [];
    let lifecycle: LifecycleInfo | null = null;
    let cpeName = "";
    if (technology.cpe) {
      try {
        cpeName = cpeWithVersion(technology.cpe, technology.version ?? "");
        const target = productFromCpeName(cpeName);
        if (record && this.database) {
          vulnerabilities = databaseVulnerabilities(this.database, record, target);
          lifecycle = lifecycleFor(record, parsed.version, technology.version ?? "");
        } else if (this.nvd) {
          vulnerabilities = await this.liveVulnerabilities(cpeName);
        } else if (!hasLibrary) {
          return {
            technology,
            status: "unknown",
            reason: "not in the vulnerability database",
            cpe_name: cpeName,
          };
        }
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        const failed: Assessment = { technology, status: "unknown", reason };
        if (cpeName) failed.cpe_name = cpeName;
        return failed;
      }
    }
    if (hasLibrary) {
      vulnerabilities = mergeVulnerabilities(
        vulnerabilities,
        libraryVulnerabilities(this.database, technology.name, parsed.version),
      );
    }
    return classify(technology, cpeName, vulnerabilities, this.kev, lifecycle);
  }

  private async liveVulnerabilities(cpeName: string): Promise<Vulnerability[]> {
    const cached = await this.cache?.get<Vulnerability[]>(cpeName);
    if (cached) {
      return cached;
    }
    if (!this.nvd) {
      return [];
    }
    const fresh = await this.nvd.vulnerabilitiesFor(cpeName);
    await this.cache?.set(cpeName, fresh);
    return fresh;
  }
}
