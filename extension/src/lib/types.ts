// Shared result types. Field names mirror the CLI's `--format json` output so both
// surfaces expose one contract.

export interface Technology {
  name: string;
  version?: string;
  cpe?: string;
  categories: string[];
  website?: string;
  icon?: string;
}

export type Status = "current" | "outdated" | "unknown" | "unsupported" | "vulnerable" | "critical";

/** Where a detected version sits within its product's release cycles. */
export interface LifecycleInfo {
  cycle: string;
  latest?: string;
  latest_date?: string;
  eol: boolean;
  eol_from?: string;
  maintained: boolean;
  behind: boolean;
}

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  url: string;
}

export interface Vulnerability {
  id: string;
  severity?: string;
  score?: number;
  description?: string;
  published?: string;
  url: string;
  advisory?: string;
  affected_range?: string;
  kev?: KevEntry;
  epss?: number;
  epss_percentile?: number;
  exploits?: string[];
}

export interface Assessment {
  technology: Technology;
  status: Status;
  reason?: string;
  cpe_name?: string;
  lifecycle?: LifecycleInfo;
  vulnerabilities?: Vulnerability[];
}

/** Everything the background worker knows about one tab's most recent page load. */
export interface TabResult {
  url: string;
  updatedAt: number;
  /** "detected" while CVE lookups are still running, "done" afterwards. */
  phase: "detected" | "done";
  assessments: Assessment[];
}

export type Theme = "auto" | "light" | "dark";

export interface Settings {
  nvdApiKey: string;
  theme: Theme;
  /** Base URL serving latest.json and the database; empty means the project's release. */
  dbUrl: string;
}
