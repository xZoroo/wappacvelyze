import type { KevEntry } from "./types.ts";

export const DEFAULT_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const KEV_CATALOG_URL =
  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=";

/** CISA's Known Exploited Vulnerabilities catalog indexed by upper-case CVE ID. */
export interface KevCatalog {
  catalogVersion: string;
  dateReleased: string;
  entries: Record<string, KevEntry>;
}

interface KevFeed {
  catalogVersion?: string;
  dateReleased?: string;
  vulnerabilities?: Omit<KevEntry, "url">[];
}

export async function fetchKev(fetchFn: typeof fetch, url = DEFAULT_KEV_URL): Promise<KevCatalog> {
  const response = await fetchFn(url);
  if (!response.ok) {
    throw new Error(`fetch KEV catalog: HTTP ${response.status}`);
  }
  const feed = (await response.json()) as KevFeed;
  const vulnerabilities = feed.vulnerabilities ?? [];
  if (vulnerabilities.length === 0) {
    throw new Error("KEV catalog is empty; the feed format may have changed");
  }
  const entries: Record<string, KevEntry> = {};
  for (const entry of vulnerabilities) {
    const id = entry.cveID.toUpperCase();
    entries[id] = { ...entry, cveID: id, url: KEV_CATALOG_URL + encodeURIComponent(id) };
  }
  return {
    catalogVersion: feed.catalogVersion ?? "",
    dateReleased: feed.dateReleased ?? "",
    entries,
  };
}

export function lookupKev(catalog: KevCatalog | null, id: string): KevEntry | undefined {
  return catalog?.entries[id.toUpperCase()];
}
