// Prebuilt vulnerability database: schema (mirrors the Go db package), checksum-verified
// download with caching, and the local lookups the assessor runs against it.

import { cpeParts, escapeCpeValue, type Product as Target } from "./cpe.ts";
import { matchApplies, NVD_DETAIL_URL } from "./nvd.ts";
import type { KeyValueStore } from "./store.ts";
import type { LifecycleInfo, Vulnerability } from "./types.ts";
import { compareVersions, parseVersion, type Version } from "./version.ts";

export const SCHEMA_VERSION = 1;
export const DEFAULT_DATABASE_URL = "https://github.com/xZoroo/wappacvelyze/releases/download/db/";

export interface Manifest {
  schema: number;
  built: string;
  path: string;
  sha256: string;
  bytes: number;
}

export interface Match {
  version: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

export interface Cycle {
  name: string;
  latest?: string;
  latestDate?: string;
  eol: boolean;
  eolFrom?: string;
  maintained: boolean;
}

export interface ProductRecord {
  matches: Record<string, Match[]>;
  lifecycle?: { product: string; cycles: Cycle[] };
}

export interface VulnerabilityRecord {
  id: string;
  published?: string;
  score?: number;
  severity?: string;
  advisory?: string;
  kev?: {
    name: string;
    dateAdded: string;
    dueDate?: string;
    requiredAction?: string;
    ransomware?: string;
  };
  epss?: number;
  epss_percentile?: number;
  exploits?: string[];
}

export interface LibraryVulnerability {
  atOrAbove?: string;
  below?: string;
  severity?: string;
  cves?: string[];
  ghsa?: string;
  summary?: string;
  info?: string[];
}

export interface Database {
  schema: number;
  built: string;
  sources: Record<string, string>;
  products: Record<string, ProductRecord>;
  vulnerabilities: Record<string, VulnerabilityRecord>;
  libraries: Record<string, { npm?: string; vulnerabilities: LibraryVulnerability[] }>;
  technology_libraries: Record<string, string>;
}

const KEV_CATALOG_URL =
  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=";

/** Where the compressed database bytes live between service-worker restarts. */
export interface BlobStore {
  get(key: string): Promise<Uint8Array | undefined>;
  set(key: string, bytes: Uint8Array): Promise<void>;
}

export class MemoryBlobStore implements BlobStore {
  private readonly blobs = new Map<string, Uint8Array>();
  get(key: string): Promise<Uint8Array | undefined> {
    return Promise.resolve(this.blobs.get(key));
  }
  set(key: string, bytes: Uint8Array): Promise<void> {
    this.blobs.set(key, bytes);
    return Promise.resolve();
  }
}

/** Keeps the blob in the Cache API, which survives worker restarts without size limits. */
export class CacheApiBlobStore implements BlobStore {
  constructor(private readonly cacheName = "wappacvelyze-db") {}
  async get(key: string): Promise<Uint8Array | undefined> {
    const cache = await caches.open(this.cacheName);
    const response = await cache.match(new Request(`https://cache.invalid/${key}`));
    return response ? new Uint8Array(await response.arrayBuffer()) : undefined;
  }
  async set(key: string, bytes: Uint8Array): Promise<void> {
    const cache = await caches.open(this.cacheName);
    const keys = await cache.keys();
    await Promise.all(keys.map((request) => cache.delete(request)));
    await cache.put(new Request(`https://cache.invalid/${key}`), new Response(bytes as BodyInit));
  }
}

export interface DatabaseClientOptions {
  baseUrl?: string;
  fetchFn?: typeof fetch;
  maxAgeMs?: number;
  now?: () => number;
}

const MANIFEST_KEY = "db:manifest";
const FETCHED_AT_KEY = "db:fetchedAt";
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Downloads the database when the cached copy is older than maxAge and the published
 * checksum changed; otherwise serves the cached copy. A stale copy is returned when the
 * refresh fails so scans keep working offline.
 */
export class DatabaseClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly maxAgeMs: number;
  private readonly now: () => number;
  private loaded: { sha256: string; database: Database } | null = null;

  constructor(
    private readonly meta: KeyValueStore,
    private readonly blobs: BlobStore,
    options: DatabaseClientOptions = {},
  ) {
    this.baseUrl = options.baseUrl ?? DEFAULT_DATABASE_URL;
    this.fetchFn = options.fetchFn ?? fetch.bind(globalThis);
    this.maxAgeMs = options.maxAgeMs ?? DAY_MS;
    this.now = options.now ?? (() => Date.now());
  }

  async load(): Promise<{ database: Database | null; warning?: string }> {
    const cached = (await this.meta.get(MANIFEST_KEY)) as Manifest | undefined;
    const fetchedAt = ((await this.meta.get(FETCHED_AT_KEY)) as number | undefined) ?? 0;
    if (cached && this.now() - fetchedAt <= this.maxAgeMs) {
      const database = await this.open(cached.sha256);
      if (database) {
        return { database };
      }
    }
    try {
      const manifest = await this.fetchManifest();
      if (
        !cached ||
        cached.sha256 !== manifest.sha256 ||
        !(await this.blobs.get(manifest.sha256))
      ) {
        await this.download(manifest);
      }
      await this.meta.set(MANIFEST_KEY, manifest);
      await this.meta.set(FETCHED_AT_KEY, this.now());
      return { database: await this.open(manifest.sha256) };
    } catch (error) {
      const warning = error instanceof Error ? error.message : String(error);
      const database = cached ? await this.open(cached.sha256) : null;
      return { database, warning };
    }
  }

  private async fetchManifest(): Promise<Manifest> {
    const response = await this.fetchFn(`${this.baseUrl}latest.json`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`fetch database manifest: HTTP ${response.status}`);
    }
    const manifest = (await response.json()) as Manifest;
    if (manifest.schema !== SCHEMA_VERSION) {
      throw new Error(`database schema ${manifest.schema} is not supported; update the extension`);
    }
    return manifest;
  }

  private async download(manifest: Manifest): Promise<void> {
    const response = await this.fetchFn(`${this.baseUrl}${manifest.path}`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`fetch database: HTTP ${response.status}`);
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    const digest = await sha256Hex(bytes);
    if (digest !== manifest.sha256) {
      throw new Error("database checksum mismatch");
    }
    await this.blobs.set(manifest.sha256, bytes);
  }

  private async open(sha256: string): Promise<Database | null> {
    if (this.loaded?.sha256 === sha256) {
      return this.loaded.database;
    }
    const bytes = await this.blobs.get(sha256);
    if (!bytes) {
      return null;
    }
    const database = await parseDatabase(bytes);
    this.loaded = { sha256, database };
    return database;
  }
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Decompresses and parses a gzipped database. */
export async function parseDatabase(bytes: Uint8Array): Promise<Database> {
  const stream = new Blob([bytes as BlobPart])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"));
  const database = (await new Response(stream).json()) as Database;
  if (database.schema !== SCHEMA_VERSION) {
    throw new Error(`database schema ${database.schema} is not supported`);
  }
  return database;
}

export function productFor(
  database: Database | null,
  cpe: string | undefined,
): ProductRecord | null {
  if (!database || !cpe) {
    return null;
  }
  const { vendor, product } = cpeParts(cpe);
  return database.products[`${vendor}:${product}`] ?? null;
}

/** Evaluates a product's stored applicability statements against the detected version. */
export function databaseVulnerabilities(
  database: Database,
  record: ProductRecord,
  target: Target,
): Vulnerability[] {
  const found: Vulnerability[] = [];
  for (const [id, matches] of Object.entries(record.matches)) {
    const vulnerability = database.vulnerabilities[id];
    if (!vulnerability) {
      continue;
    }
    for (const match of matches) {
      const criteria = `cpe:2.3:a:${target.vendor}:${target.product}:${escapeCpeValue(match.version)}:*:*:*:*:*:*:*`;
      const affected = matchApplies({ vulnerable: true, criteria, ...match }, target);
      if (affected !== null) {
        found.push(fromRecord(vulnerability, affected));
        break;
      }
    }
  }
  return found.sort((a, b) => a.id.localeCompare(b.id));
}

function fromRecord(record: VulnerabilityRecord, affected: string): Vulnerability {
  const vulnerability: Vulnerability = {
    id: record.id,
    url: NVD_DETAIL_URL + record.id,
    affected_range: affected,
  };
  if (record.severity) vulnerability.severity = record.severity;
  if (record.score !== undefined) vulnerability.score = record.score;
  if (record.published) vulnerability.published = record.published;
  if (record.advisory) vulnerability.advisory = record.advisory;
  if (record.epss !== undefined) vulnerability.epss = record.epss;
  if (record.epss_percentile !== undefined) vulnerability.epss_percentile = record.epss_percentile;
  if (record.exploits?.length) vulnerability.exploits = record.exploits;
  if (record.kev) {
    vulnerability.kev = {
      cveID: record.id,
      vendorProject: "",
      product: "",
      vulnerabilityName: record.kev.name,
      dateAdded: record.kev.dateAdded,
      shortDescription: "",
      requiredAction: record.kev.requiredAction ?? "",
      dueDate: record.kev.dueDate ?? "",
      knownRansomwareCampaignUse: record.kev.ransomware ?? "",
      url: KEV_CATALOG_URL + encodeURIComponent(record.id),
    };
  }
  return vulnerability;
}

/** Finds the release cycle a version belongs to ("8.1.12" → "8.1") and how it compares. */
export function lifecycleFor(
  record: ProductRecord | null,
  detected: Version,
  raw: string,
): LifecycleInfo | null {
  const cycles = record?.lifecycle?.cycles ?? [];
  let best: Cycle | null = null;
  for (const cycle of cycles) {
    if (
      (raw === cycle.name || raw.startsWith(`${cycle.name}.`)) &&
      (!best || cycle.name.length > best.name.length)
    ) {
      best = cycle;
    }
  }
  if (!best) {
    return null;
  }
  const latest = best.latest ? parseVersion(best.latest) : null;
  const info: LifecycleInfo = {
    cycle: best.name,
    eol: best.eol,
    maintained: best.maintained,
    behind: latest !== null && compareVersions(detected, latest) < 0,
  };
  if (best.latest) info.latest = best.latest;
  if (best.latestDate) info.latest_date = best.latestDate;
  if (best.eolFrom) info.eol_from = best.eolFrom;
  return info;
}

/** Matches a JavaScript library version against the Retire.js ranges in the database. */
export function libraryVulnerabilities(
  database: Database | null,
  technology: string,
  detected: Version,
): Vulnerability[] {
  const key = database?.technology_libraries[technology];
  const library = key === undefined ? undefined : database?.libraries[key];
  if (!key || !library) {
    return [];
  }
  const found: Vulnerability[] = [];
  library.vulnerabilities.forEach((entry, index) => {
    if (inLibraryRange(detected, entry)) {
      found.push(libraryVulnerability(key, index, entry));
    }
  });
  return found;
}

function inLibraryRange(detected: Version, entry: LibraryVulnerability): boolean {
  if (entry.atOrAbove) {
    const lower = parseVersion(entry.atOrAbove);
    if (!lower || compareVersions(detected, lower) < 0) return false;
  }
  if (entry.below) {
    const upper = parseVersion(entry.below);
    if (!upper || compareVersions(detected, upper) >= 0) return false;
  }
  return Boolean(entry.atOrAbove || entry.below);
}

function libraryVulnerability(
  key: string,
  index: number,
  entry: LibraryVulnerability,
): Vulnerability {
  const vulnerability: Vulnerability = { id: "", url: "" };
  if (entry.cves?.[0]) {
    vulnerability.id = entry.cves[0];
    vulnerability.url = NVD_DETAIL_URL + entry.cves[0];
  } else if (entry.ghsa) {
    vulnerability.id = entry.ghsa;
    vulnerability.url = `https://github.com/advisories/${entry.ghsa}`;
  } else {
    vulnerability.id = `RETIREJS-${key.toUpperCase()}-${index + 1}`;
    vulnerability.url = entry.info?.[0] ?? "";
  }
  if (entry.severity) vulnerability.severity = entry.severity;
  if (entry.summary) vulnerability.description = entry.summary;
  if (entry.info?.[0]) vulnerability.advisory = entry.info[0];
  const bounds: string[] = [];
  if (entry.atOrAbove) bounds.push(`>= ${entry.atOrAbove}`);
  if (entry.below) bounds.push(`< ${entry.below}`);
  vulnerability.affected_range = bounds.join(", ");
  return vulnerability;
}

/** Keeps the first occurrence of each ID; NVD records come first so their EPSS/KEV data win. */
export function mergeVulnerabilities(...lists: Vulnerability[][]): Vulnerability[] {
  const seen = new Set<string>();
  const merged: Vulnerability[] = [];
  for (const list of lists) {
    for (const vulnerability of list) {
      if (!seen.has(vulnerability.id)) {
        seen.add(vulnerability.id);
        merged.push(vulnerability);
      }
    }
  }
  return merged;
}
