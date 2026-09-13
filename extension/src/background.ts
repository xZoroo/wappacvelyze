// Background service worker: captures response headers, runs detection on evidence from
// the content script, looks up CVEs, and publishes per-tab results for the popup.

import categoriesJson from "./generated/categories.json";
import technologiesJson from "./generated/technologies.json";
import { Cache } from "./lib/cache.ts";
import { Assessor, rank } from "./lib/classify.ts";
import { CacheApiBlobStore, DatabaseClient, DEFAULT_DATABASE_URL } from "./lib/db.ts";
import { analyzeWithBudget, type Evidence } from "./lib/detect.ts";
import { emptyRecord } from "./lib/evidence.ts";
import {
  compileDatabase,
  referencedNames,
  type Category,
  type RawTechnology,
  type Technology as Fingerprint,
} from "./lib/fingerprints.ts";
import { fetchKev, type KevCatalog } from "./lib/kev.ts";
import { NvdClient } from "./lib/nvd.ts";
import { ChromeStore } from "./lib/store.ts";
import type { Assessment, Status, TabResult } from "./lib/types.ts";
import { headersKey, resultKey, type CollectedEvidence, type RuntimeMessage } from "./messages.ts";
import { loadSettings } from "./settings.ts";

const DAY_MS = 24 * 60 * 60 * 1000;
const KEV_CACHE_KEY = "catalog";

const local = new ChromeStore(chrome.storage.local);
const session = new ChromeStore(chrome.storage.session);
const nvdCache = new Cache(local, "nvd:", DAY_MS);
const kevCache = new Cache(local, "kev:", DAY_MS);
const blobStore = new CacheApiBlobStore();
let databaseClient: DatabaseClient | null = null;
let databaseClientUrl = "";

/** One client per configured URL, so changing the setting starts a fresh download. */
function databaseClientFor(dbUrl: string): DatabaseClient {
  const baseUrl = dbUrl.trim() || DEFAULT_DATABASE_URL;
  if (!databaseClient || databaseClientUrl !== baseUrl) {
    databaseClient = new DatabaseClient(local, blobStore, { baseUrl });
    databaseClientUrl = baseUrl;
  }
  return databaseClient;
}

let database: Map<string, Fingerprint> | null = null;
let wanted: { headers: Set<string>; cookies: Set<string> } | null = null;

/** Only header and cookie names some fingerprint reads are ever collected or stored. */
function wantedNames(): { headers: Set<string>; cookies: Set<string> } {
  wanted ??= referencedNames(fingerprints());
  return wanted;
}

/** Response headers of a tab's last main-frame load, bound to the URL they came from. */
interface StoredHeaders {
  url: string;
  headers: Record<string, string[]>;
}

function fingerprints(): Map<string, Fingerprint> {
  database ??= compileDatabase(
    technologiesJson as Record<string, RawTechnology>,
    categoriesJson as Record<string, Category>,
  );
  return database;
}

function rememberHeaders(
  details: chrome.webRequest.OnHeadersReceivedDetails,
): chrome.webRequest.BlockingResponse | undefined {
  if (details.tabId < 0 || details.type !== "main_frame") {
    return undefined;
  }
  const headers = emptyRecord<string[]>();
  for (const header of details.responseHeaders ?? []) {
    const name = header.name.toLowerCase();
    if (header.value !== undefined && wantedNames().headers.has(name)) {
      (headers[name] ??= []).push(header.value);
    }
  }
  const stored: StoredHeaders = { url: details.url, headers };
  void session.set(headersKey(details.tabId), stored);
  return undefined;
}

const headerFilter: chrome.webRequest.RequestFilter = {
  urls: ["<all_urls>"],
  types: ["main_frame"],
};
try {
  // "extraHeaders" is required to observe Set-Cookie in Chromium; Firefox rejects the value.
  chrome.webRequest.onHeadersReceived.addListener(rememberHeaders, headerFilter, [
    "responseHeaders",
    "extraHeaders",
  ]);
} catch {
  chrome.webRequest.onHeadersReceived.addListener(rememberHeaders, headerFilter, [
    "responseHeaders",
  ]);
}

async function cookiesFor(url: string): Promise<Record<string, string>> {
  const cookies = emptyRecord<string>();
  try {
    for (const cookie of await chrome.cookies.getAll({ url })) {
      const name = cookie.name.toLowerCase();
      if (wantedNames().cookies.has(name)) {
        cookies[name] = cookie.value;
      }
    }
  } catch {
    // Cookie access can be denied for some schemes; detection continues without them.
  }
  return cookies;
}

async function loadKev(): Promise<KevCatalog | null> {
  const cached = await kevCache.get<KevCatalog>(KEV_CACHE_KEY);
  if (cached) {
    return cached;
  }
  try {
    const fresh = await fetchKev(fetch);
    await kevCache.set(KEV_CACHE_KEY, fresh);
    return fresh;
  } catch (error) {
    console.warn("wappacvelyze: KEV catalog unavailable", error);
    return null;
  }
}

function worst(assessments: Assessment[]): Status {
  let status: Status = "current";
  for (const assessment of assessments) {
    if (rank(assessment.status) > rank(status)) {
      status = assessment.status;
    }
  }
  return status;
}

const BADGE_COLORS: Record<Status, string> = {
  current: "#1A7F37",
  outdated: "#9A6700",
  unknown: "#6E8099",
  unsupported: "#C2410C",
  vulnerable: "#CF222E",
  critical: "#8B0000",
};

async function updateBadge(tabId: number, result: TabResult): Promise<void> {
  const flagged = result.assessments.filter((a) => rank(a.status) >= rank("vulnerable")).length;
  const text = result.phase === "detected" ? "…" : flagged > 0 ? String(flagged) : "";
  try {
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setBadgeBackgroundColor({
      tabId,
      color: BADGE_COLORS[worst(result.assessments)],
    });
  } catch {
    // The tab may have closed while lookups were running.
  }
}

function byUrgency(a: Assessment, b: Assessment): number {
  return rank(b.status) - rank(a.status) || a.technology.name.localeCompare(b.technology.name);
}

/** Stores a sorted snapshot; the caller's array keeps its order so in-progress loops stay valid. */
async function publish(tabId: number, result: TabResult): Promise<void> {
  const snapshot: TabResult = { ...result, assessments: [...result.assessments].sort(byUrgency) };
  await session.set(resultKey(tabId), snapshot);
  await updateBadge(tabId, snapshot);
}

function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

/**
 * Headers are only used when they came from the page now being analysed, not from a
 * previous document that loaded in the same tab (e.g. after a back-forward-cache restore).
 */
async function headersFor(tabId: number, url: string): Promise<Record<string, string[]>> {
  const stored = (await session.get(headersKey(tabId))) as StoredHeaders | undefined;
  if (!stored || !sameOrigin(stored.url, url)) {
    return emptyRecord();
  }
  return stored.headers;
}

/** Latest run per tab; a newer evidence message supersedes any run still in progress. */
const generation = new Map<number, number>();

function assessmentKey(a: Assessment): string {
  return `${a.technology.name}\u0000${a.technology.version ?? ""}`;
}

/** Verdicts already reached for the same technology and version carry over between runs. */
async function priorVerdicts(tabId: number): Promise<Map<string, Assessment>> {
  const prior = (await session.get(resultKey(tabId))) as TabResult | undefined;
  const verdicts = new Map<string, Assessment>();
  for (const a of prior?.assessments ?? []) {
    if (a.reason !== "checking…") {
      verdicts.set(assessmentKey(a), a);
    }
  }
  return verdicts;
}

async function handleEvidence(tabId: number, collected: CollectedEvidence): Promise<void> {
  const run = (generation.get(tabId) ?? 0) + 1;
  generation.set(tabId, run);
  const superseded = () => generation.get(tabId) !== run;
  const evidence: Evidence = {
    headers: await headersFor(tabId, collected.url),
    cookies: await cookiesFor(collected.url),
    html: collected.html,
    scripts: collected.scripts,
    scriptSrc: collected.scriptSrc,
    meta: collected.meta,
    js: collected.js,
    dom: collected.dom,
  };
  const { technologies, truncated } = analyzeWithBudget(evidence, fingerprints());
  if (truncated) {
    console.warn("wappacvelyze: detection budget exhausted on", collected.url);
  }
  const prior = await priorVerdicts(tabId);
  const result: TabResult = {
    url: collected.url,
    updatedAt: Date.now(),
    phase: "detected",
    assessments: technologies.map(
      (technology) =>
        prior.get(assessmentKey({ technology, status: "unknown" })) ?? {
          technology,
          status: "unknown",
          reason: "checking…",
        },
    ),
  };
  if (superseded()) {
    return;
  }
  await publish(tabId, result);

  const { nvdApiKey, dbUrl } = await loadSettings();
  const { database, warning } = await databaseClientFor(dbUrl).load();
  if (warning) {
    console.warn("wappacvelyze: vulnerability database", warning);
  }
  const assessor = new Assessor(
    new NvdClient({ apiKey: nvdApiKey }),
    await loadKev(),
    nvdCache,
    database,
  );
  for (let i = 0; i < result.assessments.length; i++) {
    const pending = result.assessments[i];
    if (!pending || pending.reason !== "checking…") {
      continue;
    }
    const assessment = await assessor.assess(pending.technology);
    if (superseded()) {
      return;
    }
    result.assessments[i] = assessment;
    result.updatedAt = Date.now();
    await publish(tabId, result);
  }
  result.phase = "done";
  if (!superseded()) {
    await publish(tabId, result);
  }
}

chrome.runtime.onMessage.addListener((message: RuntimeMessage, sender) => {
  if (message.type === "evidence" && sender.tab?.id !== undefined) {
    void handleEvidence(sender.tab.id, message.evidence);
  } else if (message.type === "rescan") {
    const request: RuntimeMessage = { type: "collect" };
    void chrome.tabs.sendMessage(message.tabId, request).catch(() => undefined);
  }
  return false;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  generation.delete(tabId);
  void session.remove([resultKey(tabId), headersKey(tabId)]);
});

chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status === "loading") {
    generation.set(tabId, (generation.get(tabId) ?? 0) + 1);
    void session.remove([resultKey(tabId)]);
    void chrome.action.setBadgeText({ tabId, text: "" }).catch(() => undefined);
  }
});
