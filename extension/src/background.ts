// Background service worker: captures response headers, runs detection on evidence from
// the content script, looks up CVEs, and publishes per-tab results for the popup.

import categoriesJson from "./generated/categories.json";
import technologiesJson from "./generated/technologies.json";
import { Cache } from "./lib/cache.ts";
import { Assessor, rank } from "./lib/classify.ts";
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
import type { Assessment, Settings, Status, TabResult } from "./lib/types.ts";
import {
  headersKey,
  resultKey,
  SETTINGS_KEY,
  type CollectedEvidence,
  type RuntimeMessage,
} from "./messages.ts";

const DAY_MS = 24 * 60 * 60 * 1000;
const KEV_CACHE_KEY = "catalog";

const local = new ChromeStore(chrome.storage.local);
const session = new ChromeStore(chrome.storage.session);
const nvdCache = new Cache(local, "nvd:", DAY_MS);
const kevCache = new Cache(local, "kev:", DAY_MS);

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

async function settings(): Promise<Settings> {
  const stored = (await local.get(SETTINGS_KEY)) as Partial<Settings> | undefined;
  return { nvdApiKey: stored?.nvdApiKey ?? "" };
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
  unknown: "#6E8099",
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

async function publish(tabId: number, result: TabResult): Promise<void> {
  result.assessments.sort(byUrgency);
  await session.set(resultKey(tabId), result);
  await updateBadge(tabId, result);
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

async function handleEvidence(tabId: number, collected: CollectedEvidence): Promise<void> {
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
  const result: TabResult = {
    url: collected.url,
    updatedAt: Date.now(),
    phase: "detected",
    assessments: technologies.map((technology) => ({
      technology,
      status: "unknown",
      reason: "checking…",
    })),
  };
  await publish(tabId, result);

  const { nvdApiKey } = await settings();
  const assessor = new Assessor(new NvdClient({ apiKey: nvdApiKey }), await loadKev(), nvdCache);
  for (let i = 0; i < technologies.length; i++) {
    const technology = technologies[i];
    if (!technology) {
      continue;
    }
    result.assessments[i] = await assessor.assess(technology);
    result.updatedAt = Date.now();
    await publish(tabId, result);
  }
  result.phase = "done";
  await publish(tabId, result);
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
  void session.remove([resultKey(tabId), headersKey(tabId)]);
});

chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status === "loading") {
    void session.remove([resultKey(tabId)]);
    void chrome.action.setBadgeText({ tabId, text: "" }).catch(() => undefined);
  }
});
