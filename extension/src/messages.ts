// Message shapes exchanged between the page script, content script and background worker.

import type { DomEvidence } from "./lib/detect.ts";

export const PAGE_MESSAGE_SOURCE = "wappacvelyze";

/** Values the main-world page script can observe that the isolated world cannot. */
export interface PageEvidence {
  js: Record<string, string>;
  domProperties: Record<string, Record<string, string[]>>;
}

export interface PageMessage {
  source: typeof PAGE_MESSAGE_SOURCE;
  kind: "page-evidence" | "collect-request";
  evidence?: PageEvidence;
}

/** Evidence the content script sends to the background worker. */
export interface CollectedEvidence {
  url: string;
  html: string;
  scripts: string[];
  scriptSrc: string[];
  meta: Record<string, string[]>;
  js: Record<string, string>;
  dom: Record<string, DomEvidence>;
}

export type RuntimeMessage =
  | { type: "evidence"; evidence: CollectedEvidence }
  | { type: "rescan"; tabId: number }
  | { type: "collect" };

export function resultKey(tabId: number): string {
  return `result:${tabId}`;
}

export function headersKey(tabId: number): string {
  return `headers:${tabId}`;
}

export const SETTINGS_KEY = "settings";
