// Isolated-world content script: gathers DOM-level evidence, merges the main-world page
// script's observations, and forwards everything to the background worker.

import runtimeRulesJson from "./generated/runtime-rules.json";
import type { DomEvidence } from "./lib/detect.ts";
import { emptyRecord, sanitizePageEvidence, type PageAllowList } from "./lib/evidence.ts";
import {
  PAGE_MESSAGE_SOURCE,
  type CollectedEvidence,
  type PageEvidence,
  type PageMessage,
  type RuntimeMessage,
} from "./messages.ts";

interface RuntimeRules {
  javascriptProperties?: string[];
  dom?: {
    selector: string;
    exists?: boolean;
    text?: boolean;
    attributes?: string[];
    properties?: string[];
  }[];
}

const rules = runtimeRulesJson as RuntimeRules;
const allowList: PageAllowList = {
  chains: new Set(rules.javascriptProperties ?? []),
  domProperties: new Map(
    (rules.dom ?? [])
      .filter((rule) => rule.properties?.length)
      .map((rule) => [rule.selector, new Set(rule.properties)]),
  ),
};
const MAX_HTML_BYTES = 250_000;
const MAX_INLINE_SCRIPT_BYTES = 20_000;
const MAX_INLINE_SCRIPTS = 40;
const MAX_ELEMENTS_PER_SELECTOR = 20;
const MAX_TEXT_LENGTH = 500;
const PAGE_EVIDENCE_TIMEOUT_MS = 3000;

let pageEvidence: PageEvidence = { js: emptyRecord(), domProperties: emptyRecord() };
let sentOnce = false;
let sendTimer: ReturnType<typeof setTimeout> | undefined;
const SEND_DEBOUNCE_MS = 250;

function collectMeta(): Record<string, string[]> {
  const meta = emptyRecord<string[]>();
  for (const element of document.querySelectorAll("meta")) {
    const name = (
      element.getAttribute("name") ??
      element.getAttribute("property") ??
      ""
    ).toLowerCase();
    const content = element.getAttribute("content");
    if (name && content !== null) {
      (meta[name] ??= []).push(content);
    }
  }
  return meta;
}

function collectDom(): Record<string, DomEvidence> {
  const dom = emptyRecord<DomEvidence>();
  for (const rule of rules.dom ?? []) {
    let elements: Element[];
    try {
      elements = [...document.querySelectorAll(rule.selector)].slice(0, MAX_ELEMENTS_PER_SELECTOR);
    } catch {
      continue;
    }
    if (elements.length === 0) {
      continue;
    }
    const evidence: DomEvidence = {
      exists: true,
      text: [],
      attributes: emptyRecord(),
      properties: emptyRecord(),
    };
    if (rule.text) {
      evidence.text = elements
        .map((element) => (element.textContent ?? "").trim().slice(0, MAX_TEXT_LENGTH))
        .filter((text) => text !== "");
    }
    for (const attribute of rule.attributes ?? []) {
      const values = elements
        .map((element) => element.getAttribute(attribute))
        .filter((value): value is string => value !== null);
      if (values.length > 0) {
        evidence.attributes[attribute] = values;
      }
    }
    dom[rule.selector] = evidence;
  }
  return dom;
}

function mergePageProperties(dom: Record<string, DomEvidence>): void {
  for (const [selector, properties] of Object.entries(pageEvidence.domProperties)) {
    const evidence = (dom[selector] ??= {
      exists: true,
      text: [],
      attributes: emptyRecord(),
      properties: emptyRecord(),
    });
    evidence.properties = properties;
  }
}

function collect(): CollectedEvidence {
  const scripts = [...document.scripts];
  const dom = collectDom();
  mergePageProperties(dom);
  return {
    url: window.location.href,
    html: document.documentElement.outerHTML.slice(0, MAX_HTML_BYTES),
    scripts: scripts
      .filter((script) => !script.src && script.textContent)
      .slice(0, MAX_INLINE_SCRIPTS)
      .map((script) => (script.textContent ?? "").slice(0, MAX_INLINE_SCRIPT_BYTES)),
    scriptSrc: scripts.map((script) => script.src).filter((src) => src !== ""),
    meta: collectMeta(),
    js: pageEvidence.js,
    dom,
  };
}

function send(): void {
  sentOnce = true;
  clearTimeout(sendTimer);
  sendTimer = setTimeout(() => {
    const message: RuntimeMessage = { type: "evidence", evidence: collect() };
    void chrome.runtime.sendMessage(message).catch(() => undefined);
  }, SEND_DEBOUNCE_MS);
}

window.addEventListener("message", (event: MessageEvent<PageMessage>) => {
  const data = event.data;
  if (
    event.source !== window ||
    data?.source !== PAGE_MESSAGE_SOURCE ||
    data.kind !== "page-evidence"
  ) {
    return;
  }
  pageEvidence = sanitizePageEvidence(data.evidence, allowList);
  send();
});

chrome.runtime.onMessage.addListener((message: RuntimeMessage) => {
  if (message.type === "collect") {
    const request: PageMessage = { source: PAGE_MESSAGE_SOURCE, kind: "collect-request" };
    window.postMessage(request, window.location.origin);
  }
});

// If the main-world script never reports (blocked by CSP, or a browser without MAIN world
// support), still send what the isolated world can see.
setTimeout(() => {
  if (!sentOnce) {
    send();
  }
}, PAGE_EVIDENCE_TIMEOUT_MS);
