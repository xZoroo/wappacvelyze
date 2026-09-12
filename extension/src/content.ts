// Isolated-world content script: gathers DOM-level evidence, merges the main-world page
// script's observations, and forwards everything to the background worker.

import runtimeRulesJson from "./generated/runtime-rules.json";
import type { DomEvidence } from "./lib/detect.ts";
import {
  PAGE_MESSAGE_SOURCE,
  type CollectedEvidence,
  type PageEvidence,
  type PageMessage,
  type RuntimeMessage,
} from "./messages.ts";

interface RuntimeRules {
  dom?: { selector: string; exists?: boolean; text?: boolean; attributes?: string[] }[];
}

const rules = runtimeRulesJson as RuntimeRules;
const MAX_HTML_BYTES = 500_000;
const MAX_INLINE_SCRIPT_BYTES = 50_000;
const MAX_INLINE_SCRIPTS = 100;
const MAX_ELEMENTS_PER_SELECTOR = 20;
const MAX_TEXT_LENGTH = 500;
const PAGE_EVIDENCE_TIMEOUT_MS = 3000;

let pageEvidence: PageEvidence = { js: {}, domProperties: {} };
let sentOnce = false;

function collectMeta(): Record<string, string[]> {
  const meta: Record<string, string[]> = {};
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
  const dom: Record<string, DomEvidence> = {};
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
    const evidence: DomEvidence = { exists: true, text: [], attributes: {}, properties: {} };
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
    const evidence = (dom[selector] ??= { exists: true, text: [], attributes: {}, properties: {} });
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
  const message: RuntimeMessage = { type: "evidence", evidence: collect() };
  void chrome.runtime.sendMessage(message).catch(() => undefined);
}

/** Accepts only well-formed observations; the page can post anything to this channel. */
function sanitize(evidence: unknown): PageEvidence | null {
  if (typeof evidence !== "object" || evidence === null) {
    return null;
  }
  const { js, domProperties } = evidence as Partial<PageEvidence>;
  const cleanJs: Record<string, string> = {};
  for (const [chain, value] of Object.entries(js ?? {})) {
    if (typeof value === "string") {
      cleanJs[chain] = value.slice(0, MAX_TEXT_LENGTH);
    }
  }
  const cleanDom: Record<string, Record<string, string[]>> = {};
  for (const [selector, properties] of Object.entries(domProperties ?? {})) {
    const clean: Record<string, string[]> = {};
    for (const [name, values] of Object.entries(properties ?? {})) {
      if (Array.isArray(values)) {
        clean[name] = values
          .filter((v): v is string => typeof v === "string")
          .slice(0, MAX_ELEMENTS_PER_SELECTOR);
      }
    }
    cleanDom[selector] = clean;
  }
  return { js: cleanJs, domProperties: cleanDom };
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
  const clean = sanitize(data.evidence);
  if (clean) {
    pageEvidence = clean;
    send();
  }
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
