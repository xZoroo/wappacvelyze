// Runs in the page's main world so it can read JavaScript globals (e.g. jQuery.fn.jquery)
// and DOM element properties that the isolated content script cannot see. It never
// receives data from the extension; it only reports what it observes.

import runtimeRulesJson from "./generated/runtime-rules.json";
import { emptyRecord } from "./lib/evidence.ts";
import { PAGE_MESSAGE_SOURCE, type PageEvidence, type PageMessage } from "./messages.ts";

interface RuntimeRules {
  javascriptProperties?: string[];
  dom?: { selector: string; properties?: string[] }[];
}

const rules = runtimeRulesJson as RuntimeRules;
const MAX_ELEMENTS_PER_SELECTOR = 20;
// Frameworks expose their globals whenever their bundles finish booting, which on heavy
// pages can be well after document_idle; sample on a widening schedule and report changes.
const SAMPLE_DELAYS_MS = [500, 1500, 3000, 6000, 12000, 25000];
let lastReport = "";

function scalar(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }
  return "true";
}

/** Walks a dot/bracket chain such as `jQuery.fn.jquery` from `window`. */
function readChain(chain: string): string | undefined {
  const parts = chain.replace(/\[([^\]]+)\]/g, ".$1").split(".");
  let current: unknown = window;
  try {
    for (const part of parts) {
      if ((typeof current !== "object" && typeof current !== "function") || current === null) {
        return undefined;
      }
      if (!(part in current)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }
    return scalar(current);
  } catch {
    return undefined;
  }
}

function collect(): PageEvidence {
  const js = emptyRecord<string>();
  for (const chain of rules.javascriptProperties ?? []) {
    const value = readChain(chain);
    if (value !== undefined) {
      js[chain] = value;
    }
  }
  const domProperties = emptyRecord<Record<string, string[]>>();
  for (const rule of rules.dom ?? []) {
    if (!rule.properties?.length) {
      continue;
    }
    let elements: Element[];
    try {
      elements = [...document.querySelectorAll(rule.selector)].slice(0, MAX_ELEMENTS_PER_SELECTOR);
    } catch {
      continue;
    }
    const observed = emptyRecord<string[]>();
    for (const property of rule.properties) {
      const values = elements
        .map((element) => scalar((element as unknown as Record<string, unknown>)[property]))
        .filter((value): value is string => value !== undefined);
      if (values.length > 0) {
        observed[property] = values;
      }
    }
    if (Object.keys(observed).length > 0) {
      domProperties[rule.selector] = observed;
    }
  }
  return { js, domProperties };
}

function report(force = false): void {
  const evidence = collect();
  const serialized = JSON.stringify(evidence);
  if (!force && serialized === lastReport) {
    return;
  }
  lastReport = serialized;
  const message: PageMessage = { source: PAGE_MESSAGE_SOURCE, kind: "page-evidence", evidence };
  window.postMessage(message, window.location.origin);
}

window.addEventListener("message", (event: MessageEvent<PageMessage>) => {
  const data = event.data;
  if (
    event.source === window &&
    data?.source === PAGE_MESSAGE_SOURCE &&
    data.kind === "collect-request"
  ) {
    report(true);
  }
});

report(true);
for (const delay of SAMPLE_DELAYS_MS) {
  setTimeout(report, delay);
}
