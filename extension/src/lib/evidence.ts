// Validation for data that crosses a trust boundary: observations posted by the page's
// main world, and URLs from vulnerability feeds that end up as links.

import type { PageEvidence } from "../messages.ts";

/** A record whose keys can never collide with Object.prototype ("__proto__", "constructor"). */
export function emptyRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

export interface PageAllowList {
  chains: ReadonlySet<string>;
  /** selector → property names the rules ask for */
  domProperties: ReadonlyMap<string, ReadonlySet<string>>;
}

const MAX_VALUE_LENGTH = 500;
const MAX_VALUES = 20;

/**
 * Accepts only observations the runtime rules asked for. Any script on the page can post
 * to this channel, so keys are matched against the rule set rather than trusted.
 */
export function sanitizePageEvidence(raw: unknown, allow: PageAllowList): PageEvidence {
  const js = emptyRecord<string>();
  const domProperties = emptyRecord<Record<string, string[]>>();
  if (typeof raw !== "object" || raw === null) {
    return { js, domProperties };
  }
  const candidate = raw as { js?: unknown; domProperties?: unknown };
  for (const [chain, value] of entries(candidate.js)) {
    if (allow.chains.has(chain) && typeof value === "string") {
      js[chain] = value.slice(0, MAX_VALUE_LENGTH);
    }
  }
  for (const [selector, properties] of entries(candidate.domProperties)) {
    const allowedProperties = allow.domProperties.get(selector);
    if (!allowedProperties) {
      continue;
    }
    const clean = emptyRecord<string[]>();
    for (const [name, values] of entries(properties)) {
      if (allowedProperties.has(name) && Array.isArray(values)) {
        clean[name] = values
          .filter((v): v is string => typeof v === "string")
          .slice(0, MAX_VALUES)
          .map((v) => v.slice(0, MAX_VALUE_LENGTH));
      }
    }
    domProperties[selector] = clean;
  }
  return { js, domProperties };
}

function entries(value: unknown): [string, unknown][] {
  return typeof value === "object" && value !== null ? Object.entries(value) : [];
}

/** Only web URLs may become links; feeds could otherwise inject javascript: or data: hrefs. */
export function isSafeLink(href: string): boolean {
  try {
    const url = new URL(href);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}
