// Technology detection: matches collected page evidence against the fingerprint database.

import type { DomRule, Pattern, Technology as Fingerprint } from "./fingerprints.ts";
import type { Technology } from "./types.ts";

export interface DomEvidence {
  exists: boolean;
  text: string[];
  attributes: Record<string, string[]>;
  properties: Record<string, string[]>;
}

/** Everything observed about one page load. Header, cookie and meta names are lowercase. */
export interface Evidence {
  headers?: Record<string, string[]>;
  cookies?: Record<string, string>;
  html?: string;
  scripts?: string[];
  scriptSrc?: string[];
  meta?: Record<string, string[]>;
  js?: Record<string, string>;
  dom?: Record<string, DomEvidence>;
}

interface Detection {
  confidence: number;
  version: string;
}

const MAX_VERSION_LENGTH = 15;
const MAX_LEADING_NUMBER = 10000;

/** Substitutes capture groups into a version template, honouring `\1?yes:no` ternaries. */
export function resolveVersion(template: string, groups: RegExpExecArray): string {
  let version = template;
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i] ?? "";
    const ternary = new RegExp(`\\\\${i}\\?([^:]+):(.*)$`).exec(version);
    if (ternary) {
      version = version.replace(ternary[0], group ? (ternary[1] ?? "") : (ternary[2] ?? ""));
    }
    version = version.trim().replace(new RegExp(`\\\\${i}`, "g"), group);
  }
  return version.trim();
}

function match(pattern: Pattern, value: string): Detection | null {
  const groups = pattern.regex.exec(value);
  if (!groups) {
    return null;
  }
  return {
    confidence: pattern.confidence,
    version: pattern.version ? resolveVersion(pattern.version, groups) : "",
  };
}

function matchAll(patterns: Pattern[], values: string[], into: Detection[]): void {
  for (const pattern of patterns) {
    for (const value of values) {
      const detection = match(pattern, value);
      if (detection) {
        into.push(detection);
      }
    }
  }
}

function matchDom(rule: DomRule, evidence: DomEvidence, into: Detection[]): void {
  if (rule.exists && evidence.exists) {
    matchAll([rule.exists], [""], into);
  }
  if (rule.text) {
    matchAll([rule.text], evidence.text, into);
  }
  for (const [name, pattern] of Object.entries(rule.attributes)) {
    matchAll([pattern], evidence.attributes[name] ?? [], into);
  }
  for (const [name, pattern] of Object.entries(rule.properties)) {
    matchAll([pattern], evidence.properties[name] ?? [], into);
  }
}

function detect(fingerprint: Fingerprint, evidence: Evidence): Detection[] {
  const found: Detection[] = [];
  for (const [name, pattern] of Object.entries(fingerprint.headers)) {
    matchAll([pattern], evidence.headers?.[name] ?? [], found);
  }
  for (const [name, pattern] of Object.entries(fingerprint.cookies)) {
    const value = evidence.cookies?.[name];
    matchAll([pattern], value === undefined ? [] : [value], found);
  }
  for (const [name, patterns] of Object.entries(fingerprint.meta)) {
    matchAll(patterns, evidence.meta?.[name] ?? [], found);
  }
  matchAll(fingerprint.html, evidence.html === undefined ? [] : [evidence.html], found);
  matchAll(fingerprint.scripts, evidence.scripts ?? [], found);
  matchAll(fingerprint.scriptSrc, evidence.scriptSrc ?? [], found);
  for (const [chain, pattern] of Object.entries(fingerprint.js)) {
    const value = evidence.js?.[chain];
    matchAll([pattern], value === undefined ? [] : [value], found);
  }
  for (const [selector, rule] of Object.entries(fingerprint.dom)) {
    const observed = evidence.dom?.[selector];
    if (observed) {
      matchDom(rule, observed, found);
    }
  }
  return found;
}

/** Picks the most specific plausible version across detections, ignoring timestamps. */
function bestVersion(detections: Detection[]): string {
  let best = "";
  for (const { version } of detections) {
    const leading = Number.parseInt(version, 10) || 0;
    if (
      version.length > best.length &&
      version.length <= MAX_VERSION_LENGTH &&
      leading < MAX_LEADING_NUMBER
    ) {
      best = version;
    }
  }
  return best;
}

function toTechnology(fingerprint: Fingerprint, version: string): Technology {
  const technology: Technology = { name: fingerprint.name, categories: fingerprint.categories };
  if (version) {
    technology.version = version;
  }
  if (fingerprint.cpe) {
    technology.cpe = fingerprint.cpe;
  }
  if (fingerprint.website) {
    technology.website = fingerprint.website;
  }
  return technology;
}

/** Adds technologies implied by detected ones (without versions), transitively. */
function addImplied(found: Map<string, Technology>, database: Map<string, Fingerprint>): void {
  const queue = [...found.keys()];
  while (queue.length > 0) {
    const name = queue.pop();
    const fingerprint = name === undefined ? undefined : database.get(name);
    for (const implied of fingerprint?.implies ?? []) {
      const target = database.get(implied);
      if (target && !found.has(implied)) {
        found.set(implied, toTechnology(target, ""));
        queue.push(implied);
      }
    }
  }
}

/** Identifies technologies in evidence. Results are sorted by name. */
export function analyze(evidence: Evidence, database: Map<string, Fingerprint>): Technology[] {
  const found = new Map<string, Technology>();
  for (const fingerprint of database.values()) {
    const detections = detect(fingerprint, evidence);
    if (detections.some((d) => d.confidence > 0)) {
      found.set(fingerprint.name, toTechnology(fingerprint, bestVersion(detections)));
    }
  }
  addImplied(found, database);
  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}
