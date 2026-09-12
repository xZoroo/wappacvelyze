// Fingerprint database loading and pattern compilation. The database is generated from
// the same wappalyzergo release the CLI embeds (`npm run data`).

export interface RawDomRule {
  exists?: string;
  text?: string;
  attributes?: Record<string, string>;
  properties?: Record<string, string>;
}

/** One technology as stored in the generated technologies.json. */
export interface RawTechnology {
  cats: number[];
  website?: string;
  icon?: string;
  cpe?: string;
  implies?: string[];
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  meta?: Record<string, string[]>;
  html?: string[];
  scripts?: string[];
  scriptSrc?: string[];
  js?: Record<string, string>;
  dom?: Record<string, RawDomRule>;
}

export interface Pattern {
  regex: RegExp;
  version: string;
  confidence: number;
}

export interface DomRule {
  exists?: Pattern;
  text?: Pattern;
  attributes: Record<string, Pattern>;
  properties: Record<string, Pattern>;
}

export interface Technology {
  name: string;
  categories: string[];
  website: string;
  icon: string;
  cpe: string;
  implies: string[];
  headers: Record<string, Pattern>;
  cookies: Record<string, Pattern>;
  meta: Record<string, Pattern[]>;
  html: Pattern[];
  scripts: Pattern[];
  scriptSrc: Pattern[];
  js: Record<string, Pattern>;
  dom: Record<string, DomRule>;
}

export interface Category {
  name: string;
  priority: number;
}

const NEVER = /(?!)/;

// Unbounded quantifiers are the main source of catastrophic backtracking in V8's regex
// engine. Bounding them the same way wappalyzergo does keeps both engines equivalent while
// capping how far a crafted page can push a single pattern.
const MAX_REPEAT = 250;

export function boundQuantifiers(source: string): string {
  let bounded = "";
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (char === "\\") {
      bounded += char + (source[i + 1] ?? "");
      i++;
    } else if (char === "+") {
      bounded += `{1,${MAX_REPEAT}}`;
    } else if (char === "*") {
      bounded += `{0,${MAX_REPEAT}}`;
    } else {
      bounded += char;
    }
  }
  return bounded;
}

/**
 * Parses `regex\;version:\1\;confidence:50`. An empty regex matches anything, which is
 * how existence checks are expressed. Patterns that are not valid JavaScript regular
 * expressions never match rather than aborting detection.
 */
export function parsePattern(raw: string): Pattern {
  const [source = "", ...attributes] = raw.split("\\;");
  const pattern: Pattern = { regex: NEVER, version: "", confidence: 100 };
  try {
    pattern.regex = new RegExp(boundQuantifiers(source), "i");
  } catch {
    try {
      pattern.regex = new RegExp(source, "i");
    } catch {
      return pattern;
    }
  }
  for (const attribute of attributes) {
    const separator = attribute.indexOf(":");
    const key = attribute.slice(0, separator);
    const value = attribute.slice(separator + 1);
    if (key === "version") {
      pattern.version = value;
    } else if (key === "confidence") {
      const confidence = Number.parseInt(value, 10);
      pattern.confidence = Number.isNaN(confidence) ? 100 : confidence;
    }
  }
  return pattern;
}

function parseList(raw: string[] | undefined): Pattern[] {
  return (raw ?? []).map(parsePattern);
}

function parseMap(
  raw: Record<string, string> | undefined,
  lowercaseKeys: boolean,
): Record<string, Pattern> {
  const out: Record<string, Pattern> = {};
  for (const [key, value] of Object.entries(raw ?? {})) {
    out[lowercaseKeys ? key.toLowerCase() : key] = parsePattern(value);
  }
  return out;
}

function parseDom(raw: Record<string, RawDomRule> | undefined): Record<string, DomRule> {
  const out: Record<string, DomRule> = {};
  for (const [selector, rule] of Object.entries(raw ?? {})) {
    const compiled: DomRule = {
      attributes: parseMap(rule.attributes, false),
      properties: parseMap(rule.properties, false),
    };
    if (rule.exists !== undefined) {
      compiled.exists = parsePattern(rule.exists);
    }
    if (rule.text !== undefined) {
      compiled.text = parsePattern(rule.text);
    }
    out[selector] = compiled;
  }
  return out;
}

/** Strips the `\;confidence:N` suffix an implied technology name may carry. */
function impliedName(raw: string): string {
  return raw.split("\\;")[0] ?? raw;
}

export function compileTechnology(
  name: string,
  raw: RawTechnology,
  categories: Record<string, Category>,
): Technology {
  const meta: Record<string, Pattern[]> = {};
  for (const [key, patterns] of Object.entries(raw.meta ?? {})) {
    meta[key.toLowerCase()] = parseList(patterns);
  }
  return {
    name,
    categories: raw.cats.map((id) => categories[String(id)]?.name ?? `Category ${id}`),
    website: raw.website ?? "",
    icon: raw.icon ?? "",
    cpe: raw.cpe ?? "",
    implies: (raw.implies ?? []).map(impliedName),
    headers: parseMap(raw.headers, true),
    cookies: parseMap(raw.cookies, true),
    meta,
    html: parseList(raw.html),
    scripts: parseList(raw.scripts),
    scriptSrc: parseList(raw.scriptSrc),
    js: parseMap(raw.js, false),
    dom: parseDom(raw.dom),
  };
}

/** Header and cookie names any fingerprint reads, so collection can be limited to them. */
export function referencedNames(database: Map<string, Technology>): {
  headers: Set<string>;
  cookies: Set<string>;
} {
  const headers = new Set<string>();
  const cookies = new Set<string>();
  for (const technology of database.values()) {
    for (const name of Object.keys(technology.headers)) {
      headers.add(name);
    }
    for (const name of Object.keys(technology.cookies)) {
      cookies.add(name);
    }
  }
  return { headers, cookies };
}

export function compileDatabase(
  technologies: Record<string, RawTechnology>,
  categories: Record<string, Category>,
): Map<string, Technology> {
  const compiled = new Map<string, Technology>();
  for (const [name, raw] of Object.entries(technologies)) {
    compiled.set(name, compileTechnology(name, raw, categories));
  }
  return compiled;
}
