// CPE 2.3 formatted-string helpers, mirroring the CLI's cve/cpe.go.

import { parseVersion, type Version } from "./version.ts";

const CPE_FIELD_COUNT = 13;
const CPE_VERSION_INDEX = 5;

/** Splits a CPE on colons that are not backslash-escaped, keeping escapes intact. */
export function splitCpe(cpe: string): string[] {
  const fields: string[] = [];
  let field = "";
  let escaped = false;
  for (const char of cpe) {
    if (escaped) {
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (char === ":") {
      fields.push(field);
      field = "";
      continue;
    }
    field += char;
  }
  fields.push(field);
  return fields;
}

/** Quotes the characters a CPE 2.3 formatted string reserves (letters, digits, -._ are literal). */
export function escapeCpeValue(value: string): string {
  return value.replace(/[^A-Za-z0-9\-._]/g, (char) => `\\${char}`);
}

function unescapeCpeValue(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}

/** Returns the CPE name for one concrete version of the product that `cpe` describes. */
export function cpeWithVersion(cpe: string, version: string): string {
  const fields = splitCpe(cpe);
  if (fields.length !== CPE_FIELD_COUNT || fields[0] !== "cpe" || fields[1] !== "2.3") {
    throw new Error(`malformed CPE 2.3 name "${cpe}"`);
  }
  fields[CPE_VERSION_INDEX] = escapeCpeValue(version);
  return fields.join(":");
}

export interface Product {
  vendor: string;
  product: string;
  version: Version;
}

/** Reads the vendor, product and version out of a versioned CPE name. */
export function productFromCpeName(cpeName: string): Product {
  const fields = splitCpe(cpeName);
  if (fields.length !== CPE_FIELD_COUNT) {
    throw new Error(`malformed CPE 2.3 name "${cpeName}"`);
  }
  const raw = unescapeCpeValue(fields[CPE_VERSION_INDEX] ?? "");
  const version = parseVersion(raw);
  if (!version) {
    throw new Error(`version "${raw}" is not comparable`);
  }
  return {
    vendor: (fields[3] ?? "").toLowerCase(),
    product: (fields[4] ?? "").toLowerCase(),
    version,
  };
}

/** Vendor, product and raw version fields of any CPE 2.3 name, without validation. */
export function cpeParts(cpe: string): { vendor: string; product: string; version: string } {
  const fields = splitCpe(cpe);
  return {
    vendor: (fields[3] ?? "").toLowerCase(),
    product: (fields[4] ?? "").toLowerCase(),
    version: unescapeCpeValue(fields[CPE_VERSION_INDEX] ?? ""),
  };
}
