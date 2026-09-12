// Version comparison for the dotted, optionally pre-release version numbers found in
// fingerprints and NVD applicability statements (same semantics as hashicorp/go-version).

export interface Version {
  original: string;
  segments: number[];
  prerelease: string;
}

const versionPattern = /^v?(\d+(?:\.\d+)*)(?:-?([A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Parses a version, returning null when it is not a comparable version number. */
export function parseVersion(raw: string): Version | null {
  const match = versionPattern.exec(raw.trim());
  const numeric = match?.[1];
  if (!match || numeric === undefined) {
    return null;
  }
  return {
    original: raw.trim(),
    segments: numeric.split(".").map(Number),
    prerelease: match[2] ?? "",
  };
}

/** Compares two versions, returning a negative, zero or positive number. */
export function compareVersions(a: Version, b: Version): number {
  const length = Math.max(a.segments.length, b.segments.length);
  for (let i = 0; i < length; i++) {
    const diff = (a.segments[i] ?? 0) - (b.segments[i] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  if (a.prerelease === b.prerelease) {
    return 0;
  }
  // A pre-release sorts before the release it precedes.
  if (a.prerelease === "") {
    return 1;
  }
  if (b.prerelease === "") {
    return -1;
  }
  return a.prerelease < b.prerelease ? -1 : 1;
}
