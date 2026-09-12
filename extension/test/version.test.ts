import { describe, expect, it } from "vitest";
import { compareVersions, parseVersion } from "../src/lib/version.ts";

function cmp(a: string, b: string): number {
  const va = parseVersion(a);
  const vb = parseVersion(b);
  if (!va || !vb) {
    throw new Error(`unparseable: ${a} / ${b}`);
  }
  return Math.sign(compareVersions(va, vb));
}

describe("parseVersion", () => {
  it("accepts dotted, pre-release and metadata forms", () => {
    expect(parseVersion("7.2")?.segments).toEqual([7, 2]);
    expect(parseVersion("1.0.0-rc1")?.prerelease).toBe("rc1");
    expect(parseVersion("1.2.3beta")?.prerelease).toBe("beta");
    expect(parseVersion("v2.4.49+build")?.segments).toEqual([2, 4, 49]);
  });

  it("rejects non-versions", () => {
    for (const raw of ["1.x", "", "abc", "1..2", "1.0+"]) {
      expect(parseVersion(raw), raw).toBeNull();
    }
  });
});

describe("compareVersions", () => {
  it("compares numerically with implicit zero segments", () => {
    expect(cmp("1.18.0", "1.20.1")).toBe(-1);
    expect(cmp("7.2", "7.2.0")).toBe(0);
    expect(cmp("1.10", "1.9")).toBe(1);
    expect(cmp("8.1.12", "8.1.29")).toBe(-1);
  });

  it("sorts pre-releases before releases", () => {
    expect(cmp("1.0.0-rc1", "1.0.0")).toBe(-1);
    expect(cmp("1.0.0-beta", "1.0.0-rc1")).toBe(-1);
  });
});
