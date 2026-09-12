import { describe, expect, it } from "vitest";
import { cpeWithVersion, productFromCpeName, splitCpe } from "../src/lib/cpe.ts";

describe("cpeWithVersion", () => {
  it("splices and escapes the version", () => {
    expect(cpeWithVersion("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0")).toBe(
      "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
    );
    expect(cpeWithVersion("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", "1.0+rc1:a")).toBe(
      "cpe:2.3:a:x:y:1.0\\+rc1\\:a:*:*:*:*:*:*:*",
    );
  });

  it("keeps escaped colons in other fields", () => {
    expect(cpeWithVersion("cpe:2.3:a:ex\\:ample:y:*:*:*:*:*:*:*:*", "2.0")).toBe(
      "cpe:2.3:a:ex\\:ample:y:2.0:*:*:*:*:*:*:*",
    );
  });

  it("rejects malformed names", () => {
    for (const cpe of ["cpe:2.3:a:x:y", "cpe:/a:x:y:1:::::::", ""]) {
      expect(() => cpeWithVersion(cpe, "1"), cpe).toThrow(/malformed/);
    }
  });
});

describe("productFromCpeName", () => {
  it("reads vendor, product and an unescaped comparable version", () => {
    const product = productFromCpeName("cpe:2.3:a:F5:Nginx:1.0\\+rc1:*:*:*:*:*:*:*");
    expect(product.vendor).toBe("f5");
    expect(product.product).toBe("nginx");
    expect(product.version.original).toBe("1.0+rc1");
  });

  it("rejects non-comparable versions", () => {
    expect(() => productFromCpeName("cpe:2.3:a:f5:nginx:1.x:*:*:*:*:*:*:*")).toThrow(
      /not comparable/,
    );
  });
});

describe("splitCpe", () => {
  it("splits on unescaped colons only", () => {
    expect(splitCpe("a:b\\:c:d")).toEqual(["a", "b\\:c", "d"]);
  });
});
