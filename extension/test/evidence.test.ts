import { describe, expect, it } from "vitest";
import { analyze } from "../src/lib/detect.ts";
import { emptyRecord, isSafeLink, sanitizePageEvidence } from "../src/lib/evidence.ts";
import { fingerprintDatabase } from "./helpers.ts";

const allow = {
  chains: new Set(["jQuery.fn.jquery"]),
  domProperties: new Map([["body > div", new Set(["_reactRootContainer"])]]),
};

describe("sanitizePageEvidence", () => {
  it("keeps only observations the rules asked for", () => {
    const clean = sanitizePageEvidence(
      {
        js: { "jQuery.fn.jquery": "3.6.0", "evil.chain": "x", "React.version": 5 },
        domProperties: {
          "body > div": { _reactRootContainer: ["true"], other: ["1"] },
          "#unknown": { _reactRootContainer: ["true"] },
        },
      },
      allow,
    );
    expect(clean.js).toEqual({ "jQuery.fn.jquery": "3.6.0" });
    expect(clean.domProperties).toEqual({ "body > div": { _reactRootContainer: ["true"] } });
  });

  it("cannot pollute Object.prototype through attacker-chosen keys", () => {
    const hostile = JSON.parse(
      '{"js":{"__proto__":"x","constructor":"y"},"domProperties":{"__proto__":{"polluted":["1"]}}}',
    ) as unknown;
    const clean = sanitizePageEvidence(hostile, allow);
    expect(Object.keys(clean.js)).toEqual([]);
    expect(Object.keys(clean.domProperties)).toEqual([]);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  it("tolerates garbage and truncates values", () => {
    expect(sanitizePageEvidence(null, allow)).toEqual({ js: {}, domProperties: {} });
    expect(sanitizePageEvidence("nope", allow)).toEqual({ js: {}, domProperties: {} });
    const long = sanitizePageEvidence({ js: { "jQuery.fn.jquery": "x".repeat(2000) } }, allow);
    expect(long.js["jQuery.fn.jquery"]?.length).toBe(500);
  });
});

describe("emptyRecord", () => {
  it("has no prototype, so __proto__ is an ordinary key", () => {
    const record = emptyRecord<string[]>();
    (record["__proto__"] ??= []).push("value");
    expect(record["__proto__"]).toEqual(["value"]);
    expect(Object.getPrototypeOf(record)).toBeNull();
  });
});

describe("isSafeLink", () => {
  it("allows only http and https URLs", () => {
    expect(isSafeLink("https://nvd.nist.gov/vuln/detail/CVE-2021-1")).toBe(true);
    expect(isSafeLink("http://example.com")).toBe(true);
    for (const bad of [
      "javascript:alert(1)",
      "data:text/html,x",
      "chrome://settings",
      "not a url",
      "",
    ]) {
      expect(isSafeLink(bad), bad).toBe(false);
    }
  });
});

describe("analyze with hostile keys", () => {
  it("ignores __proto__ header and meta names without throwing", () => {
    const evidence = {
      headers: { __proto__: ["x"], server: ["nginx/1.24.0"] } as Record<string, string[]>,
      meta: JSON.parse(
        '{"__proto__":["WordPress 6.4.1"],"generator":["WordPress 6.4.1"]}',
      ) as Record<string, string[]>,
    };
    const techs = analyze(evidence, fingerprintDatabase());
    expect(techs.find((t) => t.name === "Nginx")?.version).toBe("1.24.0");
    expect(techs.find((t) => t.name === "WordPress")?.version).toBe("6.4.1");
  });
});
