import { describe, expect, it } from "vitest";
import { analyze, resolveVersion } from "../src/lib/detect.ts";
import { parsePattern } from "../src/lib/fingerprints.ts";
import { fingerprintDatabase } from "./helpers.ts";

const db = fingerprintDatabase();

function find(name: string, evidence: Parameters<typeof analyze>[0]) {
  return analyze(evidence, db).find((t) => t.name === name);
}

describe("parsePattern", () => {
  it("separates regex, version and confidence", () => {
    const pattern = parsePattern("nginx(?:/([\\d.]+))?\\;version:\\1\\;confidence:50");
    expect(pattern.version).toBe("\\1");
    expect(pattern.confidence).toBe(50);
    expect(pattern.regex.test("NGINX/1.2")).toBe(true);
  });

  it("matches anything for an empty pattern and never for an invalid one", () => {
    expect(parsePattern("").regex.test("whatever")).toBe(true);
    expect(parsePattern("(unclosed").regex.test("(unclosed")).toBe(false);
  });
});

describe("resolveVersion", () => {
  it("substitutes back-references and ternaries", () => {
    const groups = /^(next)?.*$/.exec("next-env") as RegExpExecArray;
    expect(resolveVersion("\\1?Next:", groups)).toBe("Next");
    const none = /^(next)?.*$/.exec("prod") as RegExpExecArray;
    expect(resolveVersion("\\1?Next:Legacy", none)).toBe("Legacy");
    const two = /(\d+)\.(\d+)/.exec("v4.7") as RegExpExecArray;
    expect(resolveVersion("\\1.\\2", two)).toBe("4.7");
  });
});

describe("analyze", () => {
  it("captures versions and CPEs from headers, meta and JS globals", () => {
    const evidence = {
      headers: { server: ["nginx/1.24.0"], "x-powered-by": ["PHP/8.1.12"] },
      meta: { generator: ["WordPress 6.4.1"] },
      js: { "jQuery.fn.jquery": "3.6.0" },
    };
    expect(find("Nginx", evidence)).toMatchObject({
      version: "1.24.0",
      cpe: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    });
    expect(find("PHP", evidence)?.version).toBe("8.1.12");
    expect(find("WordPress", evidence)?.version).toBe("6.4.1");
    expect(find("jQuery", evidence)?.version).toBe("3.6.0");
    expect(find("Nginx", evidence)?.categories).toContain("Web servers");
    expect(find("Nginx", evidence)?.icon).toBe("Nginx.svg");
  });

  it("reports detected technologies without a version", () => {
    const nginx = find("Nginx", { headers: { server: ["nginx"] } });
    expect(nginx).toBeDefined();
    expect(nginx?.version).toBeUndefined();
  });

  it("adds implied technologies without versions", () => {
    const evidence = { meta: { generator: ["WordPress 6.4.1"] } };
    expect(find("MySQL", evidence)).toBeDefined();
    expect(find("PHP", evidence)?.version).toBeUndefined();
  });

  it("detects from script sources and DOM evidence", () => {
    const evidence = {
      scriptSrc: ["https://cdn.example/3.7.1/jquery.min.js"],
      dom: {
        "div[id*='react-root'], span[id*='react-']": {
          exists: true,
          text: [],
          attributes: {},
          properties: {},
        },
      },
    };
    expect(find("jQuery", evidence)?.version).toBe("3.7.1");
    expect(find("React", evidence)).toBeDefined();
  });

  it("returns nothing for empty evidence and sorts by name", () => {
    expect(analyze({}, db)).toEqual([]);
    const names = analyze({ headers: { server: ["nginx"], "x-powered-by": ["PHP/8"] } }, db).map(
      (t) => t.name,
    );
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
  });
});

describe("analyzeWithBudget", () => {
  it("stops checking fingerprints once the budget is spent", async () => {
    const { analyzeWithBudget } = await import("../src/lib/detect.ts");
    let clock = 0;
    const result = analyzeWithBudget({ headers: { server: ["nginx/1.24.0"] } }, db, {
      budgetMs: 5,
      now: () => (clock += 1),
    });
    expect(result.truncated).toBe(true);
    expect(result.technologies.length).toBeLessThan(db.size);
    expect(analyzeWithBudget({ headers: { server: ["nginx/1.24.0"] } }, db).truncated).toBe(false);
  });
});

describe("boundQuantifiers", () => {
  it("bounds bare quantifiers and leaves escaped ones alone", async () => {
    const { boundQuantifiers } = await import("../src/lib/fingerprints.ts");
    expect(boundQuantifiers("a+b*c\\+d\\*")).toBe("a{1,250}b{0,250}c\\+d\\*");
    expect(new RegExp(boundQuantifiers("^nginx(?:/([\\d.]+))?$"), "i").exec("nginx/1.2")?.[1]).toBe(
      "1.2",
    );
  });
});
