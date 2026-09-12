import { describe, expect, it } from "vitest";
import { Cache } from "../src/lib/cache.ts";
import { Limiter } from "../src/lib/limiter.ts";
import { MemoryStore } from "../src/lib/store.ts";

describe("Cache", () => {
  it("returns fresh values, expires old ones and clears its prefix only", async () => {
    const store = new MemoryStore();
    await store.set("other", 1);
    const cache = new Cache(store, "nvd:", 50);
    expect(await cache.get("k")).toBeUndefined();
    await cache.set("k", [1, 2]);
    expect(await cache.get("k")).toEqual([1, 2]);
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(await cache.get("k")).toBeUndefined();
    await cache.set("k", 3);
    await cache.clear();
    expect(await cache.get("k")).toBeUndefined();
    expect(await store.get("other")).toBe(1);
  });
});

describe("Limiter", () => {
  it("allows max sends per window then reports the wait", () => {
    const limiter = new Limiter(2, 60_000);
    expect(limiter.reserve(1_000_000)).toBe(0);
    expect(limiter.reserve(1_001_000)).toBe(0);
    expect(limiter.reserve(1_002_000)).toBe(58_000);
    expect(limiter.reserve(1_061_000)).toBe(0);
  });
});
