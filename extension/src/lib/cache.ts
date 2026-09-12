import type { KeyValueStore } from "./store.ts";

interface Entry<T> {
  storedAt: number;
  value: T;
}

/** Time-limited cache over a key/value store. */
export class Cache {
  constructor(
    private readonly store: KeyValueStore,
    private readonly prefix: string,
    private readonly ttlMs: number,
  ) {}

  async get<T>(key: string): Promise<T | undefined> {
    const entry = (await this.store.get(this.prefix + key)) as Entry<T> | undefined;
    if (!entry || Date.now() - entry.storedAt > this.ttlMs) {
      return undefined;
    }
    return entry.value;
  }

  set<T>(key: string, value: T): Promise<void> {
    const entry: Entry<T> = { storedAt: Date.now(), value };
    return this.store.set(this.prefix + key, entry);
  }

  async clear(): Promise<void> {
    const keys = (await this.store.keys()).filter((k) => k.startsWith(this.prefix));
    await this.store.remove(keys);
  }
}
