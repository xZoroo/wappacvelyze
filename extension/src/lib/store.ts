/** Minimal key/value persistence so the CVE layer can be tested without browser APIs. */
export interface KeyValueStore {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
  remove(keys: string[]): Promise<void>;
  keys(): Promise<string[]>;
}

export class MemoryStore implements KeyValueStore {
  private readonly values = new Map<string, unknown>();

  get(key: string): Promise<unknown> {
    return Promise.resolve(this.values.get(key));
  }

  set(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
    return Promise.resolve();
  }

  remove(keys: string[]): Promise<void> {
    for (const key of keys) {
      this.values.delete(key);
    }
    return Promise.resolve();
  }

  keys(): Promise<string[]> {
    return Promise.resolve([...this.values.keys()]);
  }
}

/** Wraps one chrome.storage area (local or session). */
export class ChromeStore implements KeyValueStore {
  constructor(private readonly area: chrome.storage.StorageArea) {}

  async get(key: string): Promise<unknown> {
    const items = await this.area.get(key);
    return items[key];
  }

  set(key: string, value: unknown): Promise<void> {
    return this.area.set({ [key]: value });
  }

  remove(keys: string[]): Promise<void> {
    return this.area.remove(keys);
  }

  async keys(): Promise<string[]> {
    return Object.keys(await this.area.get(null));
  }
}
