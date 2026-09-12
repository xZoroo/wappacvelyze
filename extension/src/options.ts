import type { Settings } from "./lib/types.ts";
import { SETTINGS_KEY } from "./messages.ts";

const input = document.getElementById("api-key") as HTMLInputElement | null;
const status = document.getElementById("status");

function flash(text: string): void {
  if (status) {
    status.textContent = text;
    setTimeout(() => {
      status.textContent = "";
    }, 2000);
  }
}

async function load(): Promise<void> {
  const items = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = items[SETTINGS_KEY] as Partial<Settings> | undefined;
  if (input) {
    input.value = settings?.nvdApiKey ?? "";
  }
}

document.getElementById("form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const settings: Settings = { nvdApiKey: input?.value.trim() ?? "" };
  void chrome.storage.local.set({ [SETTINGS_KEY]: settings }).then(() => flash("Saved"));
});

document.getElementById("clear-cache")?.addEventListener("click", () => {
  void chrome.storage.local.get(null).then((items) => {
    const keys = Object.keys(items).filter(
      (key) => key.startsWith("nvd:") || key.startsWith("kev:"),
    );
    return chrome.storage.local.remove(keys).then(() => flash(`Cleared ${keys.length} entries`));
  });
});

void load();
