import type { Theme } from "./lib/types.ts";
import { applyTheme, loadSettings, saveSettings } from "./settings.ts";

const apiKey = document.getElementById("api-key") as HTMLInputElement | null;
const theme = document.getElementById("theme") as HTMLSelectElement | null;
const dbUrl = document.getElementById("db-url") as HTMLInputElement | null;
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
  const settings = await loadSettings();
  applyTheme(settings.theme);
  if (apiKey) {
    apiKey.value = settings.nvdApiKey;
  }
  if (theme) {
    theme.value = settings.theme;
  }
  if (dbUrl) {
    dbUrl.value = settings.dbUrl;
  }
}

theme?.addEventListener("change", () => {
  applyTheme(theme.value as Theme);
});

document.getElementById("form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  void saveSettings({
    nvdApiKey: apiKey?.value.trim() ?? "",
    theme: (theme?.value as Theme | undefined) ?? "auto",
    dbUrl: dbUrl?.value.trim() ?? "",
  }).then(() => flash("Saved"));
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
