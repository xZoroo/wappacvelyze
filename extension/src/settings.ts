import type { Settings, Theme } from "./lib/types.ts";
import { SETTINGS_KEY } from "./messages.ts";

const DEFAULTS: Settings = { nvdApiKey: "", theme: "auto" };
const THEMES: readonly Theme[] = ["auto", "light", "dark"];

export async function loadSettings(): Promise<Settings> {
  const items = await chrome.storage.local.get(SETTINGS_KEY);
  const stored = items[SETTINGS_KEY] as Partial<Settings> | undefined;
  return {
    nvdApiKey: typeof stored?.nvdApiKey === "string" ? stored.nvdApiKey : DEFAULTS.nvdApiKey,
    theme: THEMES.includes(stored?.theme as Theme) ? (stored?.theme as Theme) : DEFAULTS.theme,
  };
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const settings = { ...(await loadSettings()), ...patch };
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
  return settings;
}

/** "auto" follows the OS; an explicit choice is stamped on <html> for the stylesheet. */
export function applyTheme(theme: Theme): void {
  if (theme === "auto") {
    delete document.documentElement.dataset["theme"];
  } else {
    document.documentElement.dataset["theme"] = theme;
  }
}

export function nextTheme(theme: Theme): Theme {
  return THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length] ?? "auto";
}
