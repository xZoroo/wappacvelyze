// Popup: renders the background worker's result for the active tab and keeps it live.

import { rank } from "./lib/classify.ts";
import { isSafeLink } from "./lib/evidence.ts";
import type { Assessment, Status, TabResult, Technology, Theme } from "./lib/types.ts";
import { resultKey, type RuntimeMessage } from "./messages.ts";
import { applyTheme, loadSettings, nextTheme, saveSettings } from "./settings.ts";

const LABELS: Record<Status, string> = {
  current: "Current",
  outdated: "Outdated",
  unknown: "Unknown",
  unsupported: "End of life",
  vulnerable: "Vulnerable",
  critical: "Critical · KEV",
};

const SUMMARY_ORDER: Status[] = [
  "critical",
  "vulnerable",
  "unsupported",
  "outdated",
  "unknown",
  "current",
];

const THEME_TITLES: Record<Theme, string> = {
  auto: "Theme: follows system (click for light)",
  light: "Theme: light (click for dark)",
  dark: "Theme: dark (click for system)",
};

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  text = "",
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  if (text) {
    node.textContent = text;
  }
  return node;
}

function link(href: string, text: string): HTMLElement {
  if (!isSafeLink(href)) {
    return element("span", "", text);
  }
  const anchor = element("a", "", text);
  anchor.href = href;
  anchor.target = "_blank";
  anchor.rel = "noopener noreferrer";
  return anchor;
}

/** Reasons common enough that the badge alone explains them; the detail line stays empty. */
const QUIET_REASONS: Record<string, string> = {
  "version not disclosed": "No version",
  "no CPE mapping for this technology": "No CVE data",
  "checking…": "Checking…",
};

function badgeText(assessment: Assessment): string {
  const top = assessment.vulnerabilities?.[0];
  if (assessment.status === "unknown") {
    return QUIET_REASONS[assessment.reason ?? ""] ?? LABELS.unknown;
  }
  if (!top || rank(assessment.status) < rank("vulnerable")) {
    return LABELS[assessment.status];
  }
  return assessment.status === "critical" ? `KEV · ${top.id}` : top.id;
}

function detail(assessment: Assessment): HTMLElement | null {
  const node = element("div", "detail");
  const top = assessment.vulnerabilities?.[0];
  if (assessment.status === "unknown") {
    if ((assessment.reason ?? "") in QUIET_REASONS) {
      return null;
    }
    node.textContent = assessment.reason ?? "";
    return node;
  }
  const lifecycle = assessment.lifecycle;
  if (assessment.status === "outdated" && lifecycle) {
    node.textContent = `${lifecycle.latest ?? "a newer release"} is available in cycle ${lifecycle.cycle}`;
    return node;
  }
  if (assessment.status === "unsupported" && lifecycle) {
    node.textContent = `cycle ${lifecycle.cycle} reached end of life${lifecycle.eol_from ? ` on ${lifecycle.eol_from}` : ""}`;
    return node;
  }
  if (!top) {
    return null;
  }
  const parts: string[] = [];
  if (top.severity) {
    parts.push(`${top.severity} ${top.score ?? ""}`.trim());
  }
  if (top.epss !== undefined) {
    parts.push(`EPSS ${Math.round(top.epss * 100)}%`);
  }
  if (top.exploits?.length) {
    parts.push(`exploit: ${top.exploits.join(", ")}`);
  }
  if (top.affected_range) {
    parts.push(`affects ${top.affected_range}`);
  }
  const more = (assessment.vulnerabilities?.length ?? 1) - 1;
  if (more > 0) {
    parts.push(`+${more} more`);
  }
  node.append(parts.join(" · "), parts.length ? " — " : "");
  node.append(link(top.kev?.url ?? top.url, top.kev ? "CISA KEV" : "NVD"));
  if (top.advisory && top.advisory !== top.url) {
    node.append(" · ", link(top.advisory, "advisory"));
  }
  return node;
}

/** The technology's logo when bundled, otherwise its initial; a broken image falls back too. */
function avatar(technology: Technology): HTMLElement {
  const initial = element("span", "avatar", technology.name.charAt(0).toUpperCase());
  if (!technology.icon) {
    return initial;
  }
  const image = document.createElement("img");
  image.className = "avatar-img";
  image.alt = "";
  image.src = `icons/${encodeURIComponent(technology.icon)}`;
  image.addEventListener("error", () => holder.replaceWith(initial));
  const holder = element("span", "avatar avatar-logo");
  holder.append(image);
  return holder;
}

function row(assessment: Assessment): HTMLElement {
  const { technology } = assessment;
  const node = element("div", "row");
  node.append(avatar(technology));
  const name = element("span", "name");
  name.append(technology.website ? link(technology.website, technology.name) : technology.name);
  if (technology.version) {
    name.append(element("span", "version", technology.version));
  }
  node.append(name);
  const badge = element("span", `badge badge-${assessment.status}`, badgeText(assessment));
  if (assessment.vulnerabilities?.[0]?.kev) {
    badge.title = assessment.vulnerabilities[0].kev.vulnerabilityName;
  }
  node.append(badge);
  const extra = detail(assessment);
  if (extra) {
    node.append(extra);
  }
  return node;
}

function groupByCategory(assessments: Assessment[]): Map<string, Assessment[]> {
  const groups = new Map<string, Assessment[]>();
  for (const assessment of assessments) {
    const category = assessment.technology.categories[0] ?? "Other";
    const group = groups.get(category) ?? [];
    group.push(assessment);
    groups.set(category, group);
  }
  const worst = (list: Assessment[]) => Math.max(...list.map((a) => rank(a.status)));
  return new Map([...groups.entries()].sort(([, a], [, b]) => worst(b) - worst(a)));
}

function renderSummary(assessments: Assessment[]): void {
  const summary = document.getElementById("summary");
  if (!summary) {
    return;
  }
  summary.replaceChildren();
  for (const status of SUMMARY_ORDER) {
    const count = assessments.filter((a) => a.status === status).length;
    if (count > 0) {
      summary.append(element("span", `pill pill-${status}`, `${count} ${LABELS[status]}`));
    }
  }
}

function render(result: TabResult | undefined): void {
  const results = document.getElementById("results");
  const host = document.getElementById("host");
  const state = document.getElementById("state");
  if (!results || !host || !state) {
    return;
  }
  results.replaceChildren();
  if (!result) {
    host.textContent = "No scan yet";
    state.textContent = "";
    renderSummary([]);
    results.append(element("div", "empty", "Reload the page or press Rescan to analyse it."));
    return;
  }
  host.textContent = new URL(result.url).host;
  state.textContent =
    result.phase === "detected"
      ? "Checking CVEs…"
      : `${result.assessments.length} technolog${result.assessments.length === 1 ? "y" : "ies"}`;
  renderSummary(result.assessments);
  if (result.assessments.length === 0) {
    results.append(element("div", "empty", "No technologies detected on this page."));
    return;
  }
  for (const [category, assessments] of groupByCategory(result.assessments)) {
    const section = element("section", "category");
    section.append(element("div", "category-title", category));
    for (const assessment of assessments) {
      section.append(row(assessment));
    }
    results.append(section);
  }
}

function showTheme(theme: Theme): void {
  applyTheme(theme);
  const button = document.getElementById("theme");
  if (!button) {
    return;
  }
  button.title = THEME_TITLES[theme];
  for (const icon of button.querySelectorAll<SVGElement>(".icon")) {
    icon.toggleAttribute("hidden", !icon.classList.contains(`icon-${theme}`));
  }
}

/** The active tab, or the tab named by `?tab=<id>` when opened as a page for debugging. */
async function activeTabId(): Promise<number | undefined> {
  const override = new URLSearchParams(window.location.search).get("tab");
  if (override !== null && /^\d+$/.test(override)) {
    return Number(override);
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id;
}

async function load(tabId: number): Promise<boolean> {
  const items = await chrome.storage.session.get(resultKey(tabId));
  const result = items[resultKey(tabId)] as TabResult | undefined;
  render(result);
  return result !== undefined;
}

async function main(): Promise<void> {
  let { theme } = await loadSettings();
  showTheme(theme);
  document.getElementById("theme")?.addEventListener("click", () => {
    theme = nextTheme(theme);
    showTheme(theme);
    void saveSettings({ theme });
  });
  document.getElementById("settings")?.addEventListener("click", () => {
    void chrome.runtime.openOptionsPage();
  });

  const tabId = await activeTabId();
  if (tabId === undefined) {
    render(undefined);
    return;
  }
  const hasResult = await load(tabId);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && resultKey(tabId) in changes) {
      void load(tabId);
    }
  });
  const rescan = () =>
    void chrome.runtime.sendMessage({ type: "rescan", tabId } satisfies RuntimeMessage);
  document.getElementById("rescan")?.addEventListener("click", rescan);
  // The content script only auto-runs on new page loads, so a tab left open from before
  // install or an update has no data yet; ask the background worker to collect it now
  // instead of leaving the user to find and press Rescan themselves.
  if (!hasResult) {
    rescan();
  }
}

void main();
