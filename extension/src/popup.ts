// Popup: renders the background worker's result for the active tab and keeps it live.

import { rank } from "./lib/classify.ts";
import type { Assessment, Status, TabResult } from "./lib/types.ts";
import { resultKey, type RuntimeMessage } from "./messages.ts";

const LABELS: Record<Status, string> = {
  current: "Current",
  unknown: "Unknown",
  vulnerable: "Vulnerable",
  critical: "Critical · KEV",
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

function link(href: string, text: string): HTMLAnchorElement {
  const anchor = element("a", "", text);
  anchor.href = href;
  anchor.target = "_blank";
  anchor.rel = "noopener noreferrer";
  return anchor;
}

function badgeText(assessment: Assessment): string {
  const top = assessment.vulnerabilities?.[0];
  if (!top || rank(assessment.status) < rank("vulnerable")) {
    return LABELS[assessment.status];
  }
  return assessment.status === "critical" ? `KEV · ${top.id}` : top.id;
}

function detail(assessment: Assessment): HTMLElement | null {
  const node = element("div", "detail");
  const top = assessment.vulnerabilities?.[0];
  if (assessment.status === "unknown") {
    node.textContent = assessment.reason ?? "";
    return node;
  }
  if (!top) {
    return null;
  }
  const parts: string[] = [];
  if (top.severity) {
    parts.push(`${top.severity} ${top.score ?? ""}`.trim());
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

function row(assessment: Assessment): HTMLElement {
  const node = element("div", "row");
  node.append(element("span", `dot dot-${assessment.status}`));
  const name = element("span", "name");
  const { technology } = assessment;
  name.append(technology.website ? link(technology.website, technology.name) : technology.name);
  if (technology.version) {
    name.append(element("span", "version", technology.version));
  }
  node.append(name);
  node.append(element("span", `badge badge-${assessment.status}`, badgeText(assessment)));
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
    (groups.get(category) ?? groups.set(category, []).get(category))?.push(assessment);
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
  for (const status of ["critical", "vulnerable", "unknown", "current"] as const) {
    const count = assessments.filter((a) => a.status === status).length;
    if (count > 0) {
      summary.append(element("span", `pill pill-${status}`, `${count} ${LABELS[status]}`));
    }
  }
}

function render(result: TabResult | undefined): void {
  const results = document.getElementById("results");
  const host = document.getElementById("host");
  if (!results || !host) {
    return;
  }
  results.replaceChildren();
  if (!result) {
    host.textContent = "";
    renderSummary([]);
    results.append(
      element("div", "empty", "No scan for this page yet. Reload it or press Rescan."),
    );
    return;
  }
  host.textContent = new URL(result.url).host;
  renderSummary(result.assessments);
  if (result.assessments.length === 0) {
    results.append(element("div", "empty", "No technologies detected."));
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

/** The active tab, or the tab named by `?tab=<id>` when the popup is opened as a page for debugging. */
async function activeTabId(): Promise<number | undefined> {
  const override = new URLSearchParams(window.location.search).get("tab");
  if (override !== null && /^\d+$/.test(override)) {
    return Number(override);
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id;
}

async function load(tabId: number): Promise<void> {
  const items = await chrome.storage.session.get(resultKey(tabId));
  render(items[resultKey(tabId)] as TabResult | undefined);
}

async function main(): Promise<void> {
  const tabId = await activeTabId();
  if (tabId === undefined) {
    render(undefined);
    return;
  }
  await load(tabId);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && resultKey(tabId) in changes) {
      void load(tabId);
    }
  });
  document.getElementById("rescan")?.addEventListener("click", () => {
    const message: RuntimeMessage = { type: "rescan", tabId };
    void chrome.runtime.sendMessage(message);
  });
  document.getElementById("settings")?.addEventListener("click", () => {
    void chrome.runtime.openOptionsPage();
  });
}

void main();
