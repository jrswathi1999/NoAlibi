// No Alibi UI. Vanilla JS, no dependencies, works offline.
// Everything rendered from data goes through textContent (h()), never innerHTML:
// domains, SNI names and policy quotes are attacker-controlled strings.

const $ = (sel, root = document) => root.querySelector(sel);
const main = $("#main");

// ------------------------------------------------------------------ helpers

function h(tag, attrs = {}, ...children) {
  const svgTags = new Set(["svg", "g", "circle", "line", "path", "text", "rect", "use", "title", "tspan"]);
  const el = svgTags.has(tag)
    ? document.createElementNS("http://www.w3.org/2000/svg", tag)
    : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.setAttribute("class", v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const icon = (id, cls = "") => {
  const s = h("svg", { class: cls, "aria-hidden": "true" });
  s.append(h("use", { href: `#i-${id}` }));
  return s;
};

function fmtBytes(n) {
  if (n == null) return "–";
  if (n < 1000) return `${n} B`;
  if (n < 1e6) return `${(n / 1000).toFixed(n < 10000 ? 1 : 0)} KB`;
  return `${(n / 1e6).toFixed(1)} MB`;
}
const fmtSecs = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
const fmtDate = (t) => new Date(t * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
const human = (s) => (s || "").replaceAll("_", " ");

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* not json */ }
    throw new Error(detail);
  }
  return res.json();
}

function toast(title, body = "", kind = "") {
  const el = h("div", { class: `toast ${kind}`, role: kind === "err" ? "alert" : "status" }, h("b", {}, title), body);
  $("#toasts").append(el);
  setTimeout(() => el.remove(), kind === "err" ? 9000 : 4500);
}
const announce = (text) => { $("#announcer").textContent = text; };

function confirmDialog(title, body, okLabel = "Continue", danger = false) {
  const dlg = $("#confirm");
  $("#confirm-title").textContent = title;
  $("#confirm-body").textContent = body;
  const ok = $("#confirm-ok");
  ok.textContent = okLabel;
  ok.className = `btn ${danger ? "danger" : "primary"}`;
  dlg.returnValue = "";
  dlg.showModal();
  return new Promise((resolve) => dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true }));
}

const reduceMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ------------------------------------------------------------------ categories

// Plain-language meaning of each kind of destination. `status` decides how it's presented:
// normal (expected for almost any app), notable (worth knowing), attention (check the promise).
const CATS = {
  ai_provider: { label: "AI company", color: "var(--c-ai)", status: "attention", what: "Receives whatever the app sends to its AI feature." },
  analytics: { label: "Usage analytics", color: "var(--c-analytics)", status: "notable", what: "Records how you use the app: screens, clicks, features." },
  tracker: { label: "Advertising & tracking", color: "var(--c-tracker)", status: "attention", what: "Builds a profile of you across apps and websites." },
  error_reporting: { label: "Crash & error reports", color: "var(--c-error)", status: "notable", what: "Gets a report when something breaks; can include details about your device." },
  first_party: { label: "The app's own servers", color: "var(--c-first)", status: "normal", what: "The app maker's own service. Normal." },
  update: { label: "Update checks", color: "var(--c-update)", status: "normal", what: "Checks for a newer version. Normal." },
  cdn: { label: "Content delivery & cloud hosting", color: "var(--c-cdn)", status: "normal", what: "Delivers files, images and pages for many companies. Normal for almost every app." },
  platform: { label: "macOS services", color: "var(--c-platform)", status: "normal", what: "Apple system services the app relies on. Normal." },
  unknown: { label: "Unidentified servers", color: "var(--c-unknown)", status: "normal", what: "We couldn't tell who these belong to (usually cloud hosting). Never flagged." },
  identifying: { label: "Identifying…", color: "var(--c-unknown)", status: "normal", what: "" },
};
const cat = (k) => CATS[k] || CATS.unknown;
const STATUS = {
  attention: { label: "Check this", cls: "st-attention" },
  notable: { label: "Worth knowing", cls: "st-notable" },
  normal: { label: "Normal", cls: "st-normal" },
};
const CONF_LABEL = { confirmed: "verified", likely: "probable", possible: "unsure", weak: "unsure", unknown: "unknown" };
const CONF_TEXT = {
  confirmed: "Verified: the address and the server's own name tag (certificate) agree.",
  likely: "Probable: matched by address or by the server's name tag.",
  possible: "Unsure: this address is shared by many companies, so we can't be certain.",
  weak: "Unsure: only a rough reverse lookup.",
  unknown: "We couldn't find a name.",
};

const RULE_WHY = {
  R1_undisclosed_ai_provider: "The privacy policy never says this AI company gets your data, but the app sent it data.",
  R2_local_promise_broken: "The policy says your data stays on your device, but data went to another company right after you used the app.",
  R3_background_telemetry: "While you weren't using the app, it checked in with this company on a regular schedule, which is typical of background tracking.",
  R4_content_upload_suspicion: "Right after you used the feature, the app sent a chunk of data big enough to include what you typed. (We can't see inside it.)",
  R5_silent_on_training: "The app uses an AI company, but the policy doesn't clearly say whether your data is used to train AI.",
  R6_unknown_recipient: "We couldn't confirm who this is.",
};
const CLAIM_Q = {
  data_stays_local: "Keeps your data on your device",
  names_ai_provider: "Names the AI company it uses",
  trains_on_user_data: "Uses your data to train AI",
  retention_stated: "Says how long it keeps data",
  ai_opt_out: "Lets you opt out of AI",
  shares_with_third_parties: "Shares data with other companies",
};
// Which answer is good news for the user (drives the icon colour, not the literal yes/no).
const GOOD_ANSWER = {
  data_stays_local: "yes",
  names_ai_provider: "yes",
  trains_on_user_data: "no",
  retention_stated: "yes",
  ai_opt_out: "yes",
  shares_with_third_parties: "no",
};
const VERDICT = {
  NO_ALIBI: { word: "No alibi", icon: "x", line: "It broke a promise in its privacy policy." },
  QUESTIONABLE: { word: "Worth a look", icon: "alert", line: "No broken promise, but something you may want to know." },
  ALIBI_HOLDS: { word: "Alibi holds", icon: "check", line: "It kept its promises during this check." },
};

const sevBadge = (sev) =>
  h("span", { class: `sev ${sev}` }, icon(sev === "red" ? "x" : sev === "amber" ? "alert" : "info"),
    sev === "red" ? "Broken promise" : sev === "amber" ? "Worth knowing" : "Background");

function appIcon(app, size = "") {
  const name = (app && app.name) || "?";
  if (app && app.icon) {
    const img = h("img", { src: app.icon, alt: "", width: 56, height: 56, class: size, decoding: "async" });
    img.addEventListener("error", () => img.replaceWith(h("div", { class: `ph ${size}`, "aria-hidden": "true" }, name[0])));
    return img;
  }
  return h("div", { class: `ph ${size}`, "aria-hidden": "true" }, name[0]);
}

// ------------------------------------------------------------------ global state

const state = { health: null, apps: null, selected: null, es: null };

async function refreshHealth() {
  try {
    state.health = await api("/api/health");
  } catch {
    state.health = null;
  }
  const sys = $("#sys");
  sys.replaceChildren();
  const hl = state.health;
  if (!hl) {
    sys.append(h("span", { class: "chip bad" }, h("span", { class: "dot" }), "Server offline"));
    return;
  }
  sys.append(
    h("span", { class: `chip ${hl.nettop ? "ok" : "bad"}`, title: "Per-process socket counters, no root needed" },
      h("span", { class: "dot" }), hl.nettop ? "Sensor ready" : "Sensor unavailable"),
    h("span", { class: `chip ${hl.ollama.ok ? "ok" : "warn"}`, title: "The privacy policy is read by this local model" },
      h("span", { class: "dot" }), hl.ollama.ok ? `Local AI: ${hl.ollama.model}` : "Local AI offline"),
    h("span", { class: `chip ${hl.search ? "ok" : ""}`, title: "Optional: look up unknown domains by name only" },
      h("span", { class: "dot" }), hl.search ? "Domain lookup on" : "Domain lookup off"),
  );
}

// ------------------------------------------------------------------ theme + keys

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("#theme").replaceChildren(icon(t === "light" ? "moon" : "sun"));
  try { localStorage.setItem("na-theme", t); } catch { /* private mode */ }
}
function initTheme() {
  let t = null;
  try { t = localStorage.getItem("na-theme"); } catch { /* ignore */ }
  if (!t) t = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  applyTheme(t);
  $("#theme").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light"));
}

const keyHandlers = new Map();
document.addEventListener("keydown", (e) => {
  const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
  if (document.querySelector("dialog[open]")) return;
  if (e.key === "?" && !typing) { e.preventDefault(); $("#help").showModal(); return; }
  if ((e.key === "t" || e.key === "T") && !typing && !e.metaKey && !e.ctrlKey) {
    applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
    return;
  }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  const fn = keyHandlers.get(e.key.toLowerCase()) || keyHandlers.get(e.code);
  if (fn) { e.preventDefault(); fn(); }
});
$("#help-btn").addEventListener("click", () => $("#help").showModal());

// ------------------------------------------------------------------ router

function setNav(name) {
  document.querySelectorAll("[data-nav]").forEach((a) => {
    if (a.dataset.nav === name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}

async function route() {
  keyHandlers.clear();
  if (state.es) { state.es.close(); state.es = null; }
  window.onresize = null;
  const [, view, id, tab] = (location.hash || "#/").split("/");
  main.replaceChildren();
  try {
    if (view === "audit" && id) { setNav(""); await renderLive(id); }
    else if (view === "case" && id) { setNav("runs"); await renderVerdict(id, tab); }
    else if (view === "runs") { setNav("runs"); await renderRuns(); }
    else { setNav("home"); await renderHome(); }
  } catch (err) {
    main.append(h("div", { class: "empty" }, h("b", {}, "Something went wrong. "), err.message, " ", h("a", { href: "#/" }, "Go back home")));
  }
  const h1 = main.querySelector("h1");
  if (h1) { h1.setAttribute("tabindex", "-1"); h1.focus({ preventScroll: true }); }
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", route);

// ------------------------------------------------------------------ home

async function renderHome() {
  main.append(
    h("section", { class: "hero" },
      h("div", {},
        h("h1", {}, "Apps make promises.", h("br"), h("em", {}, "Check their alibi.")),
        h("p", { class: "lede" },
          "No Alibi reads an app's privacy policy with a local AI, watches every connection the app makes, and shows you exactly where the two disagree. No root, no decryption, nothing about you leaves this Mac."),
      ),
      h("ol", { class: "steps" },
        h("li", {}, icon("doc"), h("div", {}, h("b", {}, "1 · Read the promise"), h("span", {}, "A local model pulls six promises from the policy, each with a quote we verify word for word."))),
        h("li", {}, icon("eye"), h("div", {}, h("b", {}, "2 · Watch the behavior"), h("span", {}, "Every connection of every process inside the app, attributed by the kernel's own counters."))),
        h("li", {}, icon("scale"), h("div", {}, h("b", {}, "3 · Deliver the verdict"), h("span", {}, "Broken promises linked to the exact network evidence, sealed with SHA-256."))),
      ),
    ),
  );

  const search = h("input", { type: "search", id: "app-search", placeholder: "Search installed apps", "aria-label": "Search installed apps", autocomplete: "off" });
  const grid = h("div", { class: "app-grid", role: "list", "aria-label": "Installed apps" });
  const setupSlot = h("div");
  main.append(
    h("div", { class: "section-head" }, h("h2", {}, "Pick an app to put on trial"), h("div", { class: "search" }, search, h("kbd", {}, "/"))),
    grid, setupSlot,
  );
  keyHandlers.set("/", () => search.focus());

  const recentSlot = h("div");
  main.append(h("div", { class: "section-head" }, h("h2", {}, "Recent case files")), recentSlot);

  grid.append(h("div", { class: "empty" }, "Looking for installed apps…"));
  try {
    state.apps = state.apps || (await api("/api/apps"));
  } catch (err) {
    grid.replaceChildren(h("div", { class: "empty" }, `Could not list apps: ${err.message}`));
    return;
  }
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const apps = state.apps.filter((a) => a.name.toLowerCase().includes(q));
    // Apps whose policy we know and that are running come first: most useful choices.
    apps.sort((a, b) => (b.running - a.running) || (!!b.policy_url - !!a.policy_url) || a.name.localeCompare(b.name));
    grid.replaceChildren(...apps.map((a) => {
      const tile = h("button", { class: "app-tile", type: "button", role: "listitem", "aria-pressed": state.selected?.bundle_id === a.bundle_id ? "true" : "false" },
        appIcon(a),
        h("span", { class: "name" }, a.name),
        h("span", { class: "meta" }, a.version ? `v${a.version}` : a.bundle_id),
        h("span", { class: "badges" },
          a.running ? h("span", { class: "tag live" }, "Running") : null,
          a.policy_url ? h("span", { class: "tag policy" }, "Policy known") : null),
      );
      tile.addEventListener("click", () => {
        // Toggle selection in place: re-sorting the grid under the pointer would be disorienting.
        state.selected = a;
        grid.querySelectorAll(".app-tile").forEach((t) => t.setAttribute("aria-pressed", t === tile ? "true" : "false"));
        renderSetup(setupSlot, a);
      });
      return tile;
    }));
    if (!apps.length) grid.append(h("div", { class: "empty" }, "No app matches that search."));
  };
  search.addEventListener("input", draw);
  draw();
  if (state.selected) renderSetup(setupSlot, state.selected);

  api("/api/runs").then((runs) => recentSlot.append(runList(runs.slice(0, 5)))).catch(() => {});
}

function renderSetup(slot, app) {
  const url = h("input", { type: "url", id: "policy-url", value: app.policy_url || "", placeholder: "https://example.com/privacy", required: true, "aria-describedby": "policy-hint" });
  const hint = h("div", { class: "hint", id: "policy-hint" },
    app.policy_url ? "We already know where this app's policy lives. Change it if you want a different one." : "Paste the public privacy policy URL. Only this page is downloaded.");
  const noRestart = app.bundle_id === "com.electron.ollama" || app.hosts_self;
  const fresh = h("input", { type: "checkbox", checked: !noRestart, disabled: !!app.hosts_self });
  const cert = h("input", { type: "checkbox", checked: true });
  const start = h("button", { class: "btn primary big", type: "submit" }, icon("eye"), "Start audit");
  const ollamaSelf = app.bundle_id === "com.electron.ollama";

  const form = h("form", { class: "setup", "aria-labelledby": "setup-title", novalidate: true },
    appIcon(app),
    h("div", {},
      h("h2", { id: "setup-title" }, `Audit ${app.name}`),
      h("div", { class: "muted" }, `${app.bundle_id}${app.version ? ` · version ${app.version}` : ""}`),
      h("div", { class: "field" }, h("label", { for: "policy-url" }, "Privacy policy"), url, hint),
      h("div", { class: "toggles" },
        h("label", { class: "toggle" }, fresh, h("div", {}, h("b", {}, "Restart the app first (recommended)"),
          h("span", {}, app.hosts_self
            ? `Not possible: No Alibi itself is running inside ${app.name}, so closing it would stop the check.`
            : ollamaSelf
              ? "Off for Ollama: restarting it would also stop the local AI that reads the policy."
              : `We close ${app.name} and open it again, so we also see what it does the moment it starts. Save your work in it first.`))),
        h("label", { class: "toggle" }, cert, h("div", {}, h("b", {}, "Find out which company each server belongs to (recommended)"),
          h("span", {}, "We read the public name tag (certificate) of servers the app contacts. Nothing of yours is sent."))),
      ),
      h("div", { class: "setup-actions" },
        start,
        h("button", { class: "btn ghost", type: "button", onclick: () => { state.selected = null; slot.replaceChildren(); document.querySelectorAll(".app-tile[aria-pressed=true]").forEach((t) => t.setAttribute("aria-pressed", "false")); } }, "Cancel"),
        h("span", { class: "hint" }, "Next: use the app normally and try its AI feature once. Takes about a minute."),
      ),
    ),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    let ok = true;
    try { new URL(url.value); } catch { ok = false; }
    if (!ok || !/^https?:/.test(url.value)) {
      url.setAttribute("aria-invalid", "true");
      hint.className = "hint err";
      hint.textContent = "That isn't a web address. It should start with https://";
      url.focus();
      return;
    }
    url.removeAttribute("aria-invalid");
    if (fresh.checked && app.running) {
      const go = await confirmDialog(`Close and reopen ${app.name}?`, `${app.name} is open. No Alibi will close it and open it again so it can watch from the very start. Save any unsaved work in ${app.name} first.`, `Close and reopen`);
      if (!go) return;
    }
    start.disabled = true;
    start.replaceChildren(h("span", { class: "spinner" }), "Starting…");
    try {
      const res = await api("/api/audits", { method: "POST", body: { bundle_id: app.bundle_id, policy_url: url.value, fresh_launch: fresh.checked, cert_probe: cert.checked } });
      sessionStorage.setItem(`na-app-${res.run_id}`, JSON.stringify(app));
      location.hash = `#/audit/${res.run_id}`;
    } catch (err) {
      toast("Couldn't start the audit", err.message, "err");
      start.disabled = false;
      start.replaceChildren(icon("eye"), "Start audit");
    }
  });
  slot.replaceChildren(form);
  requestAnimationFrame(() => form.scrollIntoView({ behavior: reduceMotion() ? "auto" : "smooth", block: "center" }));
  url.focus({ preventScroll: true });
}

function runList(runs) {
  if (!runs.length) return h("div", { class: "empty" }, "No case files yet. Your first verdict will appear here.");
  return h("div", { class: "runs-list" }, runs.map((r) => {
    const v = VERDICT[r.verdict] || VERDICT.QUESTIONABLE;
    const app = (state.apps || []).find((a) => a.bundle_id === r.app?.bundle_id) || { name: r.app?.name };
    return h("a", { class: "run-row", href: `#/case/${r.run_id}` },
      appIcon(app),
      h("div", { style: { minWidth: 0 } }, h("b", {}, r.app?.name || r.run_id), h("div", { class: "line" }, r.one_liner)),
      h("span", { class: "muted", style: { fontSize: "13px" } }, r.started_at ? fmtDate(r.started_at) : ""),
      h("span", { class: `verdict-pill v-${r.verdict}` }, icon(v.icon), v.word),
    );
  }));
}

async function renderRuns() {
  main.append(h("h1", { style: { fontFamily: "var(--serif)", fontSize: "34px", margin: "6px 0 18px" } }, "Case files"));
  const runs = await api("/api/runs");
  state.apps = state.apps || (await api("/api/apps").catch(() => []));
  main.append(h("p", { class: "muted" }, "Every audit stays on this Mac. Delete any of them from its case page."), runList(runs));
}

// ------------------------------------------------------------------ live audit

const SECTORS = [
  { cats: ["ai_provider"], label: "AI providers", a0: -135, a1: -45 },
  { cats: ["analytics", "tracker"], label: "Analytics & trackers", a0: -45, a1: 30 },
  { cats: ["error_reporting"], label: "Crash reporting", a0: 30, a1: 75 },
  { cats: ["first_party", "update"], label: "App's own servers", a0: 75, a1: 135 },
  { cats: ["cdn", "platform", "unknown", "identifying"], label: "CDN · OS · unknown", a0: 135, a1: 225 },
];
const VB = { w: 1000, h: 800, cx: 500, cy: 400, r: 330 };
const rad = (d) => (d * Math.PI) / 180;

class Constellation {
  constructor(appName) {
    this.nodes = new Map(); // key -> {key, domain, owner, category, confidence, out, in, el, x, y}
    this.svg = h("svg", { class: "constellation", viewBox: `0 0 ${VB.w} ${VB.h}`, role: "img", "aria-label": `Live map of ${appName}'s connections` });
    for (const f of [0.55, 0.78, 1]) this.svg.append(h("circle", { class: "ring", cx: VB.cx, cy: VB.cy, r: VB.r * f }));
    for (const s of SECTORS) {
      const a = rad((s.a0 + s.a1) / 2);
      this.svg.append(h("text", { class: "sector-label", x: VB.cx + Math.cos(a) * (VB.r + 42), y: VB.cy + Math.sin(a) * (VB.r + 30), "text-anchor": "middle" }, s.label));
    }
    this.edges = h("g");
    this.packets = h("g");
    this.layer = h("g");
    this.svg.append(this.edges, this.packets, this.layer);
    const center = h("g", { class: "center" },
      h("circle", { cx: VB.cx, cy: VB.cy, r: 46 }),
      h("text", { x: VB.cx, y: VB.cy + 5, "text-anchor": "middle" }, appName.length > 12 ? `${appName.slice(0, 11)}…` : appName));
    this.svg.append(center);
  }

  sectorOf(category) {
    return SECTORS.find((s) => s.cats.includes(category)) || SECTORS[SECTORS.length - 1];
  }

  upsert(flow) {
    const key = flow.domain || flow.ip;
    let n = this.nodes.get(key);
    if (!n) {
      n = { key, flows: new Map(), order: this.nodes.size };
      this.nodes.set(key, n);
      n.edge = h("line", { class: "edge", x1: VB.cx, y1: VB.cy, x2: VB.cx, y2: VB.cy });
      n.halo = h("circle", { class: "halo", r: 10 });
      n.dot = h("circle", { r: 7 });
      n.label = h("text", { "text-anchor": "middle" });
      n.sub = h("text", { class: "sub", "text-anchor": "middle" });
      n.title = h("title");
      n.el = h("g", { class: "node" }, n.title, n.halo, n.dot, n.label, n.sub);
      this.edges.append(n.edge);
      this.layer.append(n.el);
    }
    n.flows.set(flow.id, flow);
    n.domain = flow.domain;
    n.owner = flow.owner;
    n.category = flow.category;
    n.confidence = flow.confidence;
    n.out = [...n.flows.values()].reduce((s, f) => s + (f.bytes_out || 0), 0);
    n.in = [...n.flows.values()].reduce((s, f) => s + (f.bytes_in || 0), 0);
    this.layout();
    return n;
  }

  layout() {
    const bySector = new Map(SECTORS.map((s) => [s, []]));
    for (const n of this.nodes.values()) bySector.get(this.sectorOf(n.category)).push(n);
    for (const [s, list] of bySector) {
      // Stable order (first seen) so nodes don't jump around; size shows importance.
      list.sort((a, b) => a.order - b.order);
      const topKeys = new Set([...list].sort((a, b) => b.out - a.out).slice(0, 4).map((n) => n.key));
      list.forEach((n, i) => {
        const a = rad(s.a0 + ((i + 1) * (s.a1 - s.a0)) / (list.length + 1));
        const rf = [0.6, 0.92, 0.76, 0.48, 0.84][i % 5];
        const showLabel = topKeys.has(n.key) || list.length <= 6;
        n.label.style.display = showLabel ? "" : "none";
        n.sub.style.display = showLabel ? "" : "none";
        n.x = VB.cx + Math.cos(a) * VB.r * rf;
        n.y = VB.cy + Math.sin(a) * VB.r * rf;
        const c = cat(n.category).color;
        const r = 6 + Math.min(16, 3.2 * Math.log10(1 + n.out / 50));
        n.el.style.setProperty("--edge-color", c);
        n.edge.style.setProperty("--edge-color", c);
        n.el.setAttribute("class", `node ${["possible", "weak", "unknown"].includes(n.confidence) ? "weak" : ""}`);
        for (const [el, attrs] of [[n.dot, { cx: n.x, cy: n.y, r, fill: c }], [n.halo, { cx: n.x, cy: n.y, r: r + 2, style: `transform-origin:${n.x}px ${n.y}px` }],
          [n.label, { x: n.x, y: n.y - r - 8 }], [n.sub, { x: n.x, y: n.y + r + 15 }], [n.edge, { x2: n.x, y2: n.y, "stroke-width": 1 + Math.min(5, Math.log10(1 + n.out / 200)) }]]) {
          for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
        }
        const name = n.domain || n.key;
        n.label.textContent = name.length > 26 ? `…${name.slice(-25)}` : name;
        n.sub.textContent = `${n.owner ? `${n.owner} · ` : ""}↑${fmtBytes(n.out)}`;
        n.title.textContent = `${name}\n${cat(n.category).label}${n.owner ? ` · ${n.owner}` : ""}\nSent ${fmtBytes(n.out)}, received ${fmtBytes(n.in)}\n${CONF_TEXT[n.confidence] || ""}`;
      });
    }
  }

  pulse(n, bytes) {
    n.edge.classList.add("hot");
    clearTimeout(n.hotTimer);
    n.hotTimer = setTimeout(() => n.edge.classList.remove("hot"), 1200);
    if (reduceMotion()) return;
    n.halo.classList.remove("ping");
    void n.halo.getBBox();
    n.halo.classList.add("ping");
    const p = h("circle", { class: "packet", r: Math.min(7, 2.5 + Math.log10(1 + bytes / 100)), cx: 0, cy: 0 });
    p.style.setProperty("--edge-color", cat(n.category).color);
    this.packets.append(p);
    p.animate([{ transform: `translate(${VB.cx}px, ${VB.cy}px)` }, { transform: `translate(${n.x}px, ${n.y}px)` }], { duration: 750, easing: "cubic-bezier(.3,.6,.4,1)" }).onfinish = () => p.remove();
  }
}

async function renderLive(runId) {
  let app = null;
  try { app = JSON.parse(sessionStorage.getItem(`na-app-${runId}`) || "null"); } catch { /* ignore */ }
  app = app || { name: runId.split("-").slice(2).join("-") };

  const rec = h("span", { class: "rec" }, "0:00");
  const steps = ["App starting", "Watching", "You use the AI", "Verdict"].map((s) => h("li", {}, s));
  const stepper = h("ol", { class: "stepper", "aria-label": "Audit progress" }, steps);
  main.append(h("div", { class: "live-head" }, appIcon(app), h("div", {}, h("h1", {}, `Watching ${app.name}`), h("div", { class: "muted", style: { fontSize: "13px" } }, "Record only: nothing is blocked, decrypted or changed.")), rec, stepper));

  const con = new Constellation(app.name);
  const idleHint = h("div", { class: "idle-hint" }, "Each service the app contacts appears here the moment it happens. Silence is good news.");
  const legend = h("div", { class: "legend", "aria-hidden": "true" }, Object.entries(CATS).filter(([k]) => k !== "identifying").map(([, c]) => h("span", {}, h("i", { style: { background: c.color } }), c.label)));
  const stat = (k, cls = "") => { const v = h("div", { class: "v" }, "0"); return [h("div", { class: `stat ${cls}` }, h("div", { class: "k" }, k), v), v]; };
  const [sUp, vUp] = stat("Sent");
  const [sDown, vDown] = stat("Received");
  const [sDest, vDest] = stat("Services contacted");
  const [sSelf, vSelf] = stat("Your data sent by No Alibi", "self");
  const feed = h("ul", { class: "feed", "aria-label": "Destinations, most recent first" });
  const feedCount = h("span", { class: "count" }, "0");
  const policyStatus = h("div", { class: "policy-status" }, h("span", { class: "spinner" }), h("span", {}, "Starting…"));
  const claimsBox = h("div", { class: "claims-live", "aria-live": "polite" });

  main.append(h("div", { class: "live-grid" },
    h("section", { class: "panel", "aria-labelledby": "map-h" },
      h("h2", { id: "map-h" }, icon("eye"), "Live map: every service the app contacts"),
      h("div", { class: "constellation-wrap" }, con.svg, idleHint), legend),
    h("div", { style: { display: "grid", gap: "16px", alignContent: "start" } },
      h("section", { class: "panel" }, h("div", { class: "totals" }, sUp, sDown, sDest, sSelf),
        h("h2", {}, "Who it's talking to", feedCount), feed),
      h("section", { class: "panel", "aria-labelledby": "pol-h" }, h("h2", { id: "pol-h" }, icon("doc"), "What the privacy policy promises"), policyStatus, claimsBox),
    ),
  ));

  const markBtn = h("button", { class: "btn primary big mark-btn", type: "button" }, icon("hand"), "I just used the AI feature", h("kbd", { style: { marginLeft: "6px" } }, "M"), h("span", { class: "window" }));
  const stopBtn = h("button", { class: "btn big", type: "button" }, icon("stop"), "Stop & deliver verdict", h("kbd", { style: { marginLeft: "6px" } }, "S"));
  const msg = h("div", { class: "msg", role: "status" }, "Use the app normally. When you try its AI feature, press ", h("b", {}, "I just used the AI feature"), " so we can line up what it sends with what you did.");
  main.append(h("div", { class: "actionbar" }, markBtn, stopBtn, msg));

  // ---- live state
  const flows = new Map();
  let lastSeq = -1;
  let rel = 0;
  let fresh = true;
  let started = false;
  let markWindow = null; // {until, baseline: Map(flowId -> bytes_out), label}
  let judging = false;
  const setStep = (i) => steps.forEach((s, j) => { s.className = j < i ? "done" : j === i ? "now" : ""; s.toggleAttribute("aria-current", j === i); });
  setStep(0);
  const timer = setInterval(() => { if (started && !judging) { rel += 1; rec.textContent = fmtSecs(rel); } }, 1000);
  const cleanup = () => clearInterval(timer);
  window.addEventListener("hashchange", cleanup, { once: true });

  const drawFeed = () => {
    const nodes = [...con.nodes.values()].sort((a, b) => (b.last || 0) - (a.last || 0) || b.out - a.out).slice(0, 60);
    feedCount.textContent = String(con.nodes.size);
    vDest.textContent = String(con.nodes.size);
    feed.replaceChildren(...nodes.map((n) => {
      const li = h("li", { class: n.flash ? "flash" : "", style: { "--edge-color": cat(n.category).color } },
        h("span", { class: "cat-dot", style: { background: cat(n.category).color }, title: cat(n.category).label }),
        h("div", { style: { minWidth: 0 } },
          h("div", { class: "who" }, n.owner && !["cdn", "unknown"].includes(n.category) ? n.owner : cat(n.category).label,
            n.confidence && n.category !== "identifying" ? h("span", { class: `conf conf-${n.confidence}`, title: CONF_TEXT[n.confidence] }, CONF_LABEL[n.confidence]) : null),
          h("div", { class: "own" }, `${cat(n.category).status === "normal" ? "Normal · " : ""}${n.domain || n.key}`)),
        h("div", { class: "bytes" }, h("b", {}, `↑${fmtBytes(n.out)}`), h("br"), `↓${fmtBytes(n.in)}`));
      return li;
    }));
    con.nodes.forEach((n) => { n.flash = false; });
  };

  const onFlow = (f, active = false, tickT = 0) => {
    const prev = flows.get(f.id);
    flows.set(f.id, f);
    const wasNew = !con.nodes.has(f.domain || f.ip);
    const n = con.upsert(f);
    idleHint.hidden = true;
    if (active) {
      const delta = (f.bytes_out || 0) - (prev?.bytes_out || 0);
      n.last = tickT;
      n.flash = true;
      if (delta > 0 || !prev) con.pulse(n, Math.max(delta, 200));
    }
    if (wasNew && f.category !== "identifying") announce(`New destination: ${f.domain || f.ip}, ${cat(f.category).label}`);
  };

  const finishMark = () => {
    if (!markWindow) return;
    const caught = new Map();
    for (const f of flows.values()) {
      const base = markWindow.baseline.get(f.id) ?? 0;
      const d = (f.bytes_out || 0) - base;
      if (d > 0) {
        const key = f.domain || f.ip;
        const c = caught.get(key) || { key, owner: f.owner, category: f.category, bytes: 0 };
        c.bytes += d;
        caught.set(key, c);
      }
    }
    const top = [...caught.values()].sort((a, b) => b.bytes - a.bytes);
    markBtn.classList.remove("armed");
    if (!top.length) {
      msg.replaceChildren("Nothing left the app in the 5 seconds after your action. Try the feature again, or press ", h("b", {}, "Stop"), " when you're done.");
    } else {
      const t = top[0];
      msg.replaceChildren(h("b", {}, `Caught: ${fmtBytes(t.bytes)} → ${t.key}`), ` (${t.owner || cat(t.category).label}) within 5 s of your action`, top.length > 1 ? `, plus ${top.length - 1} other destination${top.length > 2 ? "s" : ""}.` : ".");
      announce(`After your action, ${fmtBytes(t.bytes)} went to ${t.key}`);
    }
    markWindow = null;
    setStep(1);
  };

  const doMark = async () => {
    if (!started || judging) return;
    try {
      await api(`/api/audits/${runId}/mark`, { method: "POST", body: { label: "used the AI feature" } });
    } catch (err) { toast("Couldn't mark the action", err.message, "err"); return; }
    markWindow = { until: Date.now() + 6000, baseline: new Map([...flows.values()].map((f) => [f.id, f.bytes_out || 0])) };
    markBtn.classList.remove("armed"); void markBtn.offsetWidth; markBtn.classList.add("armed");
    setStep(2);
    msg.replaceChildren(h("span", { class: "spinner" }), " Watching closely for the next 5 seconds…");
    setTimeout(finishMark, 6000);
  };

  const judgeView = h("div");
  const doStop = async () => {
    if (judging) return;
    judging = true;
    markBtn.disabled = true;
    stopBtn.disabled = true;
    rec.className = "rec off";
    setStep(3);
    msg.replaceChildren(h("span", { class: "spinner" }), " Stopping the capture…");
    try {
      await api(`/api/audits/${runId}/stop`, { method: "POST" });
    } catch (err) {
      toast("Couldn't stop", err.message, "err");
      judging = false; markBtn.disabled = false; stopBtn.disabled = false;
    }
  };
  markBtn.addEventListener("click", doMark);
  stopBtn.addEventListener("click", doStop);
  keyHandlers.set("m", doMark);
  keyHandlers.set("Space", doMark);
  keyHandlers.set("s", doStop);

  const handle = (m) => {
    if (m.seq <= lastSeq) return;
    lastSeq = m.seq;
    switch (m.type) {
      case "status":
        if (!judging) policyStatus.dataset.capture = m.text;
        if (judging || m.step === "evidence") msg.replaceChildren(h("span", { class: "spinner" }), ` ${m.text}…`);
        else if (!started) msg.replaceChildren(h("span", { class: "spinner" }), ` ${m.text}…`);
        break;
      case "started":
        started = true;
        fresh = m.fresh;
        setStep(fresh ? 0 : 1);
        if (!fresh) steps[0].className = "done";
        msg.replaceChildren("Use the app normally. When you try its AI feature, press ", h("b", {}, "I just used the AI feature"), ".");
        setTimeout(() => { if (!markWindow && !judging) setStep(1); }, fresh ? 10000 : 0);
        break;
      case "tick": {
        rel = Math.max(rel, Math.floor(m.rel || 0));
        if (started && !judging) rec.textContent = fmtSecs(rel);
        vUp.textContent = fmtBytes(m.total_up);
        vDown.textContent = fmtBytes(m.total_down);
        vSelf.textContent = "0 B";
        for (const f of m.active || []) onFlow(f, true, m.t);
        drawFeed();
        break;
      }
      case "flow":
        onFlow(m.flow);
        drawFeed();
        break;
      case "mark":
        break;
      case "policy":
        policyStatus.replaceChildren(m.done ? icon("check") : h("span", { class: "spinner" }), h("span", {}, m.text));
        break;
      case "policy_error":
        policyStatus.replaceChildren(icon("alert"), h("span", {}, `Couldn't read the policy: ${m.text}. The audit continues; the verdict will only use the network evidence.`));
        break;
      case "claim": {
        const c = m.claim;
        claimsBox.append(h("div", { class: "claim-mini" },
          h("div", { class: "t" }, CLAIM_Q[c.type] || human(c.type), h("span", { class: `tag ${c.value === "yes" ? "live" : c.value === "no" ? "" : "policy"}` }, c.value)),
          h("q", {}, c.quote.length > 220 ? `${c.quote.slice(0, 217)}…` : c.quote)));
        break;
      }
      case "stopped":
        msg.replaceChildren(h("span", { class: "spinner" }), " Capture stopped. Building the verdict…");
        break;
      case "done":
        cleanup();
        if (state.es) state.es.close();
        announce(`Verdict: ${(VERDICT[m.verdict] || {}).word}`);
        location.hash = `#/case/${runId}`;
        break;
      case "error":
        cleanup();
        toast("The audit stopped", m.text, "err");
        msg.replaceChildren(icon("alert"), ` ${m.text} `, h("a", { href: "#/" }, "Start again"));
        break;
      default:
    }
  };

  const es = new EventSource(`/api/audits/${runId}/stream`);
  state.es = es;
  es.onmessage = (e) => { try { handle(JSON.parse(e.data)); } catch (err) { console.error(err); } };
  es.onerror = () => {
    if (es.readyState === EventSource.CLOSED) {
      api(`/api/runs/${runId}`).then(() => { location.hash = `#/case/${runId}`; })
        .catch(() => msg.replaceChildren(icon("alert"), " Lost the connection to No Alibi. ", h("a", { href: "#/runs" }, "See case files")));
    }
  };
  judgeView.hidden = true;
}

// ------------------------------------------------------------------ verdict (tabs)

const TABS = [
  { id: "verdict", label: "Verdict" },
  { id: "promises", label: "Promises" },
  { id: "where", label: "Where your data went" },
  { id: "story", label: "Step by step" },
  { id: "about", label: "About this check" },
];

// An unsure identification is never presented as a company: it goes to "Unidentified servers".
const UNSURE = new Set(["possible", "weak", "unknown"]);
const shownCategory = (f) => (UNSURE.has(f.confidence) && cat(f.category).status !== "normal" ? "unknown" : f.category || "unknown");

// Group connections by the company behind them; normal infrastructure gets one bucket per kind.
function groupDestinations(flows, findings, evOf) {
  const flagged = new Map();
  for (const f of findings) {
    if (f.severity === "info") continue;
    for (const e of f.event_ids) { const k = evOf.get(e); if (k) flagged.set(k, f.severity === "red" || flagged.get(k) === "red" ? "red" : "amber"); }
  }
  const groups = new Map();
  for (const f of flows) {
    const fc = shownCategory(f);
    const infra = ["cdn", "unknown", "platform"].includes(fc);
    const key = infra ? `kind:${fc}` : `co:${f.owner || f.domain || f.ip}`;
    const g = groups.get(key) || { key, name: infra ? cat(fc).label : f.owner || f.domain || f.ip, category: fc, out: 0, in: 0, domains: new Map(), flag: null, best: "unknown" };
    g.out += f.bytes_out || 0;
    g.in += f.bytes_in || 0;
    const dkey = f.domain || f.ip;
    const d = g.domains.get(dkey) || { name: dkey, out: 0, in: 0, confidence: f.confidence, note: f.note, count: 0 };
    d.out += f.bytes_out || 0; d.in += f.bytes_in || 0; d.count += 1;
    g.domains.set(dkey, d);
    const fl = flagged.get(dkey);
    if (fl) g.flag = fl === "red" || g.flag === "red" ? "red" : "amber";
    const rank = { confirmed: 4, likely: 3, possible: 2, weak: 1, unknown: 0 };
    if ((rank[f.confidence] || 0) > (rank[g.best] || 0)) g.best = f.confidence;
    groups.set(key, g);
  }
  const order = { attention: 0, notable: 1, normal: 2 };
  return [...groups.values()].sort((a, b) => (a.flag ? 0 : 1) - (b.flag ? 0 : 1) || order[cat(a.category).status] - order[cat(b.category).status] || b.out - a.out);
}

async function renderVerdict(runId, tab = "verdict") {
  main.append(h("div", { class: "empty" }, h("span", { class: "spinner" }), " Opening the case file…"));
  const d = await api(`/api/runs/${runId}`);
  state.apps = state.apps || (await api("/api/apps").catch(() => []));
  main.replaceChildren();

  const run = d.run || {};
  const verdict = d.verdict || { verdict: "QUESTIONABLE" };
  const allFindings = d.findings?.findings || [];
  const findings = allFindings.filter((f) => f.severity !== "info");
  const claims = d.claims?.claims || [];
  const events = d.events?.events || [];
  const flows = d.flows?.flows || [];
  const app = (state.apps || []).find((a) => a.bundle_id === run.app?.bundle_id) || { name: run.app?.name || runId };
  const v = VERDICT[verdict.verdict] || VERDICT.QUESTIONABLE;
  const glow = { NO_ALIBI: "var(--red-bg)", QUESTIONABLE: "var(--amber-bg)", ALIBI_HOLDS: "var(--green-bg)" }[verdict.verdict];
  const duration = d.timeline?.duration || 0;

  const flowCat = new Map(flows.map((f) => [f.domain || f.ip, f]));
  const evOf = new Map(events.map((e) => [e.id, e.domain || e.ip]));
  const evById = new Map(events.map((e) => [e.id, e]));
  const claimById = new Map(claims.map((c) => [c.id, c]));
  const groups = groupDestinations(flows, allFindings, evOf);
  const companies = groups.filter((g) => !g.key.startsWith("kind:"));

  // ---- header (always visible)
  const headIcon = appIcon(app);
  headIcon.classList.add("tiny-icon");
  main.append(h("section", { class: "verdict-hero", style: { "--vglow": glow }, "aria-labelledby": "vh" },
    h("div", { class: `stamp ${verdict.verdict}`, "aria-hidden": "true" }, v.word),
    h("div", {},
      h("div", { class: "muted vmeta" }, headIcon, `${app.name}${run.app?.version ? ` ${run.app.version}` : ""} · checked ${run.started_at ? fmtDate(run.started_at) : ""} · watched for ${fmtSecs(duration)}`),
      h("h1", { id: "vh" }, h("span", { class: "sr-only" }, `Verdict: ${v.word}. `), v.line),
      h("p", { class: "summary" }, d.findings?.summary || ""),
    ),
    h("div", { class: "actions" },
      h("a", { class: "btn", href: `/api/runs/${runId}/report.html`, target: "_blank", rel: "noopener" }, icon("doc"), "Printable report"),
    ),
  ));

  // ---- tabs (WAI-ARIA tabs pattern: arrow keys move between tabs)
  const tablist = h("div", { class: "tabs", role: "tablist", "aria-label": "Case file sections" });
  const panels = h("div");
  const counts = { promises: claims.length, where: companies.length };
  const tabEls = TABS.map((t) => {
    const b = h("button", { class: "tab", role: "tab", id: `tab-${t.id}`, "aria-controls": `panel-${t.id}`, type: "button" }, t.label,
      counts[t.id] != null ? h("span", { class: "tab-count" }, String(counts[t.id])) : null);
    b.addEventListener("click", () => select(t.id, true));
    b.addEventListener("keydown", (e) => {
      const i = TABS.findIndex((x) => x.id === t.id);
      const next = e.key === "ArrowRight" ? (i + 1) % TABS.length : e.key === "ArrowLeft" ? (i - 1 + TABS.length) % TABS.length : e.key === "Home" ? 0 : e.key === "End" ? TABS.length - 1 : null;
      if (next !== null) { e.preventDefault(); select(TABS[next].id, true); tabEls[next].focus(); }
    });
    tablist.append(b);
    return b;
  });
  const panelEls = {};
  for (const t of TABS) {
    panelEls[t.id] = h("section", { class: "tabpanel", role: "tabpanel", id: `panel-${t.id}`, "aria-labelledby": `tab-${t.id}`, tabindex: "0", hidden: true });
    panels.append(panelEls[t.id]);
  }
  main.append(tablist, panels);
  function select(id, push) {
    TABS.forEach((t, i) => {
      const on = t.id === id;
      tabEls[i].setAttribute("aria-selected", on ? "true" : "false");
      tabEls[i].tabIndex = on ? 0 : -1;
      panelEls[t.id].hidden = !on;
    });
    if (push) history.replaceState(null, "", `#/case/${runId}/${id}`);
  }

  // ================= Verdict tab
  const pv = panelEls.verdict;
  if (findings.length) {
    pv.append(h("h2", { class: "tab-h" }, findings.some((f) => f.severity === "red") ? "What it did that the policy doesn't allow" : "What you may want to know"));
    for (const f of findings) {
      const claim = f.claim_ids.map((c) => claimById.get(c)).find(Boolean);
      const evs = f.event_ids.map((e) => evById.get(e)).filter(Boolean);
      const dest = [...new Set(evs.map((e) => e.domain || e.ip))];
      const owner = evs.find((e) => e.owner)?.owner;
      const sent = evs.reduce((s, e) => s + e.bytes_out, 0);
      const when = evs.length ? evs[0].phase : null;
      pv.append(h("article", { class: `case ${f.severity}` },
        h("div", { class: "case-head" }, sevBadge(f.severity), h("h3", {}, f.title)),
        h("p", { class: "case-why" }, RULE_WHY[f.rule] || ""),
        h("div", { class: "case-cols" },
          h("div", { class: "case-col" }, h("div", { class: "case-k" }, "The promise"),
            claim ? h("q", {}, claim.quote) : h("p", { class: "muted" }, "The policy says nothing about this."),
            claim ? h("a", { class: "src", href: claim.source_url, target: "_blank", rel: "noopener noreferrer" }, "Read it in the policy") : null),
          h("div", { class: "case-arrow", "aria-hidden": "true" }, "→"),
          h("div", { class: "case-col" }, h("div", { class: "case-k" }, "What actually happened"),
            h("p", { class: "case-fact" }, `${fmtBytes(sent)} sent to ${owner || dest[0] || "a server"}`),
            h("p", { class: "muted small" }, [when === "user_action" ? "Right after you used the AI feature" : when === "startup" ? "While the app was starting" : when === "idle" ? "While you weren't using the app" : "", dest.length ? ` · ${dest.slice(0, 2).join(", ")}${dest.length > 2 ? "…" : ""}` : ""].join(""))),
        ),
      ));
    }
  } else {
    pv.append(h("div", { class: "allclear" }, icon("check"),
      h("div", {}, h("h2", {}, "No broken promises found"),
        h("p", {}, `During this ${fmtSecs(duration)} check, everything ${app.name} did fits what its privacy policy says. It contacted ${companies.length || "no"} compan${companies.length === 1 ? "y" : "ies"}${groups.length > companies.length ? " plus ordinary hosting and system services" : ""}; you can see each one under “Where your data went”.`))));
  }
  // at-a-glance
  const glance = { attention: 0, notable: 0, normal: 0 };
  for (const g of groups) glance[cat(g.category).status] += 1;
  pv.append(h("h2", { class: "tab-h" }, "At a glance"),
    h("div", { class: "glance" },
      h("div", { class: "glance-item st-attention" }, h("b", {}, String(glance.attention)), h("span", {}, "AI or ad companies")),
      h("div", { class: "glance-item st-notable" }, h("b", {}, String(glance.notable)), h("span", {}, "analytics or crash reporters")),
      h("div", { class: "glance-item st-normal" }, h("b", {}, String(glance.normal)), h("span", {}, "normal services (own servers, hosting, updates)")),
      h("div", { class: "glance-item st-normal" }, h("b", {}, "0 B"), h("span", {}, "of your data sent by No Alibi")),
    ));
  // scorecard
  const card = d.findings?.scorecard || {};
  pv.append(h("h2", { class: "tab-h" }, "What the privacy policy says"),
    h("div", { class: "scorecard", role: "list" }, Object.entries(CLAIM_Q).map(([k, label]) => {
      const val = card[k] || "unclear";
      const tone = val === "unclear" ? "unclear" : val === GOOD_ANSWER[k] ? "yes" : "no";
      const word = val === "unclear" ? "Doesn't say" : val === "yes" ? "Yes" : "No";
      return h("div", { class: "score", role: "listitem" },
        h("span", { class: `ic ${tone}`, "aria-hidden": "true" }, icon(tone === "yes" ? "check" : tone === "no" ? "x" : "q")),
        h("div", {}, h("div", { class: "k" }, label), h("div", { class: "v" }, word, h("span", { class: "sr-only" }, tone === "yes" ? " (good for you)" : tone === "no" ? " (not good for you)" : ""))));
    })),
    h("p", { class: "hint" }, "Green is good for your privacy, red is not, amber means the policy is vague. See the exact sentences under “Promises”."));

  // ================= Promises tab
  const pp = panelEls.promises;
  pp.append(h("p", { class: "tab-intro" }, "A local AI on this Mac read the privacy policy and answered six questions. Every quote below was checked word for word against the real policy page."));
  for (const [k, label] of Object.entries(CLAIM_Q)) {
    const c = claims.find((x) => x.type === k);
    const tone = !c || c.value === "unclear" ? "unclear" : c.value === GOOD_ANSWER[k] ? "yes" : "no";
    pp.append(h("article", { class: "promise" },
      h("div", { class: "promise-head" }, h("span", { class: `ic ${tone}`, "aria-hidden": "true" }, icon(tone === "yes" ? "check" : tone === "no" ? "x" : "q")),
        h("h3", {}, label), h("span", { class: "promise-ans" }, !c ? "Not addressed" : c.value === "yes" ? "Yes" : c.value === "no" ? "No" : "Doesn't say clearly")),
      c ? h("q", {}, c.quote) : h("p", { class: "muted" }, "The policy doesn't say anything we could quote about this."),
      c ? h("div", { class: "src" }, h("span", { class: "tag" }, c.match === "exact" ? "Exact quote" : "Closest sentence in the policy"),
        c.providers?.length ? h("span", { class: "tag policy" }, `Names: ${c.providers.join(", ")}`) : null,
        h("a", { href: c.source_url, target: "_blank", rel: "noopener noreferrer" }, "Open the policy")) : null,
    ));
  }

  // ================= Where your data went
  const pw = panelEls.where;
  pw.append(h("p", { class: "tab-intro" }, `Every service ${app.name} contacted, grouped by the company behind it. Most apps talk to their own servers, update servers and hosting services; those are normal and never flagged.`));
  if (!groups.length) pw.append(h("div", { class: "empty" }, "The app didn't contact any service on the internet during the check."));
  for (const g of groups) {
    const c = cat(g.category);
    const st = g.flag ? { label: g.flag === "red" ? "Broke a promise" : "Worth knowing", cls: g.flag === "red" ? "st-red" : "st-notable" } : STATUS[c.status];
    const doms = [...g.domains.values()].sort((a, b) => b.out - a.out);
    pw.append(h("article", { class: `dest ${g.flag ? `flag-${g.flag}` : ""}` },
      h("span", { class: "dest-dot", style: { background: c.color }, "aria-hidden": "true" }),
      h("div", { class: "dest-main" },
        h("div", { class: "dest-top" }, h("h3", {}, g.name), h("span", { class: `status ${st.cls}` }, st.label)),
        h("div", { class: "dest-kind" }, g.key.startsWith("kind:") ? c.what : `${c.label}. ${c.what}`),
        h("details", { class: "dest-details" }, h("summary", {}, `${doms.length} address${doms.length > 1 ? "es" : ""} · technical details`),
          h("ul", {}, doms.map((x) => h("li", {}, h("span", { class: "mono" }, x.name), ` · sent ${fmtBytes(x.out)}, received ${fmtBytes(x.in)} · `, h("span", { title: CONF_TEXT[x.confidence] }, CONF_TEXT[x.confidence] || ""), x.note ? h("div", { class: "muted small" }, x.note) : null)))),
      ),
      h("div", { class: "dest-bytes" }, h("b", {}, fmtBytes(g.out)), h("span", {}, "sent"), h("span", { class: "muted" }, `${fmtBytes(g.in)} received`)),
    ));
  }

  // ================= Step by step
  const ps = panelEls.story;
  ps.append(h("p", { class: "tab-intro" }, "What the app did, in order."));
  const phases = [
    { id: "startup", title: "While the app was starting", empty: "The app was already open, so we started watching it while it ran." },
    { id: "user_action", title: "Right after you used the AI feature", empty: (d.timeline?.actions || []).length ? "Nothing was sent in the 5 seconds after you used it." : "You didn't press “I just used the AI feature” during this check." },
    { id: "idle", title: "The rest of the time", empty: "Nothing else was sent." },
  ];
  const flaggedIds = new Set(findings.flatMap((f) => f.event_ids));
  for (const ph of phases) {
    const evs = events.filter((e) => e.phase === ph.id && e.bytes_out > 0);
    const by = new Map();
    for (const e of evs) {
      const fl = flowCat.get(e.domain || e.ip) || { category: e.category, confidence: "likely" };
      const fc = shownCategory(fl);
      const infra = ["cdn", "unknown", "platform"].includes(fc);
      const name = infra ? cat(fc).label : e.owner || e.domain || e.ip;
      const it = by.get(name) || { name, category: fc, out: 0, times: 0, flagged: false };
      it.out += e.bytes_out; it.times += 1; it.flagged = it.flagged || flaggedIds.has(e.id);
      by.set(name, it);
    }
    const items = [...by.values()].sort((a, b) => b.flagged - a.flagged || b.out - a.out);
    ps.append(h("section", { class: "step" },
      h("h3", {}, ph.title),
      items.length ? h("ul", { class: "step-list" }, items.map((it) => h("li", { class: it.flagged ? "flagged" : "" },
        h("span", { class: "dest-dot", style: { background: cat(it.category).color }, "aria-hidden": "true" }),
        h("span", { class: "step-name" }, it.name),
        h("span", { class: "muted" }, `${fmtBytes(it.out)} sent${it.times > 1 ? `, ${it.times} times` : ""}`),
        it.flagged ? h("span", { class: "status st-red" }, "flagged") : cat(it.category).status === "normal" ? h("span", { class: "status st-normal" }, "normal") : null)))
        : h("p", { class: "muted" }, ph.empty),
    ));
  }

  // ================= About this check
  const pa = panelEls.about;
  const egress = d.egress || [];
  const kinds = {
    dns: "Looked up the addresses of known companies (names from our list, nothing about you)",
    "tls-cert": "Read the public name tag (certificate) of servers the app contacted",
    ptr: "Asked for the name of a server address",
    "policy-fetch": "Downloaded the public privacy policy",
    "tavily-search": "Asked Tavily who owns a website (website name only)",
    "exa-search": "Asked Exa who owns a website (website name only)",
  };
  const byKind = new Map();
  for (const e of egress) { const l = byKind.get(e.kind) || []; l.push(e.sent); byKind.set(e.kind, l); }
  pa.append(
    h("div", { class: "two" },
      h("section", { class: "panel" },
        h("h2", {}, icon("lock"), "Does No Alibi send your data anywhere?"),
        h("p", {}, h("b", {}, "No."), " The policy was read by an AI running on this Mac. Your traffic details, the quotes and the findings stay here. These are the only things No Alibi itself did on the internet during this check:"),
        h("table", { class: "ledger" },
          h("thead", {}, h("tr", {}, h("th", {}, "What"), h("th", {}, "Times"), h("th", {}, "Example"))),
          h("tbody", {}, [...byKind.entries()].map(([k, list]) => h("tr", {}, h("td", {}, kinds[k] || k), h("td", { class: "mono" }, String(list.length)), h("td", { class: "mono" }, list[0])))))),
      h("section", { class: "panel" },
        h("h2", {}, icon("lock"), "Proof this result wasn't changed"),
        h("p", { class: "muted" }, "This fingerprint (SHA-256) is calculated from the recorded evidence. If anyone edits the files, the fingerprint no longer matches."),
        h("div", { class: "hash" }, d.findings?.evidence_sha256 || "not computed"),
        h("div", { class: "setup-actions" },
          h("a", { class: "btn primary", href: `/api/runs/${runId}/evidence.zip`, download: "" }, icon("down"), "Download the evidence"),
          h("button", { class: "btn ghost", type: "button", onclick: async () => {
            if (!(await confirmDialog("Delete this case file?", "Everything recorded for this check will be removed from this Mac. This can't be undone.", "Delete", true))) return;
            try { await api(`/api/runs/${runId}`, { method: "DELETE" }); toast("Case file deleted"); location.hash = "#/runs"; } catch (err) { toast("Couldn't delete", err.message, "err"); }
          } }, icon("trash"), "Delete this case file")),
      ),
    ),
    h("section", { class: "panel", style: { marginTop: "16px" } },
      h("h2", {}, icon("info"), "How we check, and what we can't see"),
      h("ul", { class: "plain-list" },
        h("li", {}, "We watch how much data each part of the app sends and to which server, every second, using a tool built into macOS. We never read the contents, never block anything and never change the app."),
        h("li", {}, "We only flag AI companies, analytics, advertising and crash-reporting services, and only when we're sure who the server belongs to. The app's own servers, update checks and hosting services are normal and never flagged."),
        h("li", {}, "When a server's address is shared by many companies, we say “unsure” and never accuse anyone based on it."),
        h("li", {}, "“Big enough to include what you typed” is based on size and timing. We can't see inside encrypted data."),
        h("li", {}, "We can't see what a company's own servers do with your data after it arrives."),
        (d.timeline?.warnings || []).map((w) => h("li", { class: "warn" }, w)),
      )),
  );

  select(TABS.some((t) => t.id === tab) ? tab : "verdict", false);
}

// ------------------------------------------------------------------ boot

initTheme();
refreshHealth();
setInterval(refreshHealth, 15000);
route();
