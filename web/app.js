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

const CATS = {
  ai_provider: { label: "AI provider", color: "var(--c-ai)" },
  analytics: { label: "Analytics", color: "var(--c-analytics)" },
  tracker: { label: "Tracker / ads", color: "var(--c-tracker)" },
  error_reporting: { label: "Crash reporting", color: "var(--c-error)" },
  first_party: { label: "App's own server", color: "var(--c-first)" },
  update: { label: "Updates", color: "var(--c-update)" },
  cdn: { label: "CDN / cloud host", color: "var(--c-cdn)" },
  platform: { label: "OS service", color: "var(--c-platform)" },
  unknown: { label: "Unknown", color: "var(--c-unknown)" },
  identifying: { label: "Identifying…", color: "var(--c-unknown)" },
};
const cat = (k) => CATS[k] || CATS.unknown;
const CONF_TEXT = {
  confirmed: "DNS and certificate agree",
  likely: "matched by DNS or certificate",
  possible: "shared CDN address; other sites can use it too",
  weak: "reverse DNS only",
  unknown: "no name found",
};

const RULE_WHY = {
  R1_undisclosed_ai_provider: "The policy never names this AI company, yet the app sent it data.",
  R2_local_promise_broken: "The policy promises your data stays on your device.",
  R3_background_telemetry: "Clockwork-regular connections while you weren't doing anything.",
  R4_content_upload_suspicion: "A large upload right after you used the app: big enough to carry what you typed. (We can't see inside encrypted traffic.)",
  R5_silent_on_training: "It talks to an AI company, but the policy doesn't clearly say whether your data trains AI.",
  R6_unknown_recipient: "We couldn't confirm who this is.",
};
const CLAIM_Q = {
  data_stays_local: "Promises your data stays on your device",
  names_ai_provider: "Names the AI company it uses",
  trains_on_user_data: "Says your data trains AI",
  retention_stated: "States how long data is kept",
  ai_opt_out: "Lets you opt out of AI",
  shares_with_third_parties: "Shares data with third parties",
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
  NO_ALIBI: { word: "No alibi", icon: "x" },
  QUESTIONABLE: { word: "Questionable", icon: "alert" },
  ALIBI_HOLDS: { word: "Alibi holds", icon: "check" },
};

const sevBadge = (sev) =>
  h("span", { class: `sev ${sev}` }, icon(sev === "red" ? "x" : sev === "amber" ? "alert" : "info"),
    sev === "red" ? "Broken promise" : sev === "amber" ? "Suspicious" : "Context");

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
  const [, view, id] = (location.hash || "#/").split("/");
  main.replaceChildren();
  try {
    if (view === "audit" && id) { setNav(""); await renderLive(id); }
    else if (view === "case" && id) { setNav("runs"); await renderVerdict(id); }
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
        h("label", { class: "toggle" }, fresh, h("div", {}, h("b", {}, "Cold start (recommended)"),
          h("span", {}, app.hosts_self
            ? `Unavailable: No Alibi itself is running inside ${app.name}, so quitting it would stop the audit.`
            : ollamaSelf
              ? "Off for Ollama: restarting it would stop the local model that reads the policy."
              : `We quit and reopen ${app.name}, so we also see what it does the moment it launches.`))),
        h("label", { class: "toggle" }, cert, h("div", {}, h("b", {}, "Identify servers by certificate"),
          h("span", {}, "Opens our own TLS handshake to a server the app contacted, to read its name. Sends no data; listed in the self-audit."))),
      ),
      h("div", { class: "setup-actions" },
        start,
        h("button", { class: "btn ghost", type: "button", onclick: () => { state.selected = null; slot.replaceChildren(); document.querySelectorAll(".app-tile[aria-pressed=true]").forEach((t) => t.setAttribute("aria-pressed", "false")); } }, "Cancel"),
        h("span", { class: "hint" }, "Tip: have the app's AI feature ready to try once while we watch."),
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
      const go = await confirmDialog(`Restart ${app.name}?`, `${app.name} is open. No Alibi will quit it and open it again for a clean start. Save any unsaved work first.`, `Restart ${app.name}`);
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
        n.title.textContent = `${name}\n${cat(n.category).label}${n.owner ? ` · ${n.owner}` : ""}\nSent ${fmtBytes(n.out)}, received ${fmtBytes(n.in)}\nIdentification: ${CONF_TEXT[n.confidence] || n.confidence}`;
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
  const steps = ["Launch", "Watching", "Your AI action", "Verdict"].map((s) => h("li", {}, s));
  const stepper = h("ol", { class: "stepper", "aria-label": "Audit progress" }, steps);
  main.append(h("div", { class: "live-head" }, appIcon(app), h("div", {}, h("h1", {}, `Watching ${app.name}`), h("div", { class: "muted", style: { fontSize: "13px" } }, "Record only: nothing is blocked, decrypted or changed.")), rec, stepper));

  const con = new Constellation(app.name);
  const idleHint = h("div", { class: "idle-hint" }, "Connections appear here the moment the app makes them.");
  const legend = h("div", { class: "legend", "aria-hidden": "true" }, Object.entries(CATS).filter(([k]) => k !== "identifying").map(([, c]) => h("span", {}, h("i", { style: { background: c.color } }), c.label)));
  const stat = (k, cls = "") => { const v = h("div", { class: "v" }, "0"); return [h("div", { class: `stat ${cls}` }, h("div", { class: "k" }, k), v), v]; };
  const [sUp, vUp] = stat("Sent");
  const [sDown, vDown] = stat("Received");
  const [sDest, vDest] = stat("Destinations");
  const [sSelf, vSelf] = stat("No Alibi → 3rd parties", "self");
  const feed = h("ul", { class: "feed", "aria-label": "Destinations, most recent first" });
  const feedCount = h("span", { class: "count" }, "0");
  const policyStatus = h("div", { class: "policy-status" }, h("span", { class: "spinner" }), h("span", {}, "Starting…"));
  const claimsBox = h("div", { class: "claims-live", "aria-live": "polite" });

  main.append(h("div", { class: "live-grid" },
    h("section", { class: "panel", "aria-labelledby": "map-h" },
      h("h2", { id: "map-h" }, icon("eye"), "Live wiretap"),
      h("div", { class: "constellation-wrap" }, con.svg, idleHint), legend),
    h("div", { style: { display: "grid", gap: "16px", alignContent: "start" } },
      h("section", { class: "panel" }, h("div", { class: "totals" }, sUp, sDown, sDest, sSelf),
        h("h2", {}, "Destinations", feedCount), feed),
      h("section", { class: "panel", "aria-labelledby": "pol-h" }, h("h2", { id: "pol-h" }, icon("doc"), "Reading the policy (local AI)"), policyStatus, claimsBox),
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
          h("div", { class: "dom" }, n.domain || n.key, n.confidence && n.category !== "identifying" ? h("span", { class: `conf conf-${n.confidence}`, title: CONF_TEXT[n.confidence] }, n.confidence) : null),
          h("div", { class: "own" }, `${cat(n.category).label}${n.owner ? ` · ${n.owner}` : ""}`)),
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
        vSelf.textContent = fmtBytes(m.self_up || 0);
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

// ------------------------------------------------------------------ verdict

async function renderVerdict(runId) {
  main.append(h("div", { class: "empty" }, h("span", { class: "spinner" }), " Opening the case file…"));
  const d = await api(`/api/runs/${runId}`);
  state.apps = state.apps || (await api("/api/apps").catch(() => []));
  main.replaceChildren();

  const run = d.run || {};
  const verdict = d.verdict || { verdict: "QUESTIONABLE" };
  const findings = d.findings?.findings || [];
  const claims = d.claims?.claims || [];
  const events = d.events?.events || [];
  const flowsList = d.flows?.flows || [];
  const app = (state.apps || []).find((a) => a.bundle_id === run.app?.bundle_id) || { name: run.app?.name || runId };
  const v = VERDICT[verdict.verdict] || VERDICT.QUESTIONABLE;
  const glow = { NO_ALIBI: "var(--red-bg)", QUESTIONABLE: "var(--amber-bg)", ALIBI_HOLDS: "var(--green-bg)" }[verdict.verdict];

  // ---- hero
  main.append(h("section", { class: "verdict-hero", style: { "--vglow": glow }, "aria-labelledby": "vh" },
    h("div", { class: `stamp ${verdict.verdict}`, role: "img", "aria-label": `Verdict: ${v.word}` }, v.word),
    h("div", {},
      h("div", { class: "muted", style: { fontSize: "13px", display: "flex", gap: "10px", alignItems: "center" } }, appIcon(app, ""), `${app.name}${run.app?.version ? ` ${run.app.version}` : ""} · ${run.started_at ? fmtDate(run.started_at) : runId}`),
      h("h1", { id: "vh" }, verdict.one_liner),
      h("p", { class: "summary" }, d.findings?.summary || ""),
      h("div", { class: "counts" },
        verdict.red ? h("span", { class: "sev red" }, icon("x"), `${verdict.red} broken promise${verdict.red > 1 ? "s" : ""}`) : null,
        verdict.amber ? h("span", { class: "sev amber" }, icon("alert"), `${verdict.amber} suspicious`) : null,
        verdict.info ? h("span", { class: "sev info" }, icon("info"), `${verdict.info} context`) : null,
        h("span", { class: "chip" }, `${events.length} bursts · ${flowsList.length} connections`)),
    ),
    h("div", { class: "actions" },
      h("a", { class: "btn primary", href: `/api/runs/${runId}/evidence.zip`, download: "" }, icon("down"), "Evidence (.zip)"),
      h("a", { class: "btn", href: `/api/runs/${runId}/report.html`, target: "_blank", rel: "noopener" }, icon("doc"), "One-page report"),
    ),
  ));
  const hero = main.querySelector(".verdict-hero .muted img, .verdict-hero .muted .ph");
  if (hero) { hero.style.width = "22px"; hero.style.height = "22px"; hero.style.borderRadius = "6px"; }

  // ---- scorecard
  const card = d.findings?.scorecard || {};
  main.append(h("div", { class: "scorecard", role: "list", "aria-label": "What the policy says" },
    Object.entries(CLAIM_Q).map(([k, label]) => {
      const val = card[k] || "unclear";
      const tone = val === "unclear" ? "unclear" : val === GOOD_ANSWER[k] ? "yes" : "no";
      const meaning = tone === "yes" ? "good for you" : tone === "no" ? "bad for you" : "the policy doesn't say";
      return h("div", { class: "score", role: "listitem", title: meaning },
        h("span", { class: `ic ${tone}`, "aria-label": meaning }, icon(tone === "yes" ? "check" : tone === "no" ? "x" : "q")),
        h("div", {}, h("div", { class: "k" }, label), h("div", { class: "v" }, val)));
    })));

  // ---- the board
  const flowByDomain = new Map();
  for (const f of flowsList) {
    const key = f.domain || f.ip;
    const cur = flowByDomain.get(key);
    const rank = { confirmed: 4, likely: 3, possible: 2, weak: 1, unknown: 0 };
    if (!cur || (rank[f.confidence] || 0) > (rank[cur.confidence] || 0)) flowByDomain.set(key, f);
  }
  const evByKey = new Map();
  for (const e of events) {
    const key = e.domain || e.ip;
    const g = evByKey.get(key) || { key, ids: [], out: 0, in: 0, bursts: [], category: flowByDomain.get(key)?.category || e.category, owner: e.owner, flow: flowByDomain.get(key) };
    g.ids.push(e.id); g.out += e.bytes_out; g.in += e.bytes_in; g.bursts.push(e);
    evByKey.set(key, g);
  }
  const evOf = new Map();
  for (const g of evByKey.values()) for (const id of g.ids) evOf.set(id, g.key);

  const sevRank = { red: 0, amber: 1, info: 2 };
  const claimSev = new Map();
  const evSev = new Map();
  for (const f of findings) {
    for (const c of f.claim_ids) if (!claimSev.has(c) || sevRank[f.severity] < sevRank[claimSev.get(c)]) claimSev.set(c, f.severity);
    for (const e of f.event_ids) { const k = evOf.get(e); if (k && (!evSev.has(k) || sevRank[f.severity] < sevRank[evSev.get(k)])) evSev.set(k, f.severity); }
  }

  const board = h("div", { class: "board" });
  const strings = h("svg", { class: "strings", "aria-hidden": "true" });
  board.append(strings);

  const claimCol = h("section", { "aria-labelledby": "bc1" }, h("h2", { id: "bc1" }, icon("doc"), "What they promise"));
  if (!claims.length) claimCol.append(h("div", { class: "empty" }, "No verified promises (the policy couldn't be read, or every quote failed the word-for-word check)."));
  for (const c of claims) {
    claimCol.append(h("article", { class: `card claim-card ${claimSev.get(c.id) || ""}`, id: `k-${c.id}`, dataset: { claim: c.id } },
      h("div", { class: "head" }, CLAIM_Q[c.type] || human(c.type), h("span", { class: `tag ${c.value === "yes" ? "live" : ""}` }, c.value), h("span", { class: "id" }, c.id)),
      h("q", {}, c.quote),
      h("div", { class: "src" }, h("span", { class: "tag", title: c.match === "exact" ? "Found word for word in the policy" : "Closest real sentence in the policy (≥92% match)" }, c.match === "exact" ? "verbatim" : "closest sentence"),
        c.providers?.length ? h("span", { class: "tag policy" }, `names ${c.providers.join(", ")}`) : null,
        h("a", { href: c.source_url, target: "_blank", rel: "noopener noreferrer" }, new URL(c.source_url).hostname)),
    ));
  }

  const findCol = h("section", { "aria-labelledby": "bc2" }, h("h2", { id: "bc2" }, icon("scale"), "Findings"));
  if (!findings.length) findCol.append(h("div", { class: "empty" }, "Nothing the app did contradicts its policy."));
  const findingEls = [];
  for (const f of findings) {
    const el = h("article", { class: `card finding-card ${f.severity}`, id: `k-${f.id}`, tabindex: "0", dataset: { finding: f.id }, "aria-describedby": `why-${f.id}` },
      h("div", { class: "head" }, sevBadge(f.severity), h("span", { class: "id" }, f.id)),
      h("div", { class: "title" }, f.title),
      h("div", { class: "why", id: `why-${f.id}` }, RULE_WHY[f.rule] || ""),
      h("div", { class: "refs" }, [f.claim_ids.length ? `promise ${f.claim_ids.join(", ")}` : null, f.event_ids.length ? `${f.event_ids.length} burst${f.event_ids.length > 1 ? "s" : ""}` : null].filter(Boolean).join(" · ")),
    );
    findingEls.push([el, f]);
    findCol.append(el);
  }

  const evCol = h("section", { "aria-labelledby": "bc3" }, h("h2", { id: "bc3" }, icon("eye"), "What it actually did"));
  const linked = [...evByKey.values()].filter((g) => evSev.has(g.key)).sort((a, b) => sevRank[evSev.get(a.key)] - sevRank[evSev.get(b.key)] || b.out - a.out);
  const others = [...evByKey.values()].filter((g) => !evSev.has(g.key)).sort((a, b) => b.out - a.out);
  const evCard = (g) => {
    const f = g.flow || {};
    const maxOut = Math.max(...g.bursts.map((b) => b.bytes_out), 1);
    return h("article", { class: `card ev-card ${evSev.get(g.key) || ""}`, id: `k-ev-${CSS.escape(g.key)}`, dataset: { ev: g.key }, style: { "--edge-color": cat(g.category).color } },
      h("div", { class: "head" }, h("span", { class: "cat-dot", style: { width: "9px", height: "9px", borderRadius: "50%", background: cat(g.category).color, display: "inline-block" } }), cat(g.category).label, f.confidence ? h("span", { class: `conf conf-${f.confidence}`, title: CONF_TEXT[f.confidence] }, f.confidence) : null),
      h("div", { class: "dom" }, g.key),
      h("div", { class: "row" }, g.owner ? h("span", {}, g.owner) : null, h("span", { class: "mono" }, `↑${fmtBytes(g.out)} ↓${fmtBytes(g.in)}`), h("span", {}, `${g.bursts.length} burst${g.bursts.length > 1 ? "s" : ""}`), f.proc ? h("span", { title: "Process that made the connection" }, `by ${f.proc}`) : null),
      f.note ? h("div", { class: "note" }, f.note) : null,
      h("div", { class: "bars", title: "Upload size of each burst over time" }, g.bursts.slice(0, 40).map((b) => h("i", { style: { height: `${Math.max(8, (Math.log10(1 + b.bytes_out) / Math.log10(1 + maxOut)) * 100)}%` }, title: `+${b.t_rel_s}s · ${b.phase.replace("_", " ")} · ↑${fmtBytes(b.bytes_out)}` }))),
    );
  };
  if (!evByKey.size) evCol.append(h("div", { class: "empty" }, "The app made no connections to public servers during the audit."));
  linked.forEach((g) => evCol.append(evCard(g)));
  if (others.length) {
    const det = h("details", { class: "more" }, h("summary", {}, `${others.length} other destination${others.length > 1 ? "s" : ""} with nothing to flag`));
    others.forEach((g) => det.append(evCard(g)));
    det.addEventListener("toggle", () => drawStrings());
    evCol.append(det);
  }
  board.append(claimCol, findCol, evCol);
  main.append(board);

  // red strings between promise -> finding -> evidence
  function anchor(el, side) {
    const b = board.getBoundingClientRect();
    const r = el.getBoundingClientRect();
    return { x: (side === "right" ? r.right : r.left) - b.left, y: r.top - b.top + Math.min(r.height / 2, 40) };
  }
  function curve(a, b) {
    const dx = Math.max(30, (b.x - a.x) / 2);
    return `M${a.x},${a.y} C${a.x + dx},${a.y} ${b.x - dx},${b.y} ${b.x},${b.y}`;
  }
  function drawStrings() {
    strings.replaceChildren();
    if (window.matchMedia("(max-width: 1100px)").matches) return;
    for (const [el, f] of findingEls) {
      for (const c of f.claim_ids) {
        const k = document.getElementById(`k-${c}`);
        if (k) strings.append(h("path", { class: f.severity, d: curve(anchor(k, "right"), anchor(el, "left")), dataset: { f: f.id } }));
      }
      const keys = [...new Set(f.event_ids.map((e) => evOf.get(e)).filter(Boolean))];
      for (const key of keys) {
        const k = document.getElementById(`k-ev-${CSS.escape(key)}`);
        if (k && k.offsetParent) strings.append(h("path", { class: f.severity, d: curve(anchor(el, "right"), anchor(k, "left")), dataset: { f: f.id } }));
      }
    }
  }
  const focusFinding = (f, on) => {
    board.classList.toggle("focus", on);
    board.querySelectorAll(".on").forEach((x) => x.classList.remove("on"));
    if (!on) return;
    document.getElementById(`k-${f.id}`)?.classList.add("on");
    f.claim_ids.forEach((c) => document.getElementById(`k-${c}`)?.classList.add("on"));
    f.event_ids.forEach((e) => { const k = evOf.get(e); if (k) document.getElementById(`k-ev-${CSS.escape(k)}`)?.classList.add("on"); });
    strings.querySelectorAll(`path[data-f="${f.id}"]`).forEach((p) => p.classList.add("on"));
  };
  for (const [el, f] of findingEls) {
    el.addEventListener("mouseenter", () => focusFinding(f, true));
    el.addEventListener("mouseleave", () => focusFinding(f, false));
    el.addEventListener("focus", () => focusFinding(f, true));
    el.addEventListener("blur", () => focusFinding(f, false));
  }
  requestAnimationFrame(() => requestAnimationFrame(drawStrings));
  window.onresize = () => drawStrings();

  // ---- timeline
  main.append(renderTimeline(d.timeline, findings, evOf));

  // ---- self audit + evidence
  const egress = d.egress || [];
  const kinds = {
    dns: "DNS lookups of known company domains (names from our catalog, nothing about you)",
    "tls-cert": "TLS handshakes to read a server's certificate (no data sent)",
    ptr: "Reverse-DNS lookups of server addresses",
    "policy-fetch": "Downloaded the public privacy policy",
    "tavily-search": "Asked Tavily who owns a domain (domain name only)",
    "exa-search": "Asked Exa who owns a domain (domain name only)",
  };
  const byKind = new Map();
  for (const e of egress) { const l = byKind.get(e.kind) || []; l.push(e.sent); byKind.set(e.kind, l); }
  const selfConns = d.self_audit?.connections || [];
  const selfOut = selfConns.reduce((s, c) => s + (c.bytes_out || 0), 0);
  main.append(h("div", { class: "two" },
    h("section", { class: "panel", "aria-labelledby": "sa" },
      h("h2", { id: "sa" }, icon("lock"), "No Alibi's own footprint"),
      h("p", { style: { margin: "0 0 10px" } }, h("span", { class: "big-zero" }, "0"), h("span", { class: "muted" }, "  bytes of the audit's data (traffic, quotes, findings) were sent anywhere. The policy was read by the local model.")),
      h("table", { class: "ledger" },
        h("thead", {}, h("tr", {}, h("th", {}, "What No Alibi did on the network"), h("th", {}, "Count"), h("th", {}, "Example of what was sent"))),
        h("tbody", {}, [...byKind.entries()].map(([k, list]) => h("tr", {}, h("td", {}, kinds[k] || k), h("td", { class: "mono" }, String(list.length)), h("td", { class: "mono" }, list[0]))))),
      h("p", { class: "hint" }, `The same sensor also watched No Alibi itself and saw ${selfConns.length} connection${selfConns.length === 1 ? "" : "s"} (${fmtBytes(selfOut)} sent). Lookups that finish in under a second can fall between its 1-second samples, which is why No Alibi also writes down every network action it takes in the table above.`),
    ),
    h("section", { class: "panel", "aria-labelledby": "ev" },
      h("h2", { id: "ev" }, icon("lock"), "Sealed evidence"),
      h("p", { class: "muted", style: { margin: "0 0 8px", fontSize: "13.5px" } }, "SHA-256 over claims.json + events.json + the raw sensor log. Anyone with the bundle can recompute it."),
      h("div", { class: "hash" }, d.findings?.evidence_sha256 || "not computed"),
      d.manifest ? h("details", { class: "method", style: { marginTop: "10px" } }, h("summary", {}, `Manifest (${Object.keys(d.manifest.files).length} files)`),
        h("table", { class: "ledger" }, h("tbody", {}, Object.entries(d.manifest.files).map(([n, sha]) => h("tr", {}, h("td", {}, n), h("td", { class: "mono" }, `${sha.slice(0, 16)}…`)))))) : null,
      h("div", { class: "setup-actions" },
        h("a", { class: "btn primary", href: `/api/runs/${runId}/evidence.zip`, download: "" }, icon("down"), "Download evidence"),
        h("button", { class: "btn ghost", type: "button", onclick: async () => {
          if (!(await confirmDialog("Delete this case file?", "The capture, findings and evidence bundle for this audit will be removed from this Mac. This can't be undone.", "Delete", true))) return;
          try { await api(`/api/runs/${runId}`, { method: "DELETE" }); toast("Case file deleted"); location.hash = "#/runs"; } catch (err) { toast("Couldn't delete", err.message, "err"); }
        } }, icon("trash"), "Delete"),
      ),
    ),
  ));

  const warnings = d.timeline?.warnings || [];
  main.append(h("section", { class: "panel", style: { marginTop: "16px" } },
    h("details", { class: "method" }, h("summary", {}, "How this was measured, and what we can't see"),
      h("ul", {},
        h("li", {}, "Bytes come from macOS's per-socket counters (nettop), sampled every second, for every process inside the app's bundle and their children. No root, no packet capture, no decryption, nothing blocked."),
        h("li", {}, "Server names: DNS match against known company domains, cross-checked against the server's TLS certificate. Shared CDN addresses are marked 'possible' and can never produce a red finding on their own."),
        h("li", {}, "An upload 'big enough to contain what you typed' is an inference from size and timing. We never see inside encrypted traffic."),
        h("li", {}, "Server-side AI calls (the vendor's backend forwarding your data) are invisible from your Mac. We report what leaves the device."),
        h("li", {}, "Promises come from the public policy page at the time of the audit (its SHA-256 is in claims.json). Every quote is checked word for word against that page."),
        warnings.map((w) => h("li", { style: { color: "var(--amber)" } }, w)),
      ))));
}

function renderTimeline(tl, findings, evOf) {
  const panel = h("section", { class: "panel timeline-panel", "aria-labelledby": "tlh" }, h("h2", { id: "tlh" }, "Timeline: every upload burst"));
  if (!tl || !tl.bursts?.length) { panel.append(h("div", { class: "empty" }, "No uploads recorded.")); return panel; }
  const W = 1200, H = 190, padL = 46, padR = 16, padT = 22, padB = 26;
  const dur = Math.max(tl.duration || 0, ...tl.bursts.map((b) => b.rel + b.dur), 10);
  const x = (t) => padL + (Math.max(0, t) / dur) * (W - padL - padR);
  const maxLog = Math.max(...tl.bursts.map((b) => Math.log10(1 + b.out)), 1);
  const y = (bytes) => H - padB - (Math.log10(1 + bytes) / maxLog) * (H - padT - padB);
  const svg = h("svg", { class: "timeline", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": `${tl.bursts.length} upload bursts over ${Math.round(dur)} seconds` });
  if (tl.startup_s) {
    svg.append(h("rect", { class: "band", x: x(0), y: padT - 14, width: x(tl.startup_s) - x(0), height: H - padB - padT + 14 }),
      h("text", { class: "band-label", x: x(0) + 6, y: padT - 3 }, "launch"));
  }
  for (const a of tl.actions || []) {
    svg.append(h("g", { class: "action" },
      h("rect", { x: x(a.rel), y: padT - 14, width: x(a.rel + (tl.action_window_s || 5)) - x(a.rel), height: H - padB - padT + 14 }),
      h("line", { x1: x(a.rel), x2: x(a.rel), y1: padT - 14, y2: H - padB }),
      h("text", { x: x(a.rel) + 5, y: padT - 3 }, "you used the AI feature")));
  }
  const axis = h("g", { class: "axis" }, h("line", { x1: padL, x2: W - padR, y1: H - padB, y2: H - padB }));
  const step = dur > 240 ? 60 : dur > 90 ? 30 : 10;
  for (let t = 0; t <= dur; t += step) axis.append(h("text", { x: x(t), y: H - 8, "text-anchor": "middle" }, `${t}s`));
  for (const b of [1000, 100000]) if (Math.log10(1 + b) <= maxLog) axis.append(h("text", { x: 4, y: y(b) + 4 }, fmtBytes(b)), h("line", { x1: padL, x2: W - padR, y1: y(b), y2: y(b), "stroke-dasharray": "2 6" }));
  svg.append(axis);
  for (const b of tl.bursts) {
    if (!b.out) continue;
    const bw = Math.max(3, x(b.rel + Math.max(b.dur, 1)) - x(b.rel) - 1);
    svg.append(h("rect", { class: "bar", x: x(b.rel), y: y(b.out), width: bw, height: H - padB - y(b.out), rx: 1.5, fill: cat(b.category).color },
      h("title", {}, `+${b.rel.toFixed(1)}s · ${b.domain}\n${cat(b.category).label} · sent ${fmtBytes(b.out)}, received ${fmtBytes(b.in)}`)));
  }
  panel.append(svg, h("div", { class: "legend" }, [...new Set(tl.bursts.map((b) => b.category))].map((c) => h("span", {}, h("i", { style: { background: cat(c).color } }), cat(c).label))),
    h("p", { class: "hint", style: { margin: "6px 0 0" } }, "Bar height is upload size on a log scale. Hover a bar for details."));
  return panel;
}

// ------------------------------------------------------------------ boot

initTheme();
refreshHealth();
setInterval(refreshHealth, 15000);
route();
