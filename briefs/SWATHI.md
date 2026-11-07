# Brief: SWATHI, "The Courtroom" (UI + live wiretap + report + evidence)

> **To the Claude agent reading this:** you're working for Swathi on the hackathon project "No Alibi". Read `PLAN.md` and `CONTRACT.md` before writing any code. Two other agents (Shivam's and Shri's) are working in parallel. **Only edit files under `noalibi/report/` and `noalibi/web/`**, plus append-only lines in `requirements.txt`. Until H8, build **only against `fixtures/demo_run/`** and a **mock sensor** you write yourself (`noalibi/web/mock_sensor.py`, which replays `fixtures/demo_run/bursts.jsonl` as a live feed with timing scaled ×1).

## Mission

You own **everything the judges actually see.** The sensor and the rules are invisible; your screen is the demo. Two screens:

1. **The Wiretap** (live, during the audit): a dark, terminal-like feed in which each new connection appears the moment it happens: process → domain → bytes, colour-coded by phase. As the app launches, lines start appearing. That's the moment the room pays attention.
2. **The Verdict** (`report.html`, after stop): **claims on the left, observations on the right, red lines between them**, a large verdict stamp (**NO ALIBI** / **ALIBI HOLDS** / **FINE PRINT**), and a tamper-evident evidence footer.

## What you deliver

1. `noalibi/web/`: a Flask app on `127.0.0.1:5050` (`python -m noalibi.web`). Pages: `/` (pick target + preflight + Start), `/run/<id>` (wiretap + phase controls + Stop), `/run/<id>/report` (serves report.html).
2. `noalibi/report/build.py`: `build(run_dir) -> path` plus a CLI `python -m noalibi.report runs/<id>`. Reads every JSON file in CONTRACT §4 and writes `report.html`, `manifest.json`, `evidence.zip` and `evidence.sig`.
3. `noalibi/report/templates/report.html.j2`: **one self-contained HTML file** with inline CSS and JS, no CDN, no web fonts (non-negotiable 4).
4. `noalibi/web/mock_sensor.py`: implements the same `audit.py` API (CONTRACT + Shivam's brief) against the fixtures, so you're never blocked. Switch with `NOALIBI_MOCK=1`.

## Timeline

| Hours | Task | Done when |
|---|---|---|
| **0–1** | Flask skeleton + mock sensor + `build.py` producing a plain report from `fixtures/demo_run`. | You can click Start → feed → Stop → report entirely on fixtures |
| 1–2 | Help test candidate apps (take screenshots of each one's privacy marketing for Shri). | |
| 2–8 | The real report design (below) + wiretap feed + evidence bundle | **H8 integration**: report from Shivam's real replay + Shri's flags |
| 8–14 | Swap the mock for real `audit.py`. Preflight screen. Edge-case pass. Projector test. | **H14**: live end to end in under 90 s |
| 14–18 | Polish: animation timing, copy, print/PDF view. A **"control run" report for TextEdit** (ALIBI HOLDS) to show the tool isn't biased. | |
| 18–24 | Rehearse. Bug fixes only. | |

## Screen 1: Start (`/`)
- Choose the target (from `targets/*.json`). Show **"What it claims"**: the top claim quote in large type, the vendor's own words.
- **Preflight checklist** (`audit.preflight()`): sensor reachable, cold start, DNS flush capable, VPN off, Private Relay off, sync off (a manual checkbox: "I confirmed sync is off"), caffeinate. Red items show the `fix` text. **The Start button stays disabled until every item is green**, with a hidden "force" option (shift-click) for emergencies.
- A big button: **"Make it prove it."**

## Screen 2: Wiretap (`/run/<id>`)
- Poll `audit.live(run_id, since)` every 500 ms (simpler and more reliable than SSE on venue networks).
- Each line: `+2.4s  QuietNotes Help → events.cdp-example.net  ↑3.1 KB  [LAUNCH]`. A **new domain** gets a brief flash. Bytes are counted in human units (B/KB/MB). **Unattributed (OS) lines** are greyed out and labelled "macOS" so the audience sees we're being fair.
- A large **upload counter** ("↑ 21.9 KB left this machine") and a **destination count**.
- **Phase controls:** `LAUNCH` is automatic. A big button for "Go idle" (IDLE). Then **"Type the canary"**: shows the canary sentence. The presenter clicks "I'm typing", types it into the target app, then clicks "Done". This posts `record_canary` with the real `typed_start`/`typed_end`. A keyboard shortcut for each (the presenter's hands are busy).
- **Stop** → spinner "Asking the internet who these people are…" (Tavily runs at this point) → redirect to the report. Show progress steps: *Parsing capture → Identifying 6 destinations (Tavily) → Checking 3 claims → Building evidence*.

## Screen 3: The report (`report.html`), the most important artefact
Layout (aim for 1920×1080 on a projector, and readable at 1280 wide):

```
┌──────────────────────────────────────────────────────────────────┐
│ QuietNotes 3.2.1 · audited 7 Nov 2026 18:00 UTC        [NO ALIBI]│  ← rubber-stamp verdict, rotated -6°
│ "Claimed: Your notes never leave your device. Observed: 5 dest…" │
├──────────────────────────────┬───────────────────────────────────┤
│ WHAT THEY SAY                │ WHAT IT DID                       │
│ ┌ c1 marketing ────────────┐ │ ┌ F1 HIGH  +2.1s ───────────────┐ │
│ │"Your notes never leave   │═══ events.cdp-example.net         │ │
│ │ your device."   [source] │ │ │ Example CDP Inc. — customer   │ │
│ └──────────────────────────┘ │ │ data platform  [3 sources]    │ │
│ ┌ c2 marketing ────────────┐ │ └───────────────────────────────┘ │
│ ┌ c3 POLICY §4.2 (fine pr.)┐ │ ┌ F3 HIGH  +124.6s 12.0 KB ─────┐ │
│ │"We may collect anonymous ┼───│ 0.6s after you typed  🐤canary│ │
├──────────────────────────────┴───────────────────────────────────┤
│ TIMELINE  |LAUNCH|────IDLE────|──ACTION──|   ● bursts by domain  │  ← SVG, x=time, y=domain, dot size=bytes
├──────────────────────────────────────────────────────────────────┤
│ Expected & fair: update check (updates.quietnotes.example),      │
│ macOS certificate check (ocsp.apple.com — OS, not the app)       │
├──────────────────────────────────────────────────────────────────┤
│ Audit conditions · Method · What we can't see · Evidence hashes  │
└──────────────────────────────────────────────────────────────────┘
```

- **Red lines**: SVG paths from each flag card to each claim in `contradicts`. **Dashed amber** for `disclosed_by` (marketing vs fine print). Recompute on `resize` and after fonts load. Number the cards too (①②) as a fallback when lines can't be drawn.
- **Timeline strip**: one row per destination, phase bands in the background, a dot per burst (area ∝ bytes), and a vertical marker at the canary typing window. Heartbeats show up as an evenly spaced row of dots that's obvious at a glance.
- **"Expected & fair" section**: update checks, CDN downloads, OS traffic. **This is what makes the accusation credible.**
- **"What we can't see"** (always shown, in plain words): content inside TLS · destinations hidden by ECH or QUIC · data sent **after** the audit window (on next launch or the next day) · data that leaves through **another process** (iCloud, Dropbox, CloudKit's `cloudd`) · data hidden in DNS lookups · anything the app does locally without touching the network (file reads, screenshots, keystrokes). Being upfront about these is what makes the findings credible.
- **Evidence footer**: run id, tool version, macOS version, conditions, start/end UTC, SHA-256 of each evidence file, and the signature fingerprint.

## Privacy-First additions (H8–14): show that we protect users, not only expose vendors

**A. "Our own footprint" section** (on every report, just above the evidence footer):
> **No Alibi's own network activity during this audit:** 0 connections. *(Verified by our own sensor, not just claimed.)*

Or, with a cold cache: "4 HTTPS requests to api.tavily.com, sending 4 public domain names: [list]." Show the **declared** list (`egress.json`) and the **observed** list (`self/flows.json`) side by side with a ✓ when they match. If they differ, show **our own mismatch in red**. We hold ourselves to the same rules as the apps we audit. That's the Privacy-First argument in one panel.

**B. "Hold them to their word" button** (only shown with NO ALIBI or FINE PRINT, and only for flags with `enforceable:true`):
1. A confirmation dialog listing the **exact domains** and saying plainly: *"This blocks these domains for every app on this Mac until you undo it. It doesn't change QuietNotes itself."*
2. → `audit.enforce()` → `audit.reaudit()` → wiretap again (shorter: LAUNCH + ACTION only).
3. A **before/after report**: the same claims column, two observation columns (Before | After blocking). The stamp changes to **ALIBI RESTORED** if the app works and the blocked uploads are gone, or **"IT TRIED ANOTHER ROUTE"** if new destinations or IPs appear after blocking (that's an even stronger finding).
4. A **persistent banner** across every page while blocking is active: "🛡 Blocking 2 domains for QuietNotes · Undo". Undo calls `audit.unenforce()`. The banner reads its state from `GET /enforce` on load, so it survives page refreshes and server restarts.

Edge cases:
- [ ] Never preselect non-enforceable domains. The dialog shows them greyed out with the reason ("update check: blocking would break updates").
- [ ] Clicking Undo twice / enforcing twice → idempotent, no errors.
- [ ] Re-audit fails partway → still show the banner and the Undo button. Blocking must never be left active without a visible way to undo it.
- [ ] The report says the method can be bypassed (DoH, QUIC, hard-coded IPs). Say it plainly.

## Evidence bundle (the Most Startup-able story)
- `manifest.json`: `{file: sha256}` for run.json, flows.json, bursts.jsonl, claims.json, intel.json, flags.json, verdict.json, capture.filtered.pcapng, report.html.
- `evidence.sig`: an **Ed25519** signature of manifest.json (the `cryptography` library). The key lives in `~/.noalibi/signing_key` and is generated on first run. Print the public key fingerprint in the footer. Add a `verify` CLI: `python -m noalibi.report verify runs/<id>`, which re-hashes everything and checks the signature. **Demo moment:** edit one byte in flows.json, run verify, and it fails. That takes 10 seconds and judges remember it.
- `evidence.zip`: all of the above + manifest + signature + public key.
- **Say "tamper-evident", never "court-admissible".**

## Edge cases checklist

**Security (our report renders data the attacker controls)**
- [ ] **XSS through SNI.** An app can send `<img src=x onerror=…>` as its SNI. Use Jinja2 with **autoescape on**, never `|safe` on data, and build SVG text with `textContent` and never `innerHTML`. Tavily summaries and claim quotes get the same treatment. Add a test fixture with a hostile domain.
- [ ] **Data embedded in a `<script>` tag** (for the timeline): use `json.dumps` + escape `</` as `<\/`, or put it in `<script type="application/json">` and read it with `JSON.parse(el.textContent)`.
- [ ] Flask binds to **127.0.0.1 only**. Turn debug mode off for the demo (the Werkzeug debugger allows remote code execution).
- [ ] Never let the web UI pass user input into a shell or a file path. Look the target key up against `targets/*.json` filenames.

**Data shape**
- [ ] **Zero flags / zero flows** → a proud "ALIBI HOLDS ✓" page with the conditions and evidence. **This must look great**, because it's the TextEdit control run and maybe the main demo.
- [ ] **50+ destinations** (Electron apps can do this) → group by category, show the top 8, and collapse the rest into "and 42 more".
- [ ] **Very long domain names** (`o4504…ingest.us.sentry.io`): use `overflow-wrap:anywhere`, show the full name on hover.
- [ ] **Missing files** (intel.json absent because Tavily was skipped, no canary) → render the sections that exist and say "not available" for the rest. Never 500.
- [ ] **`domain:null`** → show the IP + "destination hidden".
- [ ] **Confidence `low`** → show an "unverified" pill. Show `source:"seedlist"` vs `"tavily"` as small badges ("Identified via Tavily" is our Surge track credit, so make it visible).
- [ ] **Times**: show `+Xs from launch` as the main time (more readable), with the absolute local time on hover. Run every time through one helper.
- [ ] **Bytes**: one helper (`12.0 KB`, base 1000 or 1024, pick one and state it in the footer).

**Demo environment**
- [ ] **Fully offline**: no Google Fonts, no CDN Chart.js. Use the system font stack and hand-made SVG.
- [ ] **Projector**: high contrast, minimum 18 px body text, verdict stamp readable from 10 m away, no information carried by colour alone (labels plus colour, so colour-blind judges can read it).
- [ ] **Light and dark**: default to dark for the wiretap and light for the report (light prints better). Both should look intentional.
- [ ] **Print/PDF**: `@media print` hides the SVG lines (they misalign when printed) and shows the ①② markers instead. `Cmd+P` → a clean 2-page PDF. Stretch: export a PDF with headless Chrome.
- [ ] **Browser zoom / small laptop screen**: test at 1280×800 and 1920×1080.
- [ ] **Refresh mid-run**: the wiretap recovers from `since=0` and catches up instead of crashing. Store the run id in the URL, not in memory.
- [ ] **Double-clicked Start / Stop**: disable the button on the first click. The server checks run state too (idempotent stop).
- [ ] **Sensor dies mid-run**: show a red banner, "Sensor lost — evidence up to +73s preserved", and still allow building a partial report.
- [ ] **Slow Tavily on stage**: the report builds first with seed-list intel, then **refreshes in place** when Tavily results arrive (or the cache is already warm, which is better). Never leave the audience looking at a spinner for more than 5 s.

## Acceptance tests (`noalibi/report/tests/`, `noalibi/web/tests/`)
1. `build(fixtures/demo_run)` → report.html exists, contains "NO ALIBI", contains every flag headline and every claim quote.
2. A hostile-domain fixture → the output contains `&lt;script&gt;`, never a raw `<script>` from data.
3. Empty flags → "ALIBI HOLDS".
4. `verify` passes on a fresh bundle and fails after changing one byte.
5. The Flask test client: `/` → 200. Start with `NOALIBI_MOCK=1` → `/run/<id>` → the live endpoint returns items → stop → the report is served.
6. `fixtures/demo_run` → the report contains "Our own footprint" with a ✓ match. Change `self/flows.json` to add a flow → a red mismatch appears.
7. Mock enforce → the banner appears on every page. Mock unenforce → it disappears. A non-enforceable domain can't be submitted.

## The 60-second demo flow (you design the UI around this)
1. *"QuietNotes says: your notes never leave your device."* (Start screen with the quote in large type.)
2. Click **Make it prove it.** The app opens. Lines start appearing in the wiretap: *"…and it hasn't even finished opening."*
3. Go idle. Dots appear every 30 s. *"I'm not touching anything."*
4. Type the canary. *"Watch the counter."* ↑12 KB.
5. Stop → report → the **NO ALIBI** stamp, the red line from "never leaves your device" to the CDP flag, and the Tavily sources underneath.
6. *"We didn't block it. We didn't decrypt it. We asked it to prove itself."*
7. Click **Hold them to their word** → the re-audit wiretap shows the app still working with nothing going to the tracker → **ALIBI RESTORED**. *"Now it keeps its promise, whether it wants to or not."*
8. Point at **Our own footprint: 0 connections**. *"And we hold ourselves to the same standard. This is what No Alibi sent during the audit: nothing."* (If there's time: `verify` on the bundle.)
