# No Alibi: Plan

**Pitch:** *Every privacy app asks for trust. No Alibi gives you proof, then holds them to it.*

**Verify → Enforce → Practise it.**
1. **Verify:** audit a "private" app (ideally a **local AI app**: *"local AI that never phones home"* is the track's own example). Watch its network traffic without blocking or decrypting anything, identify each destination with Tavily, and put the vendor's claims next to what the app did, connected by red lines.
2. **Enforce:** one click on "Hold them to their word" blocks the third-party domains that contradict the claims, then a re-audit shows the app now keeps its promise (or tries another route).
3. **Practise it:** No Alibi is private by design. It runs only on this machine, has no account and no telemetry, keeps metadata only and deletes runs after 7 days. It **audits its own traffic** with the same sensor and shows the result on every report.

**Tracks:** Privacy-First · Most Startup-able · Surge (Tavily). Skip Signal-to-Dose and Bravado.

### Track fit check (Privacy-First: "software that protects its users by design")
| What the track asks for | Original idea | Now |
|---|---|---|
| *Protects its users* | ❌ The original pitch literally said "it doesn't protect you" | ✅ **Enforce**: blocks the trackers that contradict the claims, then proves it worked |
| *Keeps people's data theirs* | ⚠️ Only exposed others | ✅ Exposes, blocks, and keeps the audit data local, minimal and short-lived |
| *Local AI that never phones home* | ⚠️ Target was a note app | ✅ **Target a local AI app first.** We're how you *check* that claim |
| *Protection is the architecture, not a toggle* | ⚠️ Our tool sent data to Tavily with nothing disclosed | ✅ Egress guard + `egress.json` ledger + **self-audit**: our footprint is verified, not promised |

---

## The team: give each agent its brief

| Who | Role | Brief | Owns |
|---|---|---|---|
| **Shivam** | 🎧 The Wiretap: sensor + orchestrator, demo **driver** | [briefs/SHIVAM.md](briefs/SHIVAM.md) | `noalibi/sensor/`, `noalibi/audit.py`, `fixtures/pcaps/` |
| **Shri** | ⚖️ The Prosecutor: rules + Tavily + claims + deck, demo **presenter** | [briefs/SHRI.md](briefs/SHRI.md) | `noalibi/rules/`, `noalibi/intel/`, `noalibi/pipeline.py`, `targets/`, `deck/` |
| **Swathi** | 🏛️ The Courtroom: UI + live wiretap + report + evidence signing | [briefs/SWATHI.md](briefs/SWATHI.md) | `noalibi/web/`, `noalibi/report/` |

**Shared interface:** [CONTRACT.md](CONTRACT.md), covering schemas, the API, folder ownership and the non-negotiables.
**Shared test data:** [fixtures/demo_run/](fixtures/demo_run/), a complete fake audit of a made-up app, "QuietNotes". It lets all three work streams start at minute 0 without waiting for each other.

### Kickoff prompt (paste into each person's Claude agent)
```
Read PLAN.md, CONTRACT.md, and briefs/<YOUR_NAME>.md in this repo. You are <NAME>'s agent.
Work only inside the folders your brief says you own. Build against fixtures/demo_run first.
Start with the H0–1 tasks in your brief, then go in order. Tick the edge-case checklist
as you go. Before each sync point (H1, H2, H8, H14) stop and summarise what's done,
what's blocked, and anything you need from the other two.
```

---

## How the pieces fit together

```
                (root)                               (user)
  ┌─────────────────────────────┐     HTTP+token     ┌────────────────────────┐
  │ SHIVAM  sensor daemon :8765 │ ◄────────────────► │ SWATHI  Flask UI :5050 │
  │  tcpdump -i pktap -k        │                    │  Start / Wiretap / Stop │
  │  → flows.json, bursts.jsonl │                    │  audit.py (SHIVAM)      │
  └──────────────┬──────────────┘                    └───────────┬────────────┘
                 │ runs/<id>/                                    │ on Stop
                 ▼                                               ▼
  ┌─────────────────────────────────────────┐      ┌───────────────────────────┐
  │ SHRI  pipeline.analyze(run_dir)         │ ───► │ SWATHI report.build()     │
  │  seedlists → Tavily search (cached)     │      │  claims ═══ red lines ═══ │
  │  Tavily extract → claims                │      │  flags · timeline · stamp │
  │  rules R1–R5 → flags, verdict           │      │  manifest + Ed25519 sig   │
  └─────────────────────────────────────────┘      └───────────────────────────┘
```

## Why this is interesting (the details judges remember)

1. **The live wiretap.** Connections appear on screen *while the app is still loading*. The room sees the accusation happen in real time.
2. **The canary sentence.** We type a known sentence and measure whether an upload big enough to contain it leaves within seconds. If it leaves in **plaintext**, we catch the sentence itself (R4).
3. **Three-way contradiction.** *The homepage says X. Page 4 of the policy says Y. The network says Y.* We catch marketing that contradicts the vendor's own fine print, not only the network traffic.
4. **The verdict stamp:** `NO ALIBI` / `FINE PRINT` / `ALIBI HOLDS`.
5. **The fairness section.** Update checks, CDN downloads and macOS's own traffic are shown separately as "expected". Being fair is what makes the accusation credible.
6. **The control run.** TextEdit gets `ALIBI HOLDS`, which shows the tool doesn't flag everything.
7. **Tamper evidence.** We change one byte of the evidence live and `verify` fails. That supports the B2B story in 10 seconds.
8. **We practise what we preach.** We capture everything but keep only the target's flows and delete the rest. "What does your tool do with *my* traffic?" has a good answer.
9. **"Hold them to their word".** Block the trackers, re-audit, and the stamp changes to **ALIBI RESTORED**, or **"IT TRIED ANOTHER ROUTE"** if the app finds a way around the block.
10. **"Our own footprint: 0 connections."** No Alibi audits itself with the same sensor, and the result is on every report.

## Scope: network only (decided)

We audit **what leaves the machine**, not everything that happens on it. We don't monitor files, keystrokes, screen or clipboard. Privacy claims are about data *leaving* ("never leaves your device"), and the network is where that can be proven.

**Known blind spots. Each one goes in the report's "What we can't see" section and the Q&A sheet:**
1. **Delayed sending.** The app collects now and uploads on its next launch or the next day. *Stretch, only if H14 is green:* quit and relaunch the app after the canary, and watch for uploads.
2. **Sending through another process.** iCloud Drive or Dropbox syncing the app's folder, CloudKit traffic through `cloudd`. → **Don't pick a target that syncs through CloudKit or a synced folder.**
3. **Data hidden in DNS lookups.** Queries come from `mDNSResponder`, not the app. Not detected; listed as a limitation.
4. **Local-only behaviour.** File reads, screenshots, keylogging with no network traffic are out of scope.
5. **Encrypted content.** We never decrypt. ECH- and QUIC-hidden destinations are flagged as hidden (R5).

## Timeline and sync points

| Hour | Shivam | Shri | Swathi | 🚦 Gate |
|---|---|---|---|---|
| 0–1 | Repo + **capture test** (pktap) | Tavily key, seed lists, pipeline skeleton on fixtures | Flask + mock sensor + basic report on fixtures | **H1:** capture works or fallback chosen · repo pushed |
| 1–2 | Capture candidate apps | Score candidates on claims | Screenshot candidates' claims | **H2: TARGET CHOSEN** · `targets/<key>.json` |
| 2–8 | parse.py, replay, daemon, audit.py | Rules R1–R5, Tavily, claims, matrix | Report design, wiretap, evidence signing | **H8:** real replay → full report |
| 8–14 | Edge-case hardening, live runs, **self-audit + enforce (hosts block)** | Tune on real runs + control run, **R6 AI rule, egress guard** | Real sensor, preflight, projector test, **footprint panel + Hold-them button + before/after** | **H14:** live from the browser in under 90 s, including the footprint panel |
| 14–18 | Demo machine prep, **backup video** | Deck + one-pager + Q&A, warm cache | Polish, print view, control report | **H18: FEATURE FREEZE** |
| 18–24 | Rehearse (driver) | Rehearse (presenter) | Rehearse + fixes | Sleep 🙏 |

## Risks and fallbacks (ranked)

| # | Risk | Fallback |
|---|---|---|
| 1 | pktap doesn't attribute processes on macOS 26 | `lsof` + `nettop` polling (SHIVAM.md) |
| 2 | The chosen app turns out to be clean | Pitch **ALIBI HOLDS** as the headline + show another app's finding as act two. Never invent a finding. |
| 3 | Venue Wi-Fi breaks Tavily / the app / everything | Phone hotspot · warm Tavily cache · offline seed lists · replay pcap · backup video |
| 4 | A judge says "that's just an update check" | It's already listed under "Expected & fair". Point at it. |
| 5 | Defamation concern | Factual wording only. Every claim quoted with its URL and timestamp, every destination with sources. Say "contradiction", never "liar". |
| 6 | Integration breaks at H8 | The contract + fixtures mean each piece is already tested on the shared schema. Fix the schema mismatch, not the architecture. |

## Out of scope

Decryption or MITM · DPI · a dashboard · multiple apps per run · Linux/Windows · kernel or network extensions · Bravado · anything new after H18.
