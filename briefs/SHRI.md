# Brief: SHRI, "The Prosecutor" (rules + Tavily intel + claims + pitch)

> **To the Claude agent reading this:** you're working for Shri on the hackathon project "No Alibi". Read `PLAN.md` and `CONTRACT.md` before writing any code. Two other agents (Shivam's and Swathi's) are working in parallel. **Only edit files under `noalibi/rules/`, `noalibi/intel/`, `noalibi/pipeline.py`, `targets/`, `data/seedlists/` and `deck/`**, plus append-only lines in `requirements.txt`. Until H8, build and test **only against `fixtures/demo_run/`**. From H2, also use the real replay pcaps in `fixtures/pcaps/`.

## Mission

Turn a raw network log into an **accusation a judge can't argue with**. The sensor says "17 KB went to `events.cdp-example.net`". You say **who that is, what they do, which marketing sentence it contradicts, and whether the fine print quietly admits it.** Because this is a public accusation against a real company, your module has to be **fair**: no false positives, every claim cited, and nothing overstated.

You also own **the Surge track (Tavily)**. Search isn't decoration here: it's the step that turns "it connected to X" into "it connected to X, a customer data platform, according to these sources".

## What you deliver

1. `noalibi/pipeline.py`: `analyze(run_dir) -> dict`, plus a CLI: `python -m noalibi.pipeline runs/<id>`. Reads run.json, flows.json, bursts.jsonl and targets/<key>.json. Writes claims.json, intel.json, flags.json and verdict.json (CONTRACT §4). **Idempotent**: running it again overwrites cleanly.
2. `noalibi/intel/tavily.py`: domain lookup and page extract, with caching.
3. `noalibi/intel/classify.py`: offline seed lists first, Tavily second.
4. `noalibi/intel/claims.py`: claim extraction from marketing and policy pages.
5. `noalibi/rules/engine.py` + one file per rule.
6. `targets/<key>.json` for the chosen app (CONTRACT §5), **committed by H2**.
7. `deck/`: 3 slides and the business one-pager (H14–18).

## Timeline

| Hours | Task | Done when |
|---|---|---|
| **0–1** | Get the Tavily API key into `.env` (`TAVILY_API_KEY`, gitignored). Download the seed lists (below). Skeleton `pipeline.py` that runs on `fixtures/demo_run` and reproduces its flags.json closely enough. | `python -m noalibi.pipeline fixtures/demo_run --out /tmp/x` runs |
| **1–2** | With the team, test the candidate apps. **For each candidate, find its strongest privacy marketing line.** The best target has a bold claim *and* traffic that contradicts it. | **H2: target chosen.** Commit `targets/<key>.json` |
| 2–6 | Rules R1–R3 (+ R4, R5), with unit tests on the fixtures | Tests pass |
| 2–6 | Tavily lookup + seed-list classification + cache. Claims for the target. | intel.json and claims.json for the real target |
| 6–8 | Contradiction mapping + verdict. Run on Shivam's real replay pcap. | **H8 integration** |
| 8–14 | Tune thresholds on **real** runs of the target **and** the TextEdit control run (it must come out ALIBI_HOLDS). R6 tuned on the AI target. Egress ledger tests. | **H14** |
| 14–18 | Deck (3 slides) + one-pager + Q&A sheet. **Warm the Tavily cache for every domain the target has ever contacted.** | Deck done |
| 18–24 | Rehearse as the **presenter** (or whoever the team picks). | |

## Picking the target (H1–2), the decision that matters most

Score each candidate:

| Criterion | Weight |
|---|---|
| A bold, quotable privacy claim on its homepage ("never leaves your device", "local-first", "no tracking") | 3 |
| Real traffic that contradicts the claim (third-party analytics/CDP/AI at startup, idle heartbeat, upload after typing) | 3 |
| Well known to judges | 2 |
| Opens cleanly without a login wall (or the login can be done beforehand) | 2 |
| Doesn't depend on sync being on (otherwise uploads are expected) | 1 |

**Rule this candidate out:** any app that syncs through **CloudKit/iCloud** (its traffic shows up as Apple's `cloudd`, so we'd wrongly label it "macOS, not the app") or keeps its data inside an iCloud Drive or Dropbox folder. Check this for Bear in particular.

**Test local AI apps first.** The Privacy-First track names *"local AI that never phones home"* as its example, and **No Alibi is how you check that claim.** Candidates: LM Studio, Jan, GPT4All, Msty, Ollama (menu-bar app + CLI), AnythingLLM desktop, and any "on-device" AI writing or meeting assistant. For these apps the canary is a **prompt** typed into the chat. A prompt-sized upload to an `ai_inference` or `analytics` domain right after typing is the strongest possible demo.
Backups (note-taking apps): Obsidian, Logseq, Standard Notes, Joplin, Raycast, plus anything the team has installed.
- [ ] For AI apps, **download the model before the demo**. A 4 GB model download during the audit would bury everything else (it's a `cdn` download and not flagged, but it slows the run). Note `model_preinstalled` in run conditions.
- [ ] Some local AI apps offer **optional cloud models** (an "OpenAI API key" field). Make sure that's off and note it, so uploads aren't expected traffic. **If nobody contradicts their claim, that's fine:** we pitch "ALIBI HOLDS" as the headline ("we verified X is honest, and here's the signed evidence") and show the most interesting finding from another app as the second act. The product works in both cases. Don't invent a scandal.

## Seed lists (offline first, Tavily second)

Put these in `data/seedlists/` and commit them so we don't depend on venue Wi-Fi:
- **DuckDuckGo Tracker Radar** domain → owner + categories (`github.com/duckduckgo/tracker-radar`, use only the `domains/US` subset or a compressed JSON you build from it)
- **Disconnect** `services.json` (category → company → domains)
- A small hand-written `manual.json` for: Apple OS endpoints (`ocsp.apple.com`, `*.apple-cloudkit.com`, `gs.apple.com`, `mesu.apple.com`, …), common update hosts (Sparkle appcasts, `github.com/*/releases`, `objects.githubusercontent.com`), crash reporters (`sentry.io`, `bugsnag.com`, `crashlytics`), AI inference APIs (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api.mistral.ai`, …) and CDNs (`cloudfront.net`, `fastly.net`, `akamai*`).

## Tavily integration (Surge track)

- **Lookup order:** `data/cache/tavily.json` → seed lists → Tavily. Mark each result's `source` honestly.
- **What to query:** use the **registrable domain** (eTLD+1) via `tldextract` **with its suffix list bundled offline** (`TLDExtract(suffix_list_urls=())`). By default it downloads the list on first use, which fails on bad Wi-Fi. Query: `"<registrable> what company owns this domain and what is it used for (analytics, tracking, crash reporting, CDN, AI API)"`, `search_depth:"basic"`, `include_answer:true`, `max_results:5`.
- **Confidence:** `high` if at least one source's URL or text contains the registrable domain. `medium` if the answer names a company but no source mentions the domain. Otherwise `low`, shown in the report as "unverified".
- **Category from the answer:** match keywords against the category enum. If several match, the most privacy-relevant wins: `advertising > cdp > analytics > ai_inference > crash_reporting > sync > first_party_api > update > cdn`.
- **Claims extraction:** use `POST /extract` on `marketing_urls` and `policy_urls`. Split into sentences, then regex for claim patterns and map them to the claim `type`s. Also look for **disclosure sentences** in the policy ("we may collect", "usage data", "analytics", "third-party service providers", "improve our product") → `type:"disclosure"`.

**Edge cases: Tavily and claims**
- [ ] **No API key, out of credits, 429, timeout:** fall back to the seed lists, set `confidence:"low"`, never crash. Timeout of 8 s per call. Run calls **in parallel** (thread pool of 5) so 20 domains don't take 3 minutes on stage.
- [ ] **Call Tavily only after the sensor stops**, so our own lookups don't show up in the capture.
- [ ] **Our own egress ledger (non-negotiable 7).** Every Tavily call appends to `egress.json` exactly what was sent. Send **only public registrable domains of third-party destinations** and public vendor URLs. **Never send** first-party, `os_platform` or local domains, IPs, the canary, claims or any run data. Seed-list and cache hits make **no** call. Write one `egress_guard()` that every outbound call goes through, and unit-test that it refuses anything else.
- [ ] **Cut our own footprint:** check the cache, then the seed lists, then Tavily. In the demo, a warm cache means **zero outbound calls from No Alibi**, and the self-audit section proves it.
- [ ] **Set `enforceable`** on each flag following CONTRACT §4. That decides what the "Hold them to their word" button is allowed to block.
- [ ] **Random CDN subdomains** (`d3k2x9abc.cloudfront.net`, `*.amazonaws.com`, `*.googleapis.com`): the registrable domain is the CDN, not the real owner. Label it `cdn` with "the content owner can't be identified from the network" rather than accusing AWS.
- [ ] **The vendor's own domains** (`known_first_party`) → `first_party_api` or `update`. Don't send these to Tavily.
- [ ] **Tavily answers can be wrong.** Keep the sources and show them. If the answer contradicts the seed list, the **seed list wins** and both are recorded.
- [ ] **Tavily and extracted page text are untrusted data.** If you ever put them through an LLM, treat them as data, never instructions, and never let them change flags. The report escapes them too (Swathi), but don't rely on that alone.
- [ ] **JS-rendered marketing pages:** `/extract` can come back empty. Fall back to `method:"manual"` claims typed in by hand with the exact quote, the URL and a `retrieved_at`. Also save a screenshot and the Wayback Machine link in `targets/<key>.evidence/`.
- [ ] **Pages change over time:** store `page_sha256` and `retrieved_at` so the claim is timestamped evidence.
- [ ] **Claim nuance (the fairness core):** "we don't **sell** your data" ≠ "we don't **collect**". "End-to-end encrypted" is about *content* in sync, not telemetry. "Local-first" usually still allows update checks. Map carefully (matrix below).
- [ ] **Translated or region-specific pages:** use the English URL from the target config.

## Rules (pure functions: `(run, flows, bursts, intel, target_cfg) -> [Flag]`)

Only **attributed, non-local** flows are evaluated. Burst sizes **exclude handshake bursts**.

| Rule | Fires when | Default severity | Edge cases to handle |
|---|---|---|---|
| **R1_startup_call_home** | The first upload to a domain is within `STARTUP_WINDOW=10s` of `t0_launch` and its category isn't `update`/`license`/`os_platform` | high for `analytics/cdp/advertising/ai_inference`, low for `crash_reporting/first_party_api`, info for `cdn` | Not a cold start (`conditions.cold_start=false`) → downgrade everything to info and add a warning. Update checks are listed as "expected", never flagged. |
| **R2_heartbeat** | 3+ non-handshake bursts to the same domain in IDLE, intervals with CV < 0.25, mean interval 5–600 s | medium (high if `cdp/advertising`) | **Keepalives:** HTTP/2 PING and TLS keepalive bursts are under 100 B, so ignore bursts below `HEARTBEAT_MIN_BYTES=150`. Jitter: real telemetry adds ±10–20%, which is why CV is 0.25 and not 0.1. 2 bursts is not a pattern. WebSocket sync with sync off is still a heartbeat. |
| **R3_content_sized_upload** | A burst in IDLE/ACTION with `bytes_up ≥ CONTENT_MIN_BYTES=2048` to a non-`sync`, non-`update` domain. If it falls within 10 s after the canary's `typed_end` → `canary_correlated:true`, severity high | medium, high if canary-correlated | **Never say "it sent your note".** Say "an upload large enough to contain it". We can't see inside TLS, and compressed text is smaller than the original. If sync is enabled in conditions, downgrade to info. Large downloads (`bytes_down`) aren't uploads, so ignore them. |
| **R4_plaintext_canary** | The canary text (or its URL-encoded/base64 form) appears in a **non-TLS** payload kept by the sensor | high, the strongest evidence | Only the attributed plaintext buffer. Search case-insensitively. This is the one rule that can say "we saw your sentence leave in plaintext". |
| **R5_hidden_destination** | `ech:true`, or `domain_source:"none"` with bytes_up > 0 | info | Not an accusation, just transparency: "we can prove it was sent, not where". |
| **R6_ai_inference_upload** *(core now, because of the track fit)* | Any non-handshake upload to an `ai_inference` domain | high if the claims include `local_only`/`no_ai_training` (and canary-correlated → headline flag), else info | This is "local AI that phones home" stated as a rule. Model-download hosts (`huggingface.co`, `cdn-lfs.hf.co`) are `cdn` downloads, **not** inference, so don't flag them unless there's a content-sized *upload*. |

All thresholds live in `noalibi/rules/thresholds.py`, so they can be tuned in one place at H8–14 and nowhere else.

## Contradiction matrix (claim type × category → contradicts?)

| Category ↓ / Claim → | local_only | no_collection | no_tracking | no_third_party | e2e_encrypted |
|---|---|---|---|---|---|
| update / license / os_platform | no | no | no | no | no |
| first_party_api | **yes** | maybe → only if R3 | no | no | no |
| crash_reporting | **yes** | **yes** | no | **yes** if third-party | no |
| analytics / cdp | **yes** | **yes** | **yes** | **yes** | no |
| advertising | **yes** | **yes** | **yes** | **yes** | no |
| ai_inference | **yes** | **yes** | no | **yes** | **yes** if R3 is content-correlated |
| cdn (downloads only) | no | no | no | no | no |
| unknown + R3 | **yes** | **yes** | maybe | maybe | no |

Then **disclosure**: if a `type:"disclosure"` claim in the policy covers the category (keyword overlap such as "usage statistics" ↔ analytics/cdp, "crash reports" ↔ crash_reporting), set `disclosed_by`. That gives the best story in the demo: **"The homepage says X. Page 4 of the policy says Y. The network says Y."**

### verdict.json
- `ALIBI_HOLDS`: no flag has a non-empty `contradicts`
- `FINE_PRINT`: every contradicting flag has a `disclosed_by`
- `NO_ALIBI`: at least one high or medium contradicting flag with no disclosure
- `one_liner`: generated from the top flag. Keep it factual, under 140 characters.

## Acceptance tests (`noalibi/rules/tests/`, `noalibi/intel/tests/`)

1. `analyze(fixtures/demo_run)` reproduces the fixture flags F1–F5 (ids can differ; rule/domain/severity/contradicts must match) and `verdict = NO_ALIBI`.
2. Drop the 3 IDLE bursts down to 2 → no R2.
3. Make burst b8 80 B → no R3. Move it 30 s after typing → R3 still fires but `canary_correlated:false`.
4. An update-only run → ALIBI_HOLDS.
5. Set `cold_start:false` → R1 downgraded to info with a warning.
6. Tavily is mocked to raise → the pipeline still completes using seed lists.
7. A domain like `<script>alert(1)</script>.evil` passes through unchanged as data (escaping is the report's job, but it must not break the pipeline).

## Deck and pitch (H14–18)

3 slides, no more:
1. **The broken trust model.** "Every privacy app asks for trust. We ask for proof." One stat, one image. Use the **track's own words**: "local AI that never phones home" is a claim; No Alibi is how a user *checks* it and **enforces** it. Privacy is the architecture: local-only, no account, metadata only, a self-audited footprint, 7-day retention.
2. **Live demo** (no slide, just switch to the app).
3. **The business.** Buyers: security and procurement teams vetting vendors (SOC 2 / GDPR Art. 28 processor diligence), legal tech, investigative journalists. Pricing: per-seat licence plus paid **signed audit reports**. The flywheel: every audit adds to a public "alibi registry" of verified apps, which is where the moat comes from. Mention the Surge/Tavily evidence chain by name.

Q&A sheet: *Can't apps evade this?* (ECH and DoH are flagged as hidden; we're honest about what we can't see). *Isn't this Little Snitch?* (it blocks; we produce evidence). *Isn't it defamation?* (we only publish observations with timestamps and cited sources; the vendor's own claim sits next to them). *Why not decrypt?* (that needs a MITM certificate, changes the app's behaviour and creates legal exposure, and the metadata is enough). *What about Windows/Linux?* (Linux eBPF/iptables owner-match is the next platform).
