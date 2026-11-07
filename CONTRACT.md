# No Alibi: Shared Contract

**Every agent reads this file first.** It's the only thing the three parallel work streams share. If you need to change a schema, post it in team chat first and edit this file in a commit of its own (`contract: …`). Never change a schema silently.

---

## 1. Who owns what

```
hack1984/
├── PLAN.md, CONTRACT.md, briefs/        all three (docs)
├── requirements.txt                     all three, APPEND-ONLY, one dep per line, pinned
├── targets/<target>.json                SHRI  (the config for each audited app)
├── fixtures/demo_run/                   SHARED, READ-ONLY (announce before changing)
├── fixtures/pcaps/                      SHIVAM (real captures, filtered, for replay)
├── noalibi/
│   ├── __init__.py, config.py           SHIVAM creates at H0, others edit via small commits
│   ├── sensor/                          SHIVAM: root daemon, pktap capture, parsing, replay
│   ├── audit.py                         SHIVAM: orchestrator (quit/launch app, phases, talks to sensor)
│   ├── rules/                           SHRI:   rule engine (pure functions)
│   ├── intel/                           SHRI:   Tavily lookups, seed lists, claim extraction
│   ├── pipeline.py                      SHRI:   analyze(run_dir), reads sensor output, writes flags/intel/claims
│   ├── report/                          SWATHI: build(run_dir) → report.html + evidence bundle
│   └── web/                             SWATHI: Flask UI, live wiretap feed
├── data/seedlists/                      SHRI:   offline tracker/category lists
├── deck/                                SHRI (H14+)
└── runs/<run_id>/                       generated output, gitignored
```

**Rule:** don't edit files outside the folders you own. If you need something from someone else's module, ask for it in chat and use a stub in your own folder until it arrives.

## 2. Runtime layout

Two processes, because packet capture needs root and the rest of the tool shouldn't run as root:

| Process | Runs as | Port | Owner |
|---|---|---|---|
| `sudo python -m noalibi.sensor.daemon` | root | `127.0.0.1:8765` (never `0.0.0.0`) | Shivam |
| `python -m noalibi.web` (Flask) | the logged-in user | `127.0.0.1:5050` | Swathi |

- The sensor writes a random token to `~/.noalibi/token` (mode 0600, owned by `$SUDO_USER`). Every request to the sensor sends `X-NoAlibi-Token`. This matters because a root daemon on localhost could otherwise be driven by any local process.
- The **target app is always launched as the user** (from `audit.py` in the web process), never by the root sensor.
- The sensor `chown`s every file in `runs/<id>/` to `$SUDO_USER`, so the web process can read and write them.

## 3. Sensor HTTP API (Shivam implements, `audit.py` calls it)

| Method & path | Body | Returns |
|---|---|---|
| `GET /health` | – | `{"ok":true,"method":"pktap"\|"nettop","macos":"26.6.1","warnings":[]}` |
| `POST /runs` | `{"target":"obsidian","process_prefixes":["Obsidian"],"bundle_id":"md.obsidian"}` | `{"run_id":"2026-11-07T18-00-00Z_obsidian","run_dir":"/abs/path"}` (flushes DNS, starts capture, returns only once tcpdump is actually ready) |
| `POST /runs/<id>/phase` | `{"name":"LAUNCH"\|"IDLE"\|"ACTION"\|"END","t":<epoch float, optional>}` | `{"ok":true}` |
| `POST /runs/<id>/canary` | `{"text":"...","typed_start":<epoch>,"typed_end":<epoch>}` | `{"ok":true}` |
| `POST /runs/<id>/stop` | – | `{"ok":true,"warnings":[...]}`. Returns only after `flows.json`, `bursts.jsonl` and `run.json` have been written |
| `GET /runs/<id>/live?since=<seq>` | – | `{"seq":42,"items":[LiveItem…]}`, polled every 500 ms |
| `POST /runs` *(self-audit mode)* | `{"self_audit":true,"pids":[<web pid>],"parent_run_id":"<id>"}` | Same as above. Attributes traffic **by PID and its child processes** instead of by name. Writes to `runs/<parent>/self/` |
| `GET /enforce` | – | `{"active":bool,"domains":[...],"since":<epoch>,"run_id":"…"}` |
| `POST /enforce` | `{"run_id":"…","domains":["events.cdp-example.net"]}` | Writes a marked `/etc/hosts` block (both `0.0.0.0` and `::`), flushes DNS, writes `runs/<id>/enforce.json` |
| `DELETE /enforce` | – | Removes the block, flushes DNS. **Also runs automatically when the daemon exits and when it starts up** |

`LiveItem = {"seq":int,"t":float,"proc":str,"dest":str /*domain or IP*/,"dir":"up"|"down","bytes":int,"phase":str,"new_flow":bool,"attributed":bool}`

## 4. Files in `runs/<run_id>/`

All times are **Unix epoch seconds as floats, in UTC**. Byte counts are **TCP/UDP payload bytes**: no IP or TCP headers, and retransmissions are counted only once.

| File | Writer | Reader |
|---|---|---|
| `run.json` | sensor + audit.py | everyone |
| `flows.json` | sensor | rules, report |
| `bursts.jsonl` | sensor | rules, report |
| `capture.filtered.pcapng` | sensor | evidence bundle (only the target's flows, see §6) |
| `claims.json` | pipeline (intel) | rules, report |
| `intel.json` | pipeline (intel) | rules, report |
| `flags.json` | pipeline (rules) | report |
| `verdict.json` | pipeline | report, web |
| `egress.json` | pipeline (intel) | report: **what No Alibi itself sent out** (as declared by our own code) |
| `self/flows.json` | sensor (self-audit) | report: **what No Alibi itself sent out, as observed by the sensor** |
| `enforce.json` | sensor | report, web |
| `report.html`, `manifest.json`, `evidence.zip`, `evidence.sig` | report | humans |

### egress.json: our own outbound ledger (one entry per network call No Alibi makes)
```json
[{"t":1794074565.2,"service":"tavily","endpoint":"/search","host":"api.tavily.com","sent":"cdp-example.net","why":"identify destination","bytes_up":412}]
```
`sent` is **exactly** the data that left the machine (a public registrable domain or a public vendor URL), never run data, the canary, flows or claims.

### enforce.json
```json
{"run_id":"…","domains":["events.cdp-example.net"],"applied_at":1794074600.0,"removed_at":null,"method":"hosts","note":"system-wide; DoH, QUIC or hard-coded IPs can bypass this"}
```

### run.json
```json
{
  "run_id": "2026-11-07T18-00-00Z_quietnotes",
  "tool_version": "0.1.0+<git short sha>",
  "target": {"key":"quietnotes","name":"QuietNotes","bundle_id":"example.quietnotes","app_version":"3.2.1","bundle_path":"/Applications/QuietNotes.app","process_prefixes":["QuietNotes"]},
  "started_at": 1794074395.0, "ended_at": 1794074560.0,
  "t0_launch": 1794074400.0,
  "phases": [{"name":"LAUNCH","t":1794074400.0},{"name":"IDLE","t":1794074415.0},{"name":"ACTION","t":1794074510.0},{"name":"END","t":1794074560.0}],
  "canary": {"text":"The quarterly numbers are in the blue folder.","typed_start":1794074520.0,"typed_end":1794074524.0},
  "conditions": {"cold_start":true,"dns_flushed":true,"vpn_active":false,"private_relay":false,"sync_enabled":false,"logged_in":false,"network":"phone-hotspot"},
  "host": {"macos":"26.6.1","hostname_hash":"sha256:…"},
  "capture": {"method":"pktap","warnings":["3 flows pre-existed capture start"]},
  "parent_run_id": null,
  "enforced_domains": []
}
```
A **re-audit** (after "Hold them to their word") has `parent_run_id` set to the original run and `enforced_domains` set to what was blocked. The report then shows a before/after comparison.

### flows.json: a list of Flow objects
```json
{
  "flow_id": "f2",
  "proc": "QuietNotes Help", "pid": 4312, "eproc": null,
  "proc_path": "/Applications/QuietNotes.app/Contents/Frameworks/QuietNotes Helper.app/…",
  "attributed": true,
  "attribution_reason": "proc_prefix" ,
  "proto": "tcp", "transport_note": null,
  "src": "192.168.1.20", "sport": 52011, "dst": "198.51.100.23", "dport": 443,
  "domain": "events.cdp-example.net", "domain_source": "sni",
  "tls": true, "tls_version": "1.3", "ech": false,
  "first_seen": 1794074402.1, "last_seen": 1794074525.0,
  "bytes_up": 17132, "bytes_down": 2210, "pkts_up": 31, "pkts_down": 22,
  "preexisting": false, "phase_first_seen": "LAUNCH",
  "local": false
}
```
- `attribution_reason`: `"proc_prefix" | "eproc_prefix" | "proc_path_in_bundle" | "child_of_target" | "none"`
- `domain_source`: `"sni" | "dns" | "ptr" | "none"`
- `proto`: `"tcp" | "udp" | "quic"`. `transport_note` covers cases like `"quic: SNI not parsed"`.
- Flows that aren't attributed to the target, such as OS daemons, **are still listed** with `attributed:false`, so the report can show them as "OS-level, not the app".

### bursts.jsonl: one upload burst per line
A burst is a run of upload packets on one flow with gaps of less than 300 ms between them. **Rules count bursts, not "requests"**, because HTTP/2 can carry many requests over one connection and the encrypted traffic doesn't show where one ends.
```json
{"burst_id":"b7","flow_id":"f2","t_start":1794074524.6,"t_end":1794074524.9,"bytes_up":12288,"bytes_down":310,"phase":"ACTION","is_handshake":false}
```
The ClientHello burst at the start of a flow has `is_handshake:true`, and the rules ignore it for size checks.

### claims.json
```json
{"target":"quietnotes","claims":[
  {"claim_id":"c1","type":"local_only","quote":"Your notes never leave your device.","url":"https://quietnotes.example/","source_kind":"marketing","retrieved_at":1794070000.0,"page_sha256":"…","method":"tavily_extract"}
]}
```
`type` is one of: `local_only`, `no_collection`, `no_tracking`, `no_third_party`, `e2e_encrypted`, `no_ai_training`, `disclosure` (where the fine print admits collection).
`method` is one of: `tavily_extract`, `manual` (curated by hand, still with a URL and the exact quote).

### intel.json: keyed by the domain as observed
```json
{"events.cdp-example.net":{
  "registrable":"cdp-example.net","owner":"Example CDP Inc.","category":"cdp",
  "summary":"Customer data platform that collects product events for marketing and analytics.",
  "sources":[{"url":"https://…","title":"…"}],
  "confidence":"high","source":"tavily","fetched_at":1794070100.0}}
```
`category` is one of: `first_party_api`, `update`, `license`, `sync`, `crash_reporting`, `analytics`, `cdp`, `advertising`, `ai_inference`, `cdn`, `os_platform`, `unknown`, `local`.
`confidence` is one of: `high` (the sources name the domain), `medium` (only the registrable domain matched), `low` (guessed or unknown).
`source` is one of: `tavily`, `seedlist`, `manual`, `cache`.

### flags.json: a list of Flag objects
```json
{"flag_id":"F3","rule":"R3_content_sized_upload","severity":"high",
 "domain":"events.cdp-example.net","flow_ids":["f2"],"burst_ids":["b7"],
 "bytes":12288,"t":1794074524.6,"category":"cdp",
 "headline":"12.0 KB uploaded to a customer data platform 0.6s after you typed",
 "detail":"Canary sentence (46 bytes) typed 18:02:00–18:02:04 UTC. Upload burst 12,288 B at 18:02:04.6.",
 "contradicts":["c1"],"disclosed_by":null,"canary_correlated":true,"enforceable":true}
```
`enforceable` is true only when the category is `analytics`, `cdp`, `advertising`, `crash_reporting` or `ai_inference` **and** the flag contradicts a claim. We never offer to block `first_party_api`, `update`, `license`, `sync`, `cdn` or `os_platform` domains, because that would break the app or macOS.
Rule IDs:
- `R1_startup_call_home`
- `R2_heartbeat`
- `R3_content_sized_upload`
- `R4_plaintext_canary`
- `R5_hidden_destination` (info level: ECH, or no domain resolvable)
- `R6_ai_inference_upload`

### verdict.json
```json
{"verdict":"NO_ALIBI","high":2,"medium":1,"low":0,"info":1,"one_liner":"Claimed: never leaves your device. Observed: 3 third-party destinations, 16.5 KB up."}
```
`verdict` is one of:
- `ALIBI_HOLDS`: no flag contradicts a claim
- `FINE_PRINT`: every contradiction is disclosed somewhere in the policy
- `NO_ALIBI`: at least one contradiction of high or medium severity that the policy doesn't disclose

## 5. Target config: `targets/<key>.json` (Shri)
```json
{"key":"quietnotes","name":"QuietNotes","bundle_path":"/Applications/QuietNotes.app","bundle_id":"example.quietnotes",
 "process_prefixes":["QuietNotes"],"quit_script":"tell application \"QuietNotes\" to quit",
 "background_agents":["QuietNotes Helper (Login)"],
 "marketing_urls":["https://quietnotes.example/"],"policy_urls":["https://quietnotes.example/privacy"],
 "known_first_party":["quietnotes.example"],"known_update":["updates.quietnotes.example"],
 "sync_note":"Sync is OFF by default; verify in Settings → Sync before every run."}
```

## 6. Non-negotiables

1. **No decryption, no MITM, no certificate install, no changes to the target app.** This is what the whole pitch rests on.
2. **We capture all traffic on the machine but keep only the target's.** `capture.filtered.pcapng` holds attributed flows only. Delete the unfiltered capture at `stop` unless `--keep-raw` is set. (A judge will ask what our privacy tool does with *your* traffic. We have a good answer, so make sure it's true.)
3. **Escape everything rendered into HTML.** SNI, domains, Tavily text and claim quotes are all attacker-controlled: an app can send any SNI string it likes, including `<script>`.
4. **Everything works offline once the cache is warm.** No CDN scripts or fonts in the report or UI. Tavily results are cached in `data/cache/tavily.json`.
5. **Times are UTC epoch floats in files.** Use local wall-clock time only when displaying. Use `time.monotonic()` for measuring intervals in-process.
6. **Python 3.11+**, created with `python3 -m venv .venv`. Add any new dependency to `requirements.txt` with an exact version.
7. **No Alibi follows its own rules (Privacy-First track).** No account, no cloud, no telemetry, no update check, no crash reporting. The **only** network calls are to Tavily, they happen **after the target capture stops**, they only ever send **public registrable domains of third-party destinations** (never first-party, OS or local ones) and the vendor's public URLs, and every call is logged in `egress.json`. The self-audit (`self/flows.json`) must match `egress.json`. If it doesn't, the report shows our own mismatch in red.
8. **Retention:** at startup the daemon deletes `runs/*` older than 7 days (`NOALIBI_RETENTION_DAYS`). Exported `evidence.zip` files are the user's to keep.
9. **Blocking is opt-in and always reversible.** It never happens during an audit (an audit only observes). It only happens after an explicit click with a confirmation listing the exact domains, it is undone on demand and on daemon exit, and it's never applied to non-`enforceable` domains.

## 7. Sync points (everyone stops and merges)

| Time | Gate |
|---|---|
| **H1** | The capture test passes (or we switch to the fallback). The repo is pushed. Everyone can run `fixtures/demo_run` through their own module. |
| **H2** | **Target app chosen.** Shri commits `targets/<key>.json`. |
| **H8** | Integration 1: a replay of a real pcap goes all the way to `report.html`. |
| **H14** | Integration 2: a live audit runs end to end from the browser button in under 90 seconds. |
| **H18** | **Feature freeze.** Only bug fixes, copy changes and rehearsal after this. |
