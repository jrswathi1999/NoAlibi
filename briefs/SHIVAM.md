# Brief: SHIVAM, "The Wiretap" (sensor + orchestrator)

> **To the Claude agent reading this:** you're working for Shivam on the hackathon project "No Alibi". Read `PLAN.md` and `CONTRACT.md` before writing any code. Two other agents (Shri's and Swathi's) are working in parallel on other folders. **Only edit files under `noalibi/sensor/`, `noalibi/audit.py`, `noalibi/config.py`, `noalibi/__init__.py` and `fixtures/pcaps/`**, plus append-only lines in `requirements.txt`. You can't type a sudo password: whenever something needs root, give Shivam the exact command to run and ask for the output to be pasted back.

## Mission

Build the part that **watches**. It records which process on this Mac talked to which domain, when, and how many bytes, **without a proxy, a certificate or any decryption.** Everything else in the project depends on your output files, so their **accuracy is the whole credibility of the demo**: one wrong attribution and a judge can dismiss everything.

## What you deliver

1. `noalibi/sensor/daemon.py`: the root HTTP daemon described in CONTRACT §3.
2. `noalibi/sensor/capture.py`: starts and stops tcpdump, handles the files.
3. `noalibi/sensor/parse.py`: turns a pcapng into `flows.json` + `bursts.jsonl` (CONTRACT §4). The **same code path** has to serve live runs and replays.
4. `noalibi/sensor/replay.py`: `python -m noalibi.sensor.replay <pcapng> --target <key> --out runs/<id>`.
5. `noalibi/audit.py`: the orchestrator the web UI imports. It quits the app, checks for a cold start, starts the sensor, launches the app as the user, marks phases and stops. Its API is below.
6. `fixtures/pcaps/*.pcapng`: **filtered** real captures (target flows only), so Shri and Swathi can replay real data from H2.

### audit.py API (Swathi calls this, so keep these signatures fixed)
```python
def preflight(target_key: str) -> dict       # {"ok":bool,"checks":[{"name","ok","detail","fix"}]}
def start(target_key: str) -> str            # run_id; quits app → sensor POST /runs → phase LAUNCH → open -a
def mark_phase(run_id: str, name: str) -> None
def record_canary(run_id: str, text: str, typed_start: float, typed_end: float) -> None
def live(run_id: str, since: int) -> dict    # proxies sensor /live
def stop(run_id: str) -> dict                # phase END → sensor stop → returns {"run_dir":..., "warnings":[...]}
# Privacy-First additions (H8–14)
def self_audit_start(run_id: str) -> str     # sensor POST /runs self_audit, pids=[os.getpid()]; call BEFORE pipeline.analyze
def self_audit_stop(run_id: str) -> None     # call AFTER analyze, BEFORE report.build → writes runs/<id>/self/flows.json
def enforce(run_id: str, domains: list[str]) -> dict   # only flags with enforceable:true
def unenforce() -> dict
def reaudit(run_id: str) -> str              # new run with parent_run_id + enforced_domains, same target
```

## Timeline

| Hours | Task | Done when |
|---|---|---|
| **0–0.5** | `git init`, `.gitignore` (`runs/`, `.venv/`, `data/cache/`, `*.raw.pcapng`, `.env`), skeleton package, `config.py`, push to GitHub, add Shri and Swathi. | Both teammates have cloned the repo |
| **0.5–1** | **Capture test (the most important hour of the hackathon).** See below. | GO or FALLBACK decided and posted in chat |
| **1–2** | Help the team test 4–5 candidate apps: 2-minute capture each with a quick parse script. Post one table per app (proc, domain, bytes up, time after launch). | Team picks the target at H2 |
| 2–3 | Commit a filtered pcap of the chosen target to `fixtures/pcaps/` (check it contains nothing personal first). | Others can replay |
| 2–6 | `parse.py` (flows, bursts, SNI, DNS, attribution) + `replay.py` | Replaying the fixture pcap produces valid JSON |
| 6–8 | `daemon.py` + `audit.py` + live feed | **H8 integration:** replay → report works |
| 8–14 | Edge-case hardening (checklist below). Live end-to-end runs. **Privacy-First additions: self-audit + enforce (section below).** | **H14:** live audit from the browser in under 90 s, with the self-audit section populated |
| 14–18 | Prepare the demo machine. **Record the backup video.** Keep a known-good run folder. | Backup exists on 2 devices |
| 18–24 | Rehearse as the demo **driver** (the person clicking). Bug fixes only. | |

## Capture test (H0.5–1): run this first

Ask Shivam to run these and paste the output back:
```bash
sudo tcpdump -i pktap,all -k NP -n -l -c 20 'tcp port 443'
```
- Do you see something like `proc Safari:1234:…` on each line? → **pktap works.** Note the exact text format and write a regex for it.
- Also check for `eproc` (the *effective* process for delegated sockets). This matters a lot; see the edge cases.

Then test the file path, which is the one we'll actually use:
```bash
sudo tcpdump -i pktap,all -P -U -w /tmp/na_test.pcapng -c 200 'tcp port 443 or udp port 53 or udp port 443'
tcpdump -r /tmp/na_test.pcapng -k NP -n -tt | head
python -c "from scapy.all import rdpcap; p=rdpcap('/tmp/na_test.pcapng'); print(p[0].summary(), len(p))"
```
Answer three questions and post them in chat:
1. Does `-r … -k` still show process names when **reading the file back**? If yes, replay can recover the process for every packet. 🎉
2. Can scapy decode the packets, or does it see the raw pktap link type? If it can't, read the payloads with `tcpdump -r file -x -n` (hex) and parse the bytes in Python. Don't lose an hour fighting scapy.
3. Is the pktap header kept or stripped in the pcapng? This decides how you join process metadata to packets (by packet index or by 5-tuple and timestamp).

**FALLBACK** if pktap is broken on macOS 26: capture with plain `tcpdump -i en0` (all packets, no process names). Every 250 ms, poll `lsof -nP -iTCP -iUDP -a -c <prefix>` together with `nettop -P -L 1 -J bytes_in,bytes_out -p <pid>` to map 5-tuples to PIDs. That's less precise, but it works. Record `"capture":{"method":"nettop"}` in run.json.

## Parsing design (parse.py)

- **Flow key:** (proto, local ip, local port, remote ip, remote port). Normalise the direction so the remote end is always the non-local address.
- **Bytes:** sum **TCP payload length**, not frame length. **Handle retransmits:** track the highest sequence number + payload length per direction and don't count bytes below it again.
- **Bursts:** upload packets on the same flow with gaps under 300 ms. Mark the first burst that contains the ClientHello `is_handshake:true`.
- **Domain, in priority order:**
  1. SNI from the TLS ClientHello (`domain_source:"sni"`)
  2. A DNS answer that maps this IP to a name, from any process, because DNS queries come from `mDNSResponder` and not from the app (`"dns"`)
  3. A reverse PTR lookup, done **after** the run so it doesn't create traffic during the capture (`"ptr"`)
  4. `null` (`"none"`)
- **Phase:** compare `t_start` with the `phases` list in run.json.
- **Local:** set `local:true` for RFC1918 addresses, link-local, loopback, multicast, mDNS (5353), SSDP (1900) and fe80::/10. Keep these flows in the file but mark them.

## Edge cases checklist (tick each one or write down why it's skipped)

**Process attribution, where a mistake ends the demo**
- [ ] **Process names are cut to about 16 characters** (MAXCOMLEN): `QuietNotes Helper (Renderer)` shows up as `QuietNotes Help`. Match on prefix, and also resolve `pid → full path` with `ps -o comm= -p <pid>` **the moment a new PID appears**, before the process exits. Then use "the path is inside the .app bundle" as the strongest attribution signal.
- [ ] **Electron/Chromium apps** use separate Helper, GPU and Renderer processes for networking. Attribute all of them through the bundle-path check.
- [ ] **Delegated networking.** If an app uses `NSURLSession` background tasks, the socket belongs to `nsurlsessiond` and **`eproc`** names the real app. Use `eproc` and set `attribution_reason:"eproc_prefix"`. Without this you'll miss traffic and report "clean" by mistake.
- [ ] **OS traffic triggered by launching the app**: `trustd`/`ocspd` (ocsp.apple.com), Gatekeeper and XProtect checks (`api.apple-cloudkit.com`, `*.apple.com`), `apsd`, `mDNSResponder`. List these flows with `attributed:false` so the report can say "macOS did this, not the app". It's an honest point and judges will like it.
- [ ] **Updaters that run as separate processes** (Sparkle `Autoupdate`, `Updater`, `ShipIt` for Squirrel). Their binaries sit inside the bundle, so the path check catches them.
- [ ] **PID reuse** during a run (very unlikely but cheap to handle): key processes on (pid, start time).

**Cold start**
- [ ] The app is **already running** or has a **menu-bar or login-item agent** still alive (Raycast, Obsidian, many others). `preflight` must: quit the app with the quit_script, wait, `pkill -f` anything left inside the bundle path, then confirm `pgrep` finds nothing. Otherwise the "startup call-home" rule is invalid. Record `conditions.cold_start`.
- [ ] **DNS cache**: if the app resolved names before the capture started, there's no DNS answer to map. The sensor runs as root, so run `dscacheutil -flushcache; killall -HUP mDNSResponder` in `POST /runs` and record `dns_flushed`.
- [ ] **Connections that already existed** before the capture (websockets opened earlier): no SNI, so mark `preexisting:true`. A real cold start should give zero of these, so a non-zero count is a warning sign.
- [ ] **Race condition:** don't launch the app until tcpdump is actually capturing. Wait for its "listening on" line on stderr, or for the pcapng file to have a non-zero size, then return from `POST /runs`.

**Protocols**
- [ ] **The ClientHello is split across TCP segments.** Post-quantum key shares (X25519MLKEM768) push ClientHellos to about 1.8 KB, and Chrome **randomises extension order**, so the SNI can be in the *second* segment. Reassemble the first ~4 KB of each client stream before parsing. Test this against Chrome and an Electron app specifically.
- [ ] **ECH (Encrypted Client Hello):** the SNI reads `cloudflare-ech.com` or similar, and the real name is in the encrypted extension. Set `ech:true`. The rules flag this as R5 "hidden destination". That's a finding in itself, not a parse error.
- [ ] **QUIC/HTTP3 (UDP 443):** don't decrypt the QUIC Initial. Take the domain from DNS, set `proto:"quic"` and `transport_note`. Count UDP payload bytes.
- [ ] **DNS-over-HTTPS** (some Electron and Chromium builds): no DNS on port 53. SNI usually still works. For QUIC with DoH, fall back to PTR.
- [ ] **IPv6** everywhere: addresses, the local check, DNS AAAA records.
- [ ] **Plaintext HTTP (port 80) from the target:** keep the first 64 KB of the payload so the R4 canary check (Shri) can search for the typed sentence. Only for attributed flows, never for other apps.
- [ ] **TCP keepalives and pure ACKs** (zero payload): don't create bursts from these.
- [ ] **TLS 1.2 and 1.3** both parse. Read `tls_version` from `supported_versions`.

**Operations**
- [ ] tcpdump has to stop **cleanly**: use SIGINT, then wait, then flush. Kill it with SIGKILL only if it takes more than 3 s, and add a warning. Use `-U` so packets are written to the file as they arrive.
- [ ] **tcpdump left running** after a crash: write a pidfile, kill old processes at daemon startup and in `atexit`.
- [ ] **Run folder ownership:** `chown -R $SUDO_USER` so the web process (running as the user) can write report files.
- [ ] **Your own traffic:** exclude the sensor's and Flask's localhost traffic, and also **Tavily calls made during the run**. Better still, Shri's pipeline only calls Tavily *after* stop.
- [ ] **VPN, iCloud Private Relay, corporate proxy:** `preflight` checks for `utun*` interfaces carrying default routes (`netstat -rn`) and `scutil --proxy`, and warns. Venue Wi-Fi with a captive portal is a reason to **use a phone hotspot**.
- [ ] **Capture size:** cap at 5 minutes or 200 MB, whichever comes first, then stop automatically and warn.
- [ ] **Privacy of our own tool (non-negotiable 2):** after parsing, write `capture.filtered.pcapng` containing attributed flows only (`tcpdump -r raw -w filtered '<bpf of attributed 5-tuples>'`), then **delete the raw file**. Make sure the fixture pcap you commit is the filtered one.
- [ ] **Clocks:** pcap timestamps are wall-clock time. Phases are stamped by `audit.py` with `time.time()` on the same machine, which is fine. Never mix in monotonic time.
- [ ] **Laptop sleep during the demo:** `preflight` tells the presenter to run `caffeinate -dimsu &`.
- [ ] **Daemon security:** bind to `127.0.0.1` only and require the token (CONTRACT §2). Reject `target` and `process_prefixes` values containing `/`, `..` or shell characters, because these end up in file paths and BPF filters. Never use `shell=True`.

**Launching as the user**
- [ ] `audit.py` runs as the user, so `subprocess.run(["open","-a",bundle_path])` is enough. Stamp `t0_launch` immediately *before* calling `open`.
- [ ] If the app shows a **first-run onboarding or login wall**, open it once before the demo so the run is "warm-installed but cold-started". Note this in run.json conditions.

## Privacy-First additions (H8–14): the track asks for software that protects users by design

**1. Self-audit: "we use our own sensor on ourselves".** The pipeline calls Tavily after the target capture stops. Capture that window too, attributing traffic **by PID** (the web process and its children) rather than by name. Output goes to `runs/<id>/self/flows.json` in the same Flow schema. The report puts it next to `egress.json` (what our code *says* it sent). If the two match, that's our proof of privacy by design. Edge cases:
- [ ] The Python process name is just `Python`, so attribute by **PID and child PIDs** (`pgrep -P`), never by name, or you'd pick up every Python on the machine.
- [ ] Tavily's own TLS goes to `api.tavily.com`. The expected self flows are exactly that one domain. Anything else (pip, telemetry from a library, `tldextract` downloading its suffix list) is **a bug in our product**: report it and fix it, don't hide it.
- [ ] If the cache is warm and Tavily isn't called at all, the self-audit shows **zero outbound connections**, which makes the best possible slide.

**2. Enforce: "Hold them to their word".** After a NO ALIBI verdict, the user can block the flagged third-party domains and then **re-audit** to show the app still works without them, or catch it trying a backup route. The method is a marked block in `/etc/hosts` (the sensor already runs as root):
```
# >>> no-alibi (run 2026-11-07T18-00-00Z_quietnotes) — remove with: DELETE /enforce
0.0.0.0 events.cdp-example.net
::      events.cdp-example.net
# <<< no-alibi
```
Edge cases:
- [ ] **Back up `/etc/hosts`** to `~/.noalibi/hosts.bak.<ts>` before *every* write. Write atomically (temp file + `os.replace`) and keep the original permissions (root:wheel 644).
- [ ] **Always undo it:** `DELETE /enforce` on daemon exit (`atexit`, SIGTERM, SIGINT), and at daemon **startup** remove any stale `no-alibi` block left by a crash. Leaving a judge's or teammate's laptop with a broken hosts file is not acceptable.
- [ ] Only touch lines between our markers. Never rewrite the user's own entries.
- [ ] Flush DNS after both applying and removing (`dscacheutil -flushcache; killall -HUP mDNSResponder`), and **quit and relaunch the target** for the re-audit, because already-open connections ignore hosts changes.
- [ ] Hosts entries are **exact names, not wildcards**: block each observed name.
- [ ] **Bypasses:** DNS-over-HTTPS, QUIC, hard-coded IPs. The re-audit catches these. A new connection to the same IP or a different domain in the same category after blocking becomes the finding **"it tried another route"**. Say so in `enforce.json.note`.
- [ ] **Blocking is system-wide** (it affects every app, not only the target). The UI must say so. Only domains with `enforceable:true` are accepted. Reject anything else with a 400, including `apple.com`, the vendor's first-party domains, `localhost`, and anything with whitespace or `#`, because it's going into a root-owned file.

**3. Retention:** at daemon startup, delete `runs/*` older than `NOALIBI_RETENTION_DAYS` (default 7). Log what was removed.

## Acceptance tests (write these as pytest in `noalibi/sensor/tests/`)

1. Replaying the committed fixture pcap produces flows.json and bursts.jsonl that match CONTRACT §4 (validate with a small schema check).
2. A synthetic ClientHello split across 2 segments with SNI in the second still gives the correct domain.
3. A retransmitted segment isn't counted twice.
4. A flow from `Foo Helper (Renderer)` truncated to `Foo Helper (Ren` is attributed to target `Foo`.
5. An `nsurlsessiond` flow with `eproc=Foo` is attributed.
6. Calibration: a 60 s live run on **TextEdit** with no network use produces **zero attributed non-local flows**. This "control run" is also a demo asset.
7. Enforce → hosts contains exactly our block. Unenforce → hosts is **byte-identical** to the backup. Kill the daemon with SIGTERM while enforcing → the block is gone.
8. Enforce with `apple.com` or `"evil.com\n0.0.0.0 github.com"` → 400, hosts unchanged.
9. A self-audit while `pipeline.analyze` runs with a warm cache → `self/flows.json` has zero non-local flows.

## Demo duties (H14+)

- Do the demo machine checklist: hotspot, VPN off, Private Relay off, Do Not Disturb on, notifications off, app updates paused, sensor started **before** going on stage (no sudo prompt in front of the judges), `caffeinate` running, Tavily cache warm.
- Record the **backup video** of a full good run at 1080p. Keep `runs/<best>` and its report on a USB stick and in Drive.
- Keep a **replay button** available: if the live network dies on stage, `replay.py` on the backup pcap produces the same report in 5 seconds.
