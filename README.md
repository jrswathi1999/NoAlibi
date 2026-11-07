# No Alibi

**No Alibi checks whether a desktop app keeps its privacy promises about AI and your data.**

A local model reads the app's privacy policy and pulls out what it promises. The app then runs in an
isolated Linux network namespace while No Alibi records every connection it makes. A rule engine
compares promises with behavior and produces a one-page report that links each broken promise to the
network event behind it, with a SHA-256 hash of the evidence.

We never decrypt traffic, never block traffic and never modify the audited app. Only an app name or a
domain name ever leaves the laptop (to Tavily/Exa). The policy is read by a local Ollama model.

Built at HACK1984 (Nov 7-8, 2026).

## How it works

```
             app name                                  app command
                |                                           |
                v                                           v
   +-------------------------+              +-------------------------------+
   | claims/  (Swathi)       |              | behavior/  (Shivam)           |
   | Tavily -> policy text   |              | netns sandbox + tcpdump       |
   | chunk -> local Ollama   |              | tshark -> flows -> endpoints  |
   | quote validator         |              | mark user actions             |
   +-----------+-------------+              +---------------+---------------+
               | claims.json                                | events.json + run.pcap
               +---------------------+----------------------+
                                     v
                      +------------------------------+
                      | engine/  (Shri)              |
                      | six rules -> findings.json   |
                      | SHA-256 evidence hash        |
                      | local Ollama summary         |
                      +--------------+---------------+
                                     v
                      +------------------------------+
                      | report/  (Shri)              |
                      | report.html (one page)       |
                      +------------------------------+
```

The three modules talk only through three JSON files in `data/runs/<run_id>/`, defined as pydantic
models in [`contracts/models.py`](contracts/models.py) with sample fixtures in `contracts/fixtures/`.

## Quick start

```bash
make setup                 # venv + requirements + .env from .env.example
ollama pull qwen2.5:7b     # or llama3.2:3b on slower machines
make test
```

Full audit (Linux, needs `tcpdump`, `tshark`, `iproute2`, `iptables`):

```bash
./scripts/run_audit.sh "NotesApp" "notesapp"
```

Offline demo from saved files (no network, no capture):

```bash
./scripts/run_audit.sh --offline "NotesApp"
```

API server (optional):

```bash
make serve    # POST /audit {"app_name": "...", "cmd": "..."}  ->  GET /report/{run_id}
```

## Rules

| Rule | Severity | Fires when |
|------|----------|------------|
| R1 undisclosed AI provider | red | an AI provider receives traffic but the policy never names it |
| R2 local promise broken | red | policy says data stays local, but more than 2 KB leaves to a third party right after a user action |
| R3 background telemetry | amber | 3+ evenly spaced connections to one domain while idle |
| R4 content upload suspicion | amber | more than 5 KB to one domain within 5 s of a user action |
| R5 silent on training | amber | an AI provider is contacted and the policy is unclear about training on user data |
| R6 unknown recipient | info | traffic to a domain we cannot categorize (with a search-based lookup) |

## Team

| Person | Module |
|--------|--------|
| Swathi | claims pipeline (`claims/`) |
| Shivam | behavior pipeline (`behavior/`) |
| Shri | comparison engine, report, orchestrator (`engine/`, `report/`, `app/`) |

Tracks: Privacy-First, Surge (Tavily/Exa), Most Startup-able.
