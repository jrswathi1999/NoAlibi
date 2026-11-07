# No Alibi

**Checks whether a desktop app keeps its privacy promises about AI and your data.**

1. **Claims:** a local Ollama model reads the app's privacy policy and pulls out what it promises,
   with an exact quote for each promise (quotes not found in the policy are dropped).
2. **Behavior:** while you use the app, No Alibi records every connection it makes (domain, size,
   timing, TLS). Nothing is decrypted or blocked.
3. **Verdict:** rules compare promises with behavior and produce a one-page report linking each
   broken promise to the network event behind it, with a SHA-256 hash of the evidence.

Only app names and domain names ever leave the machine (to Tavily/Exa). The policy reading runs
locally.

## Setup (Windows)

Needs Python 3.11+, [Ollama](https://ollama.com), and Wireshark (with Npcap) for `tshark`.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env          # then paste your Tavily / Exa keys into .env
ollama pull qwen2.5:7b
.\.venv\Scripts\python.exe -m pytest -q
```

## Data contracts

Modules talk only through three JSON files in `data/runs/<run_id>/`, defined in
`contracts/models.py` with samples in `contracts/fixtures/`:

| File | Written by | Holds |
|---|---|---|
| `claims.json` | `claims/` | What the policy promises, with validated quotes |
| `events.json` | `behavior/` | Every connection the app made |
| `findings.json` | `engine/` | Broken promises, scorecard, summary, evidence hash |

`run_id` looks like `20261107-201500-notesapp`. All times are ISO 8601 UTC.
