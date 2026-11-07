# No Alibi

**Apps make promises. No Alibi checks their alibi.**

No Alibi reads a desktop app's privacy policy with a **local** AI, watches every connection the app
makes while you use it, and shows you exactly where the promise and the behavior disagree, with
each broken promise tied to the network evidence and sealed with SHA-256.

- **No sandbox, no root.** It attributes traffic using macOS's own per-socket counters (`nettop`)
  for every process inside the app's bundle, so you can audit the real app in its real environment.
- **No decryption, nothing blocked, nothing modified.** Record only.
- **Nothing about you leaves the machine.** The policy is read by Ollama on localhost. Every network
  action No Alibi itself takes is written to a ledger and shown on the verdict.

Built at HACK1984 (Nov 7–8, 2026). Tracks: **Privacy-First**, **Surge (Tavily/Exa)**, **Most Startup-able**.

---

## Try it

```bash
make setup                  # venv + requirements + .env from .env.example
ollama pull qwen2.5:7b      # the local model that reads policies (llama3.2:3b also works)
make app                    # opens http://127.0.0.1:5050
```

1. **Pick an app** from your installed apps (icons, "running" and "policy known" badges).
2. **Start the audit.** A cold start quits and reopens the app so you also see what it does at launch.
3. **Use the app.** When you try its AI feature, press **I just used the AI feature** (or `M`). No Alibi
   reports what left the app in the next 5 seconds.
4. **Stop** (`S`). In under a minute you get the verdict: **NO ALIBI**, **QUESTIONABLE** or **ALIBI HOLDS**.

Optional: put `TAVILY_API_KEY` (or `EXA_API_KEY`) in `.env` to look up domains we can't identify.
Only the domain name is sent.

## What you see

| Screen | What it shows |
|---|---|
| **Live wiretap** | A constellation: the app in the center, every destination placed by kind (AI providers, analytics, crash reporting, the app's own servers, CDNs). Packets fly out as bytes leave. Live totals, including **No Alibi's own traffic to third parties**. Meanwhile the policy is read, and each promise appears with its verified quote. |
| **The case board** | Promises (left), findings (middle), evidence (right), joined by red strings. Hover a finding to light up only its promise and its connections. |
| **Timeline** | Every upload burst over time, with the launch window and your marked actions. |
| **Footprint** | Every network action No Alibi took (DNS lookups of catalog domains, certificate checks, the policy download), and what the sensor saw No Alibi send. |
| **Sealed evidence** | SHA-256 over claims + events + the raw sensor log, a manifest of every file, and a downloadable `.zip`. A printable one-page report. |

## How it works

```
                                 ┌──────────────────────────────────────────┐
   installed app ───────────────►│ sensor/ (no root)                         │
   (every process in its bundle) │  nettop: per-process socket byte counters │
                                 │  1-second bursts, phases, your marks      │
                                 │  identify: DNS match x TLS certificate x  │
                                 │  CDN ranges -> domain, owner, confidence  │──► events.json
                                 └──────────────────────────────────────────┘
                                 ┌──────────────────────────────────────────┐
   public policy URL ───────────►│ intel/                                    │
                                 │  fetch -> clean text -> local Ollama      │
                                 │  every quote verified word for word       │──► claims.json
                                 └──────────────────────────────────────────┘
                                 ┌──────────────────────────────────────────┐
                                 │ engine/  six rules -> findings            │
                                 │  evidence-strength guard, verdict         │
                                 │  local plain-English summary, SHA-256     │──► findings.json
                                 └──────────────────────────────────────────┘
                                 ┌──────────────────────────────────────────┐
                                 │ app/ (FastAPI, 127.0.0.1) + web/ (no CDN) │──► live UI, report, evidence.zip
                                 └──────────────────────────────────────────┘
```

The three JSON files follow the team contract in [`contracts/models.py`](contracts/models.py), so
this build interoperates with the sandbox capture (`behavior/`) and the claims module.
One difference: here an event is an *activity burst* on a connection (1-second resolution), so an
AI request sent over an already-open connection still lines up with the moment you clicked.

### Rules

| Rule | Severity | Fires when |
|---|---|---|
| R1 undisclosed AI provider | red | an AI company receives data but the policy never names it |
| R2 local promise broken | red | the policy says data stays on your device, yet more than 2 KB leaves for a third party right after you act |
| R3 background telemetry | amber | 3+ clockwork-regular bursts to one domain while idle |
| R4 content-sized upload | amber | more than 5 KB to one domain within 5 s of your action |
| R5 silent on training | amber | it talks to an AI company and the policy is unclear on training |
| R6 unknown recipient | info | a destination we couldn't confirm |

### Fairness: why you can trust a red finding

- **Quotes are real.** Every promise is checked word for word against the policy page. A
  near-match is replaced by the real sentence; anything else is dropped (`dropped_claims.json`).
- **AI providers are detected without a model.** `names_ai_provider` is a deterministic search, so
  it can't hallucinate a company.
- **Destinations carry a confidence.** *confirmed* (DNS and certificate agree), *likely*, *possible*
  (a shared CDN address; we bundle CloudFront, Cloudflare and Fastly's published ranges), *weak*.
  **A red finding resting only on a *possible* match is downgraded to amber and labelled.**
- **The summary can't invent.** It sees only the findings, and it's rejected if it names a company or
  domain that isn't in them, or claims a promise the policy doesn't make.
- **We don't overstate.** "An upload large enough to contain what you typed," never "it sent your note."
- **We never restart an app No Alibi runs inside** (e.g. a terminal inside it).

### What we can't see

Server-side AI calls (the vendor's backend forwarding your data), the contents of encrypted traffic,
and connections that open and close inside one 1-second sample. The verdict page says so too.

## Real results on this machine

| App | Verdict | Why |
|---|---|---|
| Ollama 0.33 | **ALIBI HOLDS** | Policy: "Your data stays on your machine." A prompt was run during the audit and **0 bytes** left the app. |
| Google Chrome 156 | **QUESTIONABLE** | A burst to a CloudFront address within 5 s of the marked action. Chrome traffic that DNS matched to a DeepSeek domain was held at *possible* (shared CDN address), not accused. |

## Repo layout

```
sensor/    nettop stream, process attribution, identification, live session, egress ledger
intel/     policy fetch, local claim extraction, optional Tavily/Exa lookup, known apps
engine/    rules, compare, evidence hash, local summary
report/    one-page printable report (Jinja2)
app/       audit orchestrator + FastAPI server (python -m app)
web/       the UI: index.html, style.css, app.js (no frameworks, no CDN)
contracts/ shared pydantic models + sample fixtures used by the tests
scripts/   update_cdn_ranges.py
tests/     pytest (make test)
```

## Team

| Person | Role |
|---|---|
| Swathi | claims pipeline, local model |
| Shivam | sandbox capture (`behavior/`) |
| Shri | engine, report, this no-sandbox build and UI, pitch |
