# Devpost draft

**Name:** No Alibi

**One-liner:** No Alibi checks whether a desktop app keeps its privacy promises about AI and your data.

## Inspiration
Every app is adding an AI button. The privacy policy says "we may share information with trusted service providers" and stops there. Vendor-risk teams approve these tools from questionnaires the vendor fills in. We wanted evidence instead of promises.

## What it does
1. A **local** Ollama model reads the app's privacy policy and subprocessor page and extracts six promises (data stays local, names its AI provider, trains on your data, retention, AI opt-out, third-party sharing), each backed by an exact quote we verify against the source text.
2. The app runs in an isolated Linux network namespace while we record every connection it makes: domain, size, timing, TLS. We never decrypt or block anything.
3. Six rules compare promises with behavior and produce a one-page report. Each broken promise links to the quote and to the network event behind it, with a SHA-256 hash of the evidence.

On **[target app]** we found: **[real red finding from CP2]**.

## How we built it
- Python 3.11, pydantic v2 contracts between three independent modules
- Ollama (`qwen2.5:7b` / `llama3.2:3b`) in JSON mode, temperature 0, quote validation with rapidfuzz
- `ip netns`, `iptables`, `tcpdump`, `tshark` for capture; SNI + DNS for domain mapping
- Tavily (Exa fallback) for policy fetch and unknown-domain lookup — **only app names and domain names** are sent
- Jinja2 single-file report (light/dark), FastAPI + one shell command for the full audit

## Challenges
- Small local models drift from the requested JSON and invent quotes — we validate every quote against the policy and re-prompt with the exact problem.
- Mapping encrypted flows to domains without decryption (SNI first, DNS second, never reverse lookup).
- Getting GUI apps to run inside a network namespace.

## Accomplishments
- The policy text and the findings never leave the laptop. Our own tool passes its own audit: **[self-audit result]**.
- Every finding is reproducible: same files, same hash.

## What's next
Windows/macOS capture, a vendor-risk export format, and continuous re-audits when an app or its policy changes.

## Tracks
Privacy-First · Surge (Tavily/Exa) · Most Startup-able

## Team
Swathi Jinka Radhakrishna (claims pipeline) · Shivam (behavior capture) · Shrivarshini Narayanan (engine, report, orchestrator)

**Links:** repo [url] · video [url from demo/backup_video_link.txt] · slides [pdf]
