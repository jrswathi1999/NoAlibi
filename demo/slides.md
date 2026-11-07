# No Alibi — slides (5 max)

Fill the `[brackets]` after the first real run (CP2). Everything else is final copy.

---

## 1. The problem

- Desktop apps are shipping AI features fast. Their privacy policies say "trusted service providers".
- Nobody checks whether the app's *behavior* matches the policy's *words*.
- Security and vendor-risk teams rely on questionnaires the vendor fills in themselves.

> "Your notes stay on your device." — then 12 KB goes to an AI company two seconds after you click Summarize.

---

## 2. How it works (3 steps)

1. **Claims** — a local Ollama model reads the privacy policy and pulls out 6 promises, each with an exact quote we verify against the text.
2. **Behavior** — the app runs in an isolated Linux network namespace. We record every connection: domain, size, timing. No decryption.
3. **Verdict** — six rules compare promises with behavior. One-page report, every finding linked to the quote and the network event, SHA-256 over the evidence.

---

## 3. Live demo

- Target: **[target app]**
- Policy says: "[vague quote]"
- App did: **[N KB to api.xxx.com, 2 s after the AI click]**
- Footer: *Only domain names left this machine. The AI that read the policy runs locally.*

---

## 4. Why it's different

|                          | Policy readers (ToS;DR etc.) | Network monitors (Little Snitch etc.) | **No Alibi** |
|--------------------------|:---:|:---:|:---:|
| Reads the policy         | ✅ | ❌ | ✅ (local LLM, verified quotes) |
| Watches real traffic     | ❌ | ✅ | ✅ (no decryption) |
| Says *which promise broke* | ❌ | ❌ | ✅ |
| Evidence you can re-hash | ❌ | ❌ | ✅ SHA-256 |
| Policy leaves the laptop | n/a | n/a | ❌ never |

---

## 5. Business model — B2B vendor risk

- **Customers:** enterprise security and vendor-risk teams approving AI tools.
- **Today:** questionnaires the vendor fills in. **With us:** verified evidence.
- **Pricing:** per seat + per exported audit report.
- **Closest comparable:** AppCensus (does this for mobile apps). We do desktop + AI.

Team: Swathi (claims, local model) · Shivam (capture) · Shri (engine, report) · Tracks: Privacy-First, Surge, Most Startup-able
