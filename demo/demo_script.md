# 90-second demo script (no-sandbox build)

Shri pitches, Shivam drives, Swathi takes model and privacy questions. Rehearse it out loud twice.
Before going on stage: `make app` is running, the target app is installed and logged in, and its AI
feature is ready to try.

| Time | Who | Say / do |
|------|-----|----------|
| 0–10 s | Shri | "Every app with an AI button says it respects your privacy. Nobody checks. No Alibi does, on your own Mac, without root, without decrypting anything." |
| 10–20 s | Shivam | Pick the app from the grid. Its policy URL is already filled in. **Start audit.** The app quits and reopens (cold start). |
| 20–40 s | Shri | Point at the constellation as destinations appear. "Every process inside the app, attributed by the kernel's own counters. Meanwhile a *local* model is reading the policy. Each promise appears with a quote we've checked word for word." |
| 40–50 s | Shivam | Use the AI feature once, press **M**. The bar says "Caught: N KB → domain within 5 s of your action" (or "nothing left the app"). |
| 50–70 s | Shivam / Shri | Press **S**. The verdict stamp lands. Hover the top finding: the red string joins the policy's sentence to the network evidence. |
| 70–85 s | Shri | Scroll to **No Alibi's own footprint**: "0 bytes of your data left. Here is every network action our tool took." Then the SHA-256 seal: "Anyone can recompute this." |
| 85–90 s | Shri | "We didn't block it, and we didn't decrypt it. We compared its promise with its behavior." |

## If the app keeps its promise

That's a result too. "ALIBI HOLDS" with sealed evidence is exactly what a vendor-risk team wants to
attach to an approval. Ollama is a good example: its policy says "Your data stays on your machine,"
and the audit shows 0 bytes leaving while a prompt runs.

## If something breaks

| Problem | Do this | Say |
|---------|---------|-----|
| The local model is slow | The audit still finishes, and the summary falls back to plain text | nothing |
| The app won't quit for a cold start | Turn off Cold start and watch it running | "We can also attach to a running app." |
| Everything fails | Open **Case files** and show the last real verdict, or play the backup video | "Here's the run we recorded an hour ago." |

## Likely judge questions (owner)

- *Why a local model?* (Swathi) The policy, the findings and your traffic never leave the laptop.
- *How do you stop hallucinations?* (Swathi) Quotes are verified word for word. Provider names are found
  without a model. The summary is rejected if it names anything not in the findings.
- *How do you know who a server is without decrypting?* (Shri) DNS matches cross-checked against the
  server's own TLS certificate, plus the CDNs' published IP ranges. Shared CDN addresses are labelled
  "possible" and can never produce a red finding alone.
- *What can't you see?* (Shri) Server-side AI calls, encrypted contents, and connections shorter than
  one second.
- *Isn't this Little Snitch?* (Shri) That blocks traffic. We produce evidence that links a promise to a
  behavior, which is what procurement and vendor-risk teams need.
