# 60-second demo script

Shri pitches, Shivam drives, Swathi takes model/privacy questions. Time it out loud twice.

| Time | Who | Say / do |
|------|-----|----------|
| 0–10 s | Shri | "This app says your data stays private. Its policy never names an AI company. Let's check." |
| 10–25 s | Shivam | Run `scripts/run_audit.sh "[App]" "[cmd]"`. App opens in the sandbox. Use the AI feature once, press **Enter** to mark it. |
| 25–40 s | Shri | Report opens. Hover the red finding. "Left: the policy's vague sentence. Right: [12 KB] to [api.openai.com] two seconds after the click. Red line between them." |
| 40–50 s | Shri | Point at the footer. "Only domain names left this laptop. The AI that read the policy runs locally." |
| 50–60 s | Shri | "We didn't block it or decrypt it. We compared its promise with its behavior. It didn't match." |

## If something breaks

| Problem | Do this | Say |
|---------|---------|-----|
| Live capture fails | `scripts/run_audit.sh --offline "[App]"` | "This is the capture we recorded an hour ago, same pipeline." |
| Ollama slow | Summary falls back automatically | nothing |
| Everything fails | Play the backup video (`demo/backup_video_link.txt`) | "Here's the recorded run." |

## Likely judge questions (owner)

- *Why a local model?* (Swathi) — the policy and findings never leave the laptop; only app/domain names go to search.
- *How do you stop hallucinations?* (Swathi) — every quote must be found in the policy text (exact or ≥92 fuzzy) or the claim is dropped; the summary is rejected if it names any company or domain not in the findings.
- *What can't you see?* (Shri) — server-side AI calls the vendor makes after the data reaches their own backend. We report what leaves the device.
- *Is this legal?* (Shri) — we never decrypt or modify traffic; we record metadata of the user's own machine.
