"""Plain-English summary of findings.json, written by a local Ollama model.

Only the findings and the scorecard are sent to the model (on localhost). Output that names a
domain or company not present in the findings is rejected, and after 3 tries we keep the
deterministic summary written by compare.py. The pipeline never fails because of this step.

CLI:  python -m engine.summarize --run-dir data/runs/<run_id>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path

import requests

from contracts.models import Findings, load_model, save_model

log = logging.getLogger("engine.summarize")

DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_HOST = "http://localhost:11434"
MAX_TRIES = 3
TIMEOUT_S = 60

# Companies a model might invent. Any of these in the summary must also appear in the findings.
# Names that are also everyday words (Segment, Heap, Together) are left out on purpose.
KNOWN_COMPANIES = [
    "OpenAI", "Anthropic", "Google", "Gemini", "Microsoft", "Azure", "Amazon", "AWS", "Meta",
    "Facebook", "Apple", "Cohere", "Mistral", "Groq", "Perplexity", "Mixpanel",
    "Amplitude", "PostHog", "Hotjar", "DoubleClick", "Sentry", "Bugsnag",
    "Datadog", "Cloudflare", "Tavily", "Exa",
]  # fmt: skip
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)

SYSTEM_PROMPT = """You explain privacy audit results to non-technical people.
You get JSON with findings (severity red = broken promise, amber = suspicious, info = context)
and sentences describing what the privacy policy says. Never contradict those sentences.
Write exactly 3 or 4 short, plain sentences. Lead with the most serious finding.
Use ONLY facts in the JSON. Do not add companies, domains, numbers or advice that are not in it.
Do not use markdown.
Reply with JSON only: {"sentences": ["<sentence 1>", "<sentence 2>", "<sentence 3>"]}"""


POLICY_FACTS = {
    "data_stays_local": (
        "The policy promises your data stays on your device.",
        "The policy does NOT promise that your data stays on your device.",
    ),
    "names_ai_provider": (
        "The policy names the AI company it uses.",
        "The policy does NOT name any AI company it uses.",
    ),
    "trains_on_user_data": (
        "The policy says your data is used to train AI.",
        "The policy says your data is NOT used to train AI.",
    ),
    "retention_stated": (
        "The policy states a concrete retention period.",
        "The policy does NOT state a concrete retention period.",
    ),
    "ai_opt_out": (
        "The policy lets you opt out of AI.",
        "The policy does NOT offer an AI opt-out.",
    ),
    "shares_with_third_parties": (
        "The policy says it shares data with third parties.",
        "The policy says it does NOT share data with third parties.",
    ),
}
NEGATION = re.compile(r"\b(not|never|no|doesn't|does not|isn't|without)\b", re.IGNORECASE)
LOCAL_PROMISE = re.compile(r"stays? (only )?on your (device|computer|machine)", re.IGNORECASE)


def policy_sentences(scorecard: dict) -> list[str]:
    """Scorecard as unambiguous sentences; small models misread bare yes/no keys."""
    out = []
    for key, value in scorecard.items():
        yes, no = POLICY_FACTS.get(key, (f"{key}: yes.", f"{key}: no."))
        if value == "yes":
            out.append(yes)
        elif value == "no":
            out.append(no)
        else:
            out.append(
                f"Unclear: the policy does not say. ({yes.removeprefix('The policy ').rstrip('.')})"
            )
    return out


def build_payload(findings: Findings) -> dict:
    """The only data the model sees: finding severities/titles and what the policy says."""
    return {
        "findings": [
            {"severity": f.severity, "rule": f.rule, "title": f.title} for f in findings.findings
        ],
        "what_the_policy_says": policy_sentences(findings.scorecard),
    }


def first_messages(payload: dict) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, indent=2)},
    ]


def _parse_reply(content: str) -> str:
    """Accept {"sentences": [...]} (asked for) or {"summary": "..."} (what small models drift to)."""
    data = json.loads(content)
    if isinstance(data.get("sentences"), list):
        parts = [str(x).strip() for x in data["sentences"] if str(x).strip()]
        text = " ".join(p if p[-1] in ".!?" else p + "." for p in parts)
    else:
        text = data["summary"]
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty summary")
    return " ".join(text.split())


def call_ollama(messages: list[dict], model: str, host: str, timeout: float = TIMEOUT_S) -> str:
    """Ask Ollama for a summary. Returns the summary text; raises RuntimeError on any failure."""
    body = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
        "messages": messages,
    }
    try:
        resp = requests.post(f"{host.rstrip('/')}/api/chat", json=body, timeout=timeout)
        resp.raise_for_status()
        return _parse_reply(resp.json()["message"]["content"])
    except requests.ConnectionError as exc:
        raise ConnectionError(f"Ollama not reachable at {host}") from exc
    except (requests.RequestException, KeyError, TypeError, AttributeError, ValueError) as exc:
        raise RuntimeError(f"bad Ollama response: {exc}") from exc


def count_sentences(text: str) -> int:
    # Ignore dots inside domains/numbers like api.openai.com or 1.5 by requiring a space after.
    return len([s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s])


def summary_problems(summary: str, findings: Findings) -> list[str]:
    """Reasons to reject a summary. Empty list means it is acceptable."""
    problems = []
    source = json.dumps(build_payload(findings)).lower()

    n = count_sentences(summary)
    if not 2 <= n <= 5:
        problems.append(f"{n} sentences, wanted 3 to 4")
    if findings.scorecard.get("data_stays_local") != "yes":
        for sentence in re.split(r"(?<=[.!?])\s+", summary):
            if LOCAL_PROMISE.search(sentence) and not NEGATION.search(sentence):
                problems.append("claims the policy promises data stays on the device; it does not")
                break
    for domain in DOMAIN_RE.findall(summary):
        if domain.lower() not in source:
            problems.append(f"names domain not in findings: {domain}")
    for company in KNOWN_COMPANIES:
        mentioned = re.search(rf"\b{re.escape(company)}\b", summary, re.IGNORECASE)
        if mentioned and company.lower() not in source:
            problems.append(f"names company not in findings: {company}")
    return problems


def summarize(findings: Findings, model: str | None = None, host: str | None = None) -> str | None:
    """Return a validated Ollama summary, or None if every try failed."""
    model = model or os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL
    host = host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST
    messages = first_messages(build_payload(findings))
    for attempt in range(1, MAX_TRIES + 1):
        try:
            text = call_ollama(messages, model, host)
        except ConnectionError as exc:
            log.warning("%s; keeping the plain summary", exc)
            return None
        except RuntimeError as exc:
            log.warning("try %d: %s", attempt, exc)
            continue
        problems = summary_problems(text, findings)
        if not problems:
            return text
        log.warning("try %d rejected: %s", attempt, "; ".join(problems))
        # Temperature is 0, so tell the model what was wrong or it repeats itself.
        messages = [
            *messages,
            {"role": "assistant", "content": json.dumps({"sentences": [text]})},
            {"role": "user", "content": "Fix this: " + "; ".join(problems) + ". Same JSON format."},
        ]
    return None


def run_summarize(run_dir: str | Path, model: str | None = None) -> Path:
    """Replace findings.json's summary with the Ollama one when it passes validation."""
    path = Path(run_dir) / "findings.json"
    findings = load_model(path, Findings)
    if not findings.findings:
        log.info("no findings, keeping the plain summary")
        return path
    text = summarize(findings, model=model)
    if text:
        save_model(path, findings.model_copy(update={"summary": text}))
        log.info("summary written by local model")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a plain-English summary with Ollama.")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--model", help=f"Ollama model (default $OLLAMA_MODEL or {DEFAULT_MODEL})")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    try:
        run_summarize(args.run_dir, model=args.model)
    except ValueError as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
