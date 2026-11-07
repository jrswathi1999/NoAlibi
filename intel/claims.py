"""Extract the six claim types from a privacy policy, locally, with verified quotes.

- names_ai_provider is deterministic: we search the policy for AI companies named in a sentence
  that is about AI. No model involved, so it cannot hallucinate a provider.
- The other five use a local Ollama model (JSON mode, temperature 0) over the most relevant
  passages only.
- Every quote is checked against the policy text. Exact substring -> "exact"; otherwise the closest
  real sentence must score >= 92 (rapidfuzz partial_ratio) and *that real sentence* becomes the
  quote -> "fuzzy". Anything else is dropped and logged to dropped_claims.json.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import requests
from rapidfuzz import fuzz

from contracts.models import AppInfo, Claim, Claims
from intel.policy import PolicyDoc

log = logging.getLogger("intel.claims")

DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_HOST = "http://localhost:11434"
FUZZY_MIN = 92
CHUNK_CHARS = 1200
CONTEXT_CHARS = 5000
TIMEOUT_S = 120

AI_WORDS = re.compile(
    r"\b(AI|artificial intelligence|machine learning|large language model|LLM|generative|"
    r"model(s)?|chatbot|assistant)\b",
    re.IGNORECASE,
)
PROVIDERS: dict[str, re.Pattern] = {
    "OpenAI": re.compile(r"\bOpenAI\b|\bChatGPT\b|\bGPT-\d", re.IGNORECASE),
    "Anthropic": re.compile(r"\bAnthropic\b", re.IGNORECASE),
    "Google": re.compile(r"\bGemini\b|\bVertex AI\b|\bGoogle (Cloud )?AI\b", re.IGNORECASE),
    "Microsoft": re.compile(r"\bAzure OpenAI\b|\bAzure AI\b|\bMicrosoft Copilot\b", re.IGNORECASE),
    "Amazon": re.compile(r"\bAmazon Bedrock\b|\bAWS Bedrock\b|\bBedrock\b", re.IGNORECASE),
    "Meta": re.compile(r"\bLlama\b|\bMeta AI\b", re.IGNORECASE),
    "Cohere": re.compile(r"\bCohere\b", re.IGNORECASE),
    "Mistral": re.compile(r"\bMistral\b", re.IGNORECASE),
}
# Names that only ever mean an AI company; the rest (Google, Amazon...) need an AI word nearby.
UNAMBIGUOUS_AI = {"OpenAI", "Anthropic", "Cohere", "Mistral"}
# Training / opt-out statements often say "service improvement" instead of "AI".
ABOUT_TRAINING = re.compile(AI_WORDS.pattern + r"|\btrain|\bimprov", re.IGNORECASE)
SHARING = re.compile(
    r"\b(service providers?|third[- ]part(y|ies)|vendors?|subprocessors?|partners)\b", re.IGNORECASE
)


@dataclass(frozen=True)
class Question:
    type: str
    ask: str
    keywords: tuple[str, ...]
    must_match: re.Pattern | None = None  # the quote has to be about this, or the answer is dropped


QUESTIONS = [
    Question(
        "data_stays_local",
        "Does the policy promise that the user's content or data stays on the user's own device "
        "(processed locally, never sent to the company's servers)? yes = it promises that; "
        "no = it says data is sent to or stored on servers or the cloud; unclear = not addressed.",
        (
            "device",
            "local",
            "locally",
            "on-device",
            "servers",
            "cloud",
            "transmit",
            "stored",
            "store",
        ),
    ),
    Question(
        "trains_on_user_data",
        "Does the policy say the company uses user data or content to train or improve AI / machine "
        "learning models? yes = it does use it; no = it explicitly says it does not; "
        "unclear = it does not clearly say either way.",
        (
            "train",
            "training",
            "model",
            "machine learning",
            "improve",
            "artificial intelligence",
            "ai",
        ),
        ABOUT_TRAINING,
    ),
    Question(
        "retention_stated",
        "Does the policy state a concrete retention period (a number of days, months or years, or an "
        "exact deletion rule) for user data? yes = a concrete period is stated; no = only vague words "
        "like 'as long as necessary'; unclear = retention is not discussed.",
        ("retain", "retention", "delete", "deletion", "days", "months", "years", "period", "keep"),
    ),
    Question(
        "ai_opt_out",
        "Can the user opt out of AI features, AI processing, or having their data used to train AI "
        "models? Only count statements about AI, models or training (cookies, marketing emails or "
        "other integrations do NOT count). yes = the user can opt out or turn it off; no = they "
        "cannot; unclear = not addressed.",
        (
            "opt out",
            "opt-out",
            "turn off",
            "disable",
            "train",
            "model",
            "ai",
            "artificial intelligence",
        ),
        ABOUT_TRAINING,
    ),
    Question(
        "shares_with_third_parties",
        "Does the policy say the company shares or discloses user data with third parties, service "
        "providers, vendors or partners? yes = it says it shares; no = it says it never shares; "
        "unclear = not addressed.",
        (
            "share",
            "third part",
            "service provider",
            "vendor",
            "partner",
            "disclose",
            "subprocessor",
        ),
    ),
]

SYSTEM = """You read privacy policies for a privacy audit. Answer ONLY from the policy text given.
Copy the quote WORD FOR WORD from the text: one or two complete sentences that justify the answer.
If the text does not address the question, answer "unclear" with an empty quote.
Reply with JSON only: {"value": "yes" | "no" | "unclear", "quote": "<exact sentence(s)>"}"""


def normalize(text: str) -> str:
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", text).strip().lower()


def sentences(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        out += [
            s.strip()
            for s in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])", line)
            if len(s.strip()) > 20
        ]
    return out


def validate_quote(
    quote: str, policy_text: str, policy_sentences: list[str]
) -> tuple[str, str] | None:
    """Return (quote_to_store, "exact"|"fuzzy") or None if the quote isn't really in the policy."""
    q = normalize(quote)
    if len(q) < 15:
        return None
    if q in normalize(policy_text):
        return quote.strip(), "exact"
    best, score = None, 0.0
    for s in policy_sentences:
        sc = fuzz.partial_ratio(q, normalize(s))
        if sc > score:
            best, score = s, sc
    if best and score >= FUZZY_MIN:
        return best, "fuzzy"
    return None


def chunk(text: str, size: int = CHUNK_CHARS) -> list[str]:
    """Paragraph-aligned chunks of at most `size` chars; long paragraphs are split by sentence."""
    pieces: list[str] = []
    for para in text.split("\n"):
        if len(para) <= size:
            pieces.append(para)
            continue
        cur = ""
        for sent in re.split(r"(?<=[.!?])\s+", para):
            if cur and len(cur) + len(sent) + 1 > size:
                pieces.append(cur)
                cur = ""
            cur = f"{cur} {sent}".strip()
        if cur:
            pieces.append(cur[: size * 2])
    chunks, cur = [], ""
    for piece in pieces:
        if cur and len(cur) + len(piece) + 1 > size:
            chunks.append(cur)
            cur = ""
        cur = f"{cur}\n{piece}" if cur else piece
    if cur:
        chunks.append(cur)
    return chunks


def relevant_context(text: str, keywords: tuple[str, ...], limit: int = CONTEXT_CHARS) -> str:
    """Highest-scoring chunks for these keywords, kept in document order, up to `limit` chars."""
    chunks = chunk(text)
    scored = []
    for i, c in enumerate(chunks):
        low = c.lower()
        score = sum(low.count(k) for k in keywords)
        if score:
            scored.append((score, i))
    picked: list[int] = []
    total = 0
    for _, i in sorted(scored, reverse=True):
        if total + len(chunks[i]) > limit:
            continue
        picked.append(i)
        total += len(chunks[i])
    if not picked and scored:  # every relevant chunk is bigger than the budget: keep the best one
        best = max(scored)[1]
        return chunks[best][:limit]
    return "\n...\n".join(chunks[i] for i in sorted(picked))


def ask_ollama(question: Question, context: str, model: str, host: str) -> dict:
    body = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"QUESTION: {question.ask}\n\nPOLICY TEXT:\n{context}"},
        ],
    }
    resp = requests.post(f"{host.rstrip('/')}/api/chat", json=body, timeout=TIMEOUT_S)
    resp.raise_for_status()
    data = json.loads(resp.json()["message"]["content"])
    value = str(data.get("value", "unclear")).lower().strip()
    if value not in ("yes", "no", "unclear"):
        value = "unclear"
    return {"value": value, "quote": str(data.get("quote") or "").strip()}


def provider_claim(doc: PolicyDoc, policy_sentences: list[str]) -> dict | None:
    """Deterministic names_ai_provider: AI companies named in AI-related sentences."""
    named: list[str] = []
    quote = None
    for s in policy_sentences:
        about_ai = bool(AI_WORDS.search(s))
        hits = [
            name
            for name, pat in PROVIDERS.items()
            if pat.search(s) and (about_ai or name in UNAMBIGUOUS_AI)
        ]
        if hits:
            named += [h for h in hits if h not in named]
            quote = quote or s
    if named and quote:
        return {"value": "yes", "providers": named, "quote": quote}
    sharing = [s for s in policy_sentences if SHARING.search(s) and len(s) < 400]
    if sharing:  # the policy talks about recipients without naming any AI company
        ai_sharing = [s for s in sharing if AI_WORDS.search(s)]
        return {"value": "no", "providers": [], "quote": (ai_sharing or sharing)[0]}
    return None


NEGATED = re.compile(r"\b(do|does|will) not\b|\bnever\b|\bdon't\b|\bdoesn't\b", re.IGNORECASE)
USES_DATA = re.compile(
    r"\b(may|will|can) use\b|\bwe use\b|\bbe used\b|\bmay be used\b", re.IGNORECASE
)
OPT_OUT = re.compile(
    r"\bopt[- ]?out\b|\bopt you out\b|\bturn off\b|\bdisable\b|\bwithdraw\b", re.IGNORECASE
)


def opt_out_claim(policy_sentences: list[str]) -> dict | None:
    """Deterministic ai_opt_out = yes: a sentence offering an opt-out from AI use / training."""
    for s in policy_sentences:
        if (
            OPT_OUT.search(s)
            and ABOUT_TRAINING.search(s)
            and not re.search(r"\bcannot\b|\bcan't\b", s, re.IGNORECASE)
        ):
            return {"value": "yes", "providers": [], "quote": s}
    return None


def extract_claims(
    run_id: str,
    app_name: str,
    doc: PolicyDoc,
    model: str | None = None,
    host: str | None = None,
    on_claim: Callable[[Claim], None] | None = None,
    on_progress: Callable[[str], None] | None = None,
    dropped_path: Path | None = None,
) -> Claims:
    """Build a validated Claims object. Ollama failures leave that claim type out (scorecard: unclear)."""
    model = model or os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL
    host = host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST
    policy_sentences = sentences(doc.text)
    claims: list[Claim] = []
    dropped: list[dict] = []

    def add(ctype: str, raw: dict) -> None:
        if (
            ctype == "trains_on_user_data"
            and raw["value"] == "yes"
            and NEGATED.search(raw["quote"])
        ):
            # A "yes" must be quoted with a sentence that says yes, not with an exception to it.
            better = next(
                (
                    x
                    for x in policy_sentences
                    if USES_DATA.search(x) and ABOUT_TRAINING.search(x) and not NEGATED.search(x)
                ),
                None,
            )
            if better:
                raw = {**raw, "quote": better}
        checked = validate_quote(raw["quote"], doc.text, policy_sentences) if raw["quote"] else None
        if not checked:
            dropped.append({"type": ctype, **raw, "reason": "quote not found in policy"})
            return
        quote, match = checked
        claim = Claim(
            id=f"c{len(claims) + 1}",
            type=ctype,  # type: ignore[arg-type]
            value=raw["value"],  # type: ignore[arg-type]
            providers=raw.get("providers", []),
            quote=quote,
            source_url=doc.url,
            validated=True,
            match=match,  # type: ignore[arg-type]
        )
        claims.append(claim)
        if on_claim:
            on_claim(claim)

    if on_progress:
        on_progress("Looking for named AI companies")
    prov = provider_claim(doc, policy_sentences)
    if prov:
        add("names_ai_provider", prov)

    opt = opt_out_claim(policy_sentences)
    if opt:
        add("ai_opt_out", opt)

    for q in QUESTIONS:
        if q.type == "ai_opt_out" and opt:
            continue  # already answered from the policy's own words
        if on_progress:
            on_progress(f"Reading: {q.type.replace('_', ' ')}")
        context = relevant_context(doc.text, q.keywords)
        if not context:
            continue
        try:
            raw = ask_ollama(q, context, model, host)
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            log.warning("%s: Ollama failed: %s", q.type, exc)
            dropped.append({"type": q.type, "reason": f"local model error: {exc}"})
            continue
        if raw["value"] == "unclear" and not raw["quote"]:
            dropped.append({"type": q.type, **raw, "reason": "policy does not address it"})
            continue
        if q.must_match and not q.must_match.search(raw["quote"]):
            dropped.append({"type": q.type, **raw, "reason": "quote is not about AI"})
            continue
        add(q.type, raw)

    if dropped_path:
        dropped_path.write_text(json.dumps(dropped, indent=1) + "\n", encoding="utf-8")
    return Claims(
        run_id=run_id,
        app=AppInfo(
            name=app_name,
            policy_url=doc.url,
            subprocessor_url=None,
            fetched_at=doc.fetched_at,
            policy_sha256=doc.sha256,
        ),
        model=model,
        claims=claims,
    )
