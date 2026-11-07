"""The six comparison rules (Section 10, R2).

Each rule takes the validated claims and events and returns a list of findings. Finding ids are
left empty here; compare.py numbers them after sorting. Rules only read their inputs.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from datetime import timedelta
from itertools import pairwise
from statistics import mean, pstdev

from contracts.models import Claim, Claims, ClaimType, Event, Events, Finding

Rule = Callable[[Claims, Events], list[Finding]]

R2_MIN_BYTES_OUT = 2048  # per event, user_action phase
R3_MIN_EVENTS = 3
R3_MAX_GAP_CV = 0.20  # std of gaps under 20% of the mean gap
R4_WINDOW = timedelta(seconds=5)
R4_MIN_BYTES_OUT = 5120  # summed per domain inside the window
R2_EXEMPT_CATEGORIES = {"first_party", "update"}

# Names that refer to the same AI company. Lower-case, letters and digits only.
PROVIDER_ALIASES: list[set[str]] = [
    {"openai", "chatgpt"},
    {"anthropic", "claude"},
    {"google", "gemini", "vertex", "googleai"},
    {"microsoft", "azure", "azureopenai"},
    {"amazon", "aws", "bedrock"},
    {"cohere"},
    {"mistral", "mistralai"},
    {"groq"},
    {"together", "togetherai"},
    {"perplexity"},
]


# ---------------------------------------------------------------- helpers


def human_bytes(n: int) -> str:
    """12034 -> '12 KB'. Decimal units, matching how the demo script reads numbers out."""
    if n < 1000:
        return f"{n} bytes"
    if n < 1_000_000:
        return f"{round(n / 1000)} KB"
    return f"{n / 1_000_000:.1f} MB"


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def provider_is_named(owner: str, providers: list[str]) -> bool:
    """True if any provider string names the same company as owner (aliases allowed)."""
    owner_n = _norm(owner)
    if not owner_n:
        return False
    names = {owner_n}
    for group in PROVIDER_ALIASES:
        if owner_n in group or any(alias in owner_n for alias in group):
            names |= group
    for provider in providers:
        prov_n = _norm(provider)
        if not prov_n:
            continue
        # Reverse containment only for real words, so a stray "AI" never matches "openai".
        if any(name in prov_n or (len(prov_n) >= 4 and prov_n in name) for name in names):
            return True
    return False


def _claims_of(claims: Claims, claim_type: ClaimType) -> list[Claim]:
    return [c for c in claims.claims if c.type == claim_type and c.validated]


def _label(event: Event) -> str:
    return event.domain or event.ip


def _group_by_label(events: list[Event]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        groups[_label(e)].append(e)
    return groups


def _join(names: list[str]) -> str:
    names = list(dict.fromkeys(names))  # dedupe, keep order
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


def _ids(events: list[Event]) -> list[str]:
    return [e.id for e in sorted(events, key=lambda e: e.t)]


def _finding(severity: str, rule: str, title: str, claims: list[Claim], events: list[Event]):
    return Finding(
        id="",
        severity=severity,  # type: ignore[arg-type]
        rule=rule,  # type: ignore[arg-type]
        title=title,
        claim_ids=[c.id for c in claims],
        event_ids=_ids(events),
    )


# ---------------------------------------------------------------- R1


def r1_undisclosed_ai_provider(claims: Claims, events: Events) -> list[Finding]:
    """Red: an ai_provider event whose owner is not in any names_ai_provider claim's providers."""
    name_claims = _claims_of(claims, "names_ai_provider")
    named: list[str] = [p for c in name_claims for p in c.providers]

    by_owner: dict[str, list[Event]] = defaultdict(list)
    for e in events.events:
        if e.category != "ai_provider":
            continue
        owner = e.owner or _label(e)
        if not provider_is_named(owner, named):
            by_owner[owner].append(e)

    findings = []
    for owner, evs in by_owner.items():
        total = sum(e.bytes_out for e in evs)
        domains = _join([_label(e) for e in evs])
        title = f"Policy never names {owner}, but the app sent {human_bytes(total)} to {domains}"
        findings.append(_finding("red", "R1_undisclosed_ai_provider", title, name_claims, evs))
    return findings


# ---------------------------------------------------------------- R2


def r2_local_promise_broken(claims: Claims, events: Events) -> list[Finding]:
    """Red: data_stays_local = yes, yet a user_action event sends > 2 KB to a third party."""
    local_claims = [c for c in _claims_of(claims, "data_stays_local") if c.value == "yes"]
    if not local_claims:
        return []

    offending = [
        e
        for e in events.events
        if e.phase == "user_action"
        and e.bytes_out > R2_MIN_BYTES_OUT
        and e.category not in R2_EXEMPT_CATEGORIES
    ]
    findings = []
    for label, evs in _group_by_label(offending).items():
        total = sum(e.bytes_out for e in evs)
        title = (
            "Policy says your data stays on your device, but the app sent "
            f"{human_bytes(total)} to {label} right after a user action"
        )
        findings.append(_finding("red", "R2_local_promise_broken", title, local_claims, evs))
    return findings


# ---------------------------------------------------------------- R3


def _every(seconds: float) -> str:
    if seconds >= 120:
        return f"about every {round(seconds / 60)} min"
    return f"about every {round(seconds)} s"


def r3_background_telemetry(claims: Claims, events: Events) -> list[Finding]:
    """Amber: 3+ idle events to one domain with roughly even gaps (std < 20% of mean gap)."""
    idle = [e for e in events.events if e.phase == "idle"]
    findings = []
    for label, evs in _group_by_label(idle).items():
        if len(evs) < R3_MIN_EVENTS:
            continue
        times = sorted(e.t for e in evs)
        gaps = [(b - a).total_seconds() for a, b in pairwise(times)]
        avg = mean(gaps)
        if avg <= 0 or pstdev(gaps) >= R3_MAX_GAP_CV * avg:
            continue
        title = f"Background telemetry: {len(evs)} idle connections to {label}, {_every(avg)}"
        findings.append(_finding("amber", "R3_background_telemetry", title, [], evs))
    return findings


# ---------------------------------------------------------------- R4


def _near_user_action(event: Event, events: Events) -> bool:
    if event.phase == "user_action":
        return True
    return any(a.t <= event.t <= a.t + R4_WINDOW for a in events.user_actions)


def r4_content_upload_suspicion(claims: Claims, events: Events) -> list[Finding]:
    """Amber: within 5 s of a user action, more than 5 KB goes out to a single domain."""
    near = [e for e in events.events if _near_user_action(e, events)]
    findings = []
    for label, evs in _group_by_label(near).items():
        total = sum(e.bytes_out for e in evs)
        if total <= R4_MIN_BYTES_OUT:
            continue
        title = f"{human_bytes(total)} left for {label} within 5 s of a user action"
        findings.append(_finding("amber", "R4_content_upload_suspicion", title, [], evs))
    return findings


# ---------------------------------------------------------------- R5


def r5_silent_on_training(claims: Claims, events: Events) -> list[Finding]:
    """Amber: an ai_provider event exists and trains_on_user_data is unclear or missing."""
    ai_events = [e for e in events.events if e.category == "ai_provider"]
    if not ai_events:
        return []
    training = _claims_of(claims, "trains_on_user_data")
    if any(c.value != "unclear" for c in training):
        return []

    owners = _join([e.owner or _label(e) for e in ai_events])
    if training:
        title = f"App talks to {owners}, but the policy is unclear about training AI on your data"
    else:
        title = (
            f"App talks to {owners}, but the policy never says whether it trains AI on your data"
        )
    return [_finding("amber", "R5_silent_on_training", title, training, ai_events)]


# ---------------------------------------------------------------- R6


def r6_unknown_recipient(claims: Claims, events: Events) -> list[Finding]:
    """Info: one finding per unknown destination (grouped by domain), with its lookup summary."""
    findings = []
    unknown = [e for e in events.events if e.category == "unknown"]
    for label, evs in _group_by_label(unknown).items():
        lookup = next((e.lookup for e in evs if e.lookup and e.lookup.summary.strip()), None)
        count = f" ({len(evs)} bursts)" if len(evs) > 1 else ""
        if lookup:
            title = f"Unknown recipient {label}{count}: {lookup.summary.strip()}"
        else:
            title = f"Unknown recipient {label}{count} (no lookup result)"
        findings.append(_finding("info", "R6_unknown_recipient", title, [], evs))
    return findings


ALL_RULES: list[Rule] = [
    r1_undisclosed_ai_provider,
    r2_local_promise_broken,
    r3_background_telemetry,
    r4_content_upload_suspicion,
    r5_silent_on_training,
    r6_unknown_recipient,
]
