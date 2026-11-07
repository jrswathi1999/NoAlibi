"""The three data contracts (build plan Section 5): claims.json, events.json, findings.json."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel, Field, ValidationError, field_validator

ClaimType = Literal[
    "data_stays_local",
    "names_ai_provider",
    "trains_on_user_data",
    "retention_stated",
    "ai_opt_out",
    "shares_with_third_parties",
]
CLAIM_TYPES: tuple[str, ...] = ClaimType.__args__  # type: ignore[attr-defined]
ClaimValue = Literal["yes", "no", "unclear"]
MatchKind = Literal["exact", "fuzzy"]

Phase = Literal["startup", "user_action", "idle"]
Category = Literal[
    "ai_provider", "tracker", "analytics", "error_reporting", "first_party", "update", "unknown"
]

Severity = Literal["red", "amber", "info"]
RuleName = Literal[
    "R1_undisclosed_ai_provider",
    "R2_local_promise_broken",
    "R3_background_telemetry",
    "R4_content_upload_suspicion",
    "R5_silent_on_training",
    "R6_unknown_recipient",
]

RUN_ID_RE = re.compile(r"^\d{8}-\d{6}-[a-z0-9-]+$")


def _valid_run_id(value: str) -> str:
    if not RUN_ID_RE.match(value):
        raise ValueError(f"run_id {value!r} must look like YYYYMMDD-HHMMSS-<appslug>")
    return value


# ---------------------------------------------------------------- 5.1 claims.json


class AppInfo(BaseModel):
    name: str
    policy_url: str
    subprocessor_url: str | None = None
    fetched_at: datetime
    policy_sha256: str


class Claim(BaseModel):
    id: str
    type: ClaimType
    value: ClaimValue
    providers: list[str] = Field(default_factory=list)
    quote: str
    source_url: str
    validated: bool
    match: MatchKind


class Claims(BaseModel):
    run_id: str
    app: AppInfo
    model: str
    claims: list[Claim]

    _check_run_id = field_validator("run_id")(_valid_run_id)


# ---------------------------------------------------------------- 5.2 events.json


class CaptureInfo(BaseModel):
    start: datetime
    end: datetime
    interface: str
    pcap_sha256: str


class UserAction(BaseModel):
    t: datetime
    label: str = ""


class Lookup(BaseModel):
    """What a web search said about an unknown domain. Only the domain name was sent."""

    source: str
    summary: str
    url: str


class Event(BaseModel):
    """One flow: one destination IP and port during the capture, with byte totals."""

    id: str
    t: datetime
    t_rel_s: float
    domain: str | None
    ip: str
    port: int
    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)
    tls: bool
    phase: Phase
    category: Category
    owner: str | None = None
    lookup: Lookup | None = None


class Events(BaseModel):
    run_id: str
    capture: CaptureInfo
    user_actions: list[UserAction] = Field(default_factory=list)
    events: list[Event]

    _check_run_id = field_validator("run_id")(_valid_run_id)


# ---------------------------------------------------------------- 5.3 findings.json


class Finding(BaseModel):
    id: str
    severity: Severity
    rule: RuleName
    title: str
    claim_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)


class Findings(BaseModel):
    run_id: str
    findings: list[Finding]
    scorecard: dict[ClaimType, ClaimValue]
    summary: str
    evidence_sha256: str

    _check_run_id = field_validator("run_id")(_valid_run_id)


# ---------------------------------------------------------------- helpers

M = TypeVar("M", bound=BaseModel)


def load_model(path: str | Path, model: type[M]) -> M:
    """Read and validate a contract file. Raises ValueError naming the file on any problem."""
    path = Path(path)
    try:
        return model.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"{path} not found") from exc
    except ValidationError as exc:
        raise ValueError(f"{path} does not match {model.__name__}: {exc}") from exc


def save_model(path: str | Path, obj: BaseModel) -> Path:
    """Write a contract file as pretty UTF-8 JSON (times as ISO 8601 UTC)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(obj.model_dump_json())
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def slugify(app_name: str) -> str:
    """'Notes App 2!' -> 'notes-app-2'."""
    slug = re.sub(r"[^a-z0-9]+", "-", app_name.lower()).strip("-")
    return slug or "app"


def make_run_id(app_name: str, now: datetime | None = None) -> str:
    """Build a run_id like 20261107-201500-notesapp (UTC time)."""
    now = now or datetime.now(UTC)
    return f"{now.astimezone(UTC):%Y%m%d-%H%M%S}-{slugify(app_name)}"
