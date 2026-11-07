"""events.json models, mirroring plan Section 5.2.

Local copy until Shri's contracts/models.py lands. When it does, import
contracts.models.Events instead and delete this file.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Phase = Literal["startup", "user_action", "idle"]
Category = Literal[
    "ai_provider",
    "tracker",
    "analytics",
    "error_reporting",
    "first_party",
    "update",
    "unknown",
]


class Capture(BaseModel):
    start: str
    end: str
    interface: str
    pcap_sha256: str


class UserAction(BaseModel):
    t: str
    label: str = ""


class Lookup(BaseModel):
    source: Literal["tavily", "exa"]
    summary: str = Field(max_length=200)
    url: str


class Event(BaseModel):
    id: str
    t: str
    t_rel_s: float
    domain: str
    ip: str
    port: int
    bytes_out: int
    bytes_in: int
    tls: bool
    phase: Phase
    category: Category
    owner: str | None = None
    lookup: Lookup | None = None


class Events(BaseModel):
    run_id: str
    capture: Capture
    user_actions: list[UserAction] = []
    events: list[Event] = []
