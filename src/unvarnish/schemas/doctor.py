"""What `unvarnish doctor --json` prints: one row per data set or tool a run needs, and the
backend probes when asked for (UNVAR-101)."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel

DOCTOR_FORMAT = 1
Status = Literal["present", "stale", "partial", "absent", "unreadable", "too old"]
# Old data is still used by a run, with a note; every other status means it is not usable.
USABLE: frozenset[str] = frozenset({"present", "stale"})


class DoctorCheck(BaseModel):
    name: str
    kind: Literal["data", "tool"]
    status: Status
    detail: str = ""
    note: str | None = None  # a caveat even when present, e.g. an old weasyprint
    date: str | None = None  # a data set's fetch date, YYYY-MM-DD
    age_days: int | None = None
    max_age_days: int | None = None  # the limit the age is held against
    version: str | None = None  # a tool's version, when it says
    needed: bool  # whether the engagement (or a new one's defaults) uses it
    needed_for: str
    refresh: str  # the command that fetches, refreshes or installs it
    ready: bool  # not needed, or usable


class BackendCheck(BaseModel):
    backend: str
    url: str  # what was asked, without user info or a query
    reachable: bool
    detail: str


class DoctorReport(BaseModel):
    format: int = DOCTOR_FORMAT
    engagement: str | None  # None: checked against a new engagement's defaults
    checked: date
    checks: list[DoctorCheck]
    backends: list[BackendCheck] | None = None  # None unless --probe-backend
    ready: bool
