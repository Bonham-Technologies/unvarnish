from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field


class AuthorStats(BaseModel):
    name: str
    email: str
    commits: int
    lines_changed: int
    share: float


class CommitInfo(BaseModel):
    sha: str
    date: datetime
    author: str
    lines_added: int
    lines_deleted: int
    files: int
    message_head: str


class WeeklyBucket(BaseModel):
    week_start: date
    commits: int
    lines_changed: int


class ChurnEntry(BaseModel):
    path: str
    changes: int
    lines_changed: int


class AiFingerprints(BaseModel):
    files: list[str] = Field(default_factory=list)
    coauthor_trailers: dict[str, int] = Field(default_factory=dict)
    message_patterns: int = 0


class GitStats(BaseModel):
    tool: str
    available: bool
    reason: str | None = None
    commit_count: int = 0
    first_commit: datetime | None = None
    last_commit: datetime | None = None
    active_days: int = 0
    authors: list[AuthorStats] = Field(default_factory=list)  # humans only
    bots: list[AuthorStats] = Field(default_factory=list)
    bus_factor: int | None = None
    top_author_share: float | None = None
    large_commits: list[CommitInfo] = Field(default_factory=list)
    large_commit_threshold: int = 2000
    weekly_velocity: list[WeeklyBucket] = Field(default_factory=list)
    churn_hotspots: list[ChurnEntry] = Field(default_factory=list)
    ai_fingerprints: AiFingerprints = Field(default_factory=AiFingerprints)
