from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.analysis.languages import Classification


class HtmlBreakdown(BaseModel):
    markup_lines: int
    script_lines: int
    style_lines: int
    markup_bytes: int
    script_bytes: int
    style_bytes: int
    script_blocks: int
    style_blocks: int


class FileMetrics(BaseModel):
    path: str
    lines: int
    bytes: int
    functions: int | None = None
    max_function_lines: int | None = None
    max_function_name: str | None = None
    max_function_start: int | None = None
    max_function_end: int | None = None
    max_nesting: int | None = None
    comment_lines: int | None = None
    html: HtmlBreakdown | None = None
    metrics_method: Literal["treesitter", "lines"]


class FileRecord(BaseModel):
    path: str
    bytes: int
    lines: int
    language: str | None
    classification: Classification
    excluded: bool
    exclusion_reason: str | None


class CensusTotals(BaseModel):
    files: int = 0
    bytes: int = 0
    lines: int = 0
    excluded_files: int = 0
    excluded_bytes: int = 0
    symlinks_skipped: int = 0
    by_classification: dict[str, int] = Field(default_factory=dict)


class Census(BaseModel):
    tool: str
    files: list[FileRecord]
    totals: CensusTotals
    languages: dict[str, int] = Field(default_factory=dict)
    frameworks: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)  # files that could not be read or measured
    # In the git index although a .gitignore rule matches them, so they are analysed (UNVAR-28).
    tracked_despite_gitignore: list[str] = Field(default_factory=list)
    # Languages whose tree-sitter grammar could not be loaded, so their files were measured by
    # line counts (UNVAR-45), and the notes the findings document shows for them.
    grammars_unavailable: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    # sha256 over every file's path and content. Phases downstream are fresh while the census
    # data is unchanged (UNVAR-34), and scan and split read the source, so an edit that keeps
    # every size and line count must still change the census.
    content_digest: str = ""


class Metrics(BaseModel):
    tool: str
    files: list[FileMetrics]


class DependencyRecord(BaseModel):
    ecosystem: str
    name: str
    constraint: str | None
    manifest: str
    dev: bool = False
    # The licences deps.dev declares for the package osv-scanner resolved for this record, in
    # online mode only; None (and left out of the artifact) when not checked (UNVAR-93).
    licences: list[str] | None = Field(default=None, exclude_if=lambda v: v is None)


class PackageLicences(BaseModel):
    """One package osv-scanner resolved in online mode, declared or transitive, with the
    licences deps.dev declares for it; an empty list when deps.dev knows none (UNVAR-93)."""
    ecosystem: str  # osv-scanner's name for it: PyPI, npm, crates.io, Go, Maven
    name: str
    version: str
    manifest: str  # the manifest or lockfile osv-scanner read it from
    licences: list[str] = Field(default_factory=list)


class Dependencies(BaseModel):
    tool: str
    dependencies: list[DependencyRecord]
    advisories_checked: bool = False
    advisories: list[dict] = Field(default_factory=list)
    advisories_note: str | None = None  # why advisories were not checked
    # The fetch date of the end-of-life data bundle the run read, or None without one (UNVAR-43)
    eol_data_date: str | None = None
    # The fetch date of the exploit data bundle (CISA KEV and EPSS) that marked the advisories,
    # or None without one, and then why not (UNVAR-90)
    exploit_data_date: str | None = None
    exploit_data_note: str | None = None
    # Package licences (UNVAR-93): checked only in online mode, from deps.dev through
    # osv-scanner. Each is left out of the artifact at its default, so an offline inventory's
    # dependencies.json is what it was before licences existed.
    licences_checked: bool = Field(default=False, exclude_if=lambda v: not v)
    licences_note: str | None = Field(default=None, exclude_if=lambda v: v is None)  # why not
    packages: list[PackageLicences] = Field(default_factory=list, exclude_if=lambda v: not v)
