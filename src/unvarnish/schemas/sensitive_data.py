"""Field names that suggest sensitive data (UNVAR-100): `inventory/sensitive-data.json`.

Name-based only: the sensitive_data scanner matches the names of columns, model fields and
typed-structure properties against a pattern set. It never reads a data value."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SensitiveField(BaseModel):
    """One field whose name matched one data class's pattern."""

    data_class: str  # the pattern set's key, e.g. "contact"
    field: str
    store: str  # the table, model, schema or type that declares the field
    store_kind: str  # "SQL table", "Django model", "TypeScript interface", ...
    persistent: bool  # a table or an ORM model, not an in-memory type
    path: str
    line: int
    matched: str  # the pattern that matched, e.g. "date of birth"


class SensitiveData(BaseModel):
    tool: str
    # The data classes of the pattern set the scan used, key -> label, in the set's order.
    classes: dict[str, str] = Field(default_factory=dict)
    patterns_overridden: bool = False  # scanners.sensitive_data.patterns changed the set
    fields: list[SensitiveField] = Field(default_factory=list)
    structures_read: int = 0  # tables, models, schemas and types whose field names were read
    files_read: int = 0
    # Files the pass could not parse (Python with a syntax error), by path.
    unparsed: list[str] = Field(default_factory=list)
    # Source files in languages whose structures the pass does not read: language -> files.
    not_read: dict[str, int] = Field(default_factory=dict)

    def classes_found(self) -> list[str]:
        """The data classes with at least one field, in the pattern set's order."""
        found = {f.data_class for f in self.fields}
        return [k for k in self.classes if k in found]
