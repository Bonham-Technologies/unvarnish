"""The end-of-life data bundle: endoflife.date's release cycles, fetched once while online
(`unvarnish eol refresh`) and read offline by the end_of_life scanner (UNVAR-43)."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field

EOL_BUNDLE_FORMAT = 1


class EolCycle(BaseModel):
    cycle: str  # endoflife.date's release name: "3.9", "18", "20.04", "10"
    codename: str | None = None  # "Buster", "Focal Fossa"
    eol_from: date | None = None  # eolFrom: the first day without support; None if unpublished
    is_eol: bool = False  # isEol on the fetch date, used when no eol_from is published
    is_maintained: bool = True  # isMaintained on the fetch date
    latest: str | None = None  # the latest release in the cycle on the fetch date


class EolProduct(BaseModel):
    label: str  # "Python", "Microsoft .NET"
    cycles: list[EolCycle] = Field(default_factory=list)  # newest first, as endoflife.date lists


class EolBundle(BaseModel):
    format: int = EOL_BUNDLE_FORMAT
    source: str = "https://endoflife.date/api/v1/products"
    attribution: str = "Data from endoflife.date (https://endoflife.date), MIT licence"
    fetched: date  # the date the data was downloaded: the report shows it
    products: dict[str, EolProduct]  # keyed by endoflife.date product slug
