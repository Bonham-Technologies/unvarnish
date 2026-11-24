"""The exploit data bundle's header: CISA's Known Exploited Vulnerabilities catalog and where
FIRST's EPSS scores came from, fetched once while online (`unvarnish vulndata refresh`) and
read offline by the inventory (UNVAR-90). The scores themselves follow the header in the
bundle file, one line each (`unvarnish.analysis.vulndata`)."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field

VULN_BUNDLE_FORMAT = 1


class VulnBundle(BaseModel):
    format: int = VULN_BUNDLE_FORMAT
    fetched: date  # the date the data was downloaded: the report shows it
    kev_source: str
    kev_catalog_version: str | None = None  # the catalog's catalogVersion
    epss_source: str
    epss_model_version: str | None = None  # from the CSV's comment line
    epss_score_date: str | None = None  # YYYY-MM-DD, from the CSV's comment line
    epss_scores: int = 0  # score lines after the header
    attribution: str = ("Known exploited vulnerabilities from CISA's KEV catalog "
                        "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog); "
                        "exploit prediction scores from FIRST's EPSS "
                        "(https://www.first.org/epss)")
    kev: dict[str, date] = Field(default_factory=dict)  # CVE id -> dateAdded
