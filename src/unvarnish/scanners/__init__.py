from __future__ import annotations

import importlib.metadata as md

from unvarnish.scanners.base import ScanContext, Scanner

ENTRY_POINT_GROUP = "unvarnish.scanners"

__all__ = ["ENTRY_POINT_GROUP", "ScanContext", "Scanner", "builtin_scanners", "load_scanners"]


def builtin_scanners() -> list[Scanner]:
    # Imported here to avoid import cycles between scanners.base and the scanner modules.
    from unvarnish.scanners.bus_factor import BusFactorScanner
    from unvarnish.scanners.client_exposure import ClientExposureScanner
    from unvarnish.scanners.dependencies import DependenciesScanner
    from unvarnish.scanners.end_of_life import EndOfLifeScanner
    from unvarnish.scanners.generated_bulk import GeneratedBulkScanner
    from unvarnish.scanners.hardcoded_infra import HardcodedInfraScanner
    from unvarnish.scanners.hygiene import HygieneScanner
    from unvarnish.scanners.oversized_files import OversizedFilesScanner
    from unvarnish.scanners.sast import SastScanner
    from unvarnish.scanners.secrets import SecretsScanner
    from unvarnish.scanners.vendored_bulk import VendoredBulkScanner

    return [SecretsScanner(), OversizedFilesScanner(), HygieneScanner(), BusFactorScanner(),
            DependenciesScanner(), HardcodedInfraScanner(), VendoredBulkScanner(),
            GeneratedBulkScanner(), ClientExposureScanner(), EndOfLifeScanner(), SastScanner()]


def load_scanners() -> list[Scanner]:
    scanners: dict[str, Scanner] = {s.name: s for s in builtin_scanners()}
    for ep in md.entry_points().select(group=ENTRY_POINT_GROUP):
        cls = ep.load()
        instance = cls() if isinstance(cls, type) else cls
        scanners[instance.name] = instance  # entry point overrides a built-in of the same name
    return list(scanners.values())
