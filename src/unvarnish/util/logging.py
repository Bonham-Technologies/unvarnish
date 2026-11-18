from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from rich.logging import RichHandler

from unvarnish.engagement import Engagement


def setup_run_logging(eng: Engagement, verbose: bool = False, prefix: str = "run") -> Path:
    """DEBUG to logs/run-<timestamp>.log, INFO (or DEBUG when verbose) to the console."""
    logger = logging.getLogger("unvarnish")
    for h in list(logger.handlers):
        if getattr(h, "_unvarnish", False):
            logger.removeHandler(h)
            h.close()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    eng.logs_dir.mkdir(parents=True, exist_ok=True)
    path = eng.logs_dir / f"{prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    ch = RichHandler(level=logging.DEBUG if verbose else logging.INFO, show_path=False,
                     rich_tracebacks=False, markup=False)
    if not verbose:  # records marked console=False (crash tracebacks) stay in the file
        ch.addFilter(lambda record: getattr(record, "console", True))
    for h in (fh, ch):
        h._unvarnish = True  # type: ignore[attr-defined]
        logger.addHandler(h)
    return path
