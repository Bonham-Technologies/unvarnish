"""A tiny tool for CI's image smoke run (UNVAR-80): enough for every phase to have input."""

from pathlib import Path

DATA_DIR = Path("/opt/app/data")


def list_reports() -> list[str]:
    """Names of the report files in the data folder, sorted."""
    return sorted(p.name for p in DATA_DIR.glob("*.csv"))


if __name__ == "__main__":
    print("\n".join(list_reports()))
