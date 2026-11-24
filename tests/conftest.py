from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests.fake_llm import FakeLLM
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import ingest_tool

os.environ.setdefault("UNVARNISH_TEST_KEY", "test-key")
# External scanners are exercised only by their own tests; everywhere else the results must not
# depend on whether gitleaks or osv-scanner happens to be installed on the machine.
os.environ.setdefault("UNVARNISH_DISABLE_OSV", "1")
os.environ.setdefault("UNVARNISH_DISABLE_GITLEAKS", "1")
# Nor on an end-of-life bundle in the developer's data directory: tests that need one point
# UNVARNISH_EOL_DIR at tests/data/eol themselves.
os.environ.setdefault("UNVARNISH_EOL_DIR", str(Path(__file__).parent / "data" / "no-eol-bundle"))
# Nor on an exploit data bundle (UNVAR-90): tests that need one write their own.
os.environ.setdefault("UNVARNISH_VULNDATA_DIR",
                      str(Path(__file__).parent / "data" / "no-vulndata-bundle"))

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Alice",
    "GIT_AUTHOR_EMAIL": "alice@example.com",
    "GIT_COMMITTER_NAME": "Alice",
    "GIT_COMMITTER_EMAIL": "alice@example.com",
}

# Real-shaped (AWS's documented example is ignored). Fixtures that look like real
# credentials are built from fragments so no tracked file holds a whole one.
LEAKED_KEY = "AKIA" + "Z7Q3V5X2W9R4T6YP"
LEAKED_DB_URL = "postgres://admin:hunter2@db.internal:5432/expenses"


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=root,
        check=True,
        capture_output=True,
        env={**os.environ, **GIT_ENV, **(env or {})},
    )


def _commit(root: Path, message: str, author: str, email: str, date: str) -> None:
    env = {
        "GIT_AUTHOR_NAME": author,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": author,
        "GIT_COMMITTER_EMAIL": email,
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message, env=env)


HTML_SAMPLE = """<!doctype html>
<html>
<head>
<style>
body { margin: 0; }
.card { padding: 4px; }
</style>
</head>
<body>
<div id="app"></div>
<script>
function render(items) {
  for (const i of items) {
    if (i.ok) {
      console.log(i);
    }
  }
}
</script>
<script>
const total = (a, b) => a + b;
</script>
</body>
</html>
"""


@pytest.fixture(scope="session")
def synthetic_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A git repo with planted problems. See the plan's Task 5 for the expected numbers."""
    root = tmp_path_factory.mktemp("synthetic") / "expense-bot"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")

    # Commit 1 (Alice): leaked secrets in app.py
    (root / "app.py").write_text(
        "import boto3\n"
        f'AWS_ACCESS_KEY_ID = "{LEAKED_KEY}"\n'
        f'DB_URL = "{LEAKED_DB_URL}"\n'
        "\n"
        "def main():\n"
        '    print("hi")\n'
    )
    (root / "README.md").write_text("# Expense bot\n")
    (root / "requirements.txt").write_text("flask==2.3.2\nrequests>=2.31\n")
    (root / ".gitignore").write_text("*.pyc\n.env\n")
    _commit(root, "initial", "Alice", "alice@example.com", "2026-01-05T10:00:00+00:00")

    # Commit 2 (Alice, AI co-authored): secrets removed, 3000-line function generated
    big = "def process_everything(data):\n"
    big += "".join(f"    x{i} = data.get('k{i}', 0)\n" for i in range(3000))
    big += "    return 0\n"
    (root / "app.py").write_text(
        "import os\n"
        'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n'
        "\n"
        "def main():\n"
        '    print("hi")\n'
        "\n" + big
    )
    (root / "CLAUDE.md").write_text("# Instructions for Claude\n")
    _commit(
        root,
        "generate processing\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "Alice",
        "alice@example.com",
        "2026-01-06T10:00:00+00:00",
    )

    # Commit 3 (Alice): vendored node_modules, HTML with inline script/style, minified asset
    (root / "node_modules" / "leftpad").mkdir(parents=True)
    (root / "node_modules" / "leftpad" / "index.js").write_text("module.exports = s => s;\n")
    (root / "static").mkdir()
    (root / "static" / "index.html").write_text(HTML_SAMPLE)
    (root / "static" / "app.min.js").write_text("!function(){var a=1}();\n")
    _commit(root, "add frontend", "Alice", "alice@example.com", "2026-01-07T10:00:00+00:00")

    # Commit 4 (Bob): tiny change
    with (root / "README.md").open("a") as fh:
        fh.write("\nMaintained by finance.\n")
    _commit(root, "tweak readme", "Bob", "bob@example.com", "2026-02-01T10:00:00+00:00")
    return root


@pytest.fixture(scope="session")
def huge_html(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A ~70K-line HTML file: 50 script blocks of ~1,200 lines, 5 style blocks, markup."""
    root = tmp_path_factory.mktemp("huge")
    path = root / "dashboard.html"
    parts = ["<!doctype html>\n<html>\n<head>\n"]
    for s in range(5):
        rules = "".join(f".c{s}-{i} {{ color: red; }}\n" for i in range(200))
        parts.append("<style>\n" + rules + "</style>\n")
    parts.append("</head>\n<body>\n")
    for s in range(50):
        body = "".join(f"  var v{s}_{i} = {i};\n" for i in range(1200))
        parts.append(f"<script>\nfunction block{s}() {{\n{body}}}\n</script>\n")
    parts.append("".join(f"<div class='row'>row {i}</div>\n" for i in range(8000)))
    parts.append("</body>\n</html>\n")
    path.write_text("".join(parts))
    return path


@pytest.fixture
def engagement(tmp_path: Path) -> Engagement:
    return Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham Technologies")


@pytest.fixture
def ingested(engagement: Engagement, synthetic_repo: Path) -> tuple[Engagement, str]:
    ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")
    return engagement, "expense-bot"


@pytest.fixture
def fake_llm() -> FakeLLM:
    fake = FakeLLM()
    fake.start()
    try:
        yield fake
    finally:
        fake.stop()


def model_config(fake: FakeLLM, kind: str = "anthropic", model: str = "fake-model",
                 **caps) -> dict:
    """Config dict with one backend pointed at the fake server and models.default set."""
    backend: dict = {"type": kind, "base_url": fake.url, "api_key_env": "UNVARNISH_TEST_KEY"}
    if kind == "openai_compatible":
        backend["base_url"] = fake.url + "/v1"
    if caps:
        backend["capabilities"] = caps
    return {"backends": {"fake": backend},
            "models": {"default": {"backend": "fake", "model": model}}}
