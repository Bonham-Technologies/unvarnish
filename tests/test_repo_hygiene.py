"""Repository hygiene for a public release (UNVAR-36).

Guards what a public repository needs: the Apache-2.0 licence and its NOTICE, least-privilege
and SHA-pinned workflows, code owners for the sensitive trees, the DCO, and no whole
real-format token in any tracked file (secret-scanner fixtures are built from fragments at
runtime, so GitHub secret scanning and push protection have nothing to act on).
"""

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
PINNED = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")

# Written in fragments so this file never matches its own patterns.
TOKEN_PATTERNS = {
    "stripe": re.compile("sk" + "_live_" + r"[0-9a-zA-Z]{10,}"),
    "gitlab": re.compile("gl" + "pat-" + r"[0-9A-Za-z_-]{20}"),
    "slack-webhook": re.compile(r"hooks\.slack\.com" + "/services/" + "T"),
    "private-key": re.compile("-----" + "BEGIN " + r"[A-Z ]*" + "PRIVATE " + "KEY-----"),
    "aws": re.compile("AK" + "IA" + r"[0-9A-Z]{16}"),
    "anthropic": re.compile("sk-" + "ant-" + "api03-" + r"[A-Za-z0-9_-]{20,}"),
}
# Vendor-documented sample keys are public by design.
DOCUMENTED_SAMPLE = "EXAMPLE"


def _workflow(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(doc: dict) -> set[str]:
    on = doc.get("on", doc.get(True))  # PyYAML reads a bare `on:` key as True
    if isinstance(on, str):
        return {on}
    return set(on or [])


def test_license_is_apache_2_with_notice():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in text and "Version 2.0, January 2004" in text
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in text
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert notice.startswith("Unvarnish\n")
    assert "Copyright 2026 Bonham Technologies, LLC" in notice


def test_package_metadata_declares_apache_2():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    # Hatchling reads `license-files` as a list (final PEP 639) only from 1.27; older
    # releases expect a table and refuse to build.
    assert "hatchling>=1.27" in pyproject["build-system"]["requires"]
    assert project["license"] == "Apache-2.0"
    assert {"LICENSE", "NOTICE"} <= set(project.get("license-files", []))
    assert not [c for c in project.get("classifiers", []) if "Proprietary" in c]


def test_docker_build_context_carries_the_licence_files():
    # pyproject's license-files makes the project build fail without them, and Apache-2.0
    # asks every redistribution (the image is one) to carry LICENSE and NOTICE.
    copies = [line.split()[1:] for line in (ROOT / "Dockerfile").read_text(encoding="utf-8")
              .splitlines() if line.startswith("COPY ") and "--from" not in line]
    assert any({"LICENSE", "NOTICE"} <= set(args) for args in copies)
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert "LICENSE" not in ignored and "NOTICE" not in ignored


def test_readme_links_the_licence():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Apache-2.0" in readme and "(LICENSE)" in readme


def test_readme_intro_states_the_product_without_slice_numbers():
    # Slice numbers are build history; the README says what the product does today (UNVAR-25).
    intro = (ROOT / "README.md").read_text(encoding="utf-8").split("\n## ", 1)[0]
    assert not re.search(r"\bslices?\b", intro, re.IGNORECASE)
    assert "(CHANGELOG.md)" in intro


def test_contributing_asks_for_dco_sign_off():
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "Signed-off-by" in text and "git commit -s" in text
    assert "https://developercertificate.org/" in text
    dco = yaml.safe_load((ROOT / ".github" / "dco.yml").read_text(encoding="utf-8"))
    assert dco == {"require": {"members": False}}


@pytest.mark.parametrize("name", ["SECURITY.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md"])
def test_community_files_exist(name: str):
    assert (ROOT / name).is_file()


def test_workflows_exist():
    assert WORKFLOWS


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_declares_top_level_permissions(path: Path):
    assert "permissions" in _workflow(path), f"{path.name}: no top-level permissions"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_has_no_privileged_pr_triggers(path: Path):
    assert not _triggers(_workflow(path)) & {"pull_request_target", "workflow_run"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_actions_pinned_by_sha(path: Path):
    unpinned = []
    for job in _workflow(path).get("jobs", {}).values():
        uses = [job["uses"]] if "uses" in job else []
        uses += [step["uses"] for step in job.get("steps", []) if "uses" in step]
        unpinned += [u for u in uses if not u.startswith("./") and not PINNED.match(u)]
    assert not unpinned, f"{path.name}: not pinned to a commit SHA: {unpinned}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_job_has_a_time_limit(path: Path):
    # GitHub's default is six hours: a hung download would hold a runner and every PR's
    # ci-status that long (UNVAR-65).
    missing = [name for name, job in _workflow(path).get("jobs", {}).items()
               if "uses" not in job and "timeout-minutes" not in job]
    assert not missing, f"{path.name}: no timeout-minutes on {missing}"


# A fork's pull request must never reach the self-hosted runner `vars.RUNS_ON` names
# (UNVAR-70): only a same-repo head may use it, everything else falls back to a hosted runner.
SAME_REPO_HEAD = "github.event.pull_request.head.repo.full_name == github.repository"
HOSTED_FALLBACK = "'ubuntu-24.04'"


def _jobs(path: Path) -> list[tuple[str, dict]]:
    return list(_workflow(path).get("jobs", {}).items())


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_self_hosted_runner_only_for_same_repo_heads(path: Path):
    for name, job in _jobs(path):
        runs_on = str(job.get("runs-on", ""))
        if not any(marker in runs_on for marker in ("RUNS_ON", "vars.", "self-hosted")):
            continue
        assert SAME_REPO_HEAD in runs_on, f"{path.name}:{name}: RUNS_ON without a same-repo guard"
        assert runs_on.rstrip("} ").endswith(f"|| {HOSTED_FALLBACK}"), (
            f"{path.name}:{name}: no {HOSTED_FALLBACK} fallback"
        )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkout_drops_its_token(path: Path):
    # Without persist-credentials: false, checkout leaves GITHUB_TOKEN in .git/config for
    # every later step, including the project's own tests (UNVAR-70).
    for name, job in _jobs(path):
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert (step.get("with") or {}).get("persist-credentials") is False, (
                    f"{path.name}:{name}: checkout keeps its credentials"
                )


def test_dependabot_bumps_action_pins():
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert "github-actions" in {u["package-ecosystem"] for u in config["updates"]}


def test_dependabot_ignores_the_tree_sitter_release_the_pin_excludes():
    # pyproject excludes tree-sitter 0.26.0 (it segfaults, docs/decisions.md); Dependabot's
    # minor-and-patch group widened the old <0.26 cap every week, so it ignores 0.26.0
    # (UNVAR-46) and never proposes the excluded release.
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    pins = [d for d in project["dependencies"] if re.match(r"tree-sitter\s*[<>=!~]", d)]
    assert pins, "tree-sitter is no longer a direct dependency; drop this test"
    pin = pins[0].replace(" ", "")
    if "<0.26" not in pin and "!=0.26.0" not in pin:
        return  # 0.26.0 is allowed again on purpose; the ignore entry may go with it
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    uv = next(u for u in config["updates"] if u["package-ecosystem"] == "uv")
    ignored = {
        version
        for entry in uv.get("ignore", [])
        if entry.get("dependency-name") == "tree-sitter"
        for version in entry.get("versions", [])
    }
    assert "0.26.0" in ignored


def test_codeowners_cover_sensitive_trees():
    lines = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines()
    owned = {line.split()[0] for line in lines if line.strip() and not line.startswith("#")}
    assert {"/.github/", "/.claude/", "/site/"} <= owned


def test_pr_template_has_no_internal_tracker_links():
    text = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    assert "atlassian.net" not in text
    assert "Ticket: " in text


_TRACKER_URL = re.compile(r"https?://[a-z0-9-]+\.atlassian\.net\b")


def test_no_internal_tracker_urls_outside_the_vendored_policy():
    # The public repository is published as a snapshot of this tree (UNVAR-37), so the
    # internal Jira and Confluence URLs must not be in it. Ticket keys stay as plain text.
    # `.claude/` is vendored from bonham-ops and changed there, not here.
    offenders = []
    for path in _tracked_files():
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(".claude/") or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if _TRACKER_URL.search(text):
            offenders.append(rel)
    assert offenders == []


def _tracked_files() -> list[Path]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    return [ROOT / p for p in out.stdout.decode("utf-8").split("\0") if p]


def test_no_tracked_file_holds_a_whole_real_format_token():
    hits = []
    for path in _tracked_files():
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.split("\n"), 1):
            for rule, pattern in TOKEN_PATTERNS.items():
                for match in pattern.finditer(line):
                    if DOCUMENTED_SAMPLE not in match.group(0):
                        # Never echo the value: file, line and rule are enough to find it.
                        hits.append(f"{path.relative_to(ROOT)}:{lineno}:{rule}")
    assert not hits, "build these fixtures from fragments at runtime:\n" + "\n".join(hits)


# Commits of the private archive's history that the old .gitleaksignore named (UNVAR-14). The
# public history starts at one snapshot commit (UNVAR-37), so a fingerprint naming one of these
# suppresses nothing and points readers at history that isn't here (UNVAR-72).
ARCHIVE_ONLY_COMMITS = {
    "24bdadea58975c4b076cb97c7d1ad78e6c7d0e10", "38a6eeffec63cd2160f8921c7befdc8807ae650b",
    "49bbbbda7153f9b6f18838eb4c11b32af1d066f2", "5dba819f28ff3b243e74bf4296796622a5ec6159",
    "a05f23f6ce1eec701166178d606f1c645d66b1a9", "c0fa978b3181245218d704deecd2bf006d7f0249",
    "f4c977775b464fd6092d14d4c2ce51ed37658ff7",
}


def test_gitleaksignore_names_no_archive_only_commit():
    # The file may come back for a fingerprint in this history (the security sweep allow-lists
    # a confirmed false positive or a revoked leak there); it may not carry the archive's.
    path = ROOT / ".gitleaksignore"
    if not path.exists():
        return
    entries = [line for line in path.read_text(encoding="utf-8").splitlines()
               if line and not line.startswith("#")]
    stale = [e for e in entries if e.split(":", 1)[0] in ARCHIVE_ONLY_COMMITS]
    assert stale == []
