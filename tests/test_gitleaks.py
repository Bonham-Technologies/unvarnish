import json
import logging
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from tests.conftest import LEAKED_KEY
from unvarnish.artifacts import read_artifact
from unvarnish.phases.base import PhaseRunner, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.scanners.gitleaks import gitleaks_commands, run_gitleaks
from unvarnish.schemas.scan import ScannerFindings

# Gitleaks finds it; the built-in rules do not. Built from fragments so no tracked file
# holds a whole real-format token.
STRIPE = "sk_" + "live_51HxQ2vKq8ZrT9mPw3LbN7cYd"


@pytest.fixture(autouse=True)
def _enable_gitleaks(monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_GITLEAKS", raising=False)


def fake_gitleaks(tmp_path: Path, tree: list, history: list) -> Path:
    bindir = tmp_path / "glbin"
    bindir.mkdir(exist_ok=True)
    (tmp_path / "tree.json").write_text(json.dumps(tree))
    (tmp_path / "hist.json").write_text(json.dumps(history))
    script = bindir / "gitleaks"
    script.write_text(
        "#!/bin/sh\n"
        f"echo \"$@\" >> {tmp_path / 'gl-args.txt'}\n"
        f"if [ \"$1\" = dir ]; then cat {tmp_path / 'tree.json'}; "
        f"else cat {tmp_path / 'hist.json'}; fi\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return bindir


def item(path: str, line: int, commit: str = "", rule: str = "stripe-access-token") -> dict:
    return {"RuleID": rule, "Description": "Stripe access token", "File": path,
            "StartLine": line, "Secret": "REDACTED", "Match": "REDACTED", "Commit": commit,
            "Fingerprint": f"{commit}:{path}:{rule}:{line}"}


def _scan(engagement, synthetic_repo, monkeypatch, bindir: Path | None, extra: dict[str, str]):
    if "alpha" not in engagement.tool_names():  # a test may scan twice: before and after
        ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha")
    for rel, body in extra.items():
        (ctx.paths.source / rel).write_text(body)
    if bindir is not None:
        monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    return ctx, [f for f in read_artifact(ctx.paths.scanner_findings,
                                          ScannerFindings).data.findings
                 if f.scanner == "secrets"]


def test_commands_always_redact(tmp_path):
    cmds = gitleaks_commands(tmp_path, history=True)
    assert [c[1] for c in cmds] == ["dir", "git"]
    assert all("--redact" in c and "--exit-code" in c for c in cmds)
    assert len(gitleaks_commands(tmp_path, history=False)) == 1


def test_run_gitleaks_notes(tmp_path, monkeypatch):
    assert run_gitleaks(tmp_path, history=False, which=lambda t: None)[2] == (
        "gitleaks not installed")
    monkeypatch.setenv("UNVARNISH_DISABLE_GITLEAKS", "1")
    assert run_gitleaks(tmp_path, history=False)[2] == "disabled by UNVARNISH_DISABLE_GITLEAKS"


def test_gitleaks_runs_in_its_own_empty_directory(tmp_path, monkeypatch):
    # gitleaks also reads .gitleaksignore from its working directory (UNVAR-66): the
    # consultant's folder must never be it.
    here = tmp_path / "consultant"
    here.mkdir()
    (here / ".gitleaksignore").write_text("anything\n", encoding="utf-8")
    monkeypatch.chdir(here)
    calls = []

    def run(cmd, **kwargs):
        cwd = Path(kwargs["cwd"])
        calls.append((cmd, cwd, sorted(p.name for p in cwd.iterdir())))
        return subprocess.CompletedProcess(cmd, 0, b"[]", b"")

    tree, history, note = run_gitleaks(tmp_path, history=True, which=lambda t: t, run=run)
    assert (tree, history, note) == ([], [], None)
    assert [c[0][1] for c in calls] == ["dir", "git"]
    for _cmd, cwd, contents in calls:
        assert cwd.resolve() != here.resolve() and contents == []
        assert not cwd.exists()  # the scanner's own temp directory, removed afterwards


def test_gitleaks_adds_what_the_built_in_rules_missed(engagement, synthetic_repo, monkeypatch,
                                                       tmp_path):
    src_hist = item("old.py", 4, commit="c" * 40)
    bindir = fake_gitleaks(tmp_path, tree=[], history=[src_hist])
    ctx, before = _scan(engagement, synthetic_repo, monkeypatch, None, {})
    # tree results carry absolute paths, like the real tool
    tree = [item(str(ctx.source_root.resolve() / "pay.py"), 1)]
    bindir = fake_gitleaks(tmp_path, tree=tree, history=[src_hist])
    ctx, after = _scan(engagement, synthetic_repo, monkeypatch, bindir,
                       {"pay.py": f'CHARGE = "{STRIPE}"\n'})
    added = [f for f in after if "gitleaks" in f.tags]
    assert sorted(f.title for f in added) == [
        "Stripe access token (gitleaks)", "Stripe access token (gitleaks) in git history"]
    tree_f = next(f for f in added if f.title.endswith("(gitleaks)"))
    assert tree_f.severity == "critical" and tree_f.evidence[0].path == "pay.py"
    assert tree_f.evidence[0].excerpt == "[redacted by gitleaks]"
    assert STRIPE not in json.dumps([f.model_dump(mode="json") for f in after])
    assert len(after) == len(before) + 2
    assert all("--redact" in line for line in (tmp_path / "gl-args.txt").read_text().splitlines())


def test_gitleaks_duplicates_are_dropped(engagement, synthetic_repo, monkeypatch, tmp_path):
    ctx, before = _scan(engagement, synthetic_repo, monkeypatch, None,
                        {"keys.py": f'AWS_ACCESS_KEY_ID = "{LEAKED_KEY}"\n'})
    first = subprocess.run(["git", "-C", str(ctx.source_root), "rev-list", "--max-parents=0",
                            "HEAD"], capture_output=True, text=True).stdout.strip()
    tree = [item(str(ctx.source_root.resolve() / "keys.py"), 1, rule="aws-access-token")]
    history = [item("app.py", 2, commit=first, rule="aws-access-token"),  # built-in found it
               item("keys.py", 1, commit="d" * 40, rule="aws-access-token")]  # tree dup
    bindir = fake_gitleaks(tmp_path, tree=tree, history=history)
    ctx, after = _scan(engagement, synthetic_repo, monkeypatch, bindir,
                       {"keys.py": f'AWS_ACCESS_KEY_ID = "{LEAKED_KEY}"\n'})
    assert [f for f in after if "gitleaks" in f.tags] == []
    assert len(after) == len(before)


def test_garbage_output_and_opt_out_leave_built_in_results(engagement, synthetic_repo,
                                                           monkeypatch, tmp_path):
    bindir = tmp_path / "bad"
    bindir.mkdir()
    script = bindir / "gitleaks"
    script.write_text("#!/bin/sh\necho not-json\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    ctx, after = _scan(engagement, synthetic_repo, monkeypatch, bindir, {})
    assert after and not any("gitleaks" in f.tags for f in after)


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_real_gitleaks_finds_a_stripe_key(engagement, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@a.io",
           "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@a.io"}
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
    (repo / "pay.py").write_text(f'CHARGE = "{STRIPE}"\n')
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-qm", "x"],
                   check=True, env=env)
    ingest_tool(engagement, "real", str(repo), "repo")
    ctx = build_context(engagement, "real")
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    findings = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data.findings
    assert any("gitleaks" in f.tags and f.evidence[0].path == "pay.py" for f in findings)
    assert STRIPE not in ctx.paths.scanner_findings.read_text()


def _commit_stripe_repo(repo: Path) -> None:
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@a.io",
           "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@a.io"}
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
    (repo / "pay.py").write_text(f'CHARGE = "{STRIPE}"\n')
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-qm", "x"],
                   check=True, env=env)


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_real_gitleaks_ignores_a_gitleaksignore_in_the_working_directory(tmp_path,
                                                                         monkeypatch):
    repo = tmp_path / "repo"
    _commit_stripe_repo(repo)
    tree, history, note = run_gitleaks(repo, history=True)
    assert note is None and len(tree) == 1 and len(history) == 1
    fingerprints = [e["Fingerprint"] for e in tree + history]
    # A .gitleaksignore in the folder Unvarnish runs from no longer hides client findings.
    here = tmp_path / "consultant"
    here.mkdir()
    (here / ".gitleaksignore").write_text("\n".join(fingerprints) + "\n", encoding="utf-8")
    monkeypatch.chdir(here)
    tree, history, note = run_gitleaks(repo, history=True)
    assert note is None and len(tree) == 1 and len(history) == 1
    # The scanned tree's own .gitleaksignore still applies (the suppression finding names it).
    (repo / ".gitleaksignore").write_text("\n".join(fingerprints) + "\n", encoding="utf-8")
    assert run_gitleaks(repo, history=True) == ([], [], None)


def test_opt_out_log_says_built_in_rules_still_ran(engagement, synthetic_repo, monkeypatch,
                                                   caplog):
    # UNVAR-121: "secrets: disabled" read as if the whole secrets scanner was off
    monkeypatch.setenv("UNVARNISH_DISABLE_GITLEAKS", "1")
    with caplog.at_level(logging.INFO, logger="unvarnish"):
        _, after = _scan(engagement, synthetic_repo, monkeypatch, None,
                         {"keys.py": f'AWS_ACCESS_KEY_ID = "{LEAKED_KEY}"\n'})
    assert after
    assert ("secrets: gitleaks disabled by UNVARNISH_DISABLE_GITLEAKS; built-in rules still ran"
            in caplog.messages)
    assert "secrets: disabled by UNVARNISH_DISABLE_GITLEAKS" not in caplog.messages
