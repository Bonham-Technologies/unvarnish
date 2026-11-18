"""Found by the OpenRouter simulation (qwen3-coder-30b): model excerpts that are prose, not
source, were printed as code; a placeholder in an example file was confirmed as a critical
credential."""
from tests.stub_backend import StubBackend
from tests.test_rollup_modules import MODULE
from tests.test_rollup_tool import TOOL
from tests.test_verify import _pipeline, _unit_reply
from unvarnish.artifacts import read_artifact
from unvarnish.phases.verify import VerifyPhase, ground_evidence, placeholder_credential
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source, Verification
from unvarnish.schemas.verify import ModelFindings

SOURCE = "def run(cmd):\n    os.system(cmd)\n    return True\n"


def _finding(excerpt=None, note=None, path="a.py", line=2, title="Command injection",
             summary="s") -> Finding:
    return Finding(tool="t", category=Category.security, severity=Severity.high, title=title,
                   summary=summary, impact="i", remediation="r", source=Source.model, model="m",
                   evidence=[Evidence(path=path, line_start=line, line_end=line,
                                      excerpt=excerpt, note=note)])


def test_paraphrased_excerpt_becomes_a_note(tmp_path):
    (tmp_path / "a.py").write_text(SOURCE, encoding="utf-8")
    f = _finding(excerpt="The function runs shell commands without validation.")
    ground_evidence([f], tmp_path)
    assert f.evidence[0].excerpt is None
    assert f.evidence[0].note == "The function runs shell commands without validation."


def test_verbatim_excerpt_is_kept_with_elisions_and_reflowed_whitespace(tmp_path):
    (tmp_path / "a.py").write_text(SOURCE, encoding="utf-8")
    kept = ["os.system(cmd)", "def run(cmd): ... return True", "def run(cmd):  os.system(cmd)",
            "def run(cmd): … return True"]
    findings = [_finding(excerpt=e) for e in kept]
    ground_evidence(findings, tmp_path)
    assert [f.evidence[0].excerpt for f in findings] == kept


def test_existing_note_is_kept_when_an_excerpt_moves(tmp_path):
    (tmp_path / "a.py").write_text(SOURCE, encoding="utf-8")
    f = _finding(excerpt="runs commands", note="value: x")
    ground_evidence([f], tmp_path)
    assert f.evidence[0].excerpt is None and f.evidence[0].note == "value: x; runs commands"


def test_excerpt_of_an_unreadable_file_is_left_alone(tmp_path):
    f = _finding(excerpt="anything", path="missing.py")
    ground_evidence([f], tmp_path)
    assert f.evidence[0].excerpt == "anything"


def _webhook(tmp_path, value: str) -> Finding:
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "job.json").write_text(
        '{\n  "sink": {\n    "headers": { "Authorization": "Bearer '
        + value + '" }\n  }\n}\n',
        encoding="utf-8")
    return _finding(path="examples/job.json", line=3, title="Hardcoded Credential in Configuration",
                    summary="Hardcoded authorization token in webhook configuration.")


def test_placeholder_credential_is_recognised(tmp_path):
    reason = placeholder_credential(_webhook(tmp_path, "REPLACE_ME"), tmp_path)
    assert reason is not None and "REPLACE_ME" in reason


def test_real_looking_credential_is_not_a_placeholder(tmp_path):
    assert placeholder_credential(_webhook(tmp_path, "sk_" + "live_9f8a7b6c5d4e3f2a1b0c"),
                                  tmp_path) is None


def test_only_credential_claims_are_judged_by_placeholder(tmp_path):
    f = _webhook(tmp_path, "REPLACE_ME")
    f.title, f.summary = "Webhook URL is caller-controlled", "SSRF through the sink URL."
    assert placeholder_credential(f, tmp_path) is None


def test_verify_rejects_placeholder_credentials_without_a_model_call(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL,
                        "Verdict": '{"verdict": "confirmed", "reason": "real"}'})
    ctx = _pipeline(eng, tool, stub)
    for path in ctx.source_root.rglob("*"):  # every cited line now holds a placeholder
        if not path.is_file() or ".git" in path.parts:
            continue
        n = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        path.write_text('TOKEN = "REPLACE_ME"\n' * n, encoding="utf-8")
    VerifyPhase(backend=stub).run(ctx)
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    creds = [f for f in mf.findings if f.title == "Hardcoded credential"]
    assert creds and all(f.verification == Verification.rejected for f in creds)
    assert all("placeholder" in (f.verification_note or "") for f in creds)
    assert mf.rejected >= len(creds)
    assert stub.count("Verdict") == mf.verified - len(creds)


def test_placeholder_is_read_from_a_verbatim_excerpt_when_line_numbers_are_off(tmp_path):
    f = _webhook(tmp_path, "REPLACE_ME")
    f.evidence[0].line_start = f.evidence[0].line_end = 5  # the model miscounted
    f.evidence[0].excerpt = '"headers": { "Authorization": "Bearer REPLACE_ME" }'
    ground_evidence([f], tmp_path)
    assert placeholder_credential(f, tmp_path) is not None


def test_placeholder_rejection_survives_a_finding_without_line_numbers(ingested, monkeypatch):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL, "Verdict": '{"verdict": "confirmed", "reason": "r"}'})
    ctx = _pipeline(eng, tool, stub)
    (ctx.source_root / "app.py").write_text('KEY = "REPLACE_ME"\n', encoding="utf-8")
    f = _finding(excerpt='KEY = "REPLACE_ME"', path="app.py", title="Hardcoded API key")
    f.evidence[0].line_start = f.evidence[0].line_end = None
    monkeypatch.setattr("unvarnish.phases.verify.collect_model_findings", lambda ctx: [f])
    VerifyPhase(backend=stub).run(ctx)
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    (got,) = mf.findings
    assert got.verification == Verification.rejected and "placeholder" in got.verification_note
    assert mf.unverified == 0 and mf.rejected == 1


REAL = "sk_" + "live_9f8a7b6c5d4e3f2a1b0c"


def _cited(tmp_path, text: str, title="Hardcoded API token") -> Finding:
    (tmp_path / "cfg.txt").write_text(text + "\n", encoding="utf-8")
    f = _finding(path="cfg.txt", line=1, title=title)
    f.evidence[0].line_end = len(text.splitlines())
    return f


def test_an_apostrophe_in_prose_does_not_swallow_a_real_credential(tmp_path):
    f = _cited(tmp_path, f"// don't ship the example: token = \"{REAL}\" (see 'docs')")
    assert placeholder_credential(f, tmp_path) is None


def test_the_first_branch_of_a_ternary_is_a_value_not_a_key(tmp_path):
    f = _cited(tmp_path, f'const token = isProd ? "{REAL}" : "REPLACE_ME";')
    assert placeholder_credential(f, tmp_path) is None


def test_a_real_credential_with_a_backslash_is_still_a_value(tmp_path):
    f = _cited(tmp_path, 'TOKEN = "REPLACE_ME"; SECRET = "a\\\\b9f8a7b6c5d4e3f2a1"')
    assert placeholder_credential(f, tmp_path) is None


def test_an_unquoted_config_value_counts(tmp_path):
    f = _cited(tmp_path, f'API_TOKEN={REAL}\nEXAMPLE_TOKEN="<your-token>"')
    assert placeholder_credential(f, tmp_path) is None


def test_a_backtick_template_value_counts(tmp_path):
    f = _cited(tmp_path,
               f"headers: {{ Authorization: `Bearer {REAL}`, 'X-Fallback': 'REPLACE_ME' }}")
    assert placeholder_credential(f, tmp_path) is None


def test_a_truncated_excerpt_with_an_open_quote_is_not_judged(tmp_path):
    f = _cited(tmp_path, f'TOKEN = "REPLACE_ME"; REAL = "{REAL}"')
    f.evidence[0].excerpt = 'TOKEN = "REPLACE_ME"; REAL = "sk_live_9f8a'  # cut at 200 chars
    f.evidence[0].line_start = f.evidence[0].line_end = None
    assert placeholder_credential(f, tmp_path) is None


def test_placeholders_in_js_single_quotes_and_dict_keys_are_still_recognised(tmp_path):
    f = _cited(tmp_path, "const headers = {\n  'Authorization': 'Bearer REPLACE_ME',\n"
                         "  \"X-Api-Key\": \"<your-key>\",\n};")
    assert placeholder_credential(f, tmp_path) is not None


def test_a_redacted_quote_stays_an_excerpt(tmp_path):
    from unvarnish.scanners.secrets import redact_text
    line = 'OPENAI_API_KEY = "sk-' + 'proj-Q9x7Lm2Vb8Nc4Zr6Tw1Ks5Hd3Jf0Pg"'
    excerpt = redact_text(line)
    assert excerpt != line  # the extract phase stores excerpts redacted
    f = _cited(tmp_path, line)
    f.evidence[0].excerpt = excerpt
    ground_evidence([f], tmp_path)
    assert f.evidence[0].excerpt == excerpt
    assert placeholder_credential(f, tmp_path) is None


def test_verify_inputs_hash_tracks_the_grounding_logic(ingested, monkeypatch):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL, "Verdict": '{"verdict": "confirmed", "reason": "r"}'})
    ctx = _pipeline(eng, tool, stub)
    before = VerifyPhase(backend=stub).inputs_hash(ctx)
    monkeypatch.setattr("unvarnish.phases.verify.VERIFY_LOGIC_VERSION", "changed")
    assert VerifyPhase(backend=stub).inputs_hash(ctx) != before


def test_a_credential_handling_claim_is_not_a_placeholder_claim(tmp_path):
    f = _cited(tmp_path, "localStorage.setItem('password', pw);",
               title="Password stored in browser localStorage")
    f.summary = "The user's password is kept in localStorage where any script can read it."
    assert placeholder_credential(f, tmp_path) is None


def test_weak_default_passwords_are_findings_not_placeholders(tmp_path):
    """`password = "password"` is a real weak credential; only template markers are skipped."""
    for value in ("password", "secret", "changeme", "test", "admin", ""):
        root = tmp_path / (value or "empty")
        root.mkdir()
        (root / "config.py").write_text(f'DB_PASSWORD = "{value}"\n', encoding="utf-8")
        f = _finding(path="config.py", line=1, title="Hardcoded database password",
                     summary="The database password is hardcoded in config.py.")
        assert placeholder_credential(f, root) is None, value


def test_template_markers_are_placeholders(tmp_path):
    for i, value in enumerate(("REPLACE_ME", "<your-api-key>", "${API_KEY}", "{{ token }}",
                               "your_api_key_here", "xxxxxxxx")):
        root = tmp_path / str(i)
        root.mkdir()
        (root / "config.py").write_text(f'API_KEY = "{value}"\n', encoding="utf-8")
        f = _finding(path="config.py", line=1, title="Hardcoded API key",
                     summary="An API key is hardcoded in config.py.")
        assert placeholder_credential(f, root) is not None, value
