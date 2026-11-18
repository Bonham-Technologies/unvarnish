"""Fixes found by simulating a GPU on-prem server through OpenRouter (qwen-2.5-coder-32b, 32k
context)."""
from types import SimpleNamespace

from tests.test_rc_fixes import _backend
from unvarnish.config import BackendCapabilities
from unvarnish.model.base import CompletionRequest, Message


def _ok():
    return SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(content="{}", refusal=None), finish_reason="stop")],
        usage=None, model="m")


def test_max_tokens_is_clamped_to_what_fits_in_the_context_window():
    """The tool rollup asked for 32,000 output tokens on a 32,768-token server; with a
    4,721-token prompt the server rejected it (400) instead of answering."""
    sent = []

    class Comp:
        def create(self, **kw):
            sent.append(kw)
            return _ok()

    b, _ = _backend([])
    b.capabilities = BackendCapabilities(context_window=32_768)
    b._client = SimpleNamespace(chat=SimpleNamespace(completions=Comp()))
    req = CompletionRequest(system="s" * 4000,
                            messages=[Message(role="user", content="u" * 14_000)],
                            max_tokens=32_000)
    b.complete(req)
    cap = sent[-1]["max_tokens"]
    assert 20_000 < cap <= 32_768 - (18_000 // 4)
    small = CompletionRequest(system="s", messages=[Message(role="user", content="u")],
                              max_tokens=500)
    b.complete(small)
    assert sent[-1]["max_tokens"] == 500  # small requests are untouched


def test_executive_summary_is_told_when_the_purpose_is_unknown(ingested):
    """With the tool rollup failed, qwen-2.5-coder-32b described plan as "a tool used by
    Bonham Technologies to analyze the internal software codebase": invented."""
    from tests.stub_backend import StubBackend
    from unvarnish.phases.base import PhaseRunner, build_context
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    eng, tool = ingested
    ctx = build_context(eng, tool)
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    stub = StubBackend({"prose": "text"})
    RenderPhase(backend=stub).run(ctx)
    summary = next(r for r in stub.requests if "executive summary" in r.messages[0].content)
    assert "not known" in summary.messages[0].content


def test_common_json_slips_are_repaired_before_a_retry():
    """35 of 103 extractions failed: OpenRouter's provider ignored the JSON schema and the
    model wrote `detail: "..."` with an unquoted key, and trailing commas."""
    from unvarnish.model.structured import _parse
    from unvarnish.schemas.analysis import UnitExtraction

    text = '''{
  "purpose": "Builds the image",
  "external_calls": [
    {
      "kind": "db",
      "system": "playwright",
     detail: "Installed as a runtime dependency via npm"
    },
  ],
  confidence: 0.9,
}'''
    e = _parse(UnitExtraction, text, "stop")
    assert e.external_calls[0].detail.startswith("Installed") and e.confidence == 0.9


def test_repair_leaves_strings_alone():
    from unvarnish.model.structured import repair_json

    good = '{"a": "x: y, }", "b": [1, 2]}'
    assert repair_json(good) == good
    assert repair_json('{"a": "url: http://x",}') == '{"a": "url: http://x"}'


def test_extra_body_is_sent_with_every_request():
    """OpenRouter routes to providers that honour response_format only with
    provider.require_parameters; vLLM takes guided-decoding options the same way."""
    from unvarnish.config import BackendConfig
    from unvarnish.model.registry import build_backend

    cfg = BackendConfig(type="openai_compatible", base_url="https://openrouter.ai/api/v1",
                        extra_body={"provider": {"require_parameters": True}})
    b = build_backend("onprem", cfg, "m")
    sent = []

    class Comp:
        def create(self, **kw):
            sent.append(kw)
            return _ok()

    b._client = SimpleNamespace(chat=SimpleNamespace(completions=Comp()))
    b.complete(CompletionRequest(system="s", messages=[Message(role="user", content="u")],
                                 max_tokens=100))
    assert sent[-1]["extra_body"] == {"provider": {"require_parameters": True}}


def test_config_check_probes_the_server_not_the_cache(tmp_path, fake_llm):
    """A probe answered from the response cache passed although the server, with new
    routing settings, would have refused every request."""
    import json

    from typer.testing import CliRunner

    from tests.test_cli_model_commands import _engagement
    from unvarnish.cli import app

    eng = _engagement(tmp_path, fake_llm)
    good = json.dumps({"purpose": "p", "interface": [], "external_calls": [], "data_read": [],
                       "data_written": [], "auth_behaviour": None, "error_handling": None,
                       "risks": [], "candidate_findings": [], "confidence": 0.5})
    fake_llm.script(good, good)
    runner = CliRunner()
    assert runner.invoke(app, ["config", "check", "-e", str(eng.root)]).exit_code == 0
    assert runner.invoke(app, ["config", "check", "-e", str(eng.root)]).exit_code == 0
    assert len(fake_llm.requests) == 2
