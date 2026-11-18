from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.model.prompts.extract import (
    GENERATED_INSTRUCTION,
    PROMPT_VERSION,
    build_extract_request,
    build_system_prompt,
    build_unit_message,
)
from unvarnish.schemas.analysis import Unit, UnitKind


def _unit(**kw) -> Unit:
    base = dict(id="u1", tool="t", module_id="app.py", path="app.py", language="python",
                kind=UnitKind.function, name="main", line_start=10, line_end=20, byte_start=0,
                byte_end=100, token_estimate=30, split_method="structural")
    base.update(kw)
    return Unit(**base)


def test_system_prompt_is_stable_and_cacheable():
    a, b = build_system_prompt(), build_system_prompt()
    assert a == b
    assert estimate_tokens(a) > 600  # comfortably over the 512-token cache minimum
    assert '"candidate_findings"' in a and "maintainability" in a and "critical" in a
    assert "{{" not in a


def test_unit_message_contents():
    msg = build_unit_message(_unit(), "def main():\n    pass\n", frameworks=["Flask"],
                             neighbourhood=["helper(): parses input", "x" * 500])
    assert "app.py" in msg and "lines 10-20" in msg and "python" in msg and "Flask" in msg
    assert "def main():" in msg
    assert "helper(): parses input" in msg
    assert ("x" * 201) not in msg  # neighbourhood entries truncated
    assert GENERATED_INSTRUCTION not in msg


def test_generated_units_get_reduced_instruction():
    msg = build_unit_message(_unit(generated=True), "var a=1", frameworks=[], neighbourhood=[])
    assert GENERATED_INSTRUCTION in msg


def test_build_extract_request():
    req = build_extract_request(_unit(), "src", frameworks=[], neighbourhood=[], effort="medium")
    assert req.effort == "medium" and req.cache_system is True
    assert req.messages[0].role == "user" and "src" in req.messages[0].content
    assert req.system == build_system_prompt()
    assert PROMPT_VERSION
