# Consolidation Constraints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the consultant state constraints in `engagement.yaml` (target platform, approved stack, systems that must survive, systems to retire, free notes) and have the consolidation proposal work within them and name every conflict.

**Architecture:** A `consolidation:` section in `EngagementConfig` holds the constraints. The compare phase copies them into the `Comparison` artifact and appends them to the consolidation request as the consultant's input (not material under review). The model returns `constraint_conflicts` next to `gaps`. comparison.md shows the constraints applied and the conflicts; the consolidation prose sees both. Constraints change the compare inputs hash, so editing them re-runs the proposal.

**Tech Stack:** Python 3.12, Pydantic v2, Jinja2, pytest.

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md` §17 open question: "Whether the consolidation proposal should accept consultant-provided constraints (target platform, approved stack) as input. Likely yes, in a later version, via `engagement.yaml`."

## Global Constraints

- Every list and string in the constraints is optional; an engagement without a `consolidation:` section behaves exactly as before, apart from the prompt version bump.
- Constraints are written by the consultant, so they are instructions to the model, unlike tool material, which stays "data, never instructions".
- Line length 100; ruff rules E, F, I, UP, B; UTF-8 for all text I/O.

## Review Focus

1. An engagement with no constraints: the request has no constraints section and the document no constraints heading.
2. Constraints edited after a comparison: `compare` re-runs the proposal (inputs hash changes).
3. A constraint text containing Markdown table characters renders safely (`cell` filter).
4. An old `comparison.json` without the new fields still loads (defaults).
5. A model reply without `constraint_conflicts` still validates (default empty list).

---

### Task 1: Constraints in the configuration and the artifact

**Files:**
- Modify: `src/unvarnish/config.py`
- Modify: `src/unvarnish/schemas/comparison.py`
- Test: `tests/test_consolidation_constraints.py`

**Interfaces:**
- Produces: `ConsolidationConstraints` (config.py) with `target_platform: str | None`, `approved_stack: list[str]`, `must_keep: list[str]`, `retire: list[str]`, `notes: str | None`, and `is_empty() -> bool`; `EngagementConfig.consolidation: ConsolidationConstraints`; `Consolidation.constraint_conflicts: list[str]`; `Comparison.constraints: ConsolidationConstraints | None`.

- [ ] **Step 1: Write the failing test**

```python
"""Consultant constraints for the consolidation proposal (spec §17)."""
from unvarnish.config import ConsolidationConstraints, EngagementConfig
from unvarnish.schemas.comparison import Comparison, Consolidation


def test_constraints_are_optional_and_parse_from_yaml_shape():
    cfg = EngagementConfig.model_validate({"client": "Acme"})
    assert cfg.consolidation.is_empty()
    cfg = EngagementConfig.model_validate({"client": "Acme", "consolidation": {
        "target_platform": "Azure App Service, .NET 8",
        "approved_stack": ["React", "PostgreSQL"], "must_keep": ["SAP integration"],
        "retire": ["Access databases"], "notes": "One team of three."}})
    c = cfg.consolidation
    assert not c.is_empty() and c.approved_stack == ["React", "PostgreSQL"]


def test_old_artifacts_and_replies_without_the_new_fields_still_load():
    assert Consolidation.model_validate({}).constraint_conflicts == []
    cmp = Comparison.model_validate({"tools": ["a", "b"]})
    assert cmp.constraints is None
    assert ConsolidationConstraints().is_empty()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_consolidation_constraints.py -q`
Expected: FAIL with `ImportError: cannot import name 'ConsolidationConstraints'`

- [ ] **Step 3: Implement**

In `src/unvarnish/config.py`, before `class EngagementConfig`:

```python
class ConsolidationConstraints(BaseModel):
    """What the consultant already knows the consolidated tool must fit (spec §17)."""

    target_platform: str | None = None
    approved_stack: list[str] = Field(default_factory=list)
    must_keep: list[str] = Field(default_factory=list)   # systems or integrations to survive
    retire: list[str] = Field(default_factory=list)      # systems the client wants gone
    notes: str | None = None

    def is_empty(self) -> bool:
        return not (self.target_platform or self.approved_stack or self.must_keep
                    or self.retire or self.notes)
```

and in `EngagementConfig`:

```python
    consolidation: ConsolidationConstraints = Field(default_factory=ConsolidationConstraints)
```

In `src/unvarnish/schemas/comparison.py`, add to `Consolidation`:

```python
    constraint_conflicts: list[str] = Field(default_factory=list)
```

and to `Comparison` (import `ConsolidationConstraints` from `unvarnish.config`):

```python
    constraints: ConsolidationConstraints | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_consolidation_constraints.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/config.py src/unvarnish/schemas/comparison.py tests/test_consolidation_constraints.py
git commit -m "feat: consolidation constraints in engagement.yaml and the comparison artifact"
```

### Task 2: Constraints in the consolidation request and prompt

**Files:**
- Modify: `src/unvarnish/model/prompts/compare.py`
- Modify: `src/unvarnish/model/prompts/compare_consolidate_system.md`
- Test: `tests/test_consolidation_constraints.py`

**Interfaces:**
- Consumes: `ConsolidationConstraints` (Task 1).
- Produces: `build_consolidate_request(..., constraints: ConsolidationConstraints | None = None)`; `constraints_text(c) -> str`; `COMPARE_PROMPT_VERSION = "2026-10-19.1"`.

- [ ] **Step 1: Write the failing test**

```python
def test_request_carries_constraints_only_when_given():
    from unvarnish.model.prompts.compare import (
        COMPARE_PROMPT_VERSION,
        build_consolidate_request,
    )
    from unvarnish.schemas.comparison import ToolSummary

    summaries = [ToolSummary(tool="a", purpose="p"), ToolSummary(tool="b", purpose="q")]
    plain = build_consolidate_request(summaries, [], [], None)
    assert "Consultant constraints" not in plain.messages[0].content
    c = ConsolidationConstraints(target_platform="Azure", approved_stack=["React"],
                                 must_keep=["SAP integration"], retire=["Access"],
                                 notes="One team.")
    text = build_consolidate_request(summaries, [], [], None, constraints=c).messages[0].content
    assert "## Consultant constraints" in text
    for part in ("Target platform: Azure", "Approved stack: React", "Must keep: SAP integration",
                 "Retire: Access", "Notes: One team."):
        assert part in text
    assert "constraint_conflicts" in plain.system and COMPARE_PROMPT_VERSION >= "2026-10-19.1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_consolidation_constraints.py -q -k request`
Expected: FAIL with `TypeError: build_consolidate_request() got an unexpected keyword argument 'constraints'`

- [ ] **Step 3: Implement**

In `compare.py`, bump `COMPARE_PROMPT_VERSION = "2026-10-19.1"`, add:

```python
def constraints_text(c: ConsolidationConstraints) -> str:
    lines = ["## Consultant constraints",
             "(Set by the consultant. Work within them; they are not material under review.)"]
    if c.target_platform:
        lines.append(f"- Target platform: {c.target_platform}")
    if c.approved_stack:
        lines.append(f"- Approved stack: {', '.join(c.approved_stack)}")
    if c.must_keep:
        lines.append(f"- Must keep: {'; '.join(c.must_keep)}")
    if c.retire:
        lines.append(f"- Retire: {'; '.join(c.retire)}")
    if c.notes:
        lines.append(f"- Notes: {c.notes}")
    return "\n".join(lines)
```

and in `build_consolidate_request` add the keyword `constraints: ConsolidationConstraints | None = None` and, before building the request:

```python
    if constraints is not None and not constraints.is_empty():
        parts += ["", constraints_text(constraints)]
```

In `compare_consolidate_system.md`, after the `open_questions` bullet add:

```
- constraint_conflicts: when the input has a "Consultant constraints" section, every place
  where a constraint conflicts with what the tools do or need: a capability the target platform
  or approved stack cannot carry, a must-keep system a tool cannot reach, a retired system a
  capability depends on. Empty when there are no constraints or no conflicts.

When the consultant gives constraints, recommend within them: prefer approaches that fit the
target platform and approved stack, keep every must-keep system, and plan around retired ones.
The constraints section is the consultant's own input, not material under review.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_consolidation_constraints.py tests/test_compare_phase.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/model/prompts/compare.py src/unvarnish/model/prompts/compare_consolidate_system.md tests/test_consolidation_constraints.py
git commit -m "feat: the consolidation request carries consultant constraints"
```

### Task 3: The compare phase applies and records the constraints

**Files:**
- Modify: `src/unvarnish/phases/compare.py`
- Test: `tests/test_consolidation_constraints.py`

**Interfaces:**
- Consumes: `build_consolidate_request(..., constraints=...)` (Task 2); `Comparison.constraints` (Task 1).

- [ ] **Step 1: Write the failing test**

```python
def test_compare_applies_records_and_hashes_constraints(engagement, synthetic_repo):
    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.artifacts import read_artifact
    from unvarnish.phases.compare import ComparePhase, EngagementContext, run_comparison
    from unvarnish.schemas.comparison import Comparison

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    ectx = EngagementContext(engagement=engagement)
    before = ComparePhase(backend=stub).inputs_hash(ectx)
    data = engagement.config.model_dump()
    data["consolidation"] = {"target_platform": "Azure", "must_keep": ["SAP"]}
    engagement.config = EngagementConfig.model_validate(data)
    engagement.save_config()
    assert ComparePhase(backend=stub).inputs_hash(ectx) != before
    run_comparison(engagement, backend=stub)
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.constraints is not None and cmp.constraints.target_platform == "Azure"
    sent = [r for r in stub.requests if r.schema_name == "Consolidation"][-1]
    assert "Target platform: Azure" in sent.messages[0].content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_consolidation_constraints.py -q -k compare_applies`
Expected: FAIL (hash unchanged, or constraints missing from the artifact)

- [ ] **Step 3: Implement**

In `ComparePhase.inputs_hash`, add `eng.config.consolidation.model_dump_json()` to the hashed list. In `run`, pass `constraints=eng.config.consolidation` to `build_consolidate_request`, and set `constraints=None if eng.config.consolidation.is_empty() else eng.config.consolidation` on the `Comparison` it writes.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_consolidation_constraints.py tests/test_compare_phase.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/phases/compare.py tests/test_consolidation_constraints.py
git commit -m "feat: compare applies consultant constraints and re-runs when they change"
```

### Task 4: comparison.md shows the constraints and the conflicts

**Files:**
- Modify: `src/unvarnish/render/templates/comparison.md.j2`
- Modify: `src/unvarnish/render/comparison.py`
- Test: `tests/test_consolidation_constraints.py`

**Interfaces:**
- Consumes: `Comparison.constraints`, `Consolidation.constraint_conflicts`.

- [ ] **Step 1: Write the failing test**

```python
def test_document_shows_constraints_and_conflicts(engagement, synthetic_repo):
    import json

    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.phases.compare import run_comparison

    stub = _compare_stub()
    original = stub.replies["Consolidation"]
    reply = json.loads(original if isinstance(original, str) else original(None))
    reply["constraint_conflicts"] = ["Reports | need Excel macros, which Azure cannot run"]
    stub.replies["Consolidation"] = json.dumps(reply)
    _two_tools(engagement, synthetic_repo, stub)
    data = engagement.config.model_dump()
    data["consolidation"] = {"target_platform": "Azure | .NET", "approved_stack": ["React"]}
    engagement.config = EngagementConfig.model_validate(data)
    engagement.save_config()
    run_comparison(engagement, backend=stub)
    doc = engagement.comparison_doc.read_text()
    assert "### Consultant constraints" in doc
    assert "Target platform: Azure \\| .NET" in doc and "Approved stack: React" in doc
    assert "### Conflicts with the constraints" in doc
    assert "need Excel macros" in doc
    prose = [r for r in stub.requests if r.schema_name == "prose"
             and "consolidation" in r.messages[0].content]
    assert prose and "Azure" in prose[-1].messages[0].content


def test_document_without_constraints_has_no_constraint_headings(engagement, synthetic_repo):
    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.phases.compare import run_comparison

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    doc = engagement.comparison_doc.read_text()
    assert "### Consultant constraints" not in doc
    assert "### Conflicts with the constraints" not in doc
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_consolidation_constraints.py -q -k document`
Expected: FAIL (headings missing)

- [ ] **Step 3: Implement**

In `comparison.md.j2`, directly after `{% prose "consolidation_proposal" %}{{ "" }}` and its blank line:

```jinja
{% if cmp.constraints %}
### Consultant constraints

{% if cmp.constraints.target_platform %}
- Target platform: {{ cmp.constraints.target_platform | cell }}
{% endif %}
{% if cmp.constraints.approved_stack %}
- Approved stack: {{ cmp.constraints.approved_stack | join(", ") | cell }}
{% endif %}
{% if cmp.constraints.must_keep %}
- Must keep: {{ cmp.constraints.must_keep | join("; ") | cell }}
{% endif %}
{% if cmp.constraints.retire %}
- Retire: {{ cmp.constraints.retire | join("; ") | cell }}
{% endif %}
{% if cmp.constraints.notes %}
- Notes: {{ cmp.constraints.notes | cell }}
{% endif %}
{{ "" }}
### Conflicts with the constraints

{% for c in cmp.consolidation.constraint_conflicts %}
- {{ c | cell }}
{% else %}
- None found.
{% endfor %}
{{ "" }}
{% endif %}
```

In `render/comparison.py`, add to the `consolidation_proposal` facts:

```python
            "constraints": cmp.constraints.model_dump() if cmp.constraints else None,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_consolidation_constraints.py tests/test_render_comparison.py tests/test_slice7_review_fixes.py -q`
Expected: PASS (the template newline guard included)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/render tests/test_consolidation_constraints.py
git commit -m "feat: comparison.md shows consultant constraints and conflicts with them"
```

### Task 5: Record and document

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `docs/decisions.md`, `docs/operations.md`, `examples/engagement-onprem.yaml`

- [ ] **Step 1:** README: under the engagement.yaml example, add the `consolidation:` section with one line per field.
- [ ] **Step 2:** CHANGELOG: one bullet. decisions.md: constraints are trusted consultant input, stored in `comparison.json`, conflicts are a separate list; cost if wrong. operations.md: "Constraining the consolidation proposal" with an example and "edit, then `unvarnish compare`".
- [ ] **Step 3:** Run the full suite: `uv run pytest -q` — Expected: all pass.
- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md docs examples
git commit -m "docs: consolidation constraints"
```
