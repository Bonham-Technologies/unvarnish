import json

from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.ask.bm25 import BM25, tokenize
from unvarnish.ask.index import AskIndex, build_index, load_or_build_index
from unvarnish.engagement import Engagement


def test_tokenize_and_bm25_rank():
    assert tokenize("Reads the Expenses-DB table; writes_nothing!") == [
        "reads", "the", "expenses", "db", "table", "writes_nothing"]
    docs = [tokenize(t) for t in ("the cat sat", "the dog sat on the log", "expenses report")]
    scores = BM25(docs).score(tokenize("expenses"))
    assert scores[2] > 0 and scores[0] == 0 == scores[1]
    scores = BM25(docs).score(tokenize("the sat"))
    assert scores[0] > scores[1] > 0  # shorter doc with the same terms ranks higher


def test_paths_exist(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    assert eng.index_file == eng.root / "cache" / "index" / "index.json"
    assert eng.ask_sessions_dir == eng.root / "ask-sessions" and eng.ask_sessions_dir.is_dir()


def test_build_index_covers_every_artifact_kind(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    index = build_index(engagement)
    kinds = {d.kind for d in index.docs}
    assert kinds == {"unit", "module", "tool", "finding", "capability"}
    assert {d.tool for d in index.docs} == {"alpha", "beta"}
    finding_docs = [d for d in index.docs if d.kind == "finding"]
    assert any("AWS access key" in d.text for d in finding_docs)  # scanner findings too
    assert any(d.text.startswith("Hardcoded credential") for d in finding_docs)
    # the README.md credential finding is rejected by the stub verifier: not indexed
    assert not any(d.path == "README.md" and d.text.startswith("Hardcoded credential")
                   for d in finding_docs)
    hits = index.search("export report", k=3)
    assert hits and hits[0].kind == "capability" and hits[0].tool in ("alpha", "beta")
    only_beta = index.search("export report", tool="beta")
    assert only_beta and all(h.tool == "beta" for h in only_beta)
    assert all(len(h.snippet) <= 240 for h in hits)


def test_index_rebuilds_when_artifacts_change(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    index, rebuilt = load_or_build_index(engagement)
    assert rebuilt and engagement.index_file.exists()
    again, rebuilt = load_or_build_index(engagement)
    assert not rebuilt and again.inputs_hash == index.inputs_hash
    tool_json = engagement.tool_paths("alpha").tool_model
    data = json.loads(tool_json.read_text())
    data["data"]["purpose"] = "Something entirely new"
    tool_json.write_text(json.dumps(data))
    fresh, rebuilt = load_or_build_index(engagement)
    assert rebuilt and fresh.inputs_hash != index.inputs_hash
    assert any("entirely new" in d.text for d in fresh.docs if d.kind == "tool")


def test_index_handles_scanner_only_tool(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub, model_for=("alpha",))
    index = build_index(engagement)
    beta = [d for d in index.docs if d.tool == "beta"]
    assert beta and {d.kind for d in beta} == {"finding"}
    assert AskIndex.model_validate(index.model_dump()).search("access key")  # round-trips
