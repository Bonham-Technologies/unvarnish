import re

from typer.testing import CliRunner

from unvarnish.cli import app, complete_doc, complete_format, complete_phase
from unvarnish.export.exporter import DATA_FORMATS, DOC_NAMES, FORMATS, SBOM_FORMATS
from unvarnish.phases import default_phases

runner = CliRunner()


def _plain(text: str) -> str:
    """Help text without colour codes, panel borders or line wrapping."""
    text = re.sub(r"[\u2500-\u257f]", " ", re.sub(r"\x1b\[[0-9;]*m", "", text))
    return re.sub(r"\s+", " ", text)


def _help(*args: str) -> str:
    out = runner.invoke(app, [*args, "--help"], env={"COLUMNS": "400", "NO_COLOR": "1"})
    assert out.exit_code == 0, out.output
    return _plain(out.output)


def test_run_help_lists_phases():
    text = _help("run")
    names = [p.name for p in default_phases()]
    for name in names:
        assert name in text
    assert ", ".join(names) in text  # the pipeline's own list, in its order


def test_export_help_lists_formats_and_docs():
    text = _help("export")
    for name in (*FORMATS, *DATA_FORMATS, *SBOM_FORMATS, *DOC_NAMES):
        assert name in text


def test_phase_completion_filters_by_prefix():
    names = [p.name for p in default_phases()]
    assert complete_phase("") == names
    assert complete_phase("ro") == [n for n in names if n.startswith("ro")]
    assert complete_phase("RO") == complete_phase("ro")
    assert complete_phase("zzz") == []


def test_format_and_doc_completion_filter_by_prefix():
    assert complete_format("") == [*FORMATS, *DATA_FORMATS, *SBOM_FORMATS, "all"]
    assert complete_format("D") == ["docx"]
    assert complete_format("s") == ["sarif"]
    assert complete_doc("") == list(DOC_NAMES)
    assert complete_doc("ar") == ["architecture"]
    assert complete_doc("zzz") == []


def _complete(words: str) -> list[str]:
    """Ask the CLI for completions the way bash does (`--install-completion` wires this up)."""
    out = runner.invoke(app, [], prog_name="unvarnish",
                        env={"_UNVARNISH_COMPLETE": "complete_bash", "COMP_WORDS": words,
                             "COMP_CWORD": str(len(words.split(" ")) - 1)})
    assert out.exit_code == 0, out.output
    return out.output.split()


def test_shell_completion_offers_valid_values():
    assert _complete("unvarnish run --phase rollup") == ["rollup_modules", "rollup_tool"]
    assert _complete("unvarnish run --phase ") == [p.name for p in default_phases()]
    assert _complete("unvarnish export --format ") == [*FORMATS, *DATA_FORMATS, *SBOM_FORMATS,
                                                       "all"]
    assert _complete("unvarnish export --doc f") == ["findings"]
