"""Branding, export polish, and the known-issues backlog."""


def test_metadata_lines_break_instead_of_running_together(ingested):
    """Exported PDFs showed "Generated: ... UTC Source: files plan" on one line."""
    from tests.test_render import _render

    eng, tool = ingested
    doc, _ = _render(eng, tool)
    line = next(ln for ln in doc.splitlines() if ln.startswith("**Client:**"))
    assert line.endswith("\\")


def test_bundled_style_is_offline_and_paged():
    from unvarnish.export.pandoc import bundled_asset

    css = bundled_asset("report.css").read_text(encoding="utf-8")
    assert "@import" not in css and "url(http" not in css  # exports run offline
    assert "counter(pages)" in css and "thead { display: table-header-group; }" in css
    assert bundled_asset("reference.docx").stat().st_size > 10_000
