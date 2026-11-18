"""Build the bundled reference.docx (the Word style for DOCX exports) from pandoc's default.

Run: uv run --with python-docx python scripts/build-reference-docx.py [out.docx]
Edit the constants to brand it, or open the result in Word, change the styles (Heading 1-4,
Normal, Block Text, Table), the footer, and the page size, and save it under a new name; then
set report.branding.reference_docx in engagement.yaml. Only styles, headers, footers, and page
setup carry over: pandoc ignores the document's text.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_TAB_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

FONT = "Calibri"
MONO = "Consolas"
INK = "1F2933"
MUTED = "52606D"
RULE = "D9E2EC"
WASH = "F5F7FA"
ACCENT = "243B53"
FOOTER_TEXT = "Confidential"
HEADINGS = {"Heading 1": 20, "Heading 2": 15, "Heading 3": 12.5, "Heading 4": 11,
            "Title": 24}


def _rgb(hex_: str) -> RGBColor:
    return RGBColor.from_string(hex_)


def _border(ppr_or_tcpr, edge: str, color: str, size: int) -> None:
    tag = "w:pBdr" if ppr_or_tcpr.tag == qn("w:pPr") else "w:tcBorders"
    box = ppr_or_tcpr.find(qn(tag))
    if box is None:
        box = OxmlElement(tag)
        ppr_or_tcpr.append(box)
    el = OxmlElement(f"w:{edge}")
    for k, v in (("w:val", "single"), ("w:sz", str(size)), ("w:space", "4"), ("w:color", color)):
        el.set(qn(k), v)
    box.append(el)


def _shade(parent, fill: str) -> None:
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    parent.append(shd)


def _field(run, instr: str) -> None:
    for kind, text in (("begin", None), (None, instr), ("separate", None), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)


def build(out: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "default.docx"
        with base.open("wb") as fh:
            subprocess.run(["pandoc", "--print-default-data-file", "reference.docx"],
                           stdout=fh, check=True)
        doc = Document(str(base))

    styles = doc.styles
    normal = styles["Normal"]
    normal.font.name, normal.font.size, normal.font.color.rgb = FONT, Pt(10.5), _rgb(INK)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.15
    for name in ("Body Text", "First Paragraph", "Compact"):
        if name in [s.name for s in styles]:
            styles[name].font.name = FONT
    for name, size in HEADINGS.items():
        if name not in [s.name for s in styles]:
            continue
        st = styles[name]
        st.font.name, st.font.size, st.font.bold = FONT, Pt(size), True
        st.font.color.rgb = _rgb(ACCENT)
        st.font.italic = False
        st.paragraph_format.space_before = Pt(18 if name in ("Heading 1", "Title") else 12)
        st.paragraph_format.space_after = Pt(6)
        st.paragraph_format.keep_with_next = True
    _border(styles["Heading 1"].element.get_or_add_pPr(), "bottom", ACCENT, 18)
    _border(styles["Heading 2"].element.get_or_add_pPr(), "bottom", RULE, 6)

    if "Block Text" in [s.name for s in styles]:
        bt = styles["Block Text"]
        bt.font.name, bt.font.size, bt.font.color.rgb = FONT, Pt(10), _rgb(MUTED)
        bt.font.italic = False
        ppr = bt.element.get_or_add_pPr()
        _border(ppr, "left", ACCENT, 18)
        _shade(ppr, WASH)
    for name in ("Source Code", "Verbatim Char"):
        if name in [s.name for s in styles]:
            styles[name].font.name, styles[name].font.size = MONO, Pt(9)

    # Pandoc's tables use the "Table" style: header row on a wash with an accent rule.
    if "Table" in [s.name for s in styles]:
        tbl = styles["Table"].element
        tbl_ppr = tbl.find(qn("w:tblPr"))
        if tbl_ppr is None:
            tbl_ppr = OxmlElement("w:tblPr")
            tbl.append(tbl_ppr)
        borders = OxmlElement("w:tblBorders")
        for edge in ("insideH", "bottom"):
            el = OxmlElement(f"w:{edge}")
            for k, v in (("w:val", "single"), ("w:sz", "4"), ("w:color", RULE)):
                el.set(qn(k), v)
            borders.append(el)
        tbl_ppr.append(borders)
        first = OxmlElement("w:tblStylePr")
        first.set(qn("w:type"), "firstRow")
        rpr = OxmlElement("w:rPr")
        bold = OxmlElement("w:b")
        rpr.append(bold)
        color = OxmlElement("w:color")
        color.set(qn("w:val"), ACCENT)
        rpr.append(color)
        first.append(rpr)
        tcpr = OxmlElement("w:tcPr")
        _shade(tcpr, WASH)
        _border(tcpr, "bottom", ACCENT, 12)
        first.append(tcpr)
        tbl.append(first)

    section = doc.sections[0]
    section.orientation = WD_ORIENT.PORTRAIT
    section.page_width, section.page_height = Inches(8.5), Inches(11)  # Letter; A4 elsewhere
    for side in ("left_margin", "right_margin"):
        setattr(section, side, Inches(0.75))
    section.top_margin, section.bottom_margin = Inches(0.85), Inches(0.8)

    footer = section.footer
    para = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    para.text = ""
    para.paragraph_format.tab_stops.add_tab_stop(Inches(7.0), WD_TAB_ALIGNMENT.RIGHT)
    run = para.add_run(f"{FOOTER_TEXT}\tPage ")
    run.font.size, run.font.color.rgb, run.font.name = Pt(8), _rgb(MUTED), FONT
    for instr, tail in (("PAGE", " of "), ("NUMPAGES", "")):
        r = para.add_run()
        r.font.size, r.font.color.rgb, r.font.name = Pt(8), _rgb(MUTED), FONT
        _field(r, instr)
        if tail:
            t = para.add_run(tail)
            t.font.size, t.font.color.rgb, t.font.name = Pt(8), _rgb(MUTED), FONT

    doc.save(str(out))


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parents[1] / "src/unvarnish/export/assets/reference.docx")
    build(target)
    print(f"wrote {target}")
