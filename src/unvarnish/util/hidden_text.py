"""Characters that change what a reader sees without showing themselves (UNVAR-92).

Bidirectional controls reorder text on screen (Trojan Source), zero-width characters and
Unicode tag characters carry text nobody sees (the "Rules File Backdoor"), and long runs of
variation selectors or private-use characters can encode a whole payload (GlassWorm). One
detector here serves the hidden-text scanner, the evidence excerpts every finding carries, and
every prompt sent to a model, so all three agree on what is hidden and how it is shown:
each hidden character becomes a visible `[U+XXXX]` escape. Escaping never adds or removes a
newline, so line numbers stay correct.

Legitimate uses are left alone: a byte order mark at the start of the text, a zero-width joiner
inside an emoji sequence, a joiner or non-joiner after a letter of a script that needs them
(Arabic, Persian, Indic), a single variation selector (an emoji's VS16), a single private-use
character (an icon font glyph) and the tag sequence of an emoji subdivision flag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

BIDI = "bidi"  # embeddings, overrides and isolates: U+202A-202E, U+2066-2069
BIDI_MARK = "bidi_mark"  # LRM, RLM, ALM: U+200E, U+200F, U+061C
ZERO_WIDTH = "zero_width"  # U+200B-200D, U+2060-2064, U+FEFF past the start
TAG = "tag"  # U+E0000-E007F
ENCODED = "encoded"  # two or more variation selectors or private-use characters in a row

BIDI_CHARS = {*range(0x202A, 0x202F), *range(0x2066, 0x206A)}
BIDI_MARKS = {0x200E, 0x200F, 0x061C}
ZERO_WIDTH_CHARS = {0x200B, 0x200C, 0x200D, *range(0x2060, 0x2065), 0xFEFF}
ZWNJ, ZWJ, BOM = 0x200C, 0x200D, 0xFEFF
VS16 = 0xFE0F
BLACK_FLAG, CANCEL_TAG = 0x1F3F4, 0xE007F

CANDIDATE_RE = re.compile(
    "[\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufe00-\\ufe0f\\ufeff"
    "\\ue000-\\uf8ff\\U000e0000-\\U000e007f\\U000e0100-\\U000e01ef"
    "\\U000f0000-\\U000ffffd\\U00100000-\\U0010fffd]")

ESCAPE_MAX_RUN = 8  # escapes written per run before "[+N more]"


def is_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def is_private_use(cp: int) -> bool:
    return 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0xFFFFD or 0x100000 <= cp <= 0x10FFFD


def is_emoji(cp: int) -> bool:
    """Code points that start or continue an emoji ZWJ sequence (pictographs, symbols, skin
    tones, the male/female and medical signs, the heart)."""
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or 0x2B00 <= cp <= 0x2BFF
            or 0x2190 <= cp <= 0x21FF or 0x2300 <= cp <= 0x23FF or cp in (0x00A9, 0x00AE,
                                                                          0x203C, 0x2049, 0x2122))


def is_joining_script(cp: int) -> bool:
    """Letters of scripts whose spelling uses ZWJ/ZWNJ: Arabic and Syriac (Persian, Urdu),
    the Indic scripts, Tibetan, Myanmar, Khmer, and Arabic presentation forms."""
    return (0x0600 <= cp <= 0x08FF or 0x0900 <= cp <= 0x0DFF or 0x0F00 <= cp <= 0x109F
            or 0x1780 <= cp <= 0x17FF or 0xFB50 <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFC)


def is_rtl_letter(cp: int) -> bool:
    """Hebrew, Arabic and the other right-to-left scripts, with their presentation forms."""
    return 0x0590 <= cp <= 0x08FF or 0xFB1D <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFC


def kind_of(cp: int) -> str | None:
    if cp in BIDI_CHARS:
        return BIDI
    if cp in BIDI_MARKS:
        return BIDI_MARK
    if cp in ZERO_WIDTH_CHARS:
        return ZERO_WIDTH
    if 0xE0000 <= cp <= 0xE007F:
        return TAG
    if is_selector(cp) or is_private_use(cp):
        return ENCODED
    return None


@dataclass(frozen=True)
class HiddenRun:
    """A run of consecutive hidden characters of one kind: text[start:end]."""

    start: int
    end: int
    kind: str
    chars: str

    @property
    def length(self) -> int:
        return self.end - self.start


def _before(text: str, i: int) -> int | None:
    """The code point before position i, skipping a VS16 or a skin-tone modifier."""
    j = i - 1
    while j >= 0 and (ord(text[j]) == VS16 or 0x1F3FB <= ord(text[j]) <= 0x1F3FF):
        j -= 1
    return ord(text[j]) if j >= 0 else None


def _legitimate(text: str, run: HiddenRun, at_start: bool) -> bool:
    if run.kind == ZERO_WIDTH and run.length == 1:
        cp = ord(run.chars)
        if cp == BOM and run.start == 0 and at_start:
            return True
        prev = _before(text, run.start)
        nxt = ord(text[run.end]) if run.end < len(text) else None
        if cp == ZWJ and prev is not None and nxt is not None and is_emoji(prev) \
                and is_emoji(nxt):
            return True
        if cp in (ZWJ, ZWNJ) and any(c is not None and is_joining_script(c)
                                     for c in (prev, nxt)):
            return True
    if run.kind == ENCODED and run.length == 1:
        return True  # an emoji's VS16, a CJK variation, an icon font glyph
    if run.kind == TAG and run.start > 0 and ord(text[run.start - 1]) == BLACK_FLAG \
            and ord(run.chars[-1]) == CANCEL_TAG and run.length <= 8:
        return True  # a subdivision flag: black flag, tag letters, cancel tag
    return False


def hidden_runs(text: str, *, at_start: bool = True) -> list[HiddenRun]:
    """Every run of hidden characters in `text` that is not a legitimate use, in order.
    `at_start`: `text` begins a file, so a BOM at its first position is legitimate."""
    if not CANDIDATE_RE.search(text):
        return []
    runs: list[HiddenRun] = []
    i, n = 0, len(text)
    while i < n:
        m = CANDIDATE_RE.search(text, i)
        if not m:
            break
        start = m.start()
        kind = kind_of(ord(text[start])) or ""
        end = start + 1
        while end < n and kind_of(ord(text[end])) == kind:
            end += 1
        if kind == ZERO_WIDTH:  # judged one by one: a BOM or joiner is legitimate alone
            span = -1  # start of the current stretch of illegitimate characters
            for k in range(start, end):
                if _legitimate(text, HiddenRun(k, k + 1, kind, text[k]), at_start):
                    if span >= 0:
                        runs.append(HiddenRun(span, k, kind, text[span:k]))
                        span = -1
                elif span < 0:
                    span = k
            if span >= 0:
                runs.append(HiddenRun(span, end, kind, text[span:end]))
        else:
            run = HiddenRun(start, end, kind, text[start:end])
            if not _legitimate(text, run, at_start):
                runs.append(run)
        i = end
    return runs


def has_hidden(text: str, *, at_start: bool = True) -> bool:
    return bool(hidden_runs(text, at_start=at_start))


def escape_run(chars: str, max_run: int = ESCAPE_MAX_RUN) -> str:
    shown = "".join(f"[U+{ord(c):04X}]" for c in chars[:max_run])
    more = len(chars) - max_run
    return shown + (f"[+{more} more]" if more > 0 else "")


def escape_hidden(text: str, *, at_start: bool = True) -> str:
    """`text` with every hidden run written as `[U+XXXX]` escapes; a run longer than
    ESCAPE_MAX_RUN ends in `[+N more]`. Newlines are never touched. Pass `at_start=False`
    for text that does not begin a file (an excerpt, a prompt), so a BOM is escaped too."""
    runs = hidden_runs(text, at_start=at_start)
    if not runs:
        return text
    parts: list[str] = []
    pos = 0
    for r in runs:
        parts.append(text[pos:r.start])
        parts.append(escape_run(r.chars))
        pos = r.end
    parts.append(text[pos:])
    return "".join(parts)


def escape_optional(text: str | None) -> str | None:
    """An excerpt or note with every hidden character escaped, a leading BOM included."""
    return escape_hidden(text, at_start=False) if text else text
