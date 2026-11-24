"""Hidden text in source, configuration and AI rule files, and agent configs that launch
servers fetched at start-up (UNVAR-92).

AI-built repositories carry rule files (`.cursorrules`, `CLAUDE.md`, `AGENTS.md`,
`.github/copilot-instructions.md`, `.cursor/rules/`) that steer every later generation, and
MCP configs that start servers with the assistant's access. Characters nobody sees in review
can hide instructions there ("Rules File Backdoor"), reorder code on screen (Trojan Source)
or carry an encoded payload (GlassWorm). Every excerpt shows them as `[U+XXXX]` escapes,
never raw. Offline and deterministic."""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from unvarnish.analysis.languages import Classification
from unvarnish.config import DEFAULT_SCANNER_OPTIONS
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.client_exposure import is_agent_config
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.secrets import redact_text, tree_skip_reason
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.hidden_text import (
    BIDI,
    BIDI_MARK,
    CANDIDATE_RE,
    ENCODED,
    TAG,
    HiddenRun,
    escape_hidden,
    hidden_runs,
    is_rtl_letter,
)
from unvarnish.util.plural import plural

NAME = "hidden_text"
MAX_EXCERPT = 200

# AI assistant rule and instruction files: by name anywhere in the tree, or any file under
# one of these directories.
RULE_NAMES = {".cursorrules", ".windsurfrules", ".clinerules", ".roorules", ".goosehints",
              "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md",
              "copilot-instructions.md"}
RULE_DIRS = ((".cursor", "rules"), (".windsurf", "rules"), (".clinerules",), (".roo",),
             (".continue", "rules"), (".kiro", "steering"), (".claude",),
             (".github", "instructions"), (".github", "prompts"), (".github", "chatmodes"),
             (".junie",), (".amazonq", "rules"), (".augment", "rules"))
# MCP configs beyond the ones client_exposure reads for credentials.
MCP_NAMES = {"mcp_config.json"}
MCP_DIRS = {".roo", ".windsurf", ".gemini", ".kiro", ".amazonq"}  # <dir>/mcp.json

# Right-to-left locale files, where LRM/RLM/ALM and isolates around placeholders are normal.
RTL_CODES = {"ar", "he", "iw", "fa", "ur", "ps", "yi", "ckb", "sd", "ug", "dv", "syr"}
LOCALE_EXTS = {".json", ".po", ".pot", ".yaml", ".yml", ".xliff", ".xlf", ".arb", ".strings",
               ".stringsdict", ".resx", ".properties", ".xml", ".ts", ".js", ".toml", ".ini",
               ".ftl", ".csv"}
# Code files count as locale files only inside a locale folder: "fa-icons.js" or "he/auth.ts"
# are code, and code is where a bidi override hides logic.
LOCALE_CODE_EXTS = {".ts", ".js"}
LOCALE_DIRS = {"locale", "locales", "i18n", "l10n", "lang", "langs", "languages",
               "translations", "messages", "intl"}

TAG_RULE = f"{NAME}:rule_file"
TAG_MCP = f"{NAME}:mcp"

RULES: dict[str, tuple[Severity, str]] = {
    "bidi": (Severity.high, "Bidirectional control characters in source"),
    "tag": (Severity.high, "Unicode tag characters in source"),
    "encoded_run": (Severity.high, "Long run of invisible encoded characters"),
    "invisible": (Severity.medium, "Invisible characters in source"),
}
SUMMARY = {
    "bidi": "bidirectional override, embedding or isolate characters: the code a "
            "reviewer sees is not the order the compiler reads (Trojan Source).",
    "tag": "Unicode tag characters, which display as nothing and can spell out text "
           "a model reads but a reviewer does not.",
    "encoded_run": "long runs of variation selectors or private-use characters, the "
                   "shape of a payload encoded in characters that display as nothing "
                   "(GlassWorm).",
    "invisible": "zero-width or invisible formatting characters outside an emoji "
                 "sequence or a script that needs them.",
}
IMPACT = {
    "bidi": "Logic can be hidden in a comment or string that renders as harmless, so a "
            "reviewed change does something other than what was approved.",
    "tag": "Hidden instructions or data reach anything that reads the file, including "
           "AI assistants, without appearing in review.",
    "encoded_run": "A decoder elsewhere in the code can turn the run back into a program and "
                   "run it; nothing about the line looks unusual in an editor or a diff.",
    "invisible": "Identifiers and strings that look identical compare unequal, and hidden "
                 "text can ride along with copied code; rarely malicious, but unreviewable.",
}
REMEDIATION = ("Remove the characters (each excerpt shows them as [U+XXXX] escapes), find "
               "the commit that added them, and add a check to CI that rejects them.")


def _option(ctx: ScanContext, key: str) -> Any:
    return ctx.options.get(key, DEFAULT_SCANNER_OPTIONS[NAME][key])


def is_rule_file(path: str) -> bool:
    p = PurePosixPath(path)
    if p.name.lower() in RULE_NAMES and (p.name.lower() != "copilot-instructions.md"
                                         or p.parent.name == ".github"):
        return True
    dirs = p.parts[:-1]
    return any(dirs[i:i + len(seq)] == seq for seq in RULE_DIRS
               for i in range(len(dirs) - len(seq) + 1))


def is_mcp_config(path: str) -> bool:
    p = PurePosixPath(path)
    return is_agent_config(path) or p.name in MCP_NAMES or (
        p.name == "mcp.json" and (p.parent.name in MCP_DIRS or p.parent.parent.name == ".kiro"))


def is_rtl_locale(path: str) -> bool:
    p = PurePosixPath(path.lower())
    if p.suffix not in LOCALE_EXTS or (p.suffix in LOCALE_CODE_EXTS
                                       and not set(p.parts[:-1]) & LOCALE_DIRS):
        return False
    tokens = {t for part in (*p.parts[:-1], p.stem) for t in re.split(r"[._-]", part)}
    return bool(tokens & RTL_CODES)


def _excerpt(line: str, at_start: bool = False) -> str:
    out = escape_hidden(line, at_start=at_start).strip()
    if len(out) > MAX_EXCERPT:
        i = out.find("[U+")
        start = max(0, i - 60)
        out = out[start:start + MAX_EXCERPT]
    return redact_text(out)


def _describe(runs: list[HiddenRun]) -> str:
    counts = Counter(ch for r in runs for ch in r.chars)
    total = sum(counts.values())
    shown = ", ".join(f"U+{ord(c):04X} x{n}" for c, n in counts.most_common(4))
    more = ", ..." if len(counts) > 4 else ""
    return f"{plural(total, 'hidden character')}: {shown}{more}"


@dataclass
class _Hit:
    path: str
    line: int
    excerpt: str
    note: str

    def evidence(self) -> Evidence:
        return Evidence(path=self.path, line_start=self.line, line_end=self.line,
                        excerpt=self.excerpt, note=self.note)


class HiddenTextScanner:
    name = NAME
    category = Category.security

    def run(self, ctx: ScanContext) -> list[Finding]:
        self._ctx = ctx
        self._max = int(_option(ctx, "max_evidence"))
        long_run = int(_option(ctx, "long_run"))
        classes = {Classification.source, Classification.config}
        if _option(ctx, "include_tests"):
            classes.add(Classification.test)
        out: list[Finding] = []
        hits: dict[str, list[_Hit]] = {rule: [] for rule in RULES}
        for rec in ctx.census.files:
            if tree_skip_reason(rec) or rec.exclusion_reason == "gitignore":
                continue
            rule_file, mcp = is_rule_file(rec.path), is_mcp_config(rec.path)
            if not (rule_file or mcp or rec.classification in classes):
                continue
            try:
                text = (ctx.source_root / rec.path).read_text(encoding="utf-8",
                                                              errors="replace")
            except OSError:
                continue
            if mcp:
                finding = self._mcp(rec.path, text)
                if finding:
                    out.append(finding)
            if not CANDIDATE_RE.search(text):
                continue
            if rule_file:
                finding = self._rule_file(rec.path, text)
                if finding:
                    out.append(finding)
            else:
                self._source(rec.path, text, long_run, hits)
        for rule, located in hits.items():
            if located:
                out.append(self._grouped(rule, located))
        return out

    def _finding(self, rule: str, severity: Severity, title: str, summary: str, impact: str,
                 remediation: str, located: list[_Hit], tags: list[str]) -> Finding:
        return Finding(tool=self._ctx.tool, category=self.category, severity=severity,
                       title=title, summary=summary, impact=impact, remediation=remediation,
                       evidence=[h.evidence() for h in located[:self._max]],
                       source=Source.scanner, scanner=self.name, tags=tags,
                       **rule_effort(self._ctx, self.name, rule))

    @staticmethod
    def _lines(path: str, text: str) -> list[tuple[int, str, list[HiddenRun]]]:
        """(line number, line, its hidden runs) for every line with any, a BOM at the very
        start of the file excepted. Marks next to right-to-left letters or in a right-to-left
        locale file, and bidi controls on a locale file's lines of right-to-left text, are
        normal text; a Trojan Source line has no right-to-left letter, so it is still found."""
        rtl_locale = is_rtl_locale(path)
        out = []
        for n, line in enumerate(text.split("\n"), start=1):
            if not CANDIDATE_RE.search(line):
                continue
            runs = hidden_runs(line, at_start=n == 1)
            rtl_line = any(is_rtl_letter(ord(c)) for c in line)
            runs = [r for r in runs if not (
                (r.kind == BIDI_MARK and (rtl_line or rtl_locale))
                or (r.kind == BIDI and rtl_line and rtl_locale))]
            if runs:
                out.append((n, line, runs))
        return out

    def _rule_file(self, path: str, text: str) -> Finding | None:
        lines = self._lines(path, text)
        if not lines:
            return None
        located = [_Hit(path, n, _excerpt(line, n == 1), _describe(runs))
                   for n, line, runs in lines]
        total = sum(r.length for _, _, runs in lines for r in runs)
        return self._finding(
            "rule_file", Severity.high, "Hidden characters in an AI rule file",
            f"{path} steers an AI assistant and holds {plural(total, 'hidden character')} on "
            f"{plural(len(located), 'line')}: zero-width, tag, bidirectional or encoded "
            "characters that display as nothing. They are shown here as [U+XXXX] escapes.",
            "Every generation the assistant makes in this repository can follow instructions "
            "no reviewer has seen (the \"Rules File Backdoor\"), and the code it writes "
            "inherits them.",
            "Remove the characters, read the file's history for who added them, and review "
            "code generated since. Add a check that rejects hidden characters in rule files.",
            located, [TAG_RULE])

    def _source(self, path: str, text: str, long_run: int,
                hits: dict[str, list[_Hit]]) -> None:
        for n, line, runs in self._lines(path, text):
            by_rule: dict[str, list[HiddenRun]] = {}
            for r in runs:
                if r.kind == BIDI:
                    rule = "bidi"
                elif r.kind == TAG:
                    rule = "tag"
                elif r.kind == ENCODED:
                    if r.length < long_run:
                        continue
                    rule = "encoded_run"
                else:  # ZERO_WIDTH, BIDI_MARK
                    rule = "invisible"
                by_rule.setdefault(rule, []).append(r)
            for rule, rs in by_rule.items():
                note = (f"run of {max(r.length for r in rs)} variation selectors or "
                        "private-use characters" if rule == "encoded_run" else _describe(rs))
                hits[rule].append(_Hit(path, n, _excerpt(line, n == 1), note))

    def _grouped(self, rule: str, located: list[_Hit]) -> Finding:
        severity, title = RULES[rule]
        located = sorted(located, key=lambda h: (h.path, h.line))
        files = len({h.path for h in located})
        shown = f" Showing the first {self._max}." if len(located) > self._max else ""
        one = len(located) == 1
        return self._finding(
            rule, severity, title,
            f"{plural(len(located), 'line')} in {plural(files, 'file')} "
            f"{'carries' if one else 'carry'} {SUMMARY[rule]}{shown}",
            IMPACT[rule], REMEDIATION, located, [f"{NAME}:{rule}"])

    # MCP configs that start a server from code fetched at launch
    def _mcp(self, path: str, text: str) -> Finding | None:
        data = _load_jsonc(text)
        if not isinstance(data, dict):
            return None
        servers = data.get("mcpServers") or data.get("servers")
        if not isinstance(servers, dict) and isinstance(data.get("mcp"), dict):
            servers = data["mcp"].get("servers")
        if not isinstance(servers, dict):
            return None
        lines = text.split("\n")
        located: list[_Hit] = []
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            verdict = unpinned_launch(spec.get("command"), spec.get("args"))
            if verdict is None:
                continue
            reason, shown = verdict
            key = re.compile(re.escape(json.dumps(str(name))) + r"\s*:")
            line = next((i for i, x in enumerate(lines, start=1) if key.search(x)), 1)
            located.append(_Hit(path, line, _excerpt(shown), f"{name}: {reason}"))
        if not located:
            return None
        return self._finding(
            "mcp_unpinned", Severity.medium,
            "Agent configuration launches an unpinned or downloaded server",
            f"{path} starts {plural(len(located), 'MCP server')} from code fetched at launch: "
            "an npm or Python package without an exact version, or a script piped from the "
            "network into a shell. Each start can run code other than what was reviewed.",
            "Whoever controls the package or the download can change what runs, with the "
            "assistant's tools and credentials, on every machine that opens the project.",
            "Pin each package to an exact version (`pkg@1.2.3`, `pkg==1.2.3`) or vendor the "
            "server, and never pipe a download into a shell.",
            located, [TAG_MCP, "review"])


def _load_jsonc(text: str) -> Any:
    """JSON, or JSON with comments and trailing commas (VS Code's mcp.json); None if neither."""
    for candidate in (text, _strip_jsonc(text)):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    return None


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r",(\s*[}\]])", r"\1", text)


NPM_RUNNERS = {"npx", "bunx"}
NPM_SUBCOMMANDS = {"pnpm": {"dlx"}, "yarn": {"dlx"}, "bun": {"x"}, "npm": {"exec", "x"}}
PY_VALUE_FLAGS = {"--from", "--python", "-p", "--with", "--index-url", "--index", "-i",
                  "--extra-index-url", "--spec"}
SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"}
# The flag after which a shell runs the rest as a command: `sh -c`, `bash -lc`, `cmd /c`,
# `powershell -Command` (Windows MCP configs wrap npx this way).
SHELL_RUN_RE = re.compile(r"(?i)^(?:-[a-z]*c|/[ck]|-command)$")
DOWNLOAD_PIPE_RE = re.compile(
    r"(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*"
    r"(?:sudo\s+)?(?:sh|bash|zsh|dash|iex|invoke-expression|python3?|node)\b")
EXACT_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][\w.]+)?$")


def _is_local(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "file:")) or "\\" in spec


def _npm_pinned(spec: str) -> bool:
    at = spec.rfind("@")
    if spec.startswith(("git+", "github:", "http://", "https://")):
        return "#" in spec
    return at > 0 and bool(EXACT_VERSION_RE.match(spec[at + 1:]))


def _first_package(args: list[str], value_flags: set[str]) -> str | None:
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in value_flags:
            skip = True
            continue
        if a.startswith("-"):
            continue
        return a
    return None


def unpinned_launch(command: Any, args: Any, _depth: int = 0) -> tuple[str, str] | None:
    """(reason, what to show) when a server's command fetches unpinned code at launch; a
    command a shell wrapper runs (`cmd /c npx -y pkg`, `sh -c "uvx srv"`) is judged too."""
    if not isinstance(command, str) or not command.strip():
        return None
    argv = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    if not argv and " " in command.strip():
        try:
            command, *argv = shlex.split(command)
        except ValueError:
            return None
    cmd = PurePosixPath(command.replace("\\", "/")).name.lower().removesuffix(".exe") \
        .removesuffix(".cmd")
    joined = " ".join([command, *argv])
    if DOWNLOAD_PIPE_RE.search(joined) and (cmd in SHELLS or cmd in {"curl", "wget"}):
        return "downloads and runs a script", joined
    if cmd in SHELLS and _depth < 2:
        at = next((i for i, a in enumerate(argv) if SHELL_RUN_RE.match(a)), None)
        inner = argv[at + 1:] if at is not None else []
        if inner:
            got = unpinned_launch(inner[0], inner[1:] or None, _depth + 1)
            if got:
                return got[0], " ".join([command, *argv[:at + 1], got[1]])
        return None
    rest: list[str] | None = None
    if cmd in NPM_RUNNERS:
        rest = argv
    elif cmd in NPM_SUBCOMMANDS and argv and argv[0] in NPM_SUBCOMMANDS[cmd]:
        rest = argv[1:]
    if rest is not None:
        explicit = next((rest[i + 1] for i, a in enumerate(rest[:-1])
                         if a in ("-p", "--package")), None)
        explicit = explicit or next((a.split("=", 1)[1] for a in rest
                                     if a.startswith("--package=")), None)
        spec = explicit or _first_package(rest, {"-p", "--package"})
        if spec and not _is_local(spec) and not _npm_pinned(spec):
            upto = argv[:argv.index(spec) + 1] if spec in argv else argv
            return "unpinned npm package", " ".join([command, *upto])
        return None
    py_rest: list[str] | None = None
    if cmd == "uvx":
        py_rest = argv
    elif cmd == "uv" and argv[:2] == ["tool", "run"]:
        py_rest = argv[2:]
    elif cmd == "pipx" and argv[:1] == ["run"]:
        py_rest = argv[1:]
    if py_rest is not None:
        frm = next((py_rest[i + 1] for i, a in enumerate(py_rest[:-1])
                    if a in ("--from", "--spec")), None)
        spec = frm or _first_package(py_rest, PY_VALUE_FLAGS)
        if spec and not _is_local(spec) and not re.search(r"==\s*\d|@\s*v?\d", spec):
            upto = argv[:argv.index(spec) + 1] if spec in argv else argv
            return "unpinned Python package", " ".join([command, *upto])
    return None


