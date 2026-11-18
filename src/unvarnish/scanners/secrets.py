from __future__ import annotations

import codecs
import hashlib
import logging
import math
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from unvarnish.analysis.languages import Classification, tool_cache_dir
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.gitleaks import run_gitleaks
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.gitcmd import GitError, git, git_lines, is_git_repo
from unvarnish.util.plural import plural

MAX_SCAN_BYTES = 5_000_000
ACRONYMS = {"api", "jwt", "aws", "gcp", "url", "ssh", "pat", "id", "oauth", "pgp", "rsa", "npm",
            "pypi", "sql", "db", "sas", "sdk", "iam", "kms", "ec", "dsa", "gpg", "uri", "hmac"}


def gitleaks_title(rule_id: str) -> str:
    """A short title from a gitleaks rule id: generic-api-key -> Generic API key."""
    words = [w for w in rule_id.replace("_", "-").split("-") if w]
    if not words:
        return "Secret"
    out = [w.upper() if w.lower() in ACRONYMS else w.lower() for w in words]
    out[0] = out[0] if out[0].isupper() else out[0].capitalize()
    return " ".join(out)


# Files that tell scanners what to ignore, and what Unvarnish does about each.
SUPPRESSION_FILES = {
    ".gitleaksignore": "gitleaks omits every finding listed here; Unvarnish cannot override it",
    ".gitleaks.toml": "overridden: Unvarnish runs gitleaks with its default rules",
    "osv-scanner.toml": "overridden: Unvarnish runs osv-scanner with an empty configuration",
    ".secrets.baseline": "detect-secrets baseline; not used by Unvarnish",
    ".trivyignore": "not used by Unvarnish",
    ".snyk": "Snyk policy; not used by Unvarnish",
}
log = logging.getLogger("unvarnish.secrets")

LITERAL_VALUES = {"undefined", "null", "none", "nil", "true", "false", "nan", "empty",
                  "current-password", "new-password", "one-time-code", "username"}
FIXTURE_PREFIXES = ("test", "fake", "mock", "dummy", "sample", "example", "placeholder",
                    "env(", "process.env", "os.environ", "secrets.", "settings.", "config.")
PLACEHOLDER_WORDS = {"changeme", "change_me", "password", "secret", "example", "placeholder",
                     "your_api_key", "your-api-key", "dummy", "test", "todo", "replace_me",
                     "xxx"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    if v in PLACEHOLDER_WORDS or v in LITERAL_VALUES:
        return True
    if v.startswith(("<", "${", "{{", "%(", "$")) or v.endswith(">"):
        return True
    if v.startswith(FIXTURE_PREFIXES):
        return True
    if len(set(v)) <= 2:  # "xxxxxxxx", "********"
        return True
    return any(word in v for word in ("your_", "your-", "example", "changeme", "placeholder"))


DOCUMENTED_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
PEM_BODY_CHARS_RE = re.compile(r"[A-Za-z0-9+/=]")
MIN_PEM_BODY_CHARS = 40
PEM_PUNCTUATION = " \t'\"`+,;)\\"


def is_documented_example(raw: str) -> bool:
    """Vendor-documented sample keys (AWS's AKIAIOSFODNN7EXAMPLE) are public, not leaks."""
    return raw in DOCUMENTED_EXAMPLES or "EXAMPLE" in raw.upper()


def pem_body_is_placeholder(body: str) -> bool:
    """A PEM body like "MIIE..." or "..." is a placeholder. A body line with a colon is a PEM
    header (Proc-Type: 4,ENCRYPTED), and an empty one is unknown: both still count as keys."""
    body = body.strip().strip(PEM_PUNCTUATION)
    if not body or ":" in body:
        return False
    return ("..." in body or "…" in body
            or len(PEM_BODY_CHARS_RE.findall(body)) < MIN_PEM_BODY_CHARS)


def _pem_inline_body(line: str, header: str) -> str:
    """The body after a PEM header on the same line, as in "-----BEGIN ...-----\\nMIIE...",
    or "" when the header ends its string ('...-----\\n' +) and the body is on the next line."""
    rest = line.split(header, 1)[1] if header in line else ""
    if not rest.startswith("\\n"):
        return ""
    first = rest[2:].split("-----END", 1)[0].split("\\n", 1)[0]
    return first.strip().strip(PEM_PUNCTUATION)


def _plausible_generic_value(raw: str) -> bool:
    v = raw.strip()
    if is_placeholder(v):
        return False
    # Real credentials are either high-entropy or carry digits/symbols; bare identifiers
    # like "undefined" and prose words are neither.
    return shannon_entropy(v) >= 2.5 or any(ch.isdigit() or not ch.isalnum() for ch in v)


def _plausible_openai_key(raw: str) -> bool:
    body = raw[3:]
    return (any(ch.isdigit() for ch in body) and any(ch.isalpha() for ch in body)
            and shannon_entropy(body) >= 3.5)


@dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    title: str
    value_group: int = 0
    keep_prefix: bool = False  # show the first 4 chars (safe only for well-known key prefixes)
    validate: Callable[[str], bool] | None = None


_GENERIC_KEYS = (
    r"api[_-]?key|secret|password|passwd|pwd|auth[_-]?token|access[_-]?token|token"
    r"|access[_-]?key"
)

RULES: list[SecretRule] = [
    SecretRule("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
               Severity.critical, "Anthropic API key", keep_prefix=True),
    SecretRule("openai_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}\b"),
               Severity.critical, "OpenAI API key", keep_prefix=True,
               validate=_plausible_openai_key),
    SecretRule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
               Severity.critical, "AWS access key ID", keep_prefix=True),
    SecretRule("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"),
               Severity.critical, "GitHub token", keep_prefix=True),
    SecretRule("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
               Severity.critical, "Slack token", keep_prefix=True),
    SecretRule(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        Severity.critical, "Private key material",
    ),
    SecretRule(
        "connection_string",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql)"
            r"://[^\s:/@]+:([^\s@]+)@[^\s'\"]+"
        ),
        Severity.critical, "Database connection string with embedded password", value_group=1,
    ),
    SecretRule(
        "generic_assignment",
        re.compile(
            rf"(?i)['\"]?\b[\w.-]*(?:{_GENERIC_KEYS})\b['\"]?\s*[:=]\s*['\"]([^'\"\s]{{8,}})['\"]"
        ),
        Severity.critical, "Hardcoded credential assignment", value_group=1,
        validate=_plausible_generic_value,
    ),
]


def fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


@dataclass
class SecretMatch:
    rule: str
    path: str
    line: int | None
    raw: str
    line_text: str
    commit: str | None = None
    identity: str | None = None  # what tells two values apart when raw does not (PEM keys)


def fingerprint_of(m: SecretMatch) -> str:
    return fingerprint(m.identity or m.raw)


# A literal each rule's match must contain; lines without it skip the regex.
RULE_HINTS: dict[str, tuple[str, ...]] = {
    "anthropic_key": ("sk-ant-",), "openai_key": ("sk-",), "aws_access_key": ("akia", "asia"),
    "github_token": ("gh",), "slack_token": ("xox",), "private_key": ("private key",),
    "connection_string": ("://",),
    "generic_assignment": ("key", "secret", "password", "passwd", "pwd", "token"),
}


def line_may_match(rule: SecretRule, line: str) -> bool:
    hints = RULE_HINTS.get(rule.name)
    if not hints:
        return True
    low = line.lower()
    return any(h in low for h in hints)


GITIGNORED_NOTE = "gitignored: present in the ingested copy, not in the repository"
# Without git, whether a file matching an ignore rule is tracked is unknown: a .env committed
# before it was ignored still matches the rule and is still in the repository.
IGNORE_RULE_NOTE = "matches a .gitignore rule: may be absent from the repository"


def tracked_paths(root) -> set[str] | None:
    """The paths git tracks in root, or None when that is unknown (no git, or git failed).
    The census's "gitignore" reason comes from the ignore rules alone, not from the index."""
    if not is_git_repo(root):
        return None
    try:
        return {p for p in git(["ls-files", "-z"], root).split("\0") if p}
    except GitError:
        return None


def ignore_note(path: str, gitignored: set[str], tracked: set[str] | None) -> str | None:
    """What a secret's evidence says about a file the census recorded as gitignored."""
    if path not in gitignored:
        return None
    if tracked is None:
        return IGNORE_RULE_NOTE
    return None if path in tracked else GITIGNORED_NOTE


def tree_skip_reason(rec) -> str | None:
    """Why the working-tree pass did not read this file, or None if it did. Tool caches are
    skipped by path, whatever the census's exclusion reason: gitignore wins there (pytest
    writes its own .gitignore into .pytest_cache), and a cache holds copies of test data, not
    credentials. Build output (dist/, .next/) is still read, because a key baked into a
    shipped bundle is a live leak, and so is every other gitignored text file (a .env)."""
    if rec.classification in (Classification.binary, Classification.vendored):
        return rec.classification.value
    if rec.bytes > MAX_SCAN_BYTES:
        return "over 5 MB"
    if rec.exclusion_reason == "lockfile":
        return "lockfile"
    cache = tool_cache_dir(PurePosixPath(rec.path))
    if cache:
        return f"tool cache: {cache}"
    return None


def dedupe_gitleaks_history(items: list[dict]) -> list[dict]:
    """One gitleaks history result per rule, file, and commit: gitleaks reports the same
    secret again at each line a later diff hunk moves it to."""
    seen: set[tuple[str, str, str]] = set()
    out = []
    for e in items:
        key = (str(e.get("RuleID")), str(e.get("File")), str(e.get("Commit")))
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def history_note(sha: str, path: str, skipped_reason: str | None) -> str:
    """The note on a secret found only in history. A file the tree pass skipped (vendored,
    oversized, a lockfile) is still present, so it was not "removed"."""
    if skipped_reason:
        return (f"added in commit {sha}; the file is still in the working tree but was not "
                f"scanned there ({skipped_reason}); recoverable by anyone with repository access")
    return (f"added in commit {sha}; removed from the working tree but recoverable by anyone "
            f"with repository access")


def _rule(name: str) -> SecretRule:
    return next(r for r in RULES if r.name == name)


def redact_line(line_text: str, matches: Iterable[SecretMatch]) -> str:
    """Redact every matched value on a line. Never returns a line containing a raw value."""
    matches = list(matches)
    out = line_text
    for m in sorted(matches, key=lambda m: -len(m.raw)):
        rule = _rule(m.rule)
        keep = m.raw[:4] if (rule.keep_prefix and len(m.raw) > 8) else ""
        out = out.replace(m.raw, f"{keep}…[redacted {len(m.raw)} chars]")
    out = out.strip()[:200]
    if any(m.raw in out for m in matches):
        return "[line redacted]"
    return out


def redact_text(text: str) -> str:
    """Redact every secret the rules recognise anywhere in free text (model output, notes)."""
    matches = scan_text("", text)
    if not matches:
        return text
    out = text
    for m in sorted(matches, key=lambda m: -len(m.raw)):
        rule = _rule(m.rule)
        keep = m.raw[:4] if (rule.keep_prefix and len(m.raw) > 8) else ""
        out = out.replace(m.raw, f"{keep}…[redacted {len(m.raw)} chars]")
    if any(m.raw in out for m in matches):
        return "[text redacted]"
    return out


def _redact_value(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    return value


def redact_model_text[M](model: M) -> M:
    """A copy of a model's output with every string run through redact_text: a model can
    repeat a secret it read in a summary, a description, or a risk."""
    data = _redact_value(model.model_dump())  # type: ignore[attr-defined]
    return type(model).model_validate(data)  # type: ignore[attr-defined]


def redact(line_text: str, raw: str, keep_prefix: bool = True) -> str:
    keep = raw[:4] if (keep_prefix and len(raw) > 8) else ""
    out = line_text.replace(raw, f"{keep}…[redacted {len(raw)} chars]").strip()[:200]
    return out if raw not in out else "[line redacted]"


def _match_line(
    rule: SecretRule, path: str, lineno: int | None, text: str, commit: str | None
) -> list[SecretMatch]:
    out = []
    if not line_may_match(rule, text):
        return out
    for m in rule.pattern.finditer(text):
        raw = m.group(rule.value_group) if rule.value_group else m.group(0)
        if rule.value_group and is_placeholder(raw):
            continue
        if is_documented_example(raw):
            continue
        if rule.validate is not None and not rule.validate(raw):
            continue
        out.append(SecretMatch(rule=rule.name, path=path, line=lineno, raw=raw,
                               line_text=text, commit=commit))
    return out


def scan_text(path: str, text: str, commit: str | None = None) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    lines = text.split("\n")
    for lineno, line in enumerate(lines, start=1):
        for rule in RULES:
            found = _match_line(rule, path, lineno, line, commit)
            if rule.name == "private_key" and found:
                inline = _pem_inline_body(line, found[0].raw)
                body = inline or (lines[lineno].strip() if lineno < len(lines) else "")
                if pem_body_is_placeholder(body):
                    continue
                for m in found:
                    m.identity = m.raw + body  # every PEM header is the same; the body is not
            matches.extend(found)
    return matches


def _unquote_git_path(s: str) -> str:
    """Decode a git-quoted path ("b/donn\\303\\251es.py" with C escapes)."""
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        raw, _ = codecs.escape_decode(s[1:-1].encode("utf-8"))  # type: ignore[arg-type]
        return raw.decode("utf-8", errors="replace")
    return s


def _diff_target_path(header: str) -> str | None:
    """Path from a '+++ b/...' header, or None for /dev/null and unknown forms."""
    rest = _unquote_git_path(header[4:].strip())
    if rest.startswith("b/"):
        return rest[2:]
    return None


def scan_history_lines(lines: Iterable[str]) -> list[SecretMatch]:
    """Consume a `git log -p --format=%x1e%H` stream; return matches on added lines."""
    matches: list[SecretMatch] = []
    commit: str | None = None
    path: str | None = None
    pending_keys: list[SecretMatch] = []  # PEM headers waiting for their first body line
    for line in lines:
        if line.startswith("\x1e"):
            commit = line[1:].strip() or None
            path = None
            pending_keys = []
        elif line.startswith("+++ "):
            path = _diff_target_path(line)
            pending_keys = []
        elif line.startswith("+") and not line.startswith("+++") and path is not None:
            content = line[1:]
            for m in pending_keys:
                m.identity = m.raw + content.strip()
            if pending_keys and pem_body_is_placeholder(content):
                matches = [m for m in matches if all(m is not k for k in pending_keys)]
            pending_keys = []
            for rule in RULES:
                found = _match_line(rule, path, None, content, commit)
                if rule.name == "private_key" and found:
                    inline = _pem_inline_body(content, found[0].raw)
                    if inline and pem_body_is_placeholder(inline):
                        continue
                    if not inline:
                        pending_keys.extend(found)
                    else:
                        for m in found:
                            m.identity = m.raw + inline
                matches.extend(found)
    return matches


HISTORY_LOG_ARGS = [
    "log", "-p", "--all", "--no-color", "--unified=0", "--no-ext-diff", "--no-textconv",
    "--src-prefix=a/", "--dst-prefix=b/", "--format=%x1e%H",
]


class SecretsScanner:
    name = "secrets"
    category = Category.security

    def __init__(self) -> None:
        self.notes: list[str] = []

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.notes = []
        current: dict[str, list[SecretMatch]] = {}
        line_groups: dict[tuple, list[SecretMatch]] = {}
        tree_seen: set[tuple[str, int | None]] = set()
        history_seen: set[tuple[str, str]] = set()
        for rec in ctx.census.files:
            if tree_skip_reason(rec):
                continue
            text = (ctx.source_root / rec.path).read_text(errors="replace", encoding="utf-8")
            for m in scan_text(rec.path, text):
                current.setdefault(fingerprint_of(m), []).append(m)
                tree_seen.add((m.path, m.line))
                line_groups.setdefault((None, m.path, m.line), []).append(m)

        history: dict[str, SecretMatch] = {}
        history_counts: dict[str, int] = {}
        if is_git_repo(ctx.source_root):
            try:
                stream = git_lines(HISTORY_LOG_ARGS, ctx.source_root)
                for m in scan_history_lines(stream):
                    history_seen.add(((m.commit or "")[:12], m.path))
                    fp = fingerprint_of(m)
                    history.setdefault(fp, m)
                    history_counts[fp] = history_counts.get(fp, 0) + 1
                    line_groups.setdefault((m.commit, m.path, m.line_text), []).append(m)
            except GitError:
                pass  # history unavailable; working-tree findings still stand

        gitignored = {r.path for r in ctx.census.files if r.exclusion_reason == "gitignore"}
        tracked = tracked_paths(ctx.source_root) if gitignored else None
        findings: list[Finding] = []
        for fp, ms in current.items():
            m = ms[0]
            rule = _rule(m.rule)
            note = f"fingerprint {fp}"
            if extra_note := ignore_note(m.path, gitignored, tracked):
                note += f"; {extra_note}"
            if fp in history_counts:
                note += f"; also appears in {plural(history_counts[fp], 'commit')} in git history"
            excerpt = redact_line(m.line_text, line_groups[(None, m.path, m.line)])
            findings.append(self._finding(ctx, rule, m, fp, rule.severity, rule.title,
                                          note, excerpt, extra=len(ms) - 1))

        skipped = {r.path: tree_skip_reason(r) for r in ctx.census.files if tree_skip_reason(r)}
        for fp, m in history.items():
            if fp in current:
                continue
            rule = _rule(m.rule)
            sha = (m.commit or "unknown")[:12]
            note = f"fingerprint {fp}; " + history_note(sha, m.path, skipped.get(m.path))
            excerpt = redact_line(m.line_text, line_groups[(m.commit, m.path, m.line_text)])
            findings.append(self._finding(ctx, rule, m, fp, Severity.high,
                                          f"{rule.title} in git history", note, excerpt,
                                          history=True))
        if ctx.options.get("use_gitleaks", True) is not False:
            findings += self._gitleaks(ctx, tree_seen, history_seen)
        return findings + self._suppression(ctx)

    def _suppression(self, ctx: ScanContext) -> list[Finding]:
        hits = [r for r in ctx.census.files if PurePosixPath(r.path).name in SUPPRESSION_FILES]
        if not hits:
            return []
        names = sorted({PurePosixPath(r.path).name for r in hits})
        return [Finding(
            tool=ctx.tool, category=self.category,
            severity=Severity.medium if ".gitleaksignore" in names else Severity.low,
            title="Scanner suppression files in the source",
            summary=(f"The repository carries files that tell security scanners what to "
                     f"ignore: {', '.join(names)}. Unvarnish's built-in secret rules ignore "
                     f"all of them; see each file's note for what gitleaks and osv-scanner do."),
            impact=("A suppression entry can silence a real secret or vulnerability for "
                    "everyone who relies on the scans."),
            remediation=("Review every entry. Each should name a confirmed false positive and "
                         "the reason; fix and remove entries that hide real issues."),
            evidence=[Evidence(path=r.path, note=SUPPRESSION_FILES[PurePosixPath(r.path).name])
                      for r in hits[:20]],
            source=Source.scanner, scanner=self.name, tags=["suppression"],
            **rule_effort(ctx, self.name, "suppression"),
        )]

    def _gitleaks(self, ctx: ScanContext, tree_seen: set, history_seen: set) -> list[Finding]:
        tree, history, note = run_gitleaks(ctx.source_root, history=is_git_repo(ctx.source_root))
        if note:
            log.info("secrets: %s", note)
            self.notes.append(f"gitleaks: {note}")
            return []
        skipped = {r.path for r in ctx.census.files
                   if r.excluded or r.classification in (Classification.binary,
                                                         Classification.vendored)}
        tree_rules = {(e.get("RuleID"), e.get("File")) for e in tree}
        out: list[Finding] = []
        seen: set[str] = set()
        history = dedupe_gitleaks_history(history)
        for entry, in_history in [(e, False) for e in tree] + [(e, True) for e in history]:
            path = str(entry.get("File") or "")
            line = int(entry.get("StartLine") or 0) or None
            rule = str(entry.get("RuleID") or "unknown")
            sha = str(entry.get("Commit") or "")[:12]
            if not path or path.startswith(("/", "../")):
                continue
            if not in_history and (path in skipped or (path, line) in tree_seen):
                continue
            if in_history and ((sha, path) in history_seen or (rule, path) in tree_rules):
                continue
            fp = hashlib.sha256(str(entry.get("Fingerprint") or f"{sha}:{path}:{rule}:{line}")
                                .encode("utf-8")).hexdigest()[:12]
            if fp in seen:
                continue
            seen.add(fp)
            desc = str(entry.get("Description") or rule)
            where = f" in commit {sha}" if in_history else ""
            out.append(Finding(
                tool=ctx.tool, category=self.category,
                severity=Severity.high if in_history else Severity.critical,
                title=(f"{gitleaks_title(rule)} (gitleaks)"
                       + (" in git history" if in_history else "")),
                summary=(f"gitleaks rule {rule} matched in {path}{where}: "
                         f"{desc.rstrip('.')}. The value is redacted by gitleaks and never "
                         "seen by Unvarnish."),
                impact=("Anyone who can read this code or its history holds a working "
                        "credential. Rotation is required regardless of whether the file is "
                        "still present."),
                remediation=("Rotate the credential now. Move it to a secret manager or "
                             "environment variable. Purge it from git history (git filter-repo) "
                             "before the repository moves anywhere."),
                evidence=[Evidence(path=path, line_start=line, line_end=line,
                                   excerpt="[redacted by gitleaks]", fingerprint=fp,
                                   note=f"gitleaks {rule}{where}")],
                source=Source.scanner, scanner=self.name,
                tags=["gitleaks", rule, *(["history"] if in_history else [])],
                **rule_effort(ctx, self.name,
                              "credential_history" if in_history else "credential"),
            ))
        return out

    def _finding(self, ctx: ScanContext, rule: SecretRule, m: SecretMatch, fp: str,
                 severity: Severity, title: str, note: str, excerpt: str,
                 extra: int = 0, history: bool = False) -> Finding:
        more = (f" ({plural(extra, 'more occurrence', 'more occurrences')} with the same value)"
                if extra else "")
        return Finding(
            tool=ctx.tool, category=self.category, severity=severity, title=title,
            summary=(f"{rule.title} found in {m.path}{more}. The value is redacted here and "
                     f"identified by fingerprint."),
            impact=("Anyone who can read this code or its history holds a working credential. "
                    "Rotation is required regardless of whether the file is still present."),
            remediation=("Rotate the credential now. Move it to a secret manager or environment "
                         "variable. Purge it from git history (git filter-repo) before the "
                         "repository moves anywhere."),
            evidence=[Evidence(path=m.path, line_start=m.line, line_end=m.line,
                               excerpt=excerpt, fingerprint=fp, note=note)],
            source=Source.scanner, scanner=self.name,
            tags=[rule.name, *(["history"] if history else [])],
            **rule_effort(ctx, self.name, "credential_history" if history else "credential"),
        )
