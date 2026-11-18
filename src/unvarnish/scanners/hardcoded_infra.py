from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from pathlib import PurePosixPath

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.secrets import redact_text, shannon_entropy
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.plural import plural

KINDS = ("url", "host", "ip", "path", "email")
MAX_FILE_BYTES = 5_000_000
MAX_LINE_CHARS = 4000
URL_RE = re.compile(
    r"\b(?:https?|ftps?|wss?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|"
    r"amqps?|mssql|sqlserver|ldaps?|smtp|sftp|s3)://[^\s'\"<>`)\]}]+", re.I)
IP_RE = re.compile(r"(?<![\w./])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?![\w.])")
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
PATH_RE = re.compile(
    r"(?<![\w.:/\\])(?:/(?:home|Users|opt|srv|mnt|data|root|Volumes|var/(?:lib|www|opt))"
    r"/[\w.\-/]+|[A-Za-z]:\\[\w.\-\\ ]+)")
# Credentials before the host: greedy to the last "@" so passwords containing "/", "@", or ")"
# are removed whole. A user name without a password ("token@host") is removed too.
USERINFO_RE = re.compile(r"(?<=://)[^\s/@'\"`<>]+(?::[^\s'\"`<>]*)?@")
USER_PATH_RE = re.compile(r"^(?:/(?:home|Users|root|Volumes)/|[A-Za-z]:\\)")
TEMPLATE_MARKERS = ("{", "$", "<", "%s", "%(", "%d")
CODE_KEYWORD_BEFORE_RE = re.compile(
    r"\b(?:import|from|package|namespace|using|require|include|module)\s+[\w.]*$")
CODE_IDENTIFIERS = {"self", "this", "cls", "threading", "settings", "env", "config", "process",
                    "window", "document", "os", "module", "exports"}
FILE_SUFFIX_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "js", "mjs", "cjs",
                    "ts", "tsx", "jsx", "css", "scss", "json", "map", "py", "md", "txt", "html",
                    "woff", "woff2", "ttf", "pdf", "zip", "gz", "lock", "yaml", "yml"}
WEB_LANGUAGES = {"javascript", "typescript", "tsx", "html", "vue", "svelte", "css", "scss"}
WEBHOOK_HOSTS = ("hooks.slack.com", "webhook.office.com", "hooks.zapier.com",
                 "api.telegram.org")
DOC_HOST_PREFIXES = ("docs.", "developer.", "developers.")
# URLs on these lines name a schema or XML namespace: identifiers, not endpoints the tool calls.
SCHEMA_DECLARATION_RE = re.compile(r"\$schema|\bxmlns(?::\w+)?\s*=|schemaLocation\s*=")
VERSION_BEFORE_RE = re.compile(r"(?:version|ver|\bv)\W{0,4}$", re.I)
BENIGN_DOMAINS = ("example.com", "example.org", "example.net", "w3.org", "json-schema.org",
                  "schema.org", "schemas.xmlsoap.org", "schemas.microsoft.com",
                  "opensource.org", "apache.org", "creativecommons.org", "purl.org",
                  "registry.npmjs.org", "npmjs.com", "pypi.org", "python.org", "localhost",
                  "schemastore.org", "mozilla.org", "readthedocs.io", "readthedocs.org",
                  "ietf.org", "rfc-editor.org", "wikipedia.org", "spdx.org", "yaml.org",
                  "swagger.io", "openapis.org", "whatwg.org", "tc39.es", "unicode.org")
TITLES = {"url": "Hardcoded URLs", "host": "Hardcoded internal hostnames",
          "ip": "Hardcoded IP addresses", "path": "Hardcoded absolute file paths",
          "email": "Hardcoded email addresses"}
LABELS = {"url": "URL", "host": "internal hostname", "ip": "IP address",
          "path": "absolute path", "email": "email address"}  # singular; plural() adds the -s
IMPACT = {
    "url": "Endpoints are fixed in code: moving a service or adding an environment means a code "
           "change, and the code reveals where the organisation's systems live.",
    "host": "Internal hostnames tie the tool to one network and map internal infrastructure for "
            "anyone who can read the code.",
    "ip": "Fixed addresses break silently when infrastructure moves and expose network layout.",
    "path": "The tool only works on machines laid out like its author's.",
    "email": "Personal or team addresses in code leak contact details and route mail to people "
             "who may have left.",
}
REMEDIATION = "Move these values to configuration (environment variables or a config file) " \
              "and document each one in the deployment guide."


def mask_userinfo(url: str) -> str:
    return USERINFO_RE.sub("***@", url)


HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
FILE_NAME_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,4}$")
TLD_RE = re.compile(r"\.(?:internal|local|lan|corp|intranet|private|localdomain)\b"
                    r"(?::\d{2,5})?", re.I)
HOST_FULL_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                          r"(?:internal|local|lan|corp|intranet|private|localdomain)"
                          r"(?::\d{2,5})?", re.I)
HOST_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
MAX_HOST_CHARS = 253
COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--|--\s)")


class _Span:
    """A minimal match object (start, end, group) for spans found without a regex search."""

    def __init__(self, line: str, start: int, end: int) -> None:
        self._line, self._start, self._end = line, start, end

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def group(self, _: int = 0) -> str:
        return self._line[self._start:self._end]


def iter_hosts(line: str) -> list[_Span]:
    """Internal hostnames, found in linear time: locate each internal TLD, then walk back over
    hostname characters (at most 253). A backtracking regex took minutes on long dotted lines."""
    out: list[_Span] = []
    for m in TLD_RE.finditer(line):
        if line[m.end():m.end() + 1] == "." and line[m.end() + 1:m.end() + 2].isalnum():
            continue  # not the last label: a later TLD match covers the whole name
        start = m.start()
        floor = max(0, m.start() - MAX_HOST_CHARS)
        while start > floor and line[start - 1] in HOST_CHARS:
            start -= 1
        while start < m.start() and not line[start].isalnum():
            start += 1  # a name cannot start with "." or "-"
        full = HOST_FULL_RE.fullmatch(line, start, m.end())
        if full:
            out.append(_Span(line, start, m.end()))
    return out


def _tokenish(segment: str) -> bool:
    """A path segment that looks like a credential. Commit hashes and file names are not."""
    if HEX_SHA_RE.match(segment) or FILE_NAME_RE.search(segment):
        return False
    return (len(segment) >= 20 and any(c.isdigit() for c in segment)
            and any(c.isalpha() for c in segment) and shannon_entropy(segment) >= 3.5)


def safe_url(value: str) -> str:
    """scheme://host[:port]/path with credentials, query, fragment, and token-like path
    segments removed. Webhook URLs keep only their host: the path is the credential."""
    value = re.split(r"[?#]", mask_userinfo(value), maxsplit=1)[0]
    scheme, _, rest = value.partition("://")
    host, slash, path = rest.partition("/")
    domain = _domain_of(value)
    if any(domain == h or domain.endswith("." + h) for h in WEBHOOK_HOSTS) or \
            "webhook" in path.lower():
        path = "[redacted]" if path else ""
    else:
        path = "/".join("[redacted]" if _tokenish(seg) else seg for seg in path.split("/"))
    return f"{scheme}://{host}{slash}{path}"


def scrub_text(text: str) -> str:
    """Free text with every URL made safe and every recognised secret redacted."""
    masked = mask_userinfo(text)
    return redact_text(URL_RE.sub(lambda m: safe_url(m.group(0)), masked))


def _domain_of(value: str) -> str:
    host = value.split("://", 1)[-1]
    host = host.split("@", 1)[-1] if "@" in host else host
    return re.split(r"[/:?#]", host, maxsplit=1)[0].lower()


def _benign_domain(domain: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in BENIGN_DOMAINS) or \
        domain.endswith(".example") or domain in ("127.0.0.1", "0.0.0.0") or \
        domain.startswith(DOC_HOST_PREFIXES)


def _benign_ip(value: str, before: str) -> bool:
    if VERSION_BEFORE_RE.search(before):
        return True
    try:
        ip = ipaddress.ip_address(value.split(":", 1)[0])
    except ValueError:
        return True  # 999.1.1.1 and similar: not an address
    return (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local
            or ip.is_reserved)  # 255.255.255.0 and other netmasks


def _free(m: re.Match, taken: list[tuple[int, int]]) -> bool:
    """True when the match does not overlap a span an earlier pattern already claimed."""
    return not any(s <= m.start() < e or s < m.end() <= e for s, e in taken)


def _code_not_host(m: re.Match, line: str) -> bool:
    """A dotted name ending in .local/.internal that is really code: an import, a namespace,
    an attribute call like threading.local(), or a module path like settings.local.x."""
    after = line[m.end():m.end() + 1]
    first = m.group(0).split(".", 1)[0].lower()
    return (after in (".", "(", "[", "_") or first in CODE_IDENTIFIERS
            or bool(CODE_KEYWORD_BEFORE_RE.search(line[:m.start()])))


def _real_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[1].lower()
    tld = domain.rsplit(".", 1)[-1]
    return (not value.startswith("git@") and tld.isalpha() and len(tld) >= 2
            and tld not in FILE_SUFFIX_TLDS and not _benign_domain(domain))


def _is_container_file(name: str, language: str | None) -> bool:
    return (language == "dockerfile" or name.startswith(("Dockerfile", "Containerfile"))
            or name.endswith(".dockerfile")
            or bool(re.match(r"(?:docker-)?compose[\w.-]*\.ya?ml$", name)))


# Package metadata names where the project lives (homepage, repository, issue tracker), not
# infrastructure the tool calls: file name -> {section: keys}, where None means every key.
METADATA_URL_KEYS: dict[str, dict[str, frozenset[str] | None]] = {
    "pyproject.toml": {
        "project.urls": None, "tool.poetry.urls": None,
        "tool.poetry": frozenset({"homepage", "repository", "documentation"}),
    },
    "cargo.toml": {"package": frozenset({"homepage", "repository", "documentation"})},
    "setup.cfg": {"metadata": frozenset({"url", "download_url", "project_urls"})},
}
PACKAGE_JSON_URL_KEYS = ("homepage", "repository", "bugs", "funding")
SECTION_RE = re.compile(r"^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(?:[#;].*)?$")
KEY_RE = re.compile(
    r"""^\s*("[^"\n]*"|'[^'\n]*'|[\w.-]+)(?:\s*\.\s*(?:"[^"\n]*"|'[^'\n]*'|[\w.-]+))*"""
    r"""\s*[=:](?!//)""")


def _ini_metadata_lines(lines: list[str], sections: dict[str, frozenset[str] | None], *,
                        indented_continues: bool) -> set[int]:
    """Line numbers holding a metadata key's value in a TOML or setup.cfg file. A value runs
    until the next key or section, so a multi-line TOML array and the indented continuation
    lines of a setup.cfg value (where an indented `name = url` is part of the value) count."""
    out: set[int] = set()
    keys: frozenset[str] | None = frozenset()
    in_value = False
    for n, line in enumerate(lines, start=1):
        header = SECTION_RE.match(line)
        if header:
            keys = sections.get(header.group(1).strip().lower(), frozenset())
            in_value = False
            continue
        key = KEY_RE.match(line)
        if key and not (indented_continues and line[:1].isspace()):
            in_value = keys is None or key.group(1).strip("\"'").lower() in keys
        if in_value:
            out.add(n)
    return out


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _package_json_metadata_urls(text: str) -> set[str]:
    """URLs inside the top-level homepage, repository, bugs and funding values. Parsed, not
    pattern-matched, so a nested "repository" key in a tool's own config, and any other URL
    on the same line (a minified file), are still scanned; an unparseable file is scanned
    as it is."""
    try:
        data = json.loads(text.lstrip("\ufeff"))
    except ValueError:
        return set()
    if not isinstance(data, dict):
        return set()
    return {m.group(0).rstrip(".,;") for key in PACKAGE_JSON_URL_KEYS
            for value in _strings(data.get(key)) for m in URL_RE.finditer(value)}


def metadata_urls(text: str, path: str) -> tuple[set[int], set[str]]:
    """(lines, URLs) of a package manifest that are project metadata, not endpoints: the
    lines of a TOML or setup.cfg metadata key, and the URL values of a package.json."""
    name = PurePosixPath(path).name.lower()
    if name == "package.json":
        return set(), _package_json_metadata_urls(text)
    if name in METADATA_URL_KEYS:
        return _ini_metadata_lines(text.split("\n"), METADATA_URL_KEYS[name],
                                   indented_continues=name == "setup.cfg"), set()
    return set(), set()


def _issue_template(path: str) -> bool:
    p = PurePosixPath(path)
    return (p.suffix.lower() in (".md", ".yml", ".yaml")
            and "/.github/issue_template/" in f"/{p.parent.as_posix().lower()}/")


def find_infra(text: str, path: str = "",
               language: str | None = None) -> list[tuple[str, str, int]]:
    """(kind, safe value, line) for every hardcoded endpoint, host, address, path, or email.

    Values never carry credentials, query strings, or token-like path segments. `path` and
    `language` let the scanner skip ignore files, container paths in Dockerfiles, and URL
    paths in web code."""
    name = PurePosixPath(path).name
    if name.startswith(".") and name.endswith("ignore"):
        return []  # .gitignore, .dockerignore: patterns, not infrastructure
    if _issue_template(path):
        return []  # issue forms and their contact links: the project's own pages
    metadata_lines, metadata_values = metadata_urls(text, path)
    container = _is_container_file(name, language)
    web = language in WEB_LANGUAGES
    out: list[tuple[str, str, int]] = []
    for n, line in enumerate(text.split("\n"), start=1):
        line = mask_userinfo(line[:MAX_LINE_CHARS])
        taken: list[tuple[int, int]] = []
        # Schema declarations name identifiers, and URLs in comments are documentation links.
        schema_line = bool(SCHEMA_DECLARATION_RE.search(line) or COMMENT_LINE_RE.match(line))
        for m in URL_RE.finditer(line):
            value = m.group(0).rstrip(".,;")
            taken.append((m.start(), m.end()))
            if schema_line or n in metadata_lines or value in metadata_values:
                continue  # an identifier, a documentation link, or package metadata
            if any(t in value for t in TEMPLATE_MARKERS):
                continue  # built at run time from a variable: not hardcoded
            if not _benign_domain(_domain_of(value)):
                out.append(("url", safe_url(value), n))
        for m in iter_hosts(line):
            if _free(m, taken):
                taken.append((m.start(), m.end()))
                if not _code_not_host(m, line):
                    out.append(("host", m.group(0).lower(), n))
        for m in IP_RE.finditer(line):
            if _free(m, taken):
                taken.append((m.start(), m.end()))
                if not _benign_ip(m.group(0), line[:m.start()]):
                    out.append(("ip", m.group(0), n))
        for m in PATH_RE.finditer(line):
            if _free(m, taken):
                taken.append((m.start(), m.end()))
                value = m.group(0).rstrip(".,;")
                if container or (web and not USER_PATH_RE.match(value)):
                    continue  # paths inside the image, or URL paths in web code
                out.append(("path", value, n))
        for m in EMAIL_RE.finditer(line):
            if _free(m, taken) and _real_email(m.group(0)):
                out.append(("email", m.group(0), n))
    return out


class HardcodedInfraScanner:
    name = "hardcoded_infra"
    category = Category.operability

    def run(self, ctx: ScanContext) -> list[Finding]:
        max_evidence = int(ctx.options.get("max_evidence", 25))
        classes = {Classification.source, Classification.config}
        if ctx.options.get("include_tests", False):
            classes.add(Classification.test)
        hits: dict[str, dict[str, list[tuple[str, int, str]]]] = defaultdict(
            lambda: defaultdict(list))
        for rec in ctx.census.files:
            if rec.excluded or rec.classification not in classes or rec.bytes > MAX_FILE_BYTES:
                continue
            try:
                text = (ctx.source_root / rec.path).read_text(encoding="utf-8",
                                                              errors="replace")
            except OSError:
                continue
            lines = text.split("\n")
            for kind, value, n in find_infra(text, rec.path, rec.language):
                hits[kind][value].append((rec.path, n, lines[n - 1]))
        findings: list[Finding] = []
        for kind in KINDS:
            values = hits.get(kind)
            if not values:
                continue
            located = [(v, p, n, t) for v, occ in sorted(values.items()) for p, n, t in occ]
            evidence = [Evidence(path=p, line_start=n, line_end=n,
                                 excerpt=scrub_text(t.strip())[:200] or None,
                                 note=f"value: {redact_text(v)}")
                        for v, p, n, t in located[:max_evidence]]
            sample = redact_text(", ".join(list(values)[:5]))
            shown = (f" Showing the first {max_evidence} locations."
                     if len(located) > max_evidence else "")
            findings.append(Finding(
                tool=ctx.tool,
                category=Category.data_handling if kind == "email" else self.category,
                severity=Severity.medium, title=TITLES[kind],
                summary=(f"{plural(len(values), 'distinct ' + LABELS[kind])} hardcoded at "
                         f"{plural(len(located), 'location')}, for example {sample}.{shown}"),
                impact=IMPACT[kind], remediation=REMEDIATION, evidence=evidence,
                source=Source.scanner, scanner=self.name,
                tags=[f"hardcoded:{kind}", f"distinct:{len(values)}"],
                **rule_effort(ctx, self.name, kind),
            ))
        return findings
