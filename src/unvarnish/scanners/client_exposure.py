"""Credentials and data shipped to the browser, tables open to it, and agent configs.

The failure modes of AI-built web apps: a Supabase service-role key in client code, a
secret behind a `NEXT_PUBLIC_` name, tables without row level security, CORS that accepts
any origin with credentials, committed `.env` and MCP config files holding credentials,
and API routes with no authentication check. Offline and deterministic."""

from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from unvarnish.analysis.languages import Classification
from unvarnish.config import DEFAULT_SCANNER_OPTIONS
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.secrets import (
    fingerprint,
    is_placeholder,
    redact_text,
    shannon_entropy,
    tree_skip_reason,
)
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.plural import plural

NAME = "client_exposure"
MAX_EXCERPT = 200
# Directories and file names that mark server code inside a client root (src/server/db.ts,
# src/app/api/x/route.ts, +page.server.ts): a server key there is not shipped to browsers.
SERVER_DIRS = {"api", "server", "servers", "backend", "functions", "lambda", "lambdas",
               "edge-functions"}

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
SB_SECRET_RE = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}")
SB_PUBLISHABLE_RE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{16,}")
FIREBASE_KEY_RE = re.compile(r"""apiKey['"]?\s*[:=]\s*['"](AIza[0-9A-Za-z_-]{35})['"]""")
# Key-shaped values redacted from every excerpt, whichever finding the line belongs to: a
# minified bundle can hold a service-role key on the same line as the anon key.
KEY_SHAPED_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{16,}|\bAIza[0-9A-Za-z_-]{35}")
FIREBASE_MARKERS = ("authDomain", "projectId")

PUBLIC_VAR_RE = re.compile(r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]+\b")
PUBLIC_VALUE_RE = re.compile(r"""['"]?\s*[:=]\s*['"]?([^'"\s,;]+)""")  # right after the name
SECRET_TOKENS = {"SECRET", "SECRETS", "KEY", "KEYS", "TOKEN", "TOKENS", "APIKEY"}

CREDENTIAL_KEY_RE = re.compile(r"(?i)key|secret|token|passw|pwd|credential|authorization")
DOTENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$")
JSON_PAIR_RE = re.compile(r'"([^"\\]+)"\s*:\s*"((?:[^"\\]|\\.)*)"')
ENV_TEMPLATE_WORDS = ("example", "sample", "template")
AGENT_CONFIG_NAMES = {".mcp.json", "claude_desktop_config.json"}
AGENT_CONFIG_DIRS = {".cursor", ".vscode"}  # <dir>/mcp.json

_TABLE = r'((?:"[^"]+"|[\w$]+)(?:\s*\.\s*(?:"[^"]+"|[\w$]+))?)'
CREATE_TABLE_RE = re.compile(
    rf"\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?{_TABLE}", re.I)
ALTER_RLS_RE = re.compile(
    rf"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{_TABLE}\s+"
    r"(enable|disable)\s+row\s+level\s+security", re.I)
DROP_TABLE_RE = re.compile(rf"\bdrop\s+table\s+(?:if\s+exists\s+)?{_TABLE}", re.I)
POLICY_RE = re.compile(rf'\bcreate\s+policy\s+(?:"[^"]*"|\w+)\s+on\s+{_TABLE}([^;]*)', re.I)
POLICY_FOR_RE = re.compile(r"\bfor\s+(all|select|insert|update|delete)\b", re.I)
_TRUE = r"\(\s*\(?\s*true\s*\)?\s*\)"
PERMISSIVE_RE = re.compile(rf"\busing\s*{_TRUE}|\bwith\s+check\s*{_TRUE}", re.I)
WITH_CHECK_RE = re.compile(r"\bwith\s+check\b", re.I)
USING_RE = re.compile(r"\busing\b", re.I)
SQL_COMMENT_RE = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)

CORS_ORIGIN_RE = re.compile(
    r"""(?i)allow_origins\s*=\s*\[\s*['"]\*['"]"""
    r"""|\borigins?\s*[:=]\s*\[?\s*['"]\*['"]"""
    r"""|\borigin\s*:\s*true\b"""
    r"""|access-control-allow-origin['"]?\s*[,:]\s*['"]\*['"]"""
    r"""|access-control-allow-origin['"]\s*,\s*['"]value['"]\s*:\s*['"]\*['"]""")
CORS_CREDENTIALS_RE = re.compile(
    r"""(?i)allow_credentials\s*=\s*true|\bcredentials\s*:\s*true"""
    r"""|supports_credentials\s*=\s*true"""
    r"""|access-control-allow-credentials['"]?\s*[,:]\s*['"]?true"""
    r"""|access-control-allow-credentials['"]\s*,\s*['"]value['"]\s*:\s*['"]true""")

NEXT_ROUTE_FILE_RE = re.compile(r"(?:^|/)app/((?:.*/)?api(?:/.*)?)/route\.(?:ts|js|tsx|jsx|mjs)$")
NEXT_HANDLER_RE = re.compile(
    r"^\s*export\s+(?:async\s+function|function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b")
EXPRESS_RE = re.compile(
    r"""\b(?:app|router|server|api)\.(get|post|put|patch|delete|all)\s*\(\s*['"`](/[^'"`]*)""")
PY_ROUTE_RE = re.compile(
    r"""^\s*@\w+\.(get|post|put|patch|delete|route|api_route)\s*\(\s*['"](/[^'"]*)""")
JS_LANGUAGES = {"javascript", "typescript", "tsx"}
# A JS file must look like server code before `x.get("/path")` counts as a route: the same
# call shape is an HTTP client request (`api.get("/users")` with axios) in browser code.
SERVER_JS_RE = re.compile(
    r"""\breq\s*,\s*res\b|\brequest\s*,\s*reply\b"""
    r"""|(?:from\s+|require\(\s*)['"](?:express|fastify|koa|hono|@koa/router)['"]""")
AUTH_RE = re.compile(
    r"(?i)auth|session|jwt|bearer|login_required|current_?user|get_?user|verify_?token"
    r"|permission|guard|protect|clerk|passport|api_?key|logged_?in|require_?login")
FILE_AUTH_RE = re.compile(r"(?i)\.use\([^)]*(?:auth|jwt|session|passport|protect|guard)")
PUBLIC_ROUTE_RE = re.compile(
    r"(?i)(?:^|/)(?:health|healthz|ping|status|ready|live|login|logout|signin|signup"
    r"|register|callback|webhooks?|auth)(?:/|$)")

TAG_CREDENTIAL = f"{NAME}:credential"
TAG_OPEN_TABLE = f"{NAME}:open_table"
TAG_ROUTES = f"{NAME}:routes"
ROTATE = ("Rotate the credential now, move it to server-side configuration or a secret "
          "manager, and purge it from git history before the repository moves anywhere.")


def _option(ctx: ScanContext, key: str) -> Any:
    return ctx.options.get(key, DEFAULT_SCANNER_OPTIONS[NAME][key])


def in_client_root(path: str, roots: list[str], extensions: list[str]) -> bool:
    """True for a browser-facing file: a client extension under a client root, at any depth
    (apps/web/src/ counts for src/), and not in a server directory or a .server. file."""
    p = PurePosixPath(path)
    if p.suffix.lower() not in {e.lower() for e in extensions}:
        return False
    if ".server." in p.name or any(part in SERVER_DIRS for part in p.parts[:-1]):
        return False
    padded = "/" + path
    return any(f"/{r.strip('/')}/" in padded for r in roots if r.strip("/"))


def jwt_role(token: str) -> str | None:
    """The `role` claim of a JWT's payload, or None if it does not decode to one."""
    seg = token.split(".")[1]
    try:
        data = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except ValueError:
        return None
    role = data.get("role") if isinstance(data, dict) else None
    return role if isinstance(role, str) else None


def is_secret_name(name: str, public_names: list[str]) -> bool:
    if any(p.upper() in name for p in public_names):
        return False
    return any(t in SECRET_TOKENS for t in name.split("_"))


def plausible_value(value: str) -> bool:
    """A value that could be a real credential: not a placeholder, a bare word, or a URL
    without credentials."""
    v = value.strip()
    if len(v) < 8 or is_placeholder(v):
        return False
    if re.match(r"^https?://", v, re.I) and "@" not in v:
        return False
    return shannon_entropy(v) >= 2.5 or any(ch.isdigit() or not ch.isalnum() for ch in v)


def excerpt(line: str, raws: tuple[str, ...] | list[str] = (), anchor: str | None = None) -> str:
    """The line with every raw value and every recognised secret redacted, cut to a window
    around `anchor` (or the first redaction) on long lines such as minified bundles."""
    out = line
    raws = set(raws) | set(KEY_SHAPED_RE.findall(line))
    for raw in sorted(raws, key=len, reverse=True):
        out = out.replace(raw, f"…[redacted {len(raw)} chars]")
    out = out.strip()
    if len(out) > MAX_EXCERPT:
        i = out.find(anchor) if anchor else -1
        i = out.find("…[redacted") if i < 0 else i
        start = max(0, i - 60)
        out = out[start:start + MAX_EXCERPT]
    out = redact_text(out)
    return "[line redacted]" if any(r in out for r in raws) else out


def _dotenv_value(rest: str) -> str:
    rest = rest.strip()
    if rest[:1] in ("'", '"'):
        end = rest.find(rest[0], 1)
        return rest[1:end] if end > 0 else rest[1:]
    return rest.split(" #", 1)[0].strip()


def is_committed_env(name: str) -> bool:
    low = name.lower()
    return ((low == ".env" or low.startswith(".env."))
            and not any(w in low for w in ENV_TEMPLATE_WORDS))


def is_agent_config(path: str) -> bool:
    p = PurePosixPath(path)
    return p.name in AGENT_CONFIG_NAMES or (
        p.name == "mcp.json" and p.parent.name in AGENT_CONFIG_DIRS)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _table_key(name: str) -> str:
    key = re.sub(r'["\s]', "", name).lower()
    return key.removeprefix("public.")


@dataclass
class _Located:
    path: str
    line: int
    excerpt: str
    note: str | None = None
    fingerprint: str | None = None

    def evidence(self) -> Evidence:
        return Evidence(path=self.path, line_start=self.line, line_end=self.line,
                        excerpt=self.excerpt or None, note=self.note,
                        fingerprint=self.fingerprint)


@dataclass
class _Scan:
    service_keys: dict[str, list[_Located]] = field(default_factory=lambda: defaultdict(list))
    anon_keys: list[_Located] = field(default_factory=list)
    public_vars: dict[str, list[_Located]] = field(default_factory=lambda: defaultdict(list))
    findings: list[Finding] = field(default_factory=list)
    routes: list[_Located] = field(default_factory=list)
    created: dict[str, _Located] = field(default_factory=dict)
    enabled: set[str] = field(default_factory=set)
    dropped: set[str] = field(default_factory=set)
    disabled: list[tuple[str, _Located]] = field(default_factory=list)
    # Signs the SQL is served by Supabase (or at least uses RLS): without one, a table
    # created without RLS is an ordinary Postgres, MySQL or SQLite schema, not an open table.
    rls_used: bool = False
    supabase_sql: bool = False


class ClientExposureScanner:
    name = NAME
    category = Category.security

    def run(self, ctx: ScanContext) -> list[Finding]:
        self._ctx = ctx
        self._max = int(_option(ctx, "max_evidence"))
        roots = list(_option(ctx, "client_roots"))
        extensions = list(_option(ctx, "client_extensions"))
        public_names = list(_option(ctx, "public_names"))
        classes = {Classification.source, Classification.config, Classification.generated}
        if _option(ctx, "include_tests"):
            classes.add(Classification.test)
        s = _Scan()
        self._supabase_dep = any("supabase" in d.name.lower()
                                 for d in ctx.dependencies.dependencies)
        for rec in ctx.census.files:
            if (tree_skip_reason(rec) or rec.exclusion_reason == "gitignore"
                    or rec.classification not in classes):
                continue
            try:
                text = (ctx.source_root / rec.path).read_text(encoding="utf-8",
                                                              errors="replace")
            except OSError:
                continue
            lines = text.split("\n")
            if in_client_root(rec.path, roots, extensions):
                self._client_keys(s, rec.path, text, lines)
            self._public_vars(s, rec.path, lines, public_names)
            name = PurePosixPath(rec.path).name
            if is_committed_env(name):
                self._credentials_file(s, rec.path, lines, public_names, dotenv=True)
            elif is_agent_config(rec.path):
                self._credentials_file(s, rec.path, lines, public_names, dotenv=False)
            if rec.language == "sql":
                self._sql(s, rec.path, text, lines)
            if rec.classification == Classification.generated:
                continue  # a bundled server repeats its source; a client bundle has no routes
            self._cors(s, rec.path, lines, int(_option(ctx, "cors_window")))
            self._routes(s, rec.path, rec.language, text, lines,
                         int(_option(ctx, "auth_window")))
        return s.findings + self._collect(s)

    def _finding(self, rule: str, severity: Severity, title: str, summary: str, impact: str,
                 remediation: str, located: list[_Located], tags: list[str]) -> Finding:
        return Finding(tool=self._ctx.tool, category=self.category, severity=severity,
                       title=title, summary=summary, impact=impact, remediation=remediation,
                       evidence=[x.evidence() for x in located[:self._max]],
                       source=Source.scanner, scanner=self.name, tags=tags,
                       **rule_effort(self._ctx, self.name, rule))

    # (a) Supabase keys and Firebase config in browser-facing files
    def _client_keys(self, s: _Scan, path: str, text: str, lines: list[str]) -> None:
        firebase_file = any(m in text for m in FIREBASE_MARKERS)
        for n, line in enumerate(lines, start=1):
            if "eyJ" in line:
                for m in JWT_RE.finditer(line):
                    token = m.group(0)
                    role = jwt_role(token)
                    if role == "service_role":
                        s.service_keys[fingerprint(token)].append(self._key_at(path, n, line,
                                                                               token))
                    elif role == "anon":
                        s.anon_keys.append(self._key_at(path, n, line, token))
            if "sb_" in line:
                for m in SB_SECRET_RE.finditer(line):
                    s.service_keys[fingerprint(m.group(0))].append(
                        self._key_at(path, n, line, m.group(0)))
                for m in SB_PUBLISHABLE_RE.finditer(line):
                    s.anon_keys.append(self._key_at(path, n, line, m.group(0)))
            if firebase_file and "AIza" in line:
                for m in FIREBASE_KEY_RE.finditer(line):
                    key = m.group(1)
                    s.findings.append(self._finding(
                        "firebase_config", Severity.low, "Firebase web config in client code",
                        f"{path} ships a Firebase web configuration. Its apiKey identifies the "
                        "project and is public by design; the data is protected only by "
                        "Firebase Security Rules and App Check.",
                        "If the Security Rules allow open reads or writes, anyone with this "
                        "config can use the database directly from a browser.",
                        "Review the Firestore, Realtime Database and Storage rules for this "
                        "project; enable App Check and restrict the key to the app's domains.",
                        [self._key_at(path, n, line, key)], [f"{NAME}:firebase"]))

    @staticmethod
    def _key_at(path: str, n: int, line: str, raw: str) -> _Located:
        fp = fingerprint(raw)
        return _Located(path=path, line=n, excerpt=excerpt(line, [raw]),
                        note=f"fingerprint {fp}", fingerprint=fp)

    # (b) secret-named variables behind a prefix the bundler inlines into the client
    def _public_vars(self, s: _Scan, path: str, lines: list[str],
                     public_names: list[str]) -> None:
        for n, line in enumerate(lines, start=1):
            if "_" not in line:
                continue
            names: list[str] = []
            raws: list[str] = []  # every value on the line, so no excerpt shows another's
            for m in PUBLIC_VAR_RE.finditer(line):
                value = PUBLIC_VALUE_RE.match(line, m.end())
                if value and not is_placeholder(value.group(1)):
                    raws.append(value.group(1))
                if is_secret_name(m.group(0), public_names):
                    names.append(m.group(0))
            for var in dict.fromkeys(names):
                s.public_vars[var].append(_Located(path=path, line=n,
                                                   excerpt=excerpt(line, raws, anchor=var),
                                                   fingerprint=fingerprint(var)))

    # (e) committed .env files and agent (MCP) configs holding credential-like values
    def _credentials_file(self, s: _Scan, path: str, lines: list[str],
                          public_names: list[str], *, dotenv: bool) -> None:
        located: list[_Located] = []
        for n, line in enumerate(lines, start=1):
            if dotenv:
                m = DOTENV_LINE_RE.match(line)
                pairs = [(m.group(1), _dotenv_value(m.group(2)))] if m else []
            else:
                pairs = JSON_PAIR_RE.findall(line)
            hits = [(key, value) for key, value in pairs
                    if CREDENTIAL_KEY_RE.search(key) and plausible_value(value)
                    and not any(p.upper() in key.upper() for p in public_names)]
            raws = [value for _, value in hits]  # minified JSON: one line, several values
            for key, value in hits:
                fp = fingerprint(value)
                located.append(_Located(path=path, line=n, excerpt=excerpt(line, raws),
                                        note=f"{key}; fingerprint {fp}", fingerprint=fp))
        if not located:
            return
        kind = "committed .env file" if dotenv else "agent configuration file"
        s.findings.append(self._finding(
            "credentials_file", Severity.critical, f"Credentials in {kind}",
            f"{path} holds {plural(len(located), 'credential-like value')}. "
            f"{'The value is' if len(located) == 1 else 'The values are'} redacted here and "
            "identified by fingerprint.",
            ("Anyone who can read the repository holds these credentials; agent configs give "
             "an AI assistant, and whoever reads its logs, the same access."
             if not dotenv else
             "Anyone who can read the repository or its history holds these credentials."),
            ROTATE + " Commit only an example file with placeholders.",
            located, [TAG_CREDENTIAL, f"exposed:{len(located)}"]))

    # (c) Supabase / Postgres migrations
    def _sql(self, s: _Scan, path: str, text: str, lines: list[str]) -> None:
        code = SQL_COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
        if "supabase" in PurePosixPath(path).parts[:-1]:
            s.supabase_sql = True

        def at(pos: int) -> _Located:
            n = _line_of(code, pos)
            return _Located(path=path, line=n, excerpt=excerpt(lines[n - 1]))

        for m in CREATE_TABLE_RE.finditer(code):
            s.created.setdefault(_table_key(m.group(1)), at(m.start()))
        for m in DROP_TABLE_RE.finditer(code):
            s.dropped.add(_table_key(m.group(1)))
        for m in ALTER_RLS_RE.finditer(code):
            s.rls_used = True
            key = _table_key(m.group(1))
            if m.group(2).lower() == "enable":
                s.enabled.add(key)
            else:
                s.disabled.append((key, at(m.start())))
        for m in POLICY_RE.finditer(code):
            s.rls_used = True
            key, body = _table_key(m.group(1)), m.group(2)
            cmd_m = POLICY_FOR_RE.search(body)
            cmd = cmd_m.group(1).lower() if cmd_m else "all"
            loc = at(m.start())
            if PERMISSIVE_RE.search(body):
                if cmd == "select":
                    s.findings.append(self._finding(
                        "policy_readable", Severity.medium, "Policy readable by every row",
                        f"A select policy on `{key}` is `using (true)`: every role it names "
                        "can read every row.",
                        "Rows meant for one user or tenant are readable by all of them, and "
                        "by anyone holding the public anon key if the policy includes anon.",
                        "Confirm the table is meant to be public; otherwise scope the policy "
                        "to the owner, for example `using (auth.uid() = user_id)`.",
                        [loc], [f"{NAME}:policy", f"table:{key}"]))
                else:
                    s.findings.append(self._finding(
                        "policy_open", Severity.high, "Policy open to every row",
                        f"A `{cmd}` policy on `{key}` is `using (true)` or "
                        "`with check (true)`: every role it names can change any row.",
                        "Any user, or anyone with the public anon key if the policy includes "
                        "anon, can modify or delete other users' data.",
                        "Scope the policy to the row's owner with matching `using` and "
                        "`with check` expressions.",
                        [loc], [TAG_OPEN_TABLE, f"table:{key}"]))
            # UPDATE falls back to its USING expression when WITH CHECK is absent.
            elif not WITH_CHECK_RE.search(body) and (
                    cmd == "insert" or (cmd == "update" and not USING_RE.search(body))):
                s.findings.append(self._finding(
                    "policy_without_check", Severity.medium,
                    "Insert or update policy without WITH CHECK",
                    f"An `{cmd}` policy on `{key}` has no `with check` expression, so new "
                    "row values are not checked against the policy.",
                    "A user may be able to write rows that belong to someone else, or move a "
                    "row out of their own scope.",
                    "Add a `with check` expression that matches the ownership rule.",
                    [loc], [f"{NAME}:policy", f"table:{key}"]))

    # (d) CORS: any origin together with credentials
    def _cors(self, s: _Scan, path: str, lines: list[str], window: int) -> None:
        cred_lines = [n for n, line in enumerate(lines) if CORS_CREDENTIALS_RE.search(line)]
        if not cred_lines:
            return
        for n, line in enumerate(lines):
            if CORS_ORIGIN_RE.search(line) and any(abs(c - n) <= window for c in cred_lines):
                s.findings.append(self._finding(
                    "cors_any_origin", Severity.high, "CORS allows any origin with credentials",
                    f"{path} accepts cross-origin requests from any origin (`*` or a reflected "
                    "origin) and allows credentials.",
                    "Any website a signed-in user visits can call this API with the user's "
                    "cookies or tokens and read the responses.",
                    "List the allowed origins explicitly, or drop credentials for public "
                    "endpoints.",
                    [_Located(path=path, line=n + 1, excerpt=excerpt(line))],
                    [f"{NAME}:cors"]))

    # (f) route handlers with no authentication identifier nearby
    def _routes(self, s: _Scan, path: str, language: str | None, text: str,
                lines: list[str], window: int) -> None:
        handlers: list[tuple[int, str, str]] = []  # (index, method, route)
        next_route = NEXT_ROUTE_FILE_RE.search(path)
        server_js = language in JS_LANGUAGES and bool(SERVER_JS_RE.search(text))
        for i, line in enumerate(lines):
            if next_route:
                m = NEXT_HANDLER_RE.match(line)
                if m:
                    handlers.append((i, m.group(1), "/" + next_route.group(1)))
            elif language in JS_LANGUAGES and server_js:
                m = EXPRESS_RE.search(line)
                if m:
                    handlers.append((i, m.group(1).upper(), m.group(2)))
            elif language == "python":
                m = PY_ROUTE_RE.match(line)
                if m:
                    handlers.append((i, m.group(1).upper(), m.group(2)))
        if not handlers or FILE_AUTH_RE.search(text):
            return
        for k, (i, method, route) in enumerate(handlers):
            if PUBLIC_ROUTE_RE.search(route):
                continue
            end = min(i + window, handlers[k + 1][0] - 1 if k + 1 < len(handlers) else i + window)
            if any(AUTH_RE.search(line) for line in lines[max(0, i - 1):end + 1]):
                continue
            s.routes.append(_Located(path=path, line=i + 1, excerpt=excerpt(lines[i]),
                                     note=f"{method} {route}"))

    def _collect(self, s: _Scan) -> list[Finding]:
        out: list[Finding] = []
        for fp, located in s.service_keys.items():
            more = (f" ({plural(len(located) - 1, 'more occurrence', 'more occurrences')})"
                    if len(located) > 1 else "")
            out.append(self._finding(
                "service_role_key", Severity.critical, "Supabase service-role key in client code",
                f"A Supabase secret (service-role) key is in browser-facing code at "
                f"{located[0].path}{more}. It bypasses row level security; the value is "
                "redacted here and identified by fingerprint.",
                "Anyone who loads the app can read, change or delete every row in the "
                "database, whatever the policies say.",
                ROTATE + " Use the anon or publishable key in the client.",
                located, [TAG_CREDENTIAL, "exposed:1", f"fingerprint:{fp}"]))
        for var, located in s.public_vars.items():
            out.append(self._finding(
                "public_secret_var", Severity.high, "Secret-named variable exposed to the browser",
                f"`{var}` uses a prefix the bundler inlines into client code, so its value "
                f"is readable by anyone who loads the app ({plural(len(located), 'location')}).",
                "A secret behind a public prefix is published with every build.",
                "Rename it without the public prefix and read it only on the server; rotate "
                "the value if it was ever built into a deployed bundle. If it is public by "
                "design (a publishable key), add the name to `public_names`.",
                located, [TAG_CREDENTIAL, "exposed:1"]))
        supabase = (s.rls_used or s.supabase_sql or self._supabase_dep or bool(s.anon_keys)
                    or bool(s.service_keys))
        tables = sorted({k for k, loc in s.created.items()
                         if supabase and "." not in k and k not in s.enabled and k not in s.dropped
                         and k not in {d for d, _ in s.disabled}})
        for key in tables:
            out.append(self._finding(
                "table_without_rls", Severity.high, "Table without row level security",
                f"`{key}` is created in the public schema and row level security is never "
                "enabled for it in the migrations.",
                "The Supabase REST API serves the table to anyone holding the public anon "
                "key: every row can be read and written.",
                f"Add `alter table {key} enable row level security;` and policies scoped to "
                "the row's owner.",
                [s.created[key]], [TAG_OPEN_TABLE, f"table:{key}"]))
        for key, loc in s.disabled:
            out.append(self._finding(
                "rls_disabled", Severity.high, "Row level security disabled",
                f"A migration disables row level security on `{key}`.",
                "Every policy on the table stops applying; anyone with the public anon key "
                "can read and write every row.",
                "Remove the statement, enable row level security, and add scoped policies.",
                [loc], [TAG_OPEN_TABLE, f"table:{key}"]))
        open_tables = tables + sorted({k for k, _ in s.disabled})
        if s.anon_keys and open_tables:
            names = ", ".join(f"`{t}`" for t in open_tables[:10])
            out.append(self._finding(
                "anon_key_open_tables", Severity.critical,
                "Supabase anon key in client code with tables open to it",
                f"The public anon key ships in client code, and "
                f"{plural(len(open_tables), 'table')} "
                f"{'has' if len(open_tables) == 1 else 'have'} no row level security: {names}.",
                "Anyone who loads the app can take the key from the page and read or change "
                "every row in those tables through the Supabase API.",
                "Enable row level security on every public table and add policies before "
                "the app is used further; the anon key itself is meant to be public.",
                s.anon_keys, [f"{NAME}:anon_open"]))
        if s.routes:
            files = len({r.path for r in s.routes})
            shown = (f" Showing the first {self._max}." if len(s.routes) > self._max else "")
            out.append(self._finding(
                "unauthenticated_routes", Severity.medium,
                "Route handlers with no authentication check nearby",
                f"{plural(len(s.routes), 'route handler')} in {plural(files, 'file')} "
                f"{'has' if len(s.routes) == 1 else 'have'} no authentication "
                "identifier (auth, session, jwt, current user, guard) near them. This is a "
                "heuristic for review: middleware or a wrapper elsewhere may protect them. "
                f"Model extraction, when configured, is asked to confirm each one.{shown}",
                "An unprotected handler that reads or changes data exposes it to anyone who "
                "can reach the server.",
                "Confirm each handler is protected; add authentication middleware or an "
                "explicit check where it is not.",
                s.routes, [TAG_ROUTES, "review"]))
        return out


def exposure_counts(findings: list[Finding]) -> dict[str, int]:
    """Client-exposed credentials (each finding's exposed:<n> tag) and distinct open tables."""
    credentials = 0
    tables: set[str] = set()
    for f in findings:
        if TAG_CREDENTIAL in f.tags:
            credentials += sum(int(t.split(":", 1)[1]) for t in f.tags
                               if t.startswith("exposed:"))
        if TAG_OPEN_TABLE in f.tags:
            tables.update(t.split(":", 1)[1] for t in f.tags if t.startswith("table:"))
    return {"credentials": credentials, "open_tables": len(tables)}


def route_hints(scanner_findings: Path) -> dict[str, list[int]]:
    """Lines of route handlers with no authentication nearby, by path, for extraction."""
    from unvarnish.artifacts import read_artifact
    from unvarnish.schemas.scan import ScannerFindings

    if not scanner_findings.exists():
        return {}
    try:
        findings = read_artifact(scanner_findings, ScannerFindings).data.findings
    except Exception:  # an unreadable artifact only loses the hints
        return {}
    hints: dict[str, set[int]] = defaultdict(set)
    for f in findings:
        if f.scanner == NAME and TAG_ROUTES in f.tags:
            for e in f.evidence:
                if e.line_start:
                    hints[e.path].add(e.line_start)
    return {p: sorted(lines) for p, lines in sorted(hints.items())}
