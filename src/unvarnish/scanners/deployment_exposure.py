"""How a tool is exposed once deployed, from its deployment files (UNVAR-98).

Compose files, Dockerfiles, Kubernetes manifests and Terraform decide whether a tool ends up
reachable from the internet, running as root, with a published database port and a literal
password. This scanner reads them offline with its own rules: YAML through PyYAML's node
tree (for line numbers), Dockerfiles and HCL by line scanning. No network call, no external
binary. One finding per rule, its evidence capped at `max_evidence`; every excerpt and note
is redacted, and a secret's value never leaves the scanner.

The rules are data (`RULES`): severity, category, title and wording per rule, effort bands in
`effort.EFFORT_RULES`. A per-rule reference such as a CWE id is one more `Rule` field.
"""

from __future__ import annotations

import functools
import json
import re
import shlex
from collections.abc import Iterable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

import yaml

from unvarnish.analysis.languages import Classification
from unvarnish.config import DEFAULT_SCANNER_OPTIONS
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.secrets import fingerprint, redact_text, tree_skip_reason
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.schemas.inventory import Census
from unvarnish.util.plural import plural

NAME = "deployment_exposure"
FAMILIES = ("compose", "dockerfile", "kubernetes", "terraform")
# How the documents name each family's files: (singular, plural).
FAMILY_NOUNS: dict[str, tuple[str, str]] = {
    "compose": ("Compose file", "Compose files"),
    "dockerfile": ("Dockerfile", "Dockerfiles"),
    "kubernetes": ("Kubernetes manifest", "Kubernetes manifests"),
    "terraform": ("Terraform file", "Terraform files"),
}
MAX_EXCERPT = 200
# A line is cut to this before the masking regexes run, after every known raw value is
# replaced on the whole line: a minified or one-line file must not make redaction slow.
MAX_REDACT_INPUT = 4 * MAX_EXCERPT
MAX_SHLEX = 65_536  # longer ENV or ARG arguments are split on whitespace
NOTE_EXAMPLES = 5
REDACTED = "…[redacted]"


@dataclass(frozen=True)
class Rule:
    id: str
    family: str
    severity: Severity
    category: Category
    title: str
    what: str  # the summary's first sentence, without its full stop
    impact: str
    remediation: str


_S, _C = Severity, Category
RULES: dict[str, Rule] = {r.id: r for r in (
    Rule("compose_database_port", "compose", _S.high, _C.security,
         "Database port published on all interfaces",
         "A database container publishes its port on every interface of the host",
         "Anyone who can reach the host, and the internet if the host is public, can connect "
         "to the database directly and try its credentials; Docker's published ports also "
         "bypass host firewalls such as ufw.",
         "Remove the port mapping so only containers on the Compose network reach the "
         "database, or bind it to 127.0.0.1 (\"127.0.0.1:5432:5432\") for local tools."),
    Rule("compose_public_port", "compose", _S.medium, _C.security,
         "Port published on all interfaces",
         "A Compose service publishes a port on every interface of the host (no host "
         "address, or 0.0.0.0)",
         "The service is reachable from every network the host is on, past any reverse proxy "
         "or authentication in front of it; Docker's published ports also bypass host "
         "firewalls such as ufw.",
         "Bind the port to 127.0.0.1 behind a reverse proxy, or replace the mapping with "
         "`expose` for traffic between containers."),
    Rule("compose_privileged", "compose", _S.high, _C.security,
         "Privileged container",
         "A Compose service runs with `privileged: true`",
         "A privileged container has every capability and the host's devices: anyone who "
         "compromises it controls the host.",
         "Remove `privileged` and add only the capabilities the service needs with `cap_add`."),
    Rule("compose_host_network", "compose", _S.medium, _C.security,
         "Container shares the host's network",
         "A Compose service uses `network_mode: host`",
         "Every port the service listens on is open on the host's interfaces, and the "
         "container can reach services the host binds to localhost.",
         "Use the default bridge network and publish only the ports that must be reachable."),
    Rule("compose_docker_socket", "compose", _S.high, _C.security,
         "Docker socket mounted into a container",
         "A Compose service mounts the Docker socket",
         "Whoever controls the container can start privileged containers through the socket, "
         "which is root on the host; a read-only mount does not prevent this.",
         "Remove the mount, or put a socket proxy in front that allows only the API calls "
         "the service needs."),
    Rule("compose_literal_password", "compose", _S.high, _C.security,
         "Literal password in a Compose file",
         "A Compose file sets a password, secret or token to a literal value",
         "Anyone who can read the repository holds the credential, and every deployment "
         "from this file shares it.",
         "Rotate the credential, read it from an environment file outside the repository or "
         "a Compose secret, and commit only a placeholder."),
    Rule("compose_password_default", "compose", _S.medium, _C.security,
         "Password with a fallback value in a Compose file",
         "A Compose file gives a password, secret or token a fallback value "
         "(`${VAR:-value}`) used when the variable is not set",
         "A deployment that forgets the variable starts with a credential everyone who reads "
         "the repository knows, and nothing says so.",
         "Remove the fallback, or use `${VAR:?message}` so a missing value stops the start."),
    Rule("dockerfile_root_user", "dockerfile", _S.medium, _C.security,
         "Container runs as root",
         "The final stage of a Dockerfile sets no `USER`, or sets root",
         "A flaw in the application gives the attacker root inside the container, which "
         "makes escaping to the host and tampering with mounted files easier.",
         "Create an unprivileged user and add `USER <name>` to the final stage, after the "
         "steps that need root."),
    Rule("dockerfile_add_url", "dockerfile", _S.medium, _C.security,
         "ADD downloads from a URL without a checksum",
         "A Dockerfile `ADD`s a remote URL without `--checksum`",
         "The build trusts whatever the server returns that day: a compromised or changed "
         "download goes into the image unnoticed.",
         "Download with `ADD --checksum=sha256:<digest>`, or fetch and verify the file in a "
         "`RUN` step."),
    Rule("dockerfile_secret_literal", "dockerfile", _S.high, _C.security,
         "Secret baked into the image",
         "A Dockerfile sets a secret-named `ENV` or `ARG` to a literal value",
         "The value is in the repository and in every copy of the image: `docker history` "
         "and `docker inspect` show it to anyone who can pull the image.",
         "Rotate the secret, remove it from the Dockerfile, and pass it at run time from a "
         "secret store."),
    Rule("dockerfile_secret_build_arg", "dockerfile", _S.medium, _C.security,
         "Secret passed as a build argument",
         "A Dockerfile takes a secret-named `ARG` or `ENV` from the build",
         "Build arguments and environment values are recorded in the image's history and "
         "configuration, so the secret ships with the image.",
         "Use a build secret mount (`RUN --mount=type=secret,id=...`) for build-time "
         "secrets, and pass run-time secrets when the container starts."),
    Rule("k8s_host_network", "kubernetes", _S.medium, _C.security,
         "Pod uses the node's network",
         "A Kubernetes workload sets `hostNetwork: true`",
         "The pod's ports open on the node's interfaces, network policies do not apply to "
         "it, and it can reach services bound to the node's localhost.",
         "Remove `hostNetwork` and expose the pod through a Service."),
    Rule("k8s_privileged", "kubernetes", _S.high, _C.security,
         "Privileged container in Kubernetes",
         "A Kubernetes container sets `securityContext.privileged: true`",
         "A privileged container has every capability and the node's devices: anyone who "
         "compromises it controls the node and the pods on it.",
         "Remove `privileged`, add only the capabilities needed, and enforce the restricted "
         "Pod Security Standard on the namespace."),
    Rule("k8s_no_limits", "kubernetes", _S.medium, _C.reliability,
         "Container without resource limits",
         "A Kubernetes container sets no `resources.limits`",
         "One runaway or attacked container can take the node's memory and CPU from every "
         "other pod on it.",
         "Set memory and CPU limits on every container, or a LimitRange on the namespace."),
    Rule("k8s_latest_image", "kubernetes", _S.low, _C.dependency,
         "Image pinned to latest or untagged",
         "A Kubernetes container runs an image tagged `latest` or without a tag",
         "What runs changes whenever the image is pushed: deployments are not reproducible "
         "and a bad or compromised push rolls out on the next restart.",
         "Pin each image to a version tag, or better a digest (`image@sha256:...`)."),
    Rule("tf_open_ingress", "terraform", _S.high, _C.security,
         "Ingress open to the internet",
         "Terraform allows inbound traffic from any address (0.0.0.0/0 or ::/0) on ports "
         "other than 80 and 443",
         "The ports are reachable from the whole internet: administration, database and "
         "internal services become targets for scanning and credential guessing.",
         "Restrict the source ranges to known networks, a VPN or a bastion, and expose only "
         "web traffic publicly."),
    Rule("tf_public_storage", "terraform", _S.high, _C.data_handling,
         "Object storage open to the public",
         "Terraform makes a storage bucket or container readable by anyone (public ACL, "
         "`allUsers`, public access block turned off, public container access)",
         "Anyone who finds or guesses the name can list or download the stored files, "
         "without credentials.",
         "Make the storage private, keep the public access block on, and serve public files "
         "through signed URLs or a CDN."),
)}


def _option(ctx: ScanContext, key: str) -> Any:
    return ctx.options.get(key, DEFAULT_SCANNER_OPTIONS[NAME][key])


# --- file selection -----------------------------------------------------------------------------

COMPOSE_NAME_RE = re.compile(r"^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$")
# YAML or JSON (`"apiVersion": ...`); no leading `\s*`, which is quadratic on blank runs.
K8S_HINT_RE = re.compile(r"(?<![\w-])[\"']?apiVersion[\"']?[ \t]*:")
K8S_KIND_RE = re.compile(r"(?<![\w-])[\"']?kind[\"']?[ \t]*:")
SKIPPED_CLASSES = {Classification.binary, Classification.vendored, Classification.docs}


def family_of(path: str) -> str | None:
    """The family a file's name puts it in; YAML that is not Compose is a Kubernetes
    candidate, judged by its content."""
    name = PurePosixPath(path).name
    low = name.lower()
    if COMPOSE_NAME_RE.match(low):
        return "compose"
    if low.endswith(".dockerignore"):
        return None
    if (name in ("Dockerfile", "Containerfile") or name.startswith(("Dockerfile.",
                                                                     "Containerfile."))
            or low.endswith((".dockerfile", ".containerfile"))):
        return "dockerfile"
    if low.endswith(".tf"):
        return "terraform"
    if low.endswith((".yaml", ".yml")):
        return "kubernetes"
    return None


def deployment_files(census: Census, options: dict[str, Any]) -> dict[str, list[str]]:
    """Candidate files per family, whatever the family toggles say. Gitignored, vendored
    and binary files are skipped; a directory the census treats as build output is read,
    because `build/` is where many projects keep their Dockerfiles."""
    include_tests = bool(options.get("include_tests", False))
    out: dict[str, list[str]] = {f: [] for f in FAMILIES}
    for rec in census.files:
        if ((rec.excluded and not (rec.exclusion_reason or "").startswith("build_output:"))
                or tree_skip_reason(rec) or rec.classification in SKIPPED_CLASSES):
            continue
        if rec.classification == Classification.test and not include_tests:
            continue
        family = family_of(rec.path)
        if family:
            out[family].append(rec.path)
    return out


# --- redaction ----------------------------------------------------------------------------------

SECRET_TOKEN_ENDS = ("PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "TOKEN", "APIKEY",
                     "CREDENTIAL", "CREDENTIALS", "PRIVATEKEY")
KEY_QUALIFIERS = {"API", "PRIVATE", "ACCESS", "SECRET", "AUTH", "ENCRYPTION", "SIGNING",
                  "MASTER", "CLIENT"}
# A last word that names something about a secret rather than the secret itself, and words
# that turn a password variable into a switch (MYSQL_ALLOW_EMPTY_PASSWORD).
NOT_SECRET_LAST = {"FILE", "PATH", "DIR", "URL", "URI", "HOST", "PORT", "USER", "USERNAME",
                   "NAME", "ID", "TYPE", "LENGTH", "MIN", "MAX", "TTL", "EXPIRY", "EXPIRES",
                   "EXPIRATION", "TIMEOUT", "LIFETIME", "AGE", "HEADER", "ALGORITHM",
                   "ENABLED", "DISABLED", "REQUIRED", "PREFIX", "FIELD", "PARAM", "POLICY",
                   "LIMIT", "COUNT", "SIZE", "ROUNDS", "LEN"}
NOT_SECRET_ANY = {"ALLOW", "EMPTY", "RANDOM", "GENERATE", "SKIP"}
SWITCH_VALUES = {"true", "false", "yes", "no", "on", "off", "null", "none", "~"}


def is_secret_name(name: str) -> bool:
    words = [w for w in re.split(r"[_.\-]", name.upper()) if w]
    if not words or words[-1] in NOT_SECRET_LAST or NOT_SECRET_ANY & set(words):
        return False
    for i, w in enumerate(words):
        if w.endswith(SECRET_TOKEN_ENDS) or w == "PASS":
            return True
        if w == "KEY" and i > 0 and words[i - 1] in KEY_QUALIFIERS:
            return True
    return False


ASSIGN_SECRET_RE = re.compile(
    r"(?i)((?<![\w.\-])[\w.\-]*(?:passw(?:or)?d|passphrase|secret|token|api_?key"
    r"|private_?key|access_?key|credential)[\w.\-]*[\"']?\s*[:=]\s*)(\S.*)$")
# Any `name: value` or `name=value`, judged by `is_secret_name` (DB_PASS, AUTH_KEY, ...).
NAME_ASSIGN_RE = re.compile(r"(?<![\w.\-])([A-Za-z_][\w.\-]*)[\"']?\s*[:=]\s*(?=\S)")
# A Kubernetes env entry written on one line: `{name: DB_PASSWORD, value: ...}`.
K8S_ENV_PAIR_RE = re.compile(
    r"(?i)[\"']?name[\"']?\s*:\s*[\"']?([A-Za-z_][\w.\-]*)[\"']?\s*,\s*"
    r"[\"']?value[\"']?\s*:\s*(?=\S)")
# The same entry with the value first: `{value: ..., name: DB_PASSWORD}`.
K8S_ENV_VALUE_FIRST_RE = re.compile(
    r"(?i)([\"']?value[\"']?\s*:\s*)(\"[^\"]*\"|'[^']*'|[^,}\]]*)"
    r"(\s*,\s*[\"']?name[\"']?\s*:\s*[\"']?([A-Za-z_][\w.\-]*))")
# A command-line flag and its value: `--password hunter2`, `'--password', 'hunter2'`.
FLAG_RE = re.compile(r"(?<![\w-])--?([A-Za-z][\w\-]*)(?:[\"']?\s*,\s*[\"']?|\s+|=)(?=\S)")
# A URL's user information, up to the last `@` before the host: `redis://:pw@h`,
# `postgres://u:p@ss@h`, `https://<token>@h`.
URL_AUTH_RE = re.compile(r"((?<![\w+.-])[a-z][\w+.-]*://)([^/\s]*)@", re.I)
# Values this short are replaced only between non-word characters, so a weak password such
# as `a` or `postgres` does not blank every word that contains it.
SHORT_RAW = 8


def strip_comment(line: str) -> str:
    """The line without a trailing ` #`, ` //` or ` /*` comment outside quotes: comments are
    not evidence, and one can hold anything. A `#` straight after a closing quote counts."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote and line[i - 1] != "\\":
                quote = None
            continue
        after = i == 0 or line[i - 1].isspace()
        if ch in "\"'":
            quote = ch
        elif ch == "#" and (after or line[i - 1] in "\"'"):
            return line[:i].rstrip()
        elif ch == "/" and line[i:i + 2] in ("//", "/*") and after:
            return line[:i].rstrip()
    return line


def _url_auth(m: re.Match[str]) -> str:
    """The whole user information goes: the user part can be the token itself
    (`https://<token>:x-oauth-basic@`, `https://<token>:@`, `https://<token>@`)."""
    return f"{m.group(1)}{REDACTED}@"


def url_passwords(text: str) -> Iterator[str]:
    """The password of each URL in `text` with `user:password@` (user may be empty)."""
    for m in URL_AUTH_RE.finditer(text):
        _, sep, pw = m.group(2).partition(":")
        if sep and pw and "$" not in pw:
            yield pw


@functools.lru_cache(maxsize=1024)
def _raw_regex(raw: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(raw) + r"(?![A-Za-z0-9_])")


def replace_raws(text: str, raws: Iterable[str]) -> str:
    """`text` with each value replaced by a marker: a long one wherever it occurs, a short
    one (under `SHORT_RAW`) where it stands as a whole word."""
    for raw in sorted({r for r in raws if r}, key=len, reverse=True):
        marker = f"…[redacted {len(raw)} chars]"
        if len(raw) >= SHORT_RAW:
            text = text.replace(raw, marker)
        elif raw in text:
            text = _raw_regex(raw).sub(marker, text)
    return text


def raw_survives(text: str, raws: Iterable[str]) -> bool:
    return any(r in text if len(r) >= SHORT_RAW else r in text and _raw_regex(r).search(text)
               for r in raws if r)


def _mask_named(text: str) -> str:
    """The text with the value of a secret-named one-line Kubernetes env entry (either
    order) masked, then cut after the first secret-named assignment or command-line flag
    whose value is not already a redaction marker."""
    text = K8S_ENV_VALUE_FIRST_RE.sub(
        lambda m: m.group(1) + (REDACTED if is_secret_name(m.group(4)) else m.group(2))
        + m.group(3), text)
    for regex in (K8S_ENV_PAIR_RE, NAME_ASSIGN_RE, FLAG_RE):
        for m in regex.finditer(text):
            if is_secret_name(m.group(1)) and not text[m.end():].startswith("…[redacted"):
                text = text[:m.end()] + REDACTED
                break
    return text


def _window(line: str, raws: list[str]) -> str | None:
    """The start of `line` the excerpt is made from: `MAX_REDACT_INPUT` characters, moved
    past any value that crosses the cut so no value is shown in part, or None when values
    keep crossing it. Each value is searched only near the start, so a line holding many
    values costs time in proportion to their number, not to their number times its length."""
    cut = min(len(line), MAX_REDACT_INPUT)
    for extend in (True, True, True, False, False, False):
        moved = False
        for r in raws:
            if cut >= len(line):
                return line
            i = line.rfind(r, 0, cut + len(r) - 1)  # the last occurrence starting before cut
            if i >= 0 and i + len(r) > cut:
                cut, moved = (i + len(r)) if extend else i, True
        if not moved:
            return line[:cut]
    return None


def redact_excerpt(line: str, raws: Iterable[str] = ()) -> str:
    """A line fit for a report: every known raw value replaced, credentials in URLs and
    after secret-named keys and flags masked, comments dropped; `[line redacted]` if a raw
    survives."""
    raws = [r for r in raws if r]
    window = _window(line, raws)
    if window is None:
        return "[line redacted]"
    out = strip_comment(replace_raws(window, [r for r in raws if r in window])).strip()
    out = URL_AUTH_RE.sub(_url_auth, out)
    out = ASSIGN_SECRET_RE.sub(
        lambda m: m.group(1) + (m.group(2) if m.group(2).startswith("…[redacted")
                                else REDACTED), out)
    out = redact_text(_mask_named(out))[:MAX_EXCERPT]
    return "[line redacted]" if raw_survives(out, raws) else out


def cut_after(line: str, key: str, raw: str | None, raws: Iterable[str] = ()) -> str:
    """The line up to `key` and its separator, then a redaction marker: never the value.
    `raws` are the other values to redact from what comes before the key."""
    i = line.find(key)
    if i < 0:
        return "[line redacted]"
    m = re.match(r"[\"']?[ \t]*[:=\s][ \t]*[\"']?", line[i + len(key):])
    head = line[:i + len(key)] + (m.group(0) if m else "")
    marker = f"…[redacted {len(raw)} chars]" if raw else REDACTED
    return redact_excerpt(head + marker, [r for r in (raw, *raws) if r])


INTERP_RE = re.compile(r"\$\{([A-Za-z_]\w*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_]\w*)")
UNKNOWN = "\x00"


def interpolate(value: str) -> str:
    """Compose interpolation: `${VAR:-x}` and `${VAR-x}` read as x, any other variable as
    unknown."""
    return INTERP_RE.sub(lambda m: m.group(3) if m.group(2) in (":-", "-") else UNKNOWN,
                         value.replace("$$", "$"))


# --- YAML nodes ---------------------------------------------------------------------------------

def load_yaml(text: str) -> list[yaml.Node] | None:
    """Every document's node tree, or None when the text is not YAML (a Helm template)."""
    try:
        return [d for d in yaml.compose_all(text, Loader=yaml.SafeLoader) if d is not None]
    except (yaml.YAMLError, RecursionError, ValueError):
        return None


class YamlTooComplex(Exception):
    """A file whose aliases and merge keys would take more work than `YAML_WORK_BUDGET`."""


# Node visits allowed per file. Aliases are shared nodes, so merge keys that repeat an
# anchor (`<<: [*a, *a, ...]`, nested) or many services merging one large anchor would
# otherwise cost exponential or quadratic time on a file of a few hundred bytes.
YAML_WORK_BUDGET = 200_000
_budget: ContextVar[list[int] | None] = ContextVar("deployment_exposure_budget", default=None)


def _spend(n: int) -> None:
    left = _budget.get()
    if left is not None:
        left[0] -= n
        if left[0] < 0:
            raise YamlTooComplex


def items(node: yaml.Node | None, depth: int = 0,
          seen: set[int] | None = None) -> list[tuple[str, yaml.Node]]:
    """A mapping's pairs with merge keys (`<<: *anchor`) resolved, its own keys first. Each
    merge source is read once, however often aliases repeat it."""
    if not isinstance(node, yaml.MappingNode) or depth > 8:
        return []
    seen = set() if seen is None else seen
    seen.add(id(node))
    _spend(len(node.value) + 1)
    own: list[tuple[str, yaml.Node]] = []
    merged: list[tuple[str, yaml.Node]] = []
    for k, v in node.value:
        if not isinstance(k, yaml.ScalarNode):
            continue
        if k.value == "<<" and k.style is None:
            for src in (v.value if isinstance(v, yaml.SequenceNode) else [v]):
                if id(src) not in seen:
                    merged.extend(items(src, depth + 1, seen))
        else:
            own.append((k.value, v))
    keys = {k for k, _ in own}
    return own + [(k, v) for k, v in merged if k not in keys]


def get(node: yaml.Node | None, *path: str) -> yaml.Node | None:
    for key in path:
        node = next((v for k, v in items(node) if k == key), None)
    return node


def seq(node: yaml.Node | None) -> list[yaml.Node]:
    if not isinstance(node, yaml.SequenceNode):
        return []
    _spend(len(node.value) + 1)
    return list(node.value)


def scalar(node: yaml.Node | None) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def truthy(node: yaml.Node | None) -> bool:
    return (scalar(node) or "").strip().lower() in ("true", "yes", "on")


def line_of(node: yaml.Node) -> int:
    return node.start_mark.line + 1


# --- collection ---------------------------------------------------------------------------------

@dataclass
class _Hit:
    path: str
    line: int
    text: str  # the raw line: redacted only in `evidence`, against every value in the file
    key: str | None = None
    raw: str | None = None
    notes: list[str] = field(default_factory=list)
    fingerprint: str | None = None

    def evidence(self, raws: Iterable[str]) -> Evidence:
        """The hit's evidence, with every credential value found in its file redacted, not
        only its own: one line can hold several (`{DB_PASS: a, API_TOKEN: b}`)."""
        raws = list(raws)
        excerpt = (cut_after(self.text, self.key, self.raw, raws) if self.key
                   else redact_excerpt(self.text, raws))
        # Notes are built from names (service, key, container, resource), never values, so
        # they are not searched for the file's values: a weak password that is also a
        # service's name (`postgres`) would blank it. They still pass the pattern redactor.
        note = "; ".join(dict.fromkeys(redact_excerpt(n) for n in self.notes)) or None
        return Evidence(path=self.path, line_start=self.line, line_end=self.line,
                        excerpt=excerpt or None, note=note, fingerprint=self.fingerprint)


DB_PORTS = {1433, 1521, 2379, 3306, 5432, 5984, 6379, 7474, 7687, 8086, 8123, 8529, 9042,
            9200, 9300, 11211, 26257, 27017, 28015}
DB_IMAGE_RE = re.compile(
    r"postgres|postgis|timescale|pgvector|mysql|mariadb|mongo|redis|valkey|keydb|elasticsearch"
    r"|opensearch|cassandra|scylla|couchdb|couchbase|neo4j|memcached|mssql|cockroach|influxdb"
    r"|clickhouse|arangodb|rethinkdb|etcd")
SOCKET_RE = re.compile(r"(?:docker|podman)\.sock$")
LOOPBACK_RE = re.compile(r"^(?:127\.\d+\.\d+\.\d+|localhost|::1|0:0:0:0:0:0:0:1)$", re.I)
ALL_INTERFACES = {"", "0.0.0.0", "::", "[::]"}
WORKLOAD_POD_SPEC: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
    **{k: ("spec", "template", "spec") for k in (
        "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job",
        "ReplicationController")},
}
CIDR_ANY_RE = re.compile(r"[\"'](?:0\.0\.0\.0/0|::/0)[\"']")
WEB_PORTS = {80, 443}


def _image_name(image: str) -> str:
    """The image's repository path without tag or digest."""
    head, _, last = image.split("@", 1)[0].rpartition("/")
    return (head + "/" if head else "") + last.split(":", 1)[0]


def _first_port(text: str) -> int | None:
    m = re.match(r"\s*(\d{1,6})(?!\d)", text)
    return int(m.group(1)) if m else None


def parse_port(spec: str) -> tuple[str, str]:
    """(host address, container port) of a Compose short-syntax port; address "" when the
    spec names none, and UNKNOWN in it when a variable without a default sets it."""
    spec = interpolate(spec.strip()).split("/", 1)[0]
    if spec.startswith("["):
        end = spec.find("]")
        return spec[1:end], spec[end + 1:].split(":")[-1]
    parts = spec.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:-2]), parts[-1]
    return "", parts[-1]


def on_all_interfaces(address: str) -> bool:
    address = address.strip()
    return UNKNOWN not in address and address in ALL_INTERFACES


class DeploymentExposureScanner:
    name = NAME
    category = Category.security
    rules = RULES

    def __init__(self) -> None:
        self.notes: list[str] = []
        self.coverage: dict[str, int] = {}

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.notes = []
        self.coverage = {}
        ignored = [str(r) for r in (_option(ctx, "ignore_rules") or [])]
        unknown = [r for r in ignored if r not in RULES]
        if unknown:
            raise ValueError(f"scanners.{NAME}.ignore_rules: unknown rule {unknown[0]!r}; "
                             "rules: " + ", ".join(RULES))
        self._ctx = ctx
        self._hits: dict[str, dict[tuple[str, int, str | None], _Hit]] = {r: {} for r in RULES}
        self._raws: dict[str, set[str]] = {}  # every credential value found, per file
        self._limit_range = False
        enabled = [f for f in FAMILIES if _option(ctx, f)]
        disabled = [f for f in FAMILIES if f not in enabled]
        candidates = deployment_files(ctx.census, ctx.options)
        unparsable: list[str] = []
        seen_any = False
        for family in enabled:
            checked = 0
            for path in candidates[family]:
                try:
                    text = (ctx.source_root / path).read_text(encoding="utf-8",
                                                              errors="replace")
                except OSError:
                    continue
                if family == "kubernetes" and not (K8S_HINT_RE.search(text)
                                                   and K8S_KIND_RE.search(text)):
                    continue
                seen_any = True
                token = _budget.set([YAML_WORK_BUDGET])
                try:
                    ok = getattr(self, f"_{family}")(path, text, text.split("\n"))
                except (YamlTooComplex, RecursionError):
                    ok = False
                finally:
                    _budget.reset(token)
                if ok:
                    checked += 1
                else:
                    unparsable.append(path)
            self.coverage[family] = checked
        if disabled:
            self.notes.append(f"{NAME}: {', '.join(disabled)} not checked (turned off in "
                              f"scanners.{NAME})")
        if enabled and not seen_any:
            nouns = ", ".join(FAMILY_NOUNS[f][1] for f in enabled)
            self.notes.append(f"{NAME}: not checked (no deployment files found: {nouns})")
        if unparsable:
            shown = ", ".join(unparsable[:NOTE_EXAMPLES])
            more = (f" and {len(unparsable) - NOTE_EXAMPLES} more"
                    if len(unparsable) > NOTE_EXAMPLES else "")
            n = len(unparsable)
            self.notes.append(f"{NAME}: {plural(n, 'file')} could not be parsed and "
                              f"{'was' if n == 1 else 'were'} not checked (a template, such "
                              f"as a Helm chart, is not plain YAML; nor is YAML nested too "
                              f"deep or whose aliases expand too far): {shown}{more}")
        if self._limit_range:
            self._hits["k8s_no_limits"] = {}  # a LimitRange gives containers default limits
        return [self._finding(RULES[rid], list(hits.values()))
                for rid, hits in self._hits.items() if hits and rid not in ignored]

    def _hit(self, rule: str, path: str, line: int, text: str, note: str | None = None,
             raw: str | None = None, key: str | None = None) -> None:
        fp = fingerprint(raw) if raw else None
        if raw:
            self._raws.setdefault(path, set()).add(raw)
        slot = (path, line, fp)
        if slot not in self._hits[rule]:
            self._hits[rule][slot] = _Hit(path=path, line=line, text=text, key=key, raw=raw,
                                          fingerprint=fp)
        hit = self._hits[rule][slot]
        if note:
            hit.notes.append(note)
        if fp:
            hit.notes.append(f"fingerprint {fp}")

    def _finding(self, rule: Rule, hits: list[_Hit]) -> Finding:
        cap = max(1, int(_option(self._ctx, "max_evidence")))
        hits = sorted(hits, key=lambda h: (h.path, h.line))
        n, files = len(hits), len({h.path for h in hits})
        shown = f" Showing the first {cap} of {n}." if n > cap else ""
        redacted = (" Values are redacted and identified by fingerprint."
                    if any(h.fingerprint for h in hits) else "")
        return Finding(
            tool=self._ctx.tool, category=rule.category, severity=rule.severity,
            title=rule.title,
            summary=(f"{rule.what} ({plural(n, 'place')} in {plural(files, 'file')})."
                     f"{redacted}{shown}"),
            impact=rule.impact, remediation=rule.remediation,
            evidence=[h.evidence(self._raws.get(h.path, ())) for h in hits[:cap]],
            source=Source.scanner,
            scanner=NAME,
            tags=[f"group:{rule.id}", f"count:{n}", f"deployment:{rule.family}"],
            **rule_effort(self._ctx, NAME, rule.id))

    # --- Compose ---------------------------------------------------------------------------

    def _compose(self, path: str, text: str, lines: list[str]) -> bool:
        docs = load_yaml(text)
        if docs is None:
            return False
        for doc in docs:
            for name, svc in items(get(doc, "services")):
                self._service(path, lines, name, svc)
        return True

    def _service(self, path: str, lines: list[str], name: str, svc: yaml.Node) -> None:
        def at(node: yaml.Node) -> tuple[int, str]:
            n = line_of(node)
            return n, lines[n - 1] if n <= len(lines) else ""

        label = f"service {name}"
        image = scalar(get(svc, "image")) or ""
        db_image = bool(DB_IMAGE_RE.search(_image_name(image).lower()))
        for port in seq(get(svc, "ports")):
            if isinstance(port, yaml.ScalarNode):
                address, container = parse_port(port.value)
            elif isinstance(port, yaml.MappingNode):
                address = interpolate(scalar(get(port, "host_ip")) or "")
                container = interpolate(scalar(get(port, "target")) or "")
            else:
                continue
            if not on_all_interfaces(address):
                continue
            number = _first_port(container)
            db = db_image or number in DB_PORTS
            n, line = at(port)
            what = f"port {number}" if number is not None else "a port"
            self._hit("compose_database_port" if db else "compose_public_port", path, n, line,
                      f"{label} publishes {what} on all interfaces")
        privileged = get(svc, "privileged")
        if truthy(privileged):
            self._hit("compose_privileged", path, *at(privileged), label)
        mode = get(svc, "network_mode")
        if (scalar(mode) or "").strip() == "host":
            self._hit("compose_host_network", path, *at(mode), label)
        for volume in seq(get(svc, "volumes")):
            source = (scalar(volume).split(":", 1)[0] if isinstance(volume, yaml.ScalarNode)
                      else scalar(get(volume, "source")) or "")
            if SOCKET_RE.search(interpolate(source).strip()):
                self._hit("compose_docker_socket", path, *at(volume), label)
        env = get(svc, "environment")
        pairs: list[tuple[str, str, yaml.Node]] = []
        if isinstance(env, yaml.MappingNode):
            pairs = [(k, v.value, v) for k, v in items(env) if isinstance(v, yaml.ScalarNode)
                     and v.tag != "tag:yaml.org,2002:null"]
        else:
            for item in seq(env):
                text = scalar(item)
                if text and "=" in text:
                    k, v = text.split("=", 1)
                    pairs.append((k.strip(), v, item))
        for key, value, node in pairs:
            n, line = at(node)
            for kind, raw in _secret_values(key, value):
                rid = ("compose_password_default" if kind == "default"
                       else "compose_literal_password")
                self._hit(rid, path, n, line, f"{label}, {key}", raw=raw,
                          key=key if kind != "url" else None)

    # --- Dockerfile ------------------------------------------------------------------------

    def _dockerfile(self, path: str, text: str, lines: list[str]) -> bool:
        stages: list[dict[str, Any]] = []
        aliases: dict[str, dict[str, Any]] = {}  # the latest stage of each `AS` name
        for start, span, instr in _instructions(lines):
            parts = instr.split(None, 1)  # a tab after the instruction is whitespace too
            word = parts[0].upper() if parts else ""
            args = parts[1].strip() if len(parts) > 1 else ""
            if word == "FROM":
                tokens = [t for t in args.split() if not t.startswith("--")]
                base = tokens[0] if tokens else ""
                alias = tokens[2].lower() if len(tokens) >= 3 and tokens[1].lower() == "as" \
                    else None
                parent = aliases.get(base.lower())
                stages.append({"alias": alias, "base": base, "line": start, "user": None,
                               "parent": parent})
                if alias:
                    aliases[alias] = stages[-1]
            elif word == "USER" and stages:
                stages[-1]["user"] = (args.split()[0] if args else "", start)
            elif word == "ADD":
                self._add(path, lines, start, args)
            elif word in ("ENV", "ARG"):
                self._env(path, lines, span, word, args)
        if stages:
            self._final_user(path, lines, stages[-1])
        return True

    def _add(self, path: str, lines: list[str], start: int, args: str) -> None:
        tokens: list[str]
        if args.lstrip().startswith("["):
            try:
                tokens = [str(t) for t in json.loads(args)]
            except ValueError:
                tokens = args.split()
        else:
            tokens = args.split()
        flags = [t for t in tokens if t.startswith("--")]
        sources = [t for t in tokens if not t.startswith("--")][:-1]
        if any(f.startswith("--checksum") for f in flags):
            return
        if any(re.match(r"https?://", s, re.I) for s in sources):
            self._hit("dockerfile_add_url", path, start, lines[start - 1])

    def _env(self, path: str, lines: list[str], span: list[int], word: str,
             args: str) -> None:
        pairs: list[tuple[str, str | None]] = []
        first = args.split(None, 1)
        if not first:
            return
        if word == "ARG" or "=" in first[0]:
            try:
                # shlex slows down sharply on long input; an ENV of that size is not real.
                if len(args) > MAX_SHLEX:
                    raise ValueError
                tokens = shlex.split(args, posix=True)
            except ValueError:
                tokens = args.split()
            for t in tokens:
                k, sep, v = t.partition("=")
                pairs.append((k, v if sep else None))
        else:  # legacy `ENV KEY value with spaces`
            pairs.append((first[0], first[1].strip() if len(first) > 1 else ""))
        index: dict[str, int] | None = None

        def line_of_key(key: str) -> int:
            """The first line of the instruction naming `key`, from one pass over it."""
            nonlocal index
            if len(span) == 1:
                return span[0]
            if index is None:
                index = {}
                for i in span:
                    for name in re.findall(r"[\w.\-]+", lines[i - 1]):
                        index.setdefault(name, i)
            return index.get(key, span[0])

        for key, value in pairs:
            if value is None or "$" in value:
                if is_secret_name(key):
                    n = line_of_key(key)
                    # The value (`Pa$$word`, `${X:-fallback}`) may hold a literal: cut it.
                    self._hit("dockerfile_secret_build_arg", path, n, lines[n - 1],
                              f"{word} {key}", key=key if value else None)
                continue
            for kind, raw in _secret_values(key, value, defaults=False):
                n = line_of_key(key)
                self._hit("dockerfile_secret_literal", path, n, lines[n - 1], f"{word} {key}",
                          raw=raw, key=key if kind == "literal" else None)

    def _final_user(self, path: str, lines: list[str], stage: dict[str, Any]) -> None:
        def effective(s: dict[str, Any] | None, depth: int = 0) -> tuple[str | None, int]:
            if s is None or depth > 32:
                return None, 0
            if s["user"] is not None:
                return s["user"]
            if s["parent"] is not None:
                return effective(s["parent"], depth + 1)
            low = s["base"].lower()
            return ("nonroot" if "nonroot" in low or "rootless" in low else None), 0

        user, line = effective(stage)
        if user is not None:
            name = user.split(":", 1)[0].strip()
            if "$" in name or name.lower() not in ("root", "0"):
                return  # a named or numeric non-root user, or one set at build time
            own = stage["user"] is not None
            self._hit("dockerfile_root_user", path, line if own else stage["line"],
                      lines[(line if own else stage["line"]) - 1],
                      "the final stage sets USER root" if own
                      else "the final stage inherits USER root from an earlier stage")
            return
        self._hit("dockerfile_root_user", path, stage["line"], lines[stage["line"] - 1],
                  "the final stage sets no USER, so it runs as the base image's user, root "
                  "for most images")

    # --- Kubernetes ------------------------------------------------------------------------

    def _kubernetes(self, path: str, text: str, lines: list[str]) -> bool:
        docs = load_yaml(text)
        if docs is None:
            return False
        for doc in docs:
            for obj in _k8s_objects(doc):
                self._workload(path, lines, obj)
        return True

    def _workload(self, path: str, lines: list[str], obj: yaml.Node) -> None:
        kind = scalar(get(obj, "kind")) or ""
        if kind == "LimitRange":
            self._limit_range = True
        spec_path = WORKLOAD_POD_SPEC.get(kind)
        if spec_path is None:
            return
        spec = get(obj, *spec_path)
        label = f"{kind} {scalar(get(obj, 'metadata', 'name')) or '(unnamed)'}"

        def hit(rule: str, node: yaml.Node, note: str) -> None:
            n = line_of(node)
            self._hit(rule, path, n, lines[n - 1] if n <= len(lines) else "", note)

        host = get(spec, "hostNetwork")
        if truthy(host):
            hit("k8s_host_network", host, label)
        for group in ("initContainers", "containers"):
            for c in seq(get(spec, group)):
                who = f"{label}, container {scalar(get(c, 'name')) or '(unnamed)'}"
                privileged = get(c, "securityContext", "privileged")
                if truthy(privileged):
                    hit("k8s_privileged", privileged, who)
                if not items(get(c, "resources", "limits")):
                    hit("k8s_no_limits", c, who)
                image = get(c, "image")
                tag = _floating_tag(scalar(image) or "")
                if image is not None and tag:
                    hit("k8s_latest_image", image, f"{who}: {tag}")

    # --- Terraform -------------------------------------------------------------------------

    def _terraform(self, path: str, text: str, lines: list[str]) -> bool:
        blocks, cidrs = parse_hcl(lines)
        for line, chain in cidrs:
            if _ingress(chain):
                self._hit("tf_open_ingress", path, line, lines[line - 1],
                          _resource_label(chain))
        for block in blocks:
            self._tf_block(path, lines, block)
        return True

    def _tf_block(self, path: str, lines: list[str], block: _Block) -> None:
        def flag(rule: str, line: int) -> None:
            self._hit(rule, path, line, lines[line - 1], block.label())

        kind = block.resource_type()
        attr = block.value
        if block.is_azure_rule() and attr("direction").lower() == "inbound" \
                and attr("access").lower() != "deny":
            for key in ("source_address_prefix", "source_address_prefixes"):
                if key in block.attrs and re.search(
                        r"[\"'](?:\*|0\.0\.0\.0/0|::/0|internet|any)[\"']",
                        block.attrs[key][0], re.I) and not _web_only(
                        [block.attrs[k][0] for k in ("destination_port_range",
                                                     "destination_port_ranges")
                         if k in block.attrs]):
                    flag("tf_open_ingress", block.attrs[key][1])
        if kind in ("aws_s3_bucket", "aws_s3_bucket_acl") and attr("acl") in (
                "public-read", "public-read-write", "authenticated-read"):
            flag("tf_public_storage", block.attrs["acl"][1])
        if kind in ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"):
            for key in ("block_public_acls", "block_public_policy", "ignore_public_acls",
                        "restrict_public_buckets"):
                if attr(key) == "false":
                    flag("tf_public_storage", block.attrs[key][1])
        if kind == "aws_s3_bucket_policy":
            body = lines[block.line - 1:block.end]
            if not any("condition" in ln.lower() for ln in body):
                for i, ln in enumerate(body, start=block.line):
                    if PRINCIPAL_ANY_RE.search(strip_comment(ln)):
                        flag("tf_public_storage", i)
        if kind.startswith("google_storage_"):
            for i, ln in enumerate(lines[block.line - 1:block.end], start=block.line):
                if re.search(r"[\"'](?:allUsers|allAuthenticatedUsers)\b", strip_comment(ln)):
                    flag("tf_public_storage", i)
            for key in ("predefined_acl", "default_acl"):
                if attr(key) in ("publicread", "publicreadwrite"):
                    flag("tf_public_storage", block.attrs[key][1])
        if kind == "azurerm_storage_container" and attr("container_access_type") in (
                "blob", "container"):
            flag("tf_public_storage", block.attrs["container_access_type"][1])
        if kind == "azurerm_storage_account":
            for key in ("allow_nested_items_to_be_public", "allow_blob_public_access"):
                if attr(key) == "true":
                    flag("tf_public_storage", block.attrs[key][1])


PRINCIPAL_ANY_RE = re.compile(
    r"(?i)[\"']?principals?[\"']?\s*[:=]\s*(?:\{\s*[\"']?aws[\"']?\s*[:=]\s*)?\[?\s*[\"']\*[\"']")


def _secret_values(key: str, value: str, *,
                   defaults: bool = True) -> Iterator[tuple[str, str]]:
    """("literal" | "default" | "url", raw) for each credential in an environment value: the
    value of a secret-named key, a `${VAR:-fallback}`'s fallback, or a password in a URL."""
    value = value.strip()
    for pw in url_passwords(value):
        yield "url", pw
    if not is_secret_name(key) or not value or value.lower() in SWITCH_VALUES:
        return
    if "$" in value:
        if defaults:
            for m in INTERP_RE.finditer(value):
                fallback = m.group(3)
                if m.group(2) in (":-", "-") and fallback and "$" not in fallback:
                    yield "default", fallback
        return
    if not any(url_passwords(value)):
        yield "literal", value


def _floating_tag(image: str) -> str | None:
    """"latest" or "no tag" for an image that floats, None for a pinned or templated one."""
    image = image.strip()
    if not image or "@" in image or "{{" in image or "$" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "no tag (pulls latest)"
    return "tag latest" if last.rsplit(":", 1)[1] == "latest" else None


def _k8s_objects(doc: yaml.Node) -> Iterator[yaml.Node]:
    if scalar(get(doc, "kind")) == "List":
        yield from (i for i in seq(get(doc, "items")) if isinstance(i, yaml.MappingNode))
    elif scalar(get(doc, "apiVersion")) and scalar(get(doc, "kind")):
        yield doc


def _instructions(lines: list[str]) -> Iterator[tuple[int, list[int], str]]:
    """(first line, every line, text) of each Dockerfile instruction: continuation lines
    joined, comments and heredoc bodies skipped."""
    i = 0
    while i < len(lines):
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        start, span, parts = i + 1, [i + 1], [raw.rstrip()]
        while parts[-1].endswith("\\") and i + 1 < len(lines):
            parts[-1] = parts[-1][:-1]
            i += 1
            while i + 1 < len(lines) and lines[i].lstrip().startswith("#"):
                i += 1  # a comment inside a continuation is dropped
            span.append(i + 1)
            parts.append(lines[i].rstrip())
        text = " ".join(p.strip() for p in parts)
        i += 1
        heredoc = re.search(r"<<-?[\"']?([A-Za-z_]\w*)[\"']?", text)
        if heredoc and text.split(None, 1)[0].upper() in ("RUN", "COPY", "ADD"):
            while i < len(lines) and lines[i].strip() != heredoc.group(1):
                i += 1
            i += 1
        yield start, span, text


# --- HCL ----------------------------------------------------------------------------------------

@dataclass
class _Block:
    words: list[str]
    line: int
    end: int = 0
    attrs: dict[str, tuple[str, int]] = field(default_factory=dict)
    children: list[_Block] = field(default_factory=list)
    top: bool = True  # not inside another block: only a top-level `resource` is a resource
    ports: list[str] | None = field(default=None, repr=False)  # `_ports`, computed once

    def resource_type(self) -> str:
        return (self.words[1] if self.top and self.words[:1] == ["resource"]
                and len(self.words) > 1 else "")

    def value(self, key: str) -> str:
        raw = self.attrs.get(key, ("", 0))[0].strip().rstrip(",")
        return raw.strip("\"'").lower()

    def is_azure_rule(self) -> bool:
        return (self.resource_type() == "azurerm_network_security_rule"
                or self.words[:1] == ["security_rule"])

    def label(self) -> str:
        return " ".join(self.words[1:3]) if self.words[:1] == ["resource"] else self.words[0]


@dataclass
class _Expr:
    key: str | None


# Blocks that only exist at the top level: one starting in column 0 closes whatever an
# unbalanced brace left open, so a missing `}` does not nest the rest of the file.
TOP_LEVEL_BLOCKS = {"resource", "data", "module", "variable", "output"}
MAX_CHAIN = 64  # blocks and expressions kept around a 0.0.0.0/0 line: the outermost and nearest
BLOCK_RE = re.compile(r"^\s*([A-Za-z_][\w-]*)((?:\s+(?:\"[^\"]*\"|[A-Za-z_][\w-]*))*)\s*\{")
ATTR_RE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=(?!=)\s*(.*)$")


def _mask(line: str, state: dict[str, Any]) -> str:
    """The line with comments removed and every string's contents blanked, so braces in
    strings and interpolations do not count. `state` carries an open /* comment."""
    out: list[str] = []
    i, n = 0, len(line)
    in_str, interp = False, 0
    while i < n:
        ch, two = line[i], line[i:i + 2]
        if state.get("comment"):
            if two == "*/":
                state["comment"] = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            if interp == 0 and ch == "\\":
                out.append("  ")
                i += 2
                continue
            if two == "${" or two == "%{":
                interp += 1
                out.append("  ")
                i += 2
                continue
            if interp and ch == "}":
                interp -= 1
            elif interp == 0 and ch == '"':
                in_str = False
                out.append('"')
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append('"')
        elif ch == "#" or two == "//":
            break
        elif two == "/*":
            state["comment"] = True
            i += 2
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def parse_hcl(lines: list[str]) -> tuple[list[_Block], list[tuple[int, list[_Block | _Expr]]]]:
    """Every block with its attributes, and each line quoting 0.0.0.0/0 or ::/0 with the
    blocks and expressions around it. Heredoc bodies and comments are skipped."""
    blocks: list[_Block] = []
    cidrs: list[tuple[int, list[_Block | _Expr]]] = []
    stack: list[_Block | _Expr] = []
    open_blocks: list[_Block] = []  # the _Block entries of `stack`, in order
    state: dict[str, Any] = {}
    heredoc: str | None = None
    for number, raw in enumerate(lines, start=1):
        if heredoc is not None:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        masked = _mask(raw, state)
        if not masked.strip():
            continue
        clean = raw[:len(masked)] if len(masked) <= len(raw) else raw
        header = BLOCK_RE.match(masked)
        attr = ATTR_RE.match(masked)
        if (header and not attr and stack and raw[:1].strip()
                and header.group(1) in TOP_LEVEL_BLOCKS):
            for b in open_blocks:
                b.end = b.end or number - 1
            stack.clear()
            open_blocks.clear()
        if CIDR_ANY_RE.search(clean):
            chain = stack if len(stack) <= MAX_CHAIN else (
                stack[:MAX_CHAIN // 2] + stack[-(MAX_CHAIN // 2):])
            cidrs.append((number, list(chain)))
        rest = masked
        if header and not attr:
            labels = re.findall(r"\"([^\"]*)\"|([A-Za-z_][\w-]*)", BLOCK_RE.match(clean)
                                .group(2) if BLOCK_RE.match(clean) else "")
            words = [header.group(1)] + [a or b for a, b in labels]
            parent = open_blocks[-1] if open_blocks else None
            block = _Block(words=words, line=number, top=parent is None)
            (parent.children if parent else blocks).append(block)
            if parent is not None:
                blocks.append(block)
            stack.append(block)
            open_blocks.append(block)
            rest = masked[header.end():]
        elif attr:
            top = stack[-1] if stack else None
            if isinstance(top, _Block):
                top.attrs.setdefault(attr.group(1), (strip_comment(raw.split("=", 1)[1]),
                                                     number))
        opener = attr.group(1) if attr else None
        for ch in rest:
            if ch == "{":
                stack.append(_Expr(key=opener))
            elif ch == "}" and stack:
                top = stack.pop()
                if isinstance(top, _Block):
                    top.end = number
                    open_blocks.pop()
        if re.search(r"<<-?\s*([A-Za-z_]\w*)\s*$", masked):
            heredoc = re.search(r"<<-?\s*([A-Za-z_]\w*)\s*$", masked).group(1)
    for b in blocks:
        b.end = b.end or len(lines)
    return blocks, cidrs


def _named(item: _Block | _Expr, name: str) -> bool:
    if isinstance(item, _Expr):
        return item.key == name
    return item.words[:1] == [name] or item.words[:2] == ["dynamic", name]


def _resource(chain: list[_Block | _Expr]) -> _Block | None:
    return next((b for b in chain if isinstance(b, _Block) and b.resource_type()), None)


def _resource_label(chain: list[_Block | _Expr]) -> str:
    res = _resource(chain)
    return res.label() if res else "terraform"


def _ports(block: _Block) -> list[str]:
    """Port attribute values of a block and its children (cached: every 0.0.0.0/0 line
    of a resource asks again)."""
    if block.ports is None:
        out = [block.attrs[k][0] for k in ("from_port", "to_port", "port", "ports",
                                           "destination_port_range", "destination_port_ranges")
               if k in block.attrs]
        for child in block.children:
            out += _ports(child)
        block.ports = out
    return block.ports


def _web_only(values: list[str]) -> bool:
    """True when the port values name only 80 and 443 (a public web server)."""
    ports: set[int] = set()
    for v in values:
        for m in re.finditer(r"\"?(\d+)(?:-(\d+))?\"?|(var\.|local\.|\*|\")", v):
            if m.group(3) or len(m.group(1)) > 6 or len(m.group(2) or "") > 6:
                return False  # a variable, or no port number (int() refuses huge ones)
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            if hi - lo > 1000:
                return False
            ports.update(range(lo, hi + 1))
    return bool(ports) and ports <= WEB_PORTS


def _ingress(chain: list[_Block | _Expr]) -> bool:
    """Whether a 0.0.0.0/0 line inside `chain` lets traffic in, beyond the web ports."""
    if any(_named(c, "egress") for c in chain):
        return False
    res = _resource(chain)
    kind = res.resource_type() if res else ""
    if any(isinstance(c, _Block) and c.is_azure_rule() for c in chain):
        return False  # judged per block, by its direction and source prefix
    scope = next((c for c in reversed(chain) if _named(c, "ingress")), None)
    if scope is not None:
        return not (isinstance(scope, _Block) and _web_only(_ports(scope)))
    if res is None:
        return False
    if kind == "aws_security_group_rule" and res.value("type") != "ingress":
        return False
    if kind == "google_compute_firewall" and res.value("direction") == "egress":
        return False
    if kind not in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
                    "google_compute_firewall"):
        return False
    return not _web_only(_ports(res))
