"""The deployment_exposure scanner (UNVAR-98): Compose, Dockerfile, Kubernetes and Terraform
files that decide whether a tool ends up reachable from the internet, running as root, with
a published database port and a literal password. Offline, no external binary."""

import csv
import hashlib
import io
import json
import shutil
import socket
import subprocess
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.artifacts import read_artifact
from unvarnish.config import DEFAULT_SCANNER_OPTIONS, EngagementConfig
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.inventory import census_files
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.deployment_exposure import (
    NAME,
    RULES,
    DeploymentExposureScanner,
    deployment_files,
)
from unvarnish.scanners.effort import EFFORT_RULES
from unvarnish.schemas.finding import Category, Effort, Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings


def _rand(seed: str, n: int = 20) -> str:
    """A credential-shaped value built at run time, so no literal sits in the source."""
    return "Zq" + hashlib.sha256(seed.encode()).hexdigest()[:n]


PG_PASSWORD = _rand("pg")
REDIS_DEFAULT = _rand("redis")
API_KEY = _rand("api-key")
LEGACY_TOKEN = _rand("legacy")
SECRET_VALUES = [PG_PASSWORD, REDIS_DEFAULT, API_KEY, LEGACY_TOKEN]

COMPOSE = f"""\
x-common: &common
  privileged: true
services:
  web:
    image: nginx:1.27
    ports:
      - "8080:80"
      - "127.0.0.1:9090:90"
      - target: 81
        host_ip: 127.0.0.1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
  db:
    image: postgres:16
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: {PG_PASSWORD}
      POSTGRES_PASSWORD_FILE: /run/secrets/db
  cache:
    image: redis:7
    network_mode: host
    <<: *common
    environment:
      - REDIS_PASSWORD=${{REDIS_PASSWORD:-{REDIS_DEFAULT}}}
  internal:
    image: postgres:16
    ports:
      - "127.0.0.1:5433:5432"
      - "${{BIND_ADDR:-127.0.0.1}}:5434:5432"
    expose:
      - "5432"
    environment:
      POSTGRES_PASSWORD: ${{PG_PASSWORD}}
"""

DOCKERFILE = f"""\
FROM node:20 AS build
USER node
ARG NPM_TOKEN
RUN npm ci
FROM node:20-slim
ADD https://downloads.example.test/tool.tar.gz /opt/
ADD --checksum=sha256:0123456789abcdef https://downloads.example.test/x.tgz /opt/
ENV API_KEY={API_KEY}
ENV DB_PASSWORD_FILE=/run/secrets/db
ENV SECRET_TOKEN {LEGACY_TOKEN}
ENV MYSQL_ALLOW_EMPTY_PASSWORD=yes
COPY --from=build /app /app
CMD ["node", "app.js"]
"""

DOCKERFILES_NON_ROOT = {
    # USER root in an earlier stage does not carry into the final one.
    "api/Dockerfile": "FROM python:3.13 AS base\nUSER root\nFROM base\nUSER app\n",
    # The final stage starts from an earlier stage and inherits its user.
    "jobs/Dockerfile": "FROM python:3.13 AS base\nUSER app\nFROM base\nRUN echo hi\n",
    "img/Containerfile": "FROM gcr.io/distroless/static:nonroot\nCOPY app /app\n",
    "uid/Dockerfile": "FROM alpine:3.20\nUSER ${APP_UID}\n",
}

DOCKERFILE_ROOT_AGAIN = "FROM python:3.13\nUSER app\nRUN make\nUSER 0:0\n"

K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: registry.example.test/app:latest
          securityContext:
            privileged: true
        - name: sidecar
          image: registry.example.test/side:1.2.3
          resources:
            limits:
              cpu: 100m
              memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: app
spec:
  ports:
    - port: 80
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  schedule: "0 1 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: busybox
              resources:
                limits:
                  memory: 32Mi
"""

TERRAFORM = """\
resource "aws_security_group" "web" {
  name = "web"
  # cidr_blocks = ["0.0.0.0/0"]
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "web-${var.env}" }
}

resource "aws_security_group_rule" "db" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.web.id
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket              = aws_s3_bucket.assets.id
  block_public_acls   = false
  block_public_policy = true
}

resource "aws_iam_policy" "p" {
  policy = <<EOF
{ "Statement": [{ "Effect": "Allow", "Resource": "*",
  "Condition": { "IpAddress": { "aws:SourceIp": "0.0.0.0/0" } } }] }
EOF
}

resource "aws_iam_policy" "q" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Condition = { IpAddress = { "aws:SourceIp" = "0.0.0.0/0" } }
    }]
  })
}

resource "google_storage_bucket_iam_member" "pub" {
  bucket = "reports"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_firewall" "ssh" {
  name          = "ssh"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "azurerm_storage_container" "c" {
  name                  = "public"
  container_access_type = "blob"
}
"""

FILES: dict[str, str] = {
    "docker-compose.yml": COMPOSE,
    "Dockerfile": DOCKERFILE,
    "worker/Dockerfile": DOCKERFILE_ROOT_AGAIN,
    **DOCKERFILES_NON_ROOT,
    "deploy/k8s/app.yaml": K8S,
    "infra/main.tf": TERRAFORM,
    ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n",
    "app.py": "print('hello')\n",
}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return root


def _ctx(root: Path, **options) -> ScanContext:
    census = Census(tool="t", files=census_files(root), totals=CensusTotals())
    return ScanContext(tool="t", source_root=root, census=census,
                       metrics=Metrics(tool="t", files=[]),
                       git=GitStats(tool="t", available=False),
                       dependencies=Dependencies(tool="t", dependencies=[]),
                       options={**DEFAULT_SCANNER_OPTIONS[NAME], **options})


def _scan(root: Path, files: dict[str, str], **options):
    scanner = DeploymentExposureScanner()
    findings = scanner.run(_ctx(_write(root, files), **options))
    return findings, scanner.notes


def _rule(f) -> str:
    return next(t.split(":", 1)[1] for t in f.tags if t.startswith("group:"))


def _by_rule(findings) -> dict:
    return {_rule(f): f for f in findings}


def _where(finding) -> set[tuple[str, int | None]]:
    return {(e.path, e.line_start) for e in finding.evidence}


def _line(text: str, needle: str, nth: int = 1) -> int:
    hits = [n for n, line in enumerate(text.split("\n"), start=1) if needle in line]
    return hits[nth - 1]


def _no_secret(blob: str) -> bool:
    return not any(v in blob for v in SECRET_VALUES)


# --- criterion 1: one test per rule family ----------------------------------------------------

def test_compose_rules_find_each_exposure_and_skip_loopback(tmp_path: Path):
    findings, _ = _scan(tmp_path, {"docker-compose.yml": COMPOSE})
    rules = _by_rule(findings)
    f = "docker-compose.yml"
    assert set(rules) == {"compose_public_port", "compose_database_port", "compose_privileged",
                          "compose_host_network", "compose_docker_socket",
                          "compose_literal_password", "compose_password_default"}
    assert _where(rules["compose_public_port"]) == {(f, _line(COMPOSE, '"8080:80"'))}
    assert _where(rules["compose_database_port"]) == {(f, _line(COMPOSE, '"5432:5432"'))}
    assert _where(rules["compose_privileged"]) == {(f, _line(COMPOSE, "privileged: true"))}
    assert "cache" in rules["compose_privileged"].evidence[0].note
    assert _where(rules["compose_host_network"]) == {(f, _line(COMPOSE, "network_mode"))}
    assert _where(rules["compose_docker_socket"]) == {(f, _line(COMPOSE, "docker.sock"))}
    assert _where(rules["compose_literal_password"]) == {
        (f, _line(COMPOSE, "POSTGRES_PASSWORD:"))}
    assert _where(rules["compose_password_default"]) == {(f, _line(COMPOSE, "REDIS_PASSWORD="))}
    assert rules["compose_database_port"].severity == Severity.high
    assert "db" in rules["compose_database_port"].evidence[0].note
    secret = rules["compose_literal_password"].evidence[0]
    assert secret.excerpt.startswith("POSTGRES_PASSWORD:") and "redacted" in secret.excerpt
    assert secret.fingerprint
    blob = json.dumps([x.model_dump(mode="json") for x in findings])
    assert _no_secret(blob)


def test_dockerfile_rules_judge_the_final_stage(tmp_path: Path):
    files = {"Dockerfile": DOCKERFILE, "worker/Dockerfile": DOCKERFILE_ROOT_AGAIN,
             **DOCKERFILES_NON_ROOT}
    findings, _ = _scan(tmp_path, files)
    rules = _by_rule(findings)
    assert set(rules) == {"dockerfile_root_user", "dockerfile_add_url",
                          "dockerfile_secret_literal", "dockerfile_secret_build_arg"}
    assert _where(rules["dockerfile_root_user"]) == {
        ("Dockerfile", _line(DOCKERFILE, "FROM node:20-slim")),
        ("worker/Dockerfile", 4)}
    assert _where(rules["dockerfile_add_url"]) == {("Dockerfile", 6)}
    assert _where(rules["dockerfile_secret_literal"]) == {
        ("Dockerfile", _line(DOCKERFILE, "ENV API_KEY")),
        ("Dockerfile", _line(DOCKERFILE, "ENV SECRET_TOKEN"))}
    assert _where(rules["dockerfile_secret_build_arg"]) == {
        ("Dockerfile", _line(DOCKERFILE, "ARG NPM_TOKEN"))}
    excerpts = [e.excerpt for e in rules["dockerfile_secret_literal"].evidence]
    assert all("redacted" in x for x in excerpts), excerpts
    assert _no_secret(json.dumps([x.model_dump(mode="json") for x in findings]))


def test_kubernetes_rules_read_every_workload_document(tmp_path: Path):
    findings, _ = _scan(tmp_path, {"deploy/k8s/app.yaml": K8S})
    rules = _by_rule(findings)
    f = "deploy/k8s/app.yaml"
    assert set(rules) == {"k8s_host_network", "k8s_privileged", "k8s_no_limits",
                          "k8s_latest_image"}
    assert _where(rules["k8s_host_network"]) == {(f, _line(K8S, "hostNetwork"))}
    assert _where(rules["k8s_privileged"]) == {(f, _line(K8S, "privileged: true"))}
    assert _where(rules["k8s_no_limits"]) == {(f, _line(K8S, "- name: app"))}
    assert _where(rules["k8s_latest_image"]) == {(f, _line(K8S, "app:latest")),
                                                 (f, _line(K8S, "image: busybox"))}
    assert rules["k8s_no_limits"].category == Category.reliability


def test_terraform_rules_find_open_ingress_and_public_storage(tmp_path: Path):
    findings, _ = _scan(tmp_path, {"infra/main.tf": TERRAFORM})
    rules = _by_rule(findings)
    f = "infra/main.tf"
    assert set(rules) == {"tf_open_ingress", "tf_public_storage"}
    assert _where(rules["tf_open_ingress"]) == {
        (f, _line(TERRAFORM, 'cidr_blocks = ["0.0.0.0/0"]', 2)),  # the first is a comment
        (f, _line(TERRAFORM, '["::/0"]')),
        (f, _line(TERRAFORM, "source_ranges"))}
    assert _where(rules["tf_public_storage"]) == {
        (f, _line(TERRAFORM, '"public-read"')),
        (f, _line(TERRAFORM, "block_public_acls")),
        (f, _line(TERRAFORM, '"allUsers"')),
        (f, _line(TERRAFORM, "container_access_type"))}
    assert rules["tf_open_ingress"].severity == Severity.high


# --- grouping, redaction, effort ----------------------------------------------------------------

def test_one_finding_per_rule_with_count_effort_and_category(tmp_path: Path):
    findings, _ = _scan(tmp_path, FILES)
    assert len({_rule(f) for f in findings}) == len(findings)
    for f in findings:
        rule = RULES[_rule(f)]
        assert f.scanner == NAME and f.category == rule.category
        assert f.severity == rule.severity
        assert f.effort == EFFORT_RULES[NAME][rule.id][0]
        assert f"{NAME}.{rule.id}" in f.effort_note
        assert f"count:{len(f.evidence)}" in f.tags
        assert f"deployment:{rule.family}" in f.tags
        assert all(e.excerpt for e in f.evidence)


def test_evidence_is_capped_and_counted(tmp_path: Path):
    ports = "".join(f'      - "{8000 + n}:80"\n' for n in range(6))
    compose = f"services:\n  web:\n    image: nginx\n    ports:\n{ports}"
    findings, _ = _scan(tmp_path, {"compose.yaml": compose}, max_evidence=2)
    (f,) = findings
    assert len(f.evidence) == 2 and "count:6" in f.tags
    assert "Showing the first 2 of 6" in f.summary


def test_no_literal_secret_reaches_any_finding_field(tmp_path: Path):
    url_secret = _rand("url")
    files = {**FILES, "compose.prod.yml": (
        "services:\n  app:\n    image: app:1\n    environment:\n"
        f"      DATABASE_URL: postgres://app:{url_secret}@db/app\n"
        f'      JWT_SECRET: "{_rand("jwt")}"\n'
        "    ports:\n"
        f'      - "80:80" # admin password {_rand("comment")}\n')}
    findings, notes = _scan(tmp_path, files)
    blob = json.dumps([f.model_dump(mode="json") for f in findings]) + "\n".join(notes)
    for raw in [*SECRET_VALUES, url_secret, _rand("jwt"), _rand("comment")]:
        assert raw not in blob


def test_every_rule_has_an_effort_band_and_a_title():
    assert set(EFFORT_RULES[NAME]) == set(RULES)
    for rid, rule in RULES.items():
        assert rule.id == rid and rule.family in {"compose", "dockerfile", "kubernetes",
                                                  "terraform"}
        assert rule.title and rule.impact and rule.remediation
        assert isinstance(rule.severity, Severity) and isinstance(rule.category, Category)


# --- criterion 2: table-driven severity, listed, toggles in engagement.yaml ----------------------

def test_scanners_list_shows_the_rule_table(tmp_path: Path, monkeypatch):
    from unvarnish.cli import app

    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(app, ["scanners", "list"], env={"COLUMNS": "400"})
    assert r.exit_code == 0, r.output
    line = next(ln for ln in r.output.splitlines() if f" {NAME} " in ln)
    assert "compose=True" in line and "terraform=True" in line
    for rule in RULES.values():
        row = next(ln for ln in r.output.splitlines() if f" {rule.id} " in ln)
        assert rule.severity.value in row and rule.family in row


def test_toggles_turn_families_and_rules_off(tmp_path: Path):
    findings, notes = _scan(tmp_path, FILES, terraform=False, kubernetes=False,
                            ignore_rules=["dockerfile_add_url"])
    families = {RULES[_rule(f)].family for f in findings}
    assert families == {"compose", "dockerfile"}
    assert "dockerfile_add_url" not in {_rule(f) for f in findings}
    assert any("kubernetes, terraform" in n and "scanners.deployment_exposure" in n
               for n in notes), notes


def test_an_unknown_rule_name_fails_the_scanner(tmp_path: Path):
    with pytest.raises(ValueError, match="ignore_rules"):
        _scan(tmp_path, FILES, ignore_rules=["no_such_rule"])


def test_registered_with_default_options():
    assert NAME in [s.name for s in builtin_scanners()]
    opts = EngagementConfig().scanners[NAME]
    assert opts["compose"] is True and opts["max_evidence"] == 25
    assert opts["ignore_rules"] == [] and opts["include_tests"] is False


# --- criterion 3: offline, no external binary -----------------------------------------------------

def test_scanner_makes_no_network_call_and_runs_no_binary(tmp_path: Path, monkeypatch):
    root = _write(tmp_path, FILES)
    ctx = _ctx(root)
    attempts: list[str] = []

    def refuse(*args, **kwargs):
        attempts.append(repr(args)[:200])
        raise AssertionError("network or process access")

    for target, attr in [(socket.socket, "connect"), (socket.socket, "connect_ex"),
                         (socket, "create_connection"), (socket, "getaddrinfo"),
                         (urllib.request, "urlopen"), (subprocess, "run"),
                         (subprocess, "Popen"), (shutil, "which")]:
        monkeypatch.setattr(target, attr, refuse)
    findings = DeploymentExposureScanner().run(ctx)
    assert attempts == [] and len(findings) >= 10


# --- criterion 5: no deployment files, unparsable files, the inputs hash -------------------------

def test_a_tool_without_deployment_files_gets_one_note_and_no_findings(tmp_path: Path):
    findings, notes = _scan(tmp_path, {"app.py": "print(1)\n",
                                       ".github/workflows/ci.yml": "on: push\n"})
    assert findings == []
    assert len(notes) == 1 and notes[0].startswith(f"{NAME}: not checked")


def test_unparsable_yaml_is_noted_not_fatal(tmp_path: Path):
    helm = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Values.name }}\n  x: [\n"
    findings, notes = _scan(tmp_path, {"chart/templates/pod.yaml": helm,
                                       "docker-compose.yml": "services: [\n"})
    assert findings == []
    (note,) = notes
    assert "could not be parsed" in note and "chart/templates/pod.yaml" in note


def test_deployment_files_by_family(tmp_path: Path):
    root = _write(tmp_path, FILES)
    census = Census(tool="t", files=census_files(root), totals=CensusTotals())
    found = deployment_files(census, DEFAULT_SCANNER_OPTIONS[NAME])
    assert found["compose"] == ["docker-compose.yml"]
    assert "Dockerfile" in found["dockerfile"] and "img/Containerfile" in found["dockerfile"]
    assert found["terraform"] == ["infra/main.tf"]
    # Kubernetes is judged by content: every .yaml/.yml file may hold a manifest.
    assert "deploy/k8s/app.yaml" in found["kubernetes"]


def test_tests_are_skipped_unless_included(tmp_path: Path):
    files = {"tests/fixtures/docker-compose.yml": COMPOSE}
    findings, _ = _scan(tmp_path, files)
    assert findings == []
    findings, _ = _scan(tmp_path, files, include_tests=True)
    assert findings


def _engagement_run(engagement, name, files, phases):
    from unvarnish.phases.ingest import ingest_tool

    src = _write(engagement.root.parent / f"{name}-src", files)
    ingest_tool(engagement, name, str(src), "files")
    ctx = build_context(engagement, name)
    results = PhaseRunner(phases).run(ctx)
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    return ctx


def _scan_phases(**kw):
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.scan import ScanPhase

    return [InventoryPhase(), GitPhase(), ScanPhase(**kw)]


def test_scan_inputs_hash_covers_the_options(engagement):
    from unvarnish.phases.scan import ScanPhase

    ctx = _engagement_run(engagement, "dep", {"Dockerfile": "FROM alpine\n"}, _scan_phases())
    before = ScanPhase().inputs_hash(ctx)
    ctx.config.scanners[NAME]["terraform"] = False
    assert ScanPhase().inputs_hash(ctx) != before
    ctx.config.scanners[NAME]["terraform"] = True
    ctx.config.scanners[NAME]["ignore_rules"] = ["k8s_latest_image"]
    assert ScanPhase().inputs_hash(ctx) != before


# --- criterion 4: findings.md, CSV and SARIF; architecture.md's paragraph -----------------------

def test_findings_reach_the_documents_and_the_exports(engagement):
    from tests.test_scanner_ai_usage import _write_tool_model
    from unvarnish.export.findings_data import csv_text, load_findings, sarif_documents
    from unvarnish.phases.render import RenderPhase

    ctx = _engagement_run(engagement, "dep", FILES, _scan_phases())
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    ours = [f for f in scan.findings if f.scanner == NAME]
    assert NAME in scan.scanners_run and not scan.skipped and ours
    _write_tool_model(ctx)
    assert PhaseRunner([RenderPhase()]).run(ctx)[0].status == PhaseStatus.ok
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    for f in ours:
        assert f.title in doc
    assert "effort: " in doc and _no_secret(doc)

    exported = load_findings(ctx.paths)
    rows = list(csv.DictReader(io.StringIO(csv_text(exported))))
    titles = {r["Summary"] for r in rows}
    assert {f.title for f in ours} <= titles
    db = next(r for r in rows if r["Summary"] == RULES["compose_database_port"].title)
    assert db["Category"] == "security" and db["Path"] == "docker-compose.yml"
    (sarif,) = sarif_documents("dep", exported)
    results = sarif["runs"][0]["results"]
    assert {f.id for f in ours} <= {r["partialFingerprints"]["unvarnishFindingId"]
                                    for r in results}
    text = csv_text(exported) + json.dumps(sarif)
    assert _no_secret(text)

    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    section = arch.split("## 6. Deployment and runtime assumptions", 1)[1].split("\n## ", 1)[0]
    para = next(p for p in section.split("\n\n") if p.startswith("**Deployment exposure.**"))
    assert "1 Compose file" in para and "Terraform" in para
    assert f"{len(ours)} rules matched (" in para and ours[0].title in para
    assert f"and {len(ours) - 3} more" in para  # short: the three most severe by name
    assert _no_secret(arch)


def test_architecture_says_not_analysed_without_deployment_files(engagement):
    from tests.test_scanner_ai_usage import _write_tool_model
    from unvarnish.phases.render import RenderPhase

    ctx = _engagement_run(engagement, "plain", {"app.py": "print(1)\n"}, _scan_phases())
    _write_tool_model(ctx)
    PhaseRunner([RenderPhase()]).run(ctx)
    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    assert ("**Deployment exposure.** No deployment files (Compose, Dockerfile, Kubernetes "
            "manifests, Terraform) were found") in arch
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    not_analysed = doc.split("## Not analysed", 1)[1]
    assert sum(1 for line in not_analysed.splitlines() if line.startswith(f"- {NAME}:")) == 1


def test_architecture_says_not_checked_without_the_scanner(engagement):
    from tests.test_scanner_ai_usage import _write_tool_model
    from unvarnish.phases.render import RenderPhase

    ctx = _engagement_run(engagement, "old", {"Dockerfile": "FROM alpine\n"},
                          _scan_phases(scanners=[]))
    _write_tool_model(ctx)
    PhaseRunner([RenderPhase()]).run(ctx)
    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    assert "**Deployment exposure.** Not checked: the deployment_exposure scanner" in arch


def test_effort_override_applies(tmp_path: Path):
    findings, _ = _scan(tmp_path, {"Dockerfile": "FROM alpine\n"},
                        effort={"dockerfile_root_user": "L"})
    (f,) = findings
    assert f.effort == Effort.L and "scanners.deployment_exposure.effort" in f.effort_note


# --- false positives and the rarer shapes ------------------------------------------------------

def test_compose_port_addresses(tmp_path: Path):
    compose = (
        "services:\n"
        "  a:\n"
        "    image: app:1\n"
        "    ports:\n"
        '      - "[::1]:8080:80"\n'          # loopback, IPv6
        '      - "10.0.0.5:8081:80"\n'       # one interface, not all
        '      - "${HOST_IP}:8082:80"\n'     # set at deploy time: cannot tell
        '      - "0.0.0.0:8083:80/tcp"\n'    # all interfaces
        '      - "${WEB_PORT:-8084}:80"\n'   # no address: all interfaces
        "      - 9000\n"                     # a random host port, all interfaces
        "      - target: 3306\n"             # long syntax with no host_ip: all interfaces
        "        published: 3306\n"
        "      - [1, 2]\n"                   # not a port: ignored
        "    volumes:\n"
        "      - type: bind\n"
        "        source: /run/podman/podman.sock\n"
        "        target: /var/run/docker.sock\n"
        "      - ./data:/data\n")
    findings, _ = _scan(tmp_path, {"compose.yaml": compose})
    rules = _by_rule(findings)
    assert {line for _, line in _where(rules["compose_public_port"])} == {
        _line(compose, "0.0.0.0:8083"), _line(compose, "WEB_PORT"), _line(compose, "- 9000")}
    assert _where(rules["compose_database_port"]) == {("compose.yaml",
                                                       _line(compose, "target: 3306"))}
    assert _where(rules["compose_docker_socket"]) == {("compose.yaml",
                                                       _line(compose, "type: bind"))}


def test_compose_files_without_services_and_odd_environments(tmp_path: Path):
    compose = (
        "version: '3'\n"
        "services:\n"
        "  a:\n"
        "    image: app:1\n"
        "    environment:\n"
        "      DB_PASSWORD:\n"                # passed through from the host
        "      SESSION_SECRET: 'true'\n"      # a switch, not a value
        "      API_TOKEN_URL: https://auth.example.test/token\n"
        "      DATABASE_URL: postgres://app:${DB_PW}@db/app\n"
        "  b: just-a-string\n")
    findings, notes = _scan(tmp_path, {"docker-compose.override.yml": compose,
                                       "compose-empty.yml": "x: 1\n"})
    assert findings == [] and notes == []


def test_kubernetes_limit_range_lists_and_templated_images(tmp_path: Path):
    manifest = (
        "apiVersion: v1\n"
        "kind: List\n"
        "items:\n"
        "  - apiVersion: v1\n"
        "    kind: Pod\n"
        "    metadata: {name: p}\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: c\n"
        "          image: registry.example.test/app@sha256:" + "a" * 64 + "\n"
        "        - name: d\n"
        "          image: localhost:5000/tool\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: LimitRange\n"
        "metadata: {name: defaults}\n")
    findings, _ = _scan(tmp_path, {"k8s/pod.yml": manifest})
    rules = _by_rule(findings)
    assert set(rules) == {"k8s_latest_image"}  # the LimitRange gives containers limits
    assert _where(rules["k8s_latest_image"]) == {("k8s/pod.yml", 12)}
    assert "no tag" in rules["k8s_latest_image"].evidence[0].note


def test_dockerfile_shapes(tmp_path: Path):
    dockerfile = (
        "# syntax=docker/dockerfile:1\n"
        "FROM --platform=$BUILDPLATFORM golang:1.23 AS build\n"
        "RUN <<EOF\n"
        "ENV FAKE_PASSWORD=" + _rand("heredoc") + "\n"
        "EOF\n"
        "ARG GITHUB_TOKEN=" + _rand("arg-default") + "\n"
        "ENV A=1 \\\n"
        "    # a comment inside a continuation\n"
        "    SIGNING_KEY=${SIGNING_KEY} B=2\n"
        'ADD ["https://downloads.example.test/a.tgz", "/opt/"]\n'
        "ADD ./local.tgz /opt/\n"
        "ENV CONN=postgres://svc:" + _rand("conn") + "@db:5432/app\n"
        "ENV TOKEN_TTL=3600 EMPTY_SECRET=\n"
        "FROM build\n"
        "USER root\n")
    findings, _ = _scan(tmp_path, {"build/app.dockerfile": dockerfile,
                                   "Dockerfile.dockerignore": "*.md\n"})
    rules = _by_rule(findings)
    f = "build/app.dockerfile"
    assert _where(rules["dockerfile_secret_literal"]) == {(f, 6), (f, 12)}
    assert _where(rules["dockerfile_secret_build_arg"]) == {(f, 9)}
    assert _where(rules["dockerfile_add_url"]) == {(f, 10)}
    assert _where(rules["dockerfile_root_user"]) == {(f, 15)}
    blob = json.dumps([x.model_dump(mode="json") for x in findings])
    for raw in (_rand("heredoc"), _rand("arg-default"), _rand("conn")):
        assert raw not in blob


def test_dockerfile_inheriting_root_from_an_earlier_stage(tmp_path: Path):
    findings, _ = _scan(tmp_path, {"Dockerfile": "FROM alpine AS base\nUSER root\n"
                                                 "FROM base\nRUN true\n"})
    (f,) = findings
    assert _where(f) == {("Dockerfile", 3)} and "inherits" in f.evidence[0].note


TERRAFORM_MORE = """\
resource "aws_security_group" "dyn" {
  dynamic "ingress" {
    for_each = var.ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  ingress = [{
    cidr_blocks = ["0.0.0.0/0"]
  }]
}

resource "aws_vpc_security_group_ingress_rule" "web" {
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 443
  to_port     = 443
}

resource "aws_vpc_security_group_ingress_rule" "rdp" {
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 3389
  to_port     = 3389
}

resource "aws_security_group_rule" "out" {
  type        = "egress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "out" {
  direction          = "EGRESS"
  destination_ranges = ["0.0.0.0/0"]
}

resource "aws_route" "default" {
  destination_cidr_block = "0.0.0.0/0"
}

resource "azurerm_network_security_group" "nsg" {
  security_rule {
    name                       = "ssh"
    direction                  = "Inbound"
    access                     = "Allow"
    destination_port_range     = "22"
    source_address_prefix      = "*"
  }
  security_rule {
    name                       = "https"
    direction                  = "Inbound"
    access                     = "Allow"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
  }
}

/* resource "aws_s3_bucket_acl" "old" {
  acl = "public-read"
} */

resource "aws_s3_bucket_policy" "pub" {
  policy = <<POLICY
{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}
POLICY
}

resource "aws_s3_bucket_policy" "vpce" {
  policy = jsonencode({
    Statement = [{ Principal = "*", Condition = { StringEquals = { "aws:SourceVpce" = "x" } } }]
  })
}

resource "azurerm_storage_account" "sa" {
  allow_nested_items_to_be_public = true # "0.0.0.0/0" in a comment
}

resource "google_storage_bucket_acl" "acl" {
  predefined_acl = "publicRead"
}
"""


def test_terraform_shapes(tmp_path: Path):
    findings, _ = _scan(tmp_path, {"infra/more.tf": TERRAFORM_MORE})
    rules = _by_rule(findings)
    f = "infra/more.tf"
    assert _where(rules["tf_open_ingress"]) == {
        (f, 7), (f, 11), (f, _line(TERRAFORM_MORE, "cidr_ipv4", 2)),
        (f, _line(TERRAFORM_MORE, 'source_address_prefix      = "*"'))}
    assert _where(rules["tf_public_storage"]) == {
        (f, _line(TERRAFORM_MORE, '"Principal": "*"')),
        (f, _line(TERRAFORM_MORE, "allow_nested_items_to_be_public")),
        (f, _line(TERRAFORM_MORE, "predefined_acl"))}


def test_unreadable_files_are_skipped(tmp_path: Path):
    root = _write(tmp_path, {"Dockerfile": "FROM alpine\n"})
    ctx = _ctx(root)
    (root / "Dockerfile").unlink()
    scanner = DeploymentExposureScanner()
    assert scanner.run(ctx) == []
    assert scanner.coverage["dockerfile"] == 0


def test_many_unparsable_files_are_counted_in_one_note(tmp_path: Path):
    bad = "apiVersion: v1\nkind: Pod\nx: [\n"
    _, notes = _scan(tmp_path, {f"t/{n}.yaml": bad for n in range(7)})
    (note,) = notes
    assert "7 files could not be parsed" in note and "and 2 more" in note


def test_malformed_lines_never_raise(tmp_path: Path):
    files = {
        "Dockerfile": ('ADD ["https://downloads.example.test/a.tgz", \n'
                       "ARG\n"
                       "ENV QUOTE_SECRET=\"unterminated\n"
                       "ENV\n"),
        "net.tf": ('resource "azurerm_network_security_rule" "r" {\n'
                   '  direction             = "Inbound"\n'
                   '  access                = "Allow"\n'
                   '  description           = "say \\"hi\\" // not a comment"\n'
                   '  source_address_prefix = "0.0.0.0/0"\n'
                   "}\n"
                   'resource "aws_security_group" "x" {\n'
                   "  ingress {\n"
                   "    from_port   = 8000 // inclusive\n"
                   "    to_port     = 9999\n"
                   '    cidr_blocks = ["0.0.0.0/0"]\n'
                   "  }\n"
                   "}\n"
                   'ingress_note = "0.0.0.0/0"\n'),
    }
    findings, _ = _scan(tmp_path, files)
    rules = _by_rule(findings)
    assert _where(rules["tf_open_ingress"]) == {("net.tf", 5), ("net.tf", 11)}
    assert set(rules) == {"tf_open_ingress", "dockerfile_secret_literal"}  # no FROM: no stage


def test_architecture_says_what_was_checked_when_nothing_matched(engagement):
    from tests.test_scanner_ai_usage import _write_tool_model
    from unvarnish.phases.render import RenderPhase

    ctx = _engagement_run(engagement, "clean", DOCKERFILES_NON_ROOT, _scan_phases())
    _write_tool_model(ctx)
    PhaseRunner([RenderPhase()]).run(ctx)
    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    assert ("**Deployment exposure.** The deployment files (4 Dockerfiles) were checked "
            "offline: no port published on all interfaces") in arch


# --- review fixes: redaction across one line, and hostile input -------------------------------

def test_no_secret_leaks_from_a_line_holding_several(tmp_path: Path):
    a, b, c, d, e, g = (_rand(s) for s in ("a", "b", "c", "d", "e", "g"))
    files = {
        # Flow style: two credentials and a published port on one line.
        "docker-compose.yml": (
            "services:\n"
            f"  db: {{image: postgres, ports: ['5432:5432'], "
            f"environment: {{DB_PASS: {a}, API_TOKEN: {b}}}}}\n"),
        # Two ENV pairs on one line; a secret name the generic pattern misses, with a `$`.
        "Dockerfile": (f"FROM alpine\nUSER app\nENV DB_PASS={c} API_TOKEN={d}\n"
                       f"ENV AUTH_KEY=${{AUTH_KEY:-{e}}}\n"
                       f"ADD https://{g}@github.com/o/r/archive/x.tgz /opt/\n"),
        # A one-line container with a secret env value next to a flagged image.
        "k.yaml": ("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n"
                   f"  containers: [{{name: a, image: x:latest, "
                   f"env: [{{name: DB_PASSWORD, value: {_rand('k')}}}]}}]\n"),
    }
    findings, notes = _scan(tmp_path, files)
    rules = _by_rule(findings)
    assert {"compose_database_port", "compose_literal_password", "dockerfile_secret_literal",
            "dockerfile_secret_build_arg", "dockerfile_add_url",
            "k8s_latest_image"} <= set(rules)
    blob = json.dumps([f.model_dump(mode="json") for f in findings]) + "\n".join(notes)
    for raw in (a, b, c, d, e, g, _rand("k")):
        assert raw not in blob


def test_alias_and_merge_key_bombs_finish_quickly(tmp_path: Path):
    import time

    bomb = ["x-l0: &l0 {privileged: true}"]
    for i in range(1, 8):
        bomb.append(f"x-l{i}: &l{i}\n  <<: [" + ", ".join([f"*l{i - 1}"] * 9) + "]")
    bomb.append("services:\n  a:\n    <<: *l7\n    image: x\n")
    big = "x-big: &big\n" + "".join(f"  k{i}: v\n" for i in range(3000))
    many = big + "services:\n" + "".join(f"  s{i}:\n    <<: *big\n" for i in range(3000))
    start = time.monotonic()
    findings, notes = _scan(tmp_path, {"docker-compose.yml": "\n".join(bomb) + "\n",
                                       "compose.yaml": many})
    assert time.monotonic() - start < 10
    assert "compose_privileged" in _by_rule(findings)  # each anchor is read once
    assert any("could not be parsed" in n and "compose.yaml" in n for n in notes)


def test_long_lines_and_blank_runs_stay_fast(tmp_path: Path):
    import time

    token = _rand("long")
    files = {
        "notes.yaml": "\n" * 200_000 + "a: 1\n",  # no apiVersion: never parsed
        "Dockerfile": f"FROM a\nUSER b\nENV X_TOKEN={token}{'a' * 300_000}\n",
        "compose.yaml": "services:\n  a: {ports: ['80:80'], x: " + "a" * 300_000 + "}\n",
    }
    start = time.monotonic()
    findings, _ = _scan(tmp_path, files)
    assert time.monotonic() - start < 10
    rules = _by_rule(findings)
    assert {"dockerfile_secret_literal", "compose_public_port"} <= set(rules)
    assert all(len(e.excerpt or "") <= 200 for f in findings for e in f.evidence)
    assert token not in json.dumps([f.model_dump(mode="json") for f in findings])


def test_counts_and_sizes_are_not_secrets(tmp_path: Path):
    findings, _ = _scan(tmp_path, {"Dockerfile": (
        "FROM a\nUSER b\nENV TOKEN_LIMIT=1000 PASSWORD_HASH_ROUNDS=12 SECRET_SIZE=32\n")})
    assert "dockerfile_secret_literal" not in _by_rule(findings)


def test_architecture_says_not_checked_when_every_family_is_off():
    from types import SimpleNamespace

    from unvarnish.render.architecture import deployment_exposure

    scan = ScannerFindings(tool="t", scanners_run=[NAME], coverage={NAME: {}})
    assert deployment_exposure(SimpleNamespace(scan=scan)).startswith(
        "Not checked: every file family is turned off")
