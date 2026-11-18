import base64
import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.artifacts import read_artifact
from unvarnish.config import DEFAULT_SCANNER_OPTIONS
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.inventory import census_files
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.client_exposure import (
    ClientExposureScanner,
    exposure_counts,
    route_hints,
)
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings

MIGRATION = "supabase/migrations/001_init.sql"
SERVICE = "Supabase service-role key in client code"
ANON_OPEN = "Supabase anon key in client code with tables open to it"
FIREBASE = "Firebase web config in client code"
PUBLIC_VAR = "Secret-named variable exposed to the browser"
NO_RLS = "Table without row level security"
RLS_OFF = "Row level security disabled"
OPEN_POLICY = "Policy open to every row"
NO_CHECK = "Insert or update policy without WITH CHECK"
CORS = "CORS allows any origin with credentials"
AGENT = "Credentials in agent configuration file"
DOTENV = "Credentials in committed .env file"
ROUTES = "Route handlers with no authentication check nearby"


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _jwt(role: str) -> str:
    """A Supabase-shaped JWT built at run time, so no token sits in the source."""
    sig = base64.urlsafe_b64encode(hashlib.sha256(role.encode()).digest()).rstrip(b"=")
    return (f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}."
            f"{_b64({'iss': 'supabase', 'ref': 'abcdefgh', 'role': role})}.{sig.decode()}")


def _rand(seed: str, n: int = 24) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n]


SERVICE_JWT = _jwt("service_role")
ANON_JWT = _jwt("anon")
SB_SECRET = "sb_secret_" + _rand("sb-secret", 32)
FIREBASE_KEY = "AIza" + _rand("firebase", 35)
MCP_TOKEN = "tok_" + _rand("mcp")
BEARER = _rand("bearer", 32)
DB_PASSWORD = _rand("dbpass")
STRIPE = _rand("stripe")
RAW_VALUES = [SERVICE_JWT, ANON_JWT, SB_SECRET, FIREBASE_KEY, MCP_TOKEN, BEARER, DB_PASSWORD,
              STRIPE]

INSECURE: dict[str, str] = {
    "src/lib/supabase.ts": (
        'import { createClient } from "@supabase/supabase-js";\n'
        'const url = "https://abcdefgh.supabase.co";\n'
        f'export const admin = createClient(url, "{SERVICE_JWT}");\n'
        f'export const pub = createClient(url, "{ANON_JWT}");\n'
    ),
    "dist/assets/app.js": f'var k="{SB_SECRET}";fetch(u,{{headers:{{apikey:k}}}});\n',
    "src/__tests__/client.test.ts": f'const key = "{SERVICE_JWT}";\n',  # tests: skipped
    "public/firebase.js": (
        "const firebaseConfig = {\n"
        f'  apiKey: "{FIREBASE_KEY}",\n'
        '  authDomain: "demo-app.firebaseapp.com",\n'
        '  projectId: "demo-app",\n'
        "};\n"
    ),
    "src/config.ts": (
        "export const openai = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n"
        "export const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n"
        "export const stripe = import.meta.env.VITE_STRIPE_SECRET;\n"
        "export const keyboard = process.env.NEXT_PUBLIC_KEYBOARD_LAYOUT;\n"
    ),
    MIGRATION: (
        "create table public.profiles (id uuid primary key, user_id uuid);\n"
        "alter table public.profiles enable row level security;\n"
        "create table orders (id uuid primary key, total int);\n"
        'create table "public"."audit_log" (id bigint);\n'
        "alter table audit_log disable row level security;\n"
        'create policy "anyone" on public.profiles for delete using (true);\n'
        'create policy "own insert" on public.profiles for insert to authenticated;\n'
        "-- create table commented_out (id int);\n"
        "create table private.secrets_store (id int);\n"
    ),
    "server.js": (
        'const express = require("express");\n'
        'const cors = require("cors");\n'
        "const app = express();\n"
        'app.use(cors({ origin: "*", credentials: true }));\n'
        'app.get("/api/orders", async (req, res) => {\n'
        "  res.json(await db.orders.findAll());\n"
        "});\n"
        'app.get("/health", (req, res) => res.send("ok"));\n'
        'const env = app.get("env");\n'
    ),
    "api/main.py": (
        "from fastapi import FastAPI\n"
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app = FastAPI()\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["*"],\n'
        "                   allow_credentials=True)\n"
        '@app.get("/items")\n'
        "def items():\n"
        "    return db.all()\n"
    ),
    "app/api/users/route.ts": (
        "export async function GET() {\n"
        "  return Response.json(await db.users.findMany());\n"
        "}\n"
    ),
    ".mcp.json": (
        "{\n"
        '  "mcpServers": {\n'
        '    "github": {\n'
        '      "command": "npx",\n'
        '      "env": {\n'
        f'        "GITHUB_TOKEN": "{MCP_TOKEN}",\n'
        '        "LOG_LEVEL": "debug"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
    ),
    ".cursor/mcp.json": (
        '{"mcpServers": {"x": {"url": "https://mcp.acme.test",\n'
        f'  "headers": {{"Authorization": "Bearer {BEARER}", "X-Api-Key": "${{env:KEY}}"}}}}}}}}\n'
    ),
    ".env.production": (
        "# production\n"
        f"DATABASE_PASSWORD={DB_PASSWORD}\n"
        "PORT=3000\n"
        f'STRIPE_SECRET_KEY="{STRIPE}"\n'
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=public-anon-value-123\n"
    ),
    ".env.example": f"DATABASE_PASSWORD={DB_PASSWORD}\n",
}

EXPECTED = {
    (SERVICE, "dist/assets/app.js", 1),
    (SERVICE, "src/lib/supabase.ts", 3),
    (ANON_OPEN, "src/lib/supabase.ts", 4),
    (FIREBASE, "public/firebase.js", 2),
    (PUBLIC_VAR, "src/config.ts", 1),
    (PUBLIC_VAR, "src/config.ts", 3),
    (NO_RLS, MIGRATION, 3),
    (RLS_OFF, MIGRATION, 5),
    (OPEN_POLICY, MIGRATION, 6),
    (NO_CHECK, MIGRATION, 7),
    (CORS, "api/main.py", 4),
    (CORS, "server.js", 4),
    (AGENT, ".cursor/mcp.json", 2),
    (AGENT, ".mcp.json", 6),
    (DOTENV, ".env.production", 2),
    (ROUTES, "api/main.py", 6),
}

CLEAN: dict[str, str] = {
    "src/lib/supabase.ts": (
        'import { createClient } from "@supabase/supabase-js";\n'
        f'export const pub = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, "{ANON_JWT}");\n'
        "export const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n"
    ),
    "src/config.ts": (
        "export const stripe = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\n"
        "export const site = process.env.NEXT_PUBLIC_SITE_URL;\n"
    ),
    "src/server/admin.ts": f'export const admin = createClient(url, "{SERVICE_JWT}");\n',
    "server/admin.ts": (
        f'const fallback = "{SERVICE_JWT}";\n'
        "export const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n"
    ),
    MIGRATION: (
        "create table public.profiles (id uuid primary key, user_id uuid);\n"
        "alter table public.profiles enable row level security;\n"
        "create table if not exists orders (id uuid primary key, user_id uuid);\n"
        "alter table only orders enable row level security;\n"
        'create policy "own rows" on orders for select using (auth.uid() = user_id);\n'
        'create policy "own insert" on orders for insert\n'
        "  with check (auth.uid() = user_id);\n"
        'create policy "own update" on public.profiles for update\n'
        "  using (auth.uid() = user_id) with check (auth.uid() = user_id);\n"
        "create table private.jobs (id int);\n"
    ),
    "server.js": (
        'const app = require("express")();\n'
        'app.use(cors({ origin: "https://app.acme.test", credentials: true }));\n'
        'app.get("/api/me", requireAuth, (req, res) => res.json(req.user));\n'
        'app.get("/health", (req, res) => res.send("ok"));\n'
        'const env = app.get("env");\n'
    ),
    "api/main.py": (
        'app.add_middleware(CORSMiddleware, allow_origins=["https://app.acme.test"],\n'
        "                   allow_credentials=True)\n"
        '@app.get("/me")\n'
        "def me(user=Depends(get_current_user)):\n"
        "    return user\n"
    ),
    "app/api/users/route.ts": (
        "export async function GET() {\n"
        "  const session = await auth();\n"
        "  return Response.json(session.user);\n"
        "}\n"
    ),
    ".mcp.json": '{"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}}}}\n',
    ".env.example": f"DATABASE_PASSWORD={DB_PASSWORD}\nSTRIPE_SECRET_KEY={STRIPE}\n",
    ".env.production": "PORT=3000\nNEXT_PUBLIC_SITE_URL=https://app.acme.test\n",
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
                       options={**DEFAULT_SCANNER_OPTIONS["client_exposure"], **options})


def _run(root: Path, files: dict[str, str], **options):
    return ClientExposureScanner().run(_ctx(_write(root, files), **options))


def _located(findings) -> set[tuple[str, str, int | None]]:
    return {(f.title, f.evidence[0].path, f.evidence[0].line_start) for f in findings}


def test_each_pattern_yields_exactly_the_expected_findings(tmp_path: Path):
    findings = _run(tmp_path, INSECURE)
    assert _located(findings) == EXPECTED
    assert len(findings) == len(EXPECTED)
    by_title = {}
    for f in findings:
        by_title.setdefault(f.title, []).append(f)
    assert all(f.scanner == "client_exposure" for f in findings)
    assert {f.severity for f in by_title[SERVICE]} == {Severity.critical}
    assert by_title[ANON_OPEN][0].severity == Severity.critical
    assert "orders" in by_title[ANON_OPEN][0].summary
    assert by_title[FIREBASE][0].severity == Severity.low
    assert {f.severity for f in by_title[PUBLIC_VAR]} == {Severity.high}
    assert "NEXT_PUBLIC_OPENAI_API_KEY" in {f.summary.split("`")[1] for f in by_title[PUBLIC_VAR]}
    dotenv = by_title[DOTENV][0]
    assert [(e.path, e.line_start) for e in dotenv.evidence] == [
        (".env.production", 2), (".env.production", 4)]
    routes = by_title[ROUTES][0]
    assert routes.severity == Severity.medium
    assert [(e.path, e.line_start) for e in routes.evidence] == [
        ("api/main.py", 6), ("app/api/users/route.ts", 1), ("server.js", 5)]
    assert "3 route handlers" in routes.summary


def test_rls_enabled_and_server_only_keys_yield_nothing(tmp_path: Path):
    assert _run(tmp_path, CLEAN) == []


def test_values_are_redacted_and_fingerprints_stable(tmp_path: Path):
    first = _run(tmp_path / "a", INSECURE)
    second = _run(tmp_path / "b", INSECURE)
    blob = json.dumps([f.model_dump(mode="json") for f in first])
    for raw in RAW_VALUES:
        assert raw not in blob
    assert "[redacted" in blob
    assert [f.id for f in first] == [f.id for f in second]
    fps = [e.fingerprint for f in first for e in f.evidence]
    assert fps == [e.fingerprint for f in second for e in f.evidence]
    service = next(f for f in first if f.evidence[0].path == "src/lib/supabase.ts"
                   and f.title == SERVICE)
    assert service.evidence[0].fingerprint and len(service.evidence[0].fingerprint) == 12


def test_counts_credentials_and_open_tables(tmp_path: Path):
    findings = _run(tmp_path, INSECURE)
    # 2 service-role keys, 2 public variables, 2 agent-config values, 2 .env values
    assert exposure_counts(findings) == {"credentials": 8, "open_tables": 3}
    assert exposure_counts([]) == {"credentials": 0, "open_tables": 0}


def test_client_roots_and_thresholds_are_configurable(tmp_path: Path):
    files = {"web/app.ts": f'const k = "{SERVICE_JWT}";\n',
             "src/app.ts": f'const k = "{SERVICE_JWT}";\n'}
    found = _run(tmp_path / "roots", files, client_roots=["web/"])
    assert _located(found) == {(SERVICE, "web/app.ts", 1)}

    route = ('app.get("/api/orders", (req, res) => {\n' + "  x();\n" * 3
             + "  requireAuth(req);\n});\n")
    assert _run(tmp_path / "near", {"server.js": route}) == []
    narrow = _run(tmp_path / "narrow", {"server.js": route}, auth_window=2)
    assert _located(narrow) == {(ROUTES, "server.js", 1)}

    many = "".join(f'app.get("/api/r{i}", (req, res) => res.json(db.all()));\n'
                   for i in range(5))
    capped = _run(tmp_path / "cap", {"server.js": many}, max_evidence=2)
    assert len(capped[0].evidence) == 2 and "5 route handlers" in capped[0].summary

    allowed = _run(tmp_path / "allow", {"src/c.ts": "x = process.env.VITE_MAPS_TOKEN;\n"},
                   public_names=["MAPS_TOKEN"])
    assert allowed == []

    tests = _run(tmp_path / "tests", {"src/__tests__/a.test.ts": f'k = "{SERVICE_JWT}";\n'},
                 include_tests=True)
    assert _located(tests) == {(SERVICE, "src/__tests__/a.test.ts", 1)}


def test_edge_cases(tmp_path: Path):
    files = {
        # a JWT whose payload is not JSON, and a non-Supabase role, are not findings
        "src/a.ts": 'const t = "eyJhbGciOiJIUzI1NiJ9.eyJub3QganNvbg.c2lnbmF0dXJlc2ln";\n'
                    f'const u = "{_jwt("authenticated")}";\n',
        # a dropped table is not open; disable RLS outside public still counts
        "db/schema.sql": "create table tmp_import (id int);\ndrop table tmp_import;\n"
                         "alter table storage.objects disable row level security;\n"
                         'create policy "r" on public.items for select using (true);\n'
                         "create table public.items (id int);\n"
                         "alter table public.items enable row level security;\n",
        # access-control headers set by hand, and a vercel.json headers block
        "handler.js": 'res.setHeader("Access-Control-Allow-Origin", "*");\n'
                      'res.setHeader("Access-Control-Allow-Credentials", "true");\n',
        "vercel.json": '{"headers": [{"key": "Access-Control-Allow-Origin", "value": "*"},\n'
                       '{"key": "Access-Control-Allow-Credentials", "value": "true"}]}\n',
        # unparseable agent config still scanned line by line
        "claude_desktop_config.json": f'{{"env": {{"API_KEY": "{MCP_TOKEN}"\n',
        # a plain .env counts; .env.local.example does not
        ".env": f"export SERVICE_TOKEN='{STRIPE}' # comment\n",
        ".env.local.example": f"SERVICE_TOKEN={STRIPE}\n",
        # a binary-looking file is skipped
        "src/blob.js": "\0" * 10,
    }
    found = _run(tmp_path, files)
    located = _located(found)
    assert located == {
        (RLS_OFF, "db/schema.sql", 3),
        ("Policy readable by every row", "db/schema.sql", 4),
        (CORS, "handler.js", 1),
        (CORS, "vercel.json", 1),
        (AGENT, "claude_desktop_config.json", 1),
        (DOTENV, ".env", 1),
    }
    policy = next(f for f in found if f.title == "Policy readable by every row")
    assert policy.severity == Severity.medium
    assert exposure_counts(found) == {"credentials": 2, "open_tables": 1}


def test_registered_with_default_options():
    assert "client_exposure" in [s.name for s in builtin_scanners()]
    opts = DEFAULT_SCANNER_OPTIONS["client_exposure"]
    assert opts["client_roots"] == ["src/", "public/", "dist/"]
    assert ".svelte" in opts["client_extensions"] and opts["auth_window"] > 0


def test_scanners_list_shows_client_exposure(tmp_path: Path, monkeypatch):
    from unvarnish.cli import app

    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scanners", "list"], env={"COLUMNS": "400"})
    assert result.exit_code == 0, result.output
    assert "client_exposure" in result.output and "client_roots" in result.output


def _engagement_run(engagement, files, phases):
    from unvarnish.phases.ingest import ingest_tool

    src = _write(engagement.root.parent / "client-src", files)
    ingest_tool(engagement, "web", str(src), "files")
    ctx = build_context(engagement, "web")
    results = PhaseRunner(phases).run(ctx)
    return ctx, results


def test_runs_offline_without_a_model_and_shows_in_the_documents(engagement):
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    assert engagement.config.models.default is None  # no model configured
    ctx, results = _engagement_run(engagement, INSECURE,
                                   [InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()])
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    assert "client_exposure" in scan.scanners_run and not scan.skipped
    assert _located([f for f in scan.findings if f.scanner == "client_exposure"]) == EXPECTED
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert "| Client-exposed credentials / open tables | 8 / 3 |" in doc
    for raw in RAW_VALUES:
        assert raw not in doc


def test_findings_doc_says_not_checked_without_the_scanner(engagement):
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    ctx, _ = _engagement_run(engagement, {"a.py": "x = 1\n"},
                             [InventoryPhase(), GitPhase(), ScanPhase(scanners=[]),
                              RenderPhase()])
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert "| Client-exposed credentials / open tables | not checked |" in doc


def test_comparison_risk_table_gains_the_count(engagement):
    from unvarnish.analysis.comparison import risk_row
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.render.comparison import _risk_measures
    from unvarnish.schemas.comparison import Comparison

    ctx, _ = _engagement_run(engagement, INSECURE, [InventoryPhase(), GitPhase(), ScanPhase()])
    p = ctx.paths
    scan = read_artifact(p.scanner_findings, ScannerFindings).data
    row = risk_row("web", read_artifact(p.census, Census).data,
                   read_artifact(p.metrics, Metrics).data, read_artifact(p.git, GitStats).data,
                   scan, None, read_artifact(p.dependencies, Dependencies).data)
    assert row.client_exposed_credentials == 8 and row.open_tables == 3
    unchecked = row.model_copy(update={"tool": "old", "client_exposed_credentials": None,
                                       "open_tables": None})
    cmp = Comparison.model_construct(risk_table=[row, unchecked])
    measures = {m["label"]: m["cells"] for m in _risk_measures(cmp)}
    assert measures["Client-exposed credentials / open tables"] == ["8 / 3", "not checked"]


def test_route_handlers_reach_extraction_as_context(engagement):
    from tests.test_render_documents import _stub
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.phases.extract import ExtractPhase
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.phases.split import SplitPhase

    stub = _stub()
    files = {"server.js": INSECURE["server.js"], "lib/util.js": "export const a = 1;\n"}
    ctx, results = _engagement_run(engagement, files, [InventoryPhase(), GitPhase(),
                                                       ScanPhase(), SplitPhase()])
    ctx.budget = BudgetTracker(None)
    assert route_hints(ctx.paths.scanner_findings) == {"server.js": [5]}
    assert PhaseRunner([ExtractPhase(backend=stub)]).run(ctx)[0].status == PhaseStatus.ok
    msgs = [r.messages[-1].content for r in stub.requests if r.schema_name == "UnitExtraction"]
    server = [m for m in msgs if "File: server.js" in m]
    other = [m for m in msgs if "File: lib/util.js" in m]
    assert server and any("Scanner note" in m and "line 5" in m for m in server)
    assert other and not any("Scanner note" in m for m in other)
    assert route_hints(ctx.paths.root / "missing.json") == {}


def test_minified_bundles_publishable_keys_and_url_values(tmp_path: Path):
    publishable = "sb_publishable_" + _rand("publishable", 32)
    bundle = "var a=1;" * 100 + f'createClient(u,"{SERVICE_JWT}");' + "var b=2;" * 100
    files = {
        "dist/index.js": bundle + "\n",
        "src/client.ts": f'const k = "{publishable}";\n',
        "db/init.sql": "create table notes (id int);\n",
        ".env.production": "TOKEN_URL=https://login.acme.test/oauth/token\n",
    }
    found = _run(tmp_path, files)
    assert _located(found) == {(SERVICE, "dist/index.js", 1), (NO_RLS, "db/init.sql", 1),
                               (ANON_OPEN, "src/client.ts", 1)}
    service = next(f for f in found if f.title == SERVICE)
    assert len(service.evidence[0].excerpt) <= 200
    assert "[redacted" in service.evidence[0].excerpt
    blob = json.dumps([f.model_dump(mode="json") for f in found])
    assert SERVICE_JWT not in blob and publishable not in blob


def test_route_hints_ignore_an_unreadable_artifact(tmp_path: Path):
    bad = tmp_path / "scanner-findings.json"
    bad.write_text("{not json", encoding="utf-8")
    assert route_hints(bad) == {}


def test_dry_run_keeps_units_with_scanner_notes(engagement):
    from tests.test_render_documents import _stub
    from unvarnish.config import ModelRef
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.model.estimate import extracted_units
    from unvarnish.phases.extract import ExtractPhase
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.phases.split import SplitPhase
    from unvarnish.schemas.analysis import UnitsIndex

    ctx, _ = _engagement_run(engagement, {"server.js": INSECURE["server.js"]},
                             [InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase()])
    ctx.budget = BudgetTracker(None)
    stub = _stub()
    engagement.config.models.default = ModelRef(backend=stub.name, model=stub.model)
    assert PhaseRunner([ExtractPhase(backend=stub)]).run(ctx)[0].status == PhaseStatus.ok
    index = read_artifact(ctx.paths.units_index, UnitsIndex).data
    assert extracted_units(ctx, index) == {u.id for u in index.units}


def test_every_key_on_a_shared_line_is_redacted(tmp_path: Path):
    """A minified line holding several values: each finding's excerpt hides all of them."""
    second = "sk_" + _rand("second-secret")
    files = {
        "src/client.ts": f'createClient(u,"{SERVICE_JWT}");createClient(u,"{ANON_JWT}");\n',
        "supabase/migrations/1.sql": "create table notes (id int);\n",
        "src/env.ts": (f'x={{NEXT_PUBLIC_A_SECRET:"{STRIPE}",'
                       f'NEXT_PUBLIC_B_TOKEN:"{second}"}};\n'),
        ".cursor/mcp.json": (f'{{"env": {{"API_TOKEN": "{MCP_TOKEN}", '
                             f'"DB_PASSWORD": "{DB_PASSWORD}"}}}}\n'),
    }
    found = _run(tmp_path, files)
    assert {f.title for f in found} >= {SERVICE, ANON_OPEN, PUBLIC_VAR, AGENT}
    blob = json.dumps([f.model_dump(mode="json") for f in found])
    for raw in (SERVICE_JWT, ANON_JWT, STRIPE, second, MCP_TOKEN, DB_PASSWORD):
        # not even a fragment of a value cut by the excerpt window
        assert not any(raw[i:i + 16] in blob for i in range(len(raw) - 15)), raw


def test_plain_sql_without_supabase_signals_is_not_an_open_table(tmp_path: Path):
    """A Flask or Go app's schema.sql is not served by a Supabase API: no RLS findings."""
    schema = "create table users (id int);\ncreate table orders (id int);\n"
    assert _run(tmp_path / "plain", {"db/schema.sql": schema}) == []
    # under supabase/, or with RLS used elsewhere in the tool, the same tables are open
    found = _run(tmp_path / "sb", {"supabase/migrations/1.sql": schema})
    assert {f.title for f in found} == {NO_RLS} and len(found) == 2
    mixed = {"db/schema.sql": schema,
             "db/rls.sql": "alter table users enable row level security;\n"}
    assert _located(_run(tmp_path / "rls", mixed)) == {(NO_RLS, "db/schema.sql", 2)}


def test_plain_sql_with_a_supabase_dependency_is_checked(tmp_path: Path):
    from unvarnish.schemas.inventory import DependencyRecord

    ctx = _ctx(_write(tmp_path, {"db/schema.sql": "create table users (id int);\n"}))
    ctx.dependencies.dependencies.append(DependencyRecord(
        ecosystem="npm", name="@supabase/supabase-js", constraint="^2", manifest="package.json"))
    assert _located(ClientExposureScanner().run(ctx)) == {(NO_RLS, "db/schema.sql", 1)}


def test_update_policy_using_without_with_check_is_not_flagged(tmp_path: Path):
    """Postgres reuses USING as the check for UPDATE when WITH CHECK is absent."""
    sql = ("create table public.profiles (id uuid);\n"
           "alter table public.profiles enable row level security;\n"
           'create policy "own update" on profiles for update using (auth.uid() = id);\n'
           'create policy "bare update" on profiles for update to authenticated;\n')
    found = _run(tmp_path, {MIGRATION: sql})
    assert _located(found) == {(NO_CHECK, MIGRATION, 4)}


def test_frontend_api_client_calls_are_not_route_handlers(tmp_path: Path):
    files = {
        "src/services/users.ts": (
            'import axios from "axios";\n'
            "const api = axios.create({ baseURL: '/api' });\n"
            'export const list = () => api.get("/users");\n'
            'export const create = (body) => api.post("/users", body);\n'
        ),
    }
    assert _run(tmp_path, files) == []


def test_generated_bundles_are_not_route_or_cors_sources(tmp_path: Path):
    bundle = ('const express=require("express");app.use(cors({origin:"*",credentials:true}));'
              'app.get("/api/orders",(req,res)=>res.json(db.all()));\n')
    assert _run(tmp_path, {"dist/server.min.js": bundle}) == []


_EXPRESS_HEAD = 'const express = require("express");\nconst app = express();\n'


@pytest.mark.parametrize("guard", [
    "isLoggedIn", "is_logged_in", "ensureLoggedIn", "ensure_logged_in", "isAuthenticated",
    "is_authenticated", "requireLogin", "require_login", "login_required",
])
def test_a_login_guard_on_the_route_line_counts_as_authentication(tmp_path: Path, guard: str):
    files = {"routes.js": _EXPRESS_HEAD
             + f'app.get("/profile", {guard}, (req, res) => res.send("ok"));\n'}
    assert ROUTES not in {f.title for f in _run(tmp_path, files)}


def test_a_route_with_no_guard_still_fires_and_a_login_path_is_not_a_guard(tmp_path: Path):
    files = {"routes.js": _EXPRESS_HEAD
             + 'app.get("/profile", (req, res) => res.send("ok"));\n'
             + 'app.get("/account/login-history", (req, res) => res.send("ok"));\n'}
    found = [f for f in _run(tmp_path, files) if f.title == ROUTES]
    assert len(found) == 1
    assert [(e.path, e.line_start) for e in found[0].evidence] == [
        ("routes.js", 3), ("routes.js", 4)]
