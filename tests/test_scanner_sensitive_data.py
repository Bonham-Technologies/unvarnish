"""The sensitive_data scanner: field names that suggest sensitive data, where they are
declared, and where the tool may send them (UNVAR-100)."""

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.cli import app
from unvarnish.config import (
    DEFAULT_SCANNER_OPTIONS,
    EngagementConfig,
    load_config,
    scanner_option_problems,
)
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.inventory import census_files
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import EFFORT_RULES
from unvarnish.scanners.sensitive_data import (
    SensitiveDataScanner,
    bundled_patterns,
    compile_patterns,
    name_words,
)
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.sensitive_data import SensitiveData

runner = CliRunner()

POSTGRES = """-- 001_init.sql: the first migration
CREATE TABLE IF NOT EXISTS public.customers (
    id BIGSERIAL PRIMARY KEY,
    first_name TEXT NOT NULL,
    "lastName" TEXT,
    email CITEXT UNIQUE,
    user_agent TEXT,
    email_template TEXT,
    date_of_birth DATE,
    balance NUMERIC(10, 2) DEFAULT 0,
    CONSTRAINT customers_email_key UNIQUE (email)
);

/* a comment that says CREATE TABLE ignored (ssn TEXT) */
CREATE TABLE payments (id serial, card_number varchar(19), iban text, note text DEFAULT 'phone');

ALTER TABLE customers ADD COLUMN ssn TEXT;
ALTER TABLE ONLY customers ADD COLUMN IF NOT EXISTS health_check boolean;
"""

DJANGO = """from django.db import models


class Patient(models.Model):
    full_name = models.CharField(max_length=200)
    phone_number = models.CharField(max_length=20)
    diagnosis = models.TextField()
    health_check = models.BooleanField(default=False)
    user_agent = models.CharField(max_length=300)

    class Meta:
        db_table = "patients"

    def __str__(self):
        email = "not a field"
        return self.full_name
"""

SQLALCHEMY = """from sqlalchemy import Column, Float, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    api_key = Column(String)
    latitude = Column(Float)
    email_template = Column(String)


class Helper:
    email = "plain class, not a data structure"
"""

PRISMA = """// schema.prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id              Int     @id @default(autoincrement())
  email           String  @unique
  phone           String?
  passport_number String?
  userAgent       String?
  posts           Post[]

  @@map("users")
}

enum Role {
  STUDENT
  ADMIN
}
"""

TYPESCRIPT = """// types.ts
export interface Customer {
  id: string;
  firstName: string;
  emailAddress?: string;
  readonly creditCardNumber: string;
  healthCheck: boolean;
  userAgent: string;
  address: { street: string; postcode: string };
  onSave: (email: string) => void;
}

export type Session = {
  accessToken: string;
  lat: number; lng: number;
  emailTemplate: string;
};

function notAType() {
  const x = { email: "literal, not a type" };
  return x;
}
"""

AC1_FILES = {
    "db/migrations/001_init.sql": POSTGRES,
    "clinic/models.py": DJANGO,
    "app/models.py": SQLALCHEMY,
    "prisma/schema.prisma": PRISMA,
    "web/src/types.ts": TYPESCRIPT,
}

AC1_EXPECTED = {
    ("identity", "customers", "first_name"), ("identity", "customers", "lastName"),
    ("contact", "customers", "email"), ("identity", "customers", "date_of_birth"),
    ("government_id", "customers", "ssn"),
    ("payment", "payments", "card_number"), ("payment", "payments", "iban"),
    ("identity", "Patient", "full_name"), ("contact", "Patient", "phone_number"),
    ("health", "Patient", "diagnosis"),
    ("credentials", "Account", "password_hash"), ("credentials", "Account", "api_key"),
    ("location", "Account", "latitude"),
    ("contact", "User", "email"), ("contact", "User", "phone"),
    ("government_id", "User", "passport_number"),
    ("identity", "Customer", "firstName"), ("contact", "Customer", "emailAddress"),
    ("payment", "Customer", "creditCardNumber"), ("contact", "Customer", "address"),
    ("contact", "Customer", "street"), ("contact", "Customer", "postcode"),
    ("credentials", "Session", "accessToken"), ("location", "Session", "lat"),
    ("location", "Session", "lng"),
}

NOT_SENSITIVE = {"user_agent", "email_template", "health_check", "userAgent", "healthCheck",
                 "emailTemplate"}


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
                       options={**DEFAULT_SCANNER_OPTIONS["sensitive_data"], **options})


def _run(root: Path, files: dict[str, str], **options) -> SensitiveData:
    ctx = _ctx(_write(root, files), **options)
    assert SensitiveDataScanner().run(ctx) == []  # an inventory, never findings
    assert isinstance(ctx.inventory, SensitiveData)
    return ctx.inventory


def _triples(sd: SensitiveData) -> set[tuple[str, str, str]]:
    return {(f.data_class, f.store, f.field) for f in sd.fields}


# --- criterion 1: the fixtures yield the expected classes, no false positives -----------------

def test_fixtures_yield_the_expected_classes(tmp_path):
    sd = _run(tmp_path, AC1_FILES)
    assert _triples(sd) == AC1_EXPECTED


def test_no_false_positive_on_user_agent_email_template_or_health_check(tmp_path):
    sd = _run(tmp_path, AC1_FILES)
    assert not {f.field for f in sd.fields} & NOT_SENSITIVE


def test_each_hit_is_evidenced_by_file_and_line(tmp_path):
    sd = _run(tmp_path, AC1_FILES)
    where = {(f.store, f.field): (f.path, f.line, f.store_kind, f.persistent) for f in sd.fields}
    assert where[("customers", "first_name")] == ("db/migrations/001_init.sql", 4, "SQL table",
                                                  True)
    assert where[("customers", "ssn")] == ("db/migrations/001_init.sql", 17, "SQL table", True)
    assert where[("payments", "iban")][:2] == ("db/migrations/001_init.sql", 15)
    assert where[("Patient", "diagnosis")] == ("clinic/models.py", 7, "Django model", True)
    assert where[("Account", "api_key")] == ("app/models.py", 13, "SQLAlchemy model", True)
    assert where[("User", "passport_number")] == ("prisma/schema.prisma", 11, "Prisma model",
                                                  True)
    assert where[("Customer", "street")] == ("web/src/types.ts", 9, "TypeScript interface",
                                             False)
    assert where[("Session", "lng")] == ("web/src/types.ts", 15, "TypeScript type", False)
    matched = {(f.field, f.data_class): f.matched for f in sd.fields}
    assert matched[("date_of_birth", "identity")] == "date of birth"
    assert matched[("creditCardNumber", "payment")] == "credit card"


def test_inventory_records_classes_and_what_was_read(tmp_path):
    files = {**AC1_FILES, "broken.py": "class X(models.Model:\n", "svc/main.go": "package x\n",
             "svc/util.go": "package x\n"}
    sd = _run(tmp_path, files)
    assert list(sd.classes) == ["identity", "contact", "government_id", "payment", "health",
                                "credentials", "location", "minors"]
    assert sd.classes["government_id"] == "Government identifier"
    assert sd.classes_found() == ["identity", "contact", "government_id", "payment", "health",
                                  "credentials", "location"]
    assert sd.unparsed == ["broken.py"]
    assert sd.not_read == {"go": 2}
    # customers (created and altered), payments, Patient, Base (no fields), Account, User,
    # Customer and Session
    assert sd.structures_read == 8
    assert not sd.patterns_overridden


@pytest.mark.parametrize("name,words", [
    ("first_name", ["first", "name"]), ("emailAddress", ["email", "address"]),
    ("userSSN", ["user", "ssn"]), ("SSNNumber", ["ssn", "number"]),
    ("address_line2", ["address", "line", "2"]), ("x-api-key", ["x", "api", "key"]),
])
def test_names_split_into_words(name, words):
    assert name_words(name) == words


@pytest.mark.parametrize("name,classes", [
    ("firstname", {"identity"}), ("dateOfBirth", {"identity"}), ("emails", {"contact"}),
    ("phone_numbers", {"contact"}), ("addresses", {"contact"}), ("ip_address", {"identity"}),
    ("mac_address", set()), ("billing_address", {"payment", "contact"}),
    ("guardian_phone", {"minors", "contact"}), ("minor_version", set()),
    ("email_label", set()), ("emailPlaceholder", set()), ("max_tokens", set()),
    ("children", set()), ("parent_id", set()), ("token_count", set()), ("is_mobile", set()),
    ("file_name", set()), ("blood_type", {"health"}), ("emailVerified", {"contact"}),
    ("lateness", set()), ("patience", set()), ("passwords", {"credentials"}),
])
def test_matching_is_by_whole_words(name, classes):
    patterns = compile_patterns(bundled_patterns())
    assert {c for c, _ in patterns.classify(name)} == classes


def test_python_typed_structures_and_migrations(tmp_path):
    files = {
        "api/schemas.py": (
            "from dataclasses import dataclass\n"
            "from typing import TypedDict\n"
            "from pydantic import BaseModel\n\n"
            "class SignUp(BaseModel):\n    email: str\n    password: str\n\n"
            "@dataclass\nclass Visit:\n    patient_id: int\n\n"
            "class Row(TypedDict):\n    surname: str\n"
        ),
        "clinic/migrations/0002_add.py": (
            "from django.db import migrations, models\n\n"
            "class Migration(migrations.Migration):\n"
            "    operations = [\n"
            "        migrations.CreateModel(name='Guardian', fields=[\n"
            "            ('id', models.AutoField(primary_key=True)),\n"
            "            ('mobile_number', models.CharField(max_length=20)),\n"
            "        ]),\n"
            "        migrations.AddField(model_name='guardian', name='ssn',\n"
            "                            field=models.CharField(max_length=11)),\n"
            "    ]\n"
        ),
        "alembic/versions/1_init.py": (
            "import sqlalchemy as sa\nfrom alembic import op\n\n"
            "def upgrade():\n"
            "    op.create_table('members', sa.Column('id', sa.Integer()),\n"
            "                    sa.Column('home_address', sa.String()))\n"
            "    op.add_column('members', sa.Column('gps', sa.String()))\n"
        ),
        "app/db.py": (
            "import sqlite3\n"
            "def init(conn):\n"
            "    conn.execute('''CREATE TABLE IF NOT EXISTS leads (\n"
            "        id INTEGER PRIMARY KEY,\n"
            "        phone TEXT)''')\n"
        ),
    }
    sd = _run(tmp_path, files)
    kinds = {(f.store, f.field): (f.store_kind, f.persistent, f.line) for f in sd.fields}
    assert kinds[("SignUp", "email")] == ("Pydantic model", False, 6)
    assert kinds[("SignUp", "password")][0] == "Pydantic model"
    assert kinds[("Visit", "patient_id")] == ("dataclass", False, 11)
    assert kinds[("Row", "surname")] == ("TypedDict", False, 14)
    assert kinds[("Guardian", "mobile_number")] == ("Django model", True, 7)
    assert kinds[("Guardian", "ssn")] == ("Django model", True, 9)  # one store, any case
    assert kinds[("members", "home_address")] == ("SQL table", True, 6)
    assert kinds[("members", "gps")] == ("SQL table", True, 7)
    assert kinds[("leads", "phone")] == ("SQL table", True, 5)


def test_javascript_schemas(tmp_path):
    files = {
        "models/user.js": (
            "const mongoose = require('mongoose');\n"
            "const userSchema = new mongoose.Schema({\n"
            "  email: { type: String, required: true },\n"
            "  dob: Date,\n"
            "  userAgent: String,\n"
            "});\n"
        ),
        "src/forms.ts": (
            "import { z } from 'zod';\n"
            "export const Checkout = z.object({\n"
            "  cardNumber: z.string(),\n"
            "  'zip-code': z.string(),\n"
            "});\n"
        ),
        "src/db/schema.ts": (
            "export const users = pgTable('users', {\n"
            "  id: serial('id').primaryKey(),\n"
            "  passwordHash: text('password_hash'),\n"
            "});\n"
        ),
        "src/entity/Member.ts": (
            "@Entity()\nexport class Member {\n"
            "  @PrimaryGeneratedColumn() id: number;\n"
            "  @Column() nationality: string;\n"
            "  greet() { const o = { email: 'x' }; return o; }\n"
            "}\n"
        ),
    }
    sd = _run(tmp_path, files)
    kinds = {(f.store, f.field): (f.store_kind, f.line) for f in sd.fields}
    assert kinds == {
        ("userSchema", "email"): ("Mongoose schema", 3),
        ("userSchema", "dob"): ("Mongoose schema", 4),
        ("Checkout", "cardNumber"): ("Zod schema", 3),
        ("Checkout", "zip-code"): ("Zod schema", 4),
        ("users", "passwordHash"): ("Drizzle table", 3),
        ("Member", "nationality"): ("TypeORM entity", 4),
    }


def test_tests_are_skipped_unless_asked(tmp_path):
    files = {"tests/test_models.py": "from pydantic import BaseModel\n"
                                     "class F(BaseModel):\n    email: str\n"}
    assert _run(tmp_path / "a", files).fields == []
    assert len(_run(tmp_path / "b", files, include_tests=True).fields) == 1


def test_no_data_value_reaches_the_inventory(tmp_path):
    files = {"seed.sql": "CREATE TABLE people (email text);\n"
                         "INSERT INTO people (email) VALUES ('jane.doe@example.org');\n"}
    sd = _run(tmp_path, files)
    assert _triples(sd) == {("contact", "people", "email")}
    assert "jane.doe" not in sd.model_dump_json()


# --- criterion 2: the pattern set is data, overridable and listed ------------------------------

def test_pattern_set_is_bundled_data_and_the_default_option():
    bundled = bundled_patterns()
    assert set(bundled["classes"]) == {"identity", "contact", "government_id", "payment",
                                       "health", "credentials", "location", "minors"}
    assert DEFAULT_SCANNER_OPTIONS["sensitive_data"]["patterns"] == bundled
    assert DEFAULT_SCANNER_OPTIONS["sensitive_data"]["include_tests"] is False
    assert EngagementConfig().scanners["sensitive_data"]["patterns"] == bundled
    assert EFFORT_RULES["sensitive_data"] == {}  # no findings, so no effort bands


def test_engagement_yaml_overrides_the_patterns(tmp_path, monkeypatch):
    monkeypatch.setenv("UNVARNISH_CONFIG_DIR", str(tmp_path / "user"))
    f = tmp_path / "engagement.yaml"
    f.write_text(yaml.safe_dump({"scanners": {"sensitive_data": {"patterns": {
        "classes": {"contact": {"terms": ["fax"]},
                    "employee": {"label": "Employee records", "terms": ["payroll id"]}},
    }}}}), encoding="utf-8")
    cfg = load_config(f)
    patterns = cfg.scanners["sensitive_data"]["patterns"]
    assert patterns["classes"]["contact"]["terms"] == ["fax"]
    assert patterns["classes"]["contact"]["exclude"]  # kept from the bundled set
    assert patterns["classes"]["identity"] == bundled_patterns()["classes"]["identity"]
    assert patterns["ignore"] == bundled_patterns()["ignore"]
    files = {"m.sql": "CREATE TABLE staff (email text, fax text, payroll_id text);\n"}
    sd = _run(tmp_path / "src", files, **cfg.scanners["sensitive_data"])
    assert _triples(sd) == {("contact", "staff", "fax"), ("employee", "staff", "payroll_id")}
    assert sd.classes["employee"] == "Employee records"
    assert sd.patterns_overridden


@pytest.mark.parametrize("patterns,problem", [
    ({"classes": {"x": {"terms": "email"}}}, "classes.x.terms"),
    ({"classes": {"x": {"label": "X", "terms": [3]}}}, "classes.x.terms"),
    ({"classes": {"x": {"terms": ["email"], "colour": "red"}}}, "classes.x.colour"),
    ({"ignore": "user agent"}, "ignore"),
    ({"classes": []}, "classes"),
    ("bundled", "patterns"),
])
def test_bad_patterns_are_reported_by_config_check_and_fail_the_scanner(tmp_path, patterns,
                                                                        problem):
    cfg = EngagementConfig.model_validate({"scanners": {"sensitive_data": {
        "patterns": patterns}}})
    problems = scanner_option_problems(cfg.scanners)
    assert [k for k, _ in problems] == ["scanners.sensitive_data.patterns"]
    assert problem in problems[0][1]
    with pytest.raises(ValueError, match="scanners.sensitive_data.patterns"):
        _run(tmp_path, {"a.sql": "CREATE TABLE t (email text);\n"},
             **cfg.scanners["sensitive_data"])


def test_scanners_list_shows_the_pattern_set():
    r = runner.invoke(app, ["scanners", "list"], env={"COLUMNS": "400"})
    assert r.exit_code == 0, r.output
    line = next(line for line in r.output.splitlines() if " sensitive_data " in line)
    assert "patterns=8 data classes" in line and "include_tests=False" in line
    assert "{" not in line  # the set is listed below the table, not dumped into a cell
    out = " ".join(r.output.split())
    assert "sensitive_data patterns" in out
    assert "government_id" in out and "Government identifier" in out
    assert "date of birth" in out and "passport" in out
    assert "user agent" in out and "health check" in out  # the names never classified


def test_scanners_list_shows_an_engagement_override(tmp_path):
    from unvarnish.engagement import Engagement

    eng = Engagement.create(tmp_path / "acme")
    eng.config_file.write_text(yaml.safe_dump({"scanners": {"sensitive_data": {"patterns": {
        "classes": {"employee": {"label": "Employee records", "terms": ["payroll id"]}}}}}}),
        encoding="utf-8")
    r = runner.invoke(app, ["scanners", "list", "-e", str(eng.root)], env={"COLUMNS": "400"})
    assert r.exit_code == 0, r.output
    assert "patterns=9 data classes" in r.output
    assert "Employee records" in r.output and "payroll id" in r.output


def test_scanner_is_registered_last_and_the_scan_reruns():
    from unvarnish.phases.scan import SCANNER_TEXT_VERSION

    assert [s.name for s in builtin_scanners()][-1] == "sensitive_data"
    assert SCANNER_TEXT_VERSION == "2026-11-26.2"


# --- the pipeline: the artifact and requirements.md -------------------------------------------

AI_FILE = ("from openai import OpenAI\nclient = OpenAI()\n"
           "def ask(q):\n"
           "    return client.chat.completions.create(model='gpt-4o-mini', max_tokens=10,\n"
           "        messages=[{'role': 'user', 'content': q}])\n")

APP_FILES = {
    "app.py": (
        "from flask_sqlalchemy import SQLAlchemy\n"
        "import stripe\n"
        "db = SQLAlchemy()\n\n"
        "class Customer(db.Model):\n"
        "    id = db.Column(db.Integer, primary_key=True)\n"
        "    email = db.Column(db.String)\n"
        "    card_number = db.Column(db.String)\n"
    ),
    "ai.py": AI_FILE,
    "migrations/001.sql": "CREATE TABLE notes (id int, diagnosis text);\n",
}


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


def _section(doc: str) -> str:
    return doc.split(" Sensitive data\n", 1)[1].split("\n## ", 1)[0]


def test_scan_writes_the_inventory_artifact(engagement):
    from unvarnish.phases.scan import ScanPhase

    ctx = _engagement_run(engagement, "app", APP_FILES, _scan_phases())
    sd = read_artifact(ctx.paths.sensitive_data, SensitiveData).data
    assert _triples(sd) == {("contact", "Customer", "email"),
                            ("payment", "Customer", "card_number"),
                            ("health", "notes", "diagnosis")}
    assert ctx.paths.sensitive_data in ScanPhase().outputs(ctx)
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    assert "sensitive_data" in scan.scanners_run
    assert not [f for f in scan.findings if f.scanner == "sensitive_data"]


def test_without_a_model_requirements_md_renders_the_section(engagement):
    """Criterion 4: no model configured, the section still renders from the deterministic
    pass, and its destinations are the ai_usage scanner's providers alone."""
    from unvarnish.phases.render import RenderPhase

    assert engagement.config.models.default is None
    ctx = _engagement_run(engagement, "app", APP_FILES, [*_scan_phases(), RenderPhase()])
    assert ctx.paths.requirements_doc in RenderPhase().outputs(ctx)
    doc = ctx.paths.requirements_doc.read_text(encoding="utf-8")
    assert doc.startswith("# app: Requirements Inventory")
    assert "no model was configured" in doc
    assert "## 1. Actors" not in doc and "PROSE" not in doc
    section = _section(doc)
    # criterion 3: name-based, no values read, what was not analysed; never a legal conclusion
    assert "Field names suggest" in section
    assert "by name alone" in section
    assert "No data values were read" in section
    assert "not a legal" in section
    assert "**Not analysed**" in section
    assert "| Contact details | `email` | `Customer` (SQLAlchemy model) | `app.py:7` |" in section
    assert "| Health | `diagnosis` | `notes` (SQL table) | `migrations/001.sql:1` |" in section
    assert "| Payment | `card_number` | `Customer` (SQLAlchemy model) | `app.py:8` |" in section
    dest = section.split("**Where this data may go**", 1)[1]
    assert "| OpenAI | AI model provider (hosted) | ai_usage scanner | `ai.py` | — | — |" in dest
    assert "External systems from the tool model are not included because no model" in dest


def test_with_a_tool_model_the_destinations_join_external_systems(engagement):
    """Criterion 4: the destinations table is a join of tool.json, ai-usage.json and
    sensitive-data.json; the store in app.py shares a file with Stripe."""
    from unvarnish.phases.render import RenderPhase
    from unvarnish.schemas.cost import Usage
    from unvarnish.schemas.toolmodel import (
        DataFlow,
        ExternalSystem,
        RequirementsInventory,
        ToolModel,
    )

    ctx = _engagement_run(engagement, "app", APP_FILES, _scan_phases())
    tm = ToolModel(
        tool="app", purpose="p", actors=[], entry_points=[], data_stores=[],
        external_systems=[
            ExternalSystem(name="Stripe", kind="payment", direction="outbound",
                           description="charges cards", modules=["app.py"]),
            ExternalSystem(name="Mixpanel", kind="http", direction="both",
                           description="analytics", modules=["track.py"]),
            ExternalSystem(name="Okta", kind="auth", direction="inbound",
                           description="sign-in", modules=["app.py"]),
        ],
        internal_stack=[], module_map=[],
        data_flows=[DataFlow(source="app", target="Stripe", data="card details | amount")],
        deployment_assumptions=[], capabilities=[], business_rules=[], open_questions=[],
        confidence=0.9, backend="stub", model="stub", usage=Usage(), prompt_version="t")
    write_artifact(ctx.paths.tool_model, tm, produced_by="rollup_tool", inputs_hash="")
    req = RequirementsInventory(tool="app", actors=[], capabilities=[], data_inventory=[],
                                business_rules=[], open_questions=[])
    write_artifact(ctx.paths.capabilities, req, produced_by="rollup_tool", inputs_hash="")
    assert PhaseRunner([RenderPhase()]).run(ctx)[0].status == PhaseStatus.ok
    doc = ctx.paths.requirements_doc.read_text(encoding="utf-8")
    assert "## 1. Actors" in doc and "## 6. Open questions" in doc
    dest = _section(doc).split("**Where this data may go**", 1)[1]
    assert ("| Stripe | payment | tool model | `app.py` | `Customer` (Contact details, Payment) "
            "| card details \\| amount |") in dest
    assert "| Mixpanel | http | tool model | `track.py` | — | — |" in dest
    assert "Okta" not in dest  # inbound only: not a destination
    assert "| OpenAI | AI model provider (hosted) | ai_usage scanner | `ai.py` | — | — |" in dest
    assert "not included" not in dest


def test_a_tool_with_no_sensitive_names_and_no_model_has_no_requirements_md(engagement):
    from unvarnish.phases.render import RenderPhase

    files = {"m.sql": "CREATE TABLE things (id int, title text);\n"}
    ctx = _engagement_run(engagement, "plain", files, [*_scan_phases(), RenderPhase()])
    assert read_artifact(ctx.paths.sensitive_data, SensitiveData).data.fields == []
    assert not ctx.paths.requirements_doc.exists()
    assert RenderPhase().outputs(ctx) == [ctx.paths.render_state, ctx.paths.findings_doc]


def test_none_found_and_not_checked_wording(engagement):
    from unvarnish.phases.render import RenderPhase
    from unvarnish.schemas.toolmodel import RequirementsInventory

    req = RequirementsInventory(tool="x", actors=[], capabilities=[], data_inventory=[],
                                business_rules=[], open_questions=[])
    files = {"m.sql": "CREATE TABLE things (id int, title text);\n"}
    ctx = _engagement_run(engagement, "plain", files, _scan_phases())
    write_artifact(ctx.paths.capabilities, req, produced_by="rollup_tool", inputs_hash="")
    PhaseRunner([RenderPhase()]).run(ctx)
    section = _section(ctx.paths.requirements_doc.read_text(encoding="utf-8"))
    assert "Field names suggest none of the sensitive data classes" in section
    assert "No data values were read" in section

    ctx = _engagement_run(engagement, "old", files, _scan_phases(scanners=[]))
    assert not ctx.paths.sensitive_data.exists()
    write_artifact(ctx.paths.capabilities, req, produced_by="rollup_tool", inputs_hash="")
    PhaseRunner([RenderPhase()]).run(ctx)
    section = _section(ctx.paths.requirements_doc.read_text(encoding="utf-8"))
    assert "Not checked: the sensitive_data scanner did not run for this tool." in section


def test_an_unreadable_inventory_is_not_checked(engagement):
    from unvarnish.render.inputs import load_render_inputs

    ctx = _engagement_run(engagement, "app", APP_FILES, _scan_phases())
    ctx.paths.sensitive_data.write_text(json.dumps({"broken": True}), encoding="utf-8")
    assert load_render_inputs(ctx).sensitive_data is None


def test_more_python_and_prisma_forms(tmp_path):
    files = {
        "models.py": (
            "import attr\n"
            "from typing import NamedTuple\n"
            "from sqlalchemy.orm import declarative_base\n"
            "from sqlmodel import SQLModel\n"
            "from mongoengine import Document\n"
            "from marshmallow import Schema, fields\n"
            "Base = declarative_base()\n\n"
            "class Card(Base):\n    iban = Column(String)\n\n"
            "class Hero(SQLModel, table=True):\n    secret_name: str\n\n"
            "class Point(NamedTuple):\n    latitude: float\n\n"
            "class Doc(Document):\n    medical = StringField()\n\n"
            "class Out(Schema):\n    username = fields.Str()\n\n"
            "@attr.s\nclass Kid:\n    guardian = attr.ib()\n"
        ),
        "schema.prisma": "type Address {\n  street String // comment\n}\n",
    }
    sd = _run(tmp_path, files)
    kinds = {(f.store, f.field): (f.store_kind, f.persistent) for f in sd.fields}
    assert kinds == {
        ("Card", "iban"): ("SQLAlchemy model", True),
        ("Hero", "secret_name"): ("SQLModel model", True),
        ("Point", "latitude"): ("NamedTuple", False),
        ("Doc", "medical"): ("MongoEngine document", True),
        ("Out", "username"): ("schema", False),
        ("Kid", "guardian"): ("attrs class", False),
        ("Address", "street"): ("Prisma type", False),
    }


def test_large_and_unreadable_files_are_skipped(tmp_path, monkeypatch):
    from unvarnish.scanners import sensitive_data

    ctx = _ctx(_write(tmp_path, {"a.sql": "CREATE TABLE t (email text);\n"}))
    (tmp_path / "a.sql").unlink()  # in the census, gone from disk
    SensitiveDataScanner().run(ctx)
    assert ctx.inventory.fields == [] and ctx.inventory.files_read == 0
    _write(tmp_path, {"a.sql": "CREATE TABLE t (email text);\n"})
    monkeypatch.setattr(sensitive_data, "MAX_FILE_BYTES", 5)
    SensitiveDataScanner().run(ctx)
    assert ctx.inventory.fields == []


# --- review fixes: hostile input, data files, one bad file, no wasted prose ------------------

HOSTILE = {
    "a.ts": "interface X<a> extends b" + "> extends c" * 20_000,
    "b.ts": "type X<" * 20_000,
    "c.ts": "@Entity() class X " * 20_000,
    "d.ts": "interface A {" * 20_000,
    "e.js": ("const a: " + "x" * 50) * 5_000,
    "f.sql": "CREATE TABLE a (" * 20_000,
    "g.py": "x = '''CREATE TABLE a (''' + '''CREATE TABLE a (''' * 1\n" + "# CREATE TABLE a (\n"
            * 20_000,
    "h.py": "x = a" + ".b()" * 5_000 + "\n",
    # Exponential before: each decorator doubled the work of a field match that fails.
    "i.ts": "interface A {\n" + "@x " * 26 + "}",
    "j.js": "const s = new Schema({\n" + "@x " * 26 + "})",
    # Quadratic before: every line restarted a field match that ran to the body's end.
    "k.ts": "interface A {\n" + "@x(\n)\n" * 6_000,
    "l.ts": "interface A {\n" + "readonly\n" * 20_000,
    "m.js": "new Schema<" * 60_000,
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_input_cannot_hang_the_pass(tmp_path, name):
    """Unclosed bodies, unterminated generics and long lines are linear, not quadratic:
    each of these took from seconds to minutes before the per-file scan budget and the
    bounded patterns."""
    import time

    start = time.perf_counter()
    _run(tmp_path, {name: HOSTILE[name]})
    assert time.perf_counter() - start < 5


def test_data_files_are_never_opened(tmp_path, monkeypatch):
    """Exports, records and configuration (CSV, JSON Lines, JSON, YAML, XML, TOML) are not
    declarations: the section says no data or configuration file was opened, so none is."""
    from unvarnish.scanners import sensitive_data

    opened: list[str] = []
    real = sensitive_data.SensitiveDataScanner._structures

    def spy(self, root, path, out):
        opened.append(path)
        return real(self, root, path, out)

    monkeypatch.setattr(sensitive_data.SensitiveDataScanner, "_structures", spy)
    leak = "CREATE TABLE leak (ssn text);"
    sd = _run(tmp_path, {"export.csv": f"note\n{leak}\n",
                         "rows.jsonl": f'{{"q": "{leak}"}}\n',
                         "data/customers.json": f'{{"q": "{leak}"}}\n',
                         "export.xml": f"<q>{leak}</q>\n",
                         "users.yaml": f"q: '{leak}'\n",
                         "settings.toml": f"q = '{leak}'\n",
                         "schema.prisma": "model User {\n  email String\n}\n"})
    assert _triples(sd) == {("contact", "User", "email")}
    assert opened == ["schema.prisma"]
    assert sd.files_read == 1


def test_sql_dump_rows_are_skipped(tmp_path):
    """A `COPY ... FROM stdin` row with an apostrophe (O'Brien) must not flip which parts
    of the rest of the dump count as strings, and INSERT values are never parsed."""
    dump = ("COPY public.people (id, surname) FROM stdin;\n"
            "1\tO'Brien\n"
            "\\.\n"
            "CREATE TABLE contacts (id int, email text);\n"
            "INSERT INTO notes VALUES ('x', 'CREATE TABLE leak (ssn text)');\n"
            "INSERT INTO notes VALUES (1, 2) ; CREATE TABLE more (phone text);\n")
    sd = _run(tmp_path, {"db/dump.sql": dump})
    assert _triples(sd) == {("contact", "contacts", "email"), ("contact", "more", "phone")}


@pytest.mark.parametrize("name", ["minor", "minor_units", "minorUnits", "amount_minor",
                                  "price_minor"])
def test_money_and_version_minor_are_not_minors(name):
    p = compile_patterns(bundled_patterns())
    assert p.classify(name) == []


def test_minors_flags_still_count(tmp_path):
    p = compile_patterns(bundled_patterns())
    for name in ("is_minor", "isMinor", "minor_flag", "is_child", "guardian"):
        assert [k for k, _ in p.classify(name)] == ["minors"], name
    sd = _run(tmp_path, {"v.ts": "interface Version { major: number; minor: number; "
                                 "patch: number }\n"})
    assert sd.fields == []


def test_names_with_backticks_cannot_break_a_code_span():
    from unvarnish.render.inputs import RenderInputs
    from unvarnish.render.requirements import sensitive_context
    from unvarnish.schemas.sensitive_data import SensitiveField

    sd = SensitiveData(tool="t", classes={"contact": "Contact details"}, fields=[
        SensitiveField(data_class="contact", field="e`mail", store="a`b", store_kind="x",
                       persistent=True, path="p`q.ts", line=1, matched="email")])
    ctx = sensitive_context(RenderInputs(**{**_bare_inputs(), "sensitive_data": sd}))
    row = ctx["rows"][0]
    for cell in (row["fields"], row["stores"], row["evidence"]):
        assert cell.count("`") == 2, cell


def _bare_inputs() -> dict:
    import dataclasses

    from unvarnish.render.inputs import RenderInputs

    required = [f.name for f in dataclasses.fields(RenderInputs)
                if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING]
    return dict.fromkeys(required)


def test_lead_sentence_says_stores_or_handles(engagement):
    from unvarnish.phases.render import RenderPhase

    ctx = _engagement_run(engagement, "app", APP_FILES, [*_scan_phases(), RenderPhase()])
    section = _section(ctx.paths.requirements_doc.read_text(encoding="utf-8"))
    assert "Field names suggest the tool stores 3 classes of sensitive data" in section
    assert "the tool holds" not in section
    assert "`name`, `age`, `token`" in section  # left out of the bundled set, on purpose

    files = {"t.ts": "export interface Signup { email: string; password: string }\n"}
    ctx = _engagement_run(engagement, "ts", files, [*_scan_phases(), RenderPhase()])
    section = _section(ctx.paths.requirements_doc.read_text(encoding="utf-8"))
    assert "Field names suggest the tool handles 2 classes of sensitive data" in section
    assert "types and schemas for data in memory or in transit" in section


def test_a_file_that_breaks_a_parser_costs_that_file_alone(tmp_path, monkeypatch):
    from unvarnish.scanners import sensitive_data

    def boom(text):
        raise RecursionError("deep")

    monkeypatch.setattr(sensitive_data, "_prisma_structures", boom)
    sd = _run(tmp_path, {"schema.prisma": "model U {\n  email String\n}\n",
                         "a.sql": "CREATE TABLE t (phone text);\n"})
    assert _triples(sd) == {("contact", "t", "phone")}
    assert sd.unparsed == ["schema.prisma"]


@pytest.mark.parametrize("source", ["x = " + "-" * 200_000 + "1\n",  # MemoryError
                                    "x = a" + ".b" * 300_000 + "\n"])  # RecursionError
def test_python_too_deep_to_parse_is_unparsed(tmp_path, source):
    sd = _run(tmp_path, {"deep.py": source, "a.sql": "CREATE TABLE t (phone text);\n"})
    assert _triples(sd) == {("contact", "t", "phone")}
    assert sd.unparsed == ["deep.py"]


def test_a_model_without_capabilities_asks_for_no_requirements_prose(engagement):
    """A model is configured but its phases did not produce capabilities.json (a budget stop):
    requirements.md holds the sensitive data section alone, and its prose blocks, which that
    page never shows, are not requested."""
    from tests.stub_backend import StubBackend
    from unvarnish.phases.render import RenderPhase
    from unvarnish.render.markdown import prose_block_names

    ctx = _engagement_run(engagement, "app", APP_FILES, _scan_phases())
    stub = StubBackend(default="Prose.")
    assert RenderPhase(backend=stub).run(ctx).status == PhaseStatus.ok
    doc = ctx.paths.requirements_doc.read_text(encoding="utf-8")
    assert "No model was configured" not in doc
    assert "holds only the sensitive data section" in doc
    env = RenderPhase()._env(ctx)
    assert stub.count("prose") == len(prose_block_names(env, "findings.md.j2"))
