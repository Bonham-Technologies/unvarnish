"""The ai_usage scanner: which model providers a tool's code calls, and four checks (UNVAR-91)."""

import hashlib
import json
from pathlib import Path

from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.config import DEFAULT_SCANNER_OPTIONS
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.inventory import census_files
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.ai_usage import AIUsageScanner, ai_hints
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import EFFORT_RULES
from unvarnish.schemas.ai_usage import AIUsage
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings


def _rand(seed: str, n: int = 40) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n]


# Built at run time, so no key-shaped value sits in this file.
OPENAI_KEY = "sk-proj-" + _rand("openai-key", 48)
PLAIN_KEY = "k" + _rand("plain-key", 20)

AI_FILES: dict[str, str] = {
    "app/openai_chat.py": (
        "from flask import Flask, request\n"
        "from openai import OpenAI\n"
        "\n"
        "app = Flask(__name__)\n"
        f'client = OpenAI(api_key="{OPENAI_KEY}")\n'
        "\n"
        '@app.post("/ask")\n'
        "def ask():\n"
        '    question = request.json["question"]\n'
        '    prompt = f"You are a calculator. Answer only with Python: {question}"\n'
        "    resp = client.chat.completions.create(\n"
        '        model="gpt-4o-mini", max_tokens=300,\n'
        '        messages=[{"role": "user", "content": prompt}],\n'
        "    )\n"
        "    code = resp.choices[0].message.content\n"
        "    return str(eval(code))\n"
    ),
    "svc/anthropic_http.js": (
        'const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";\n'
        "export async function summarise(text) {\n"
        "  const res = await fetch(ANTHROPIC_URL, {\n"
        '    method: "POST",\n'
        f'    headers: {{ "x-api-key": "{PLAIN_KEY}", "content-type": "application/json" }},\n'
        '    body: JSON.stringify({ model: "claude-sonnet-4-5", max_tokens: 512,\n'
        '                           messages: [{ role: "user", content: text }] }),\n'
        "    signal: AbortSignal.timeout(30000),\n"
        "  });\n"
        "  return res.json();\n"
        "}\n"
    ),
    "tools/local_llm.py": (
        "import subprocess\n"
        "import requests\n"
        "\n"
        'OLLAMA_URL = "http://localhost:11434/api/generate"\n'
        "\n"
        "\n"
        "def suggest_command(task):\n"
        '    r = requests.post(OLLAMA_URL, json={"model": "llama3.1:8b", "prompt": task})\n'
        '    command = r.json()["response"]\n'
        "    return subprocess.run(command, shell=True, check=False)\n"
    ),
    "agent/tools.py": (
        "import os\n"
        "from anthropic import Anthropic\n"
        "\n"
        "client = Anthropic()\n"
        "TOOLS = [{\n"
        '    "name": "delete_file",\n'
        '    "description": "Delete a file",\n'
        '    "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},\n'
        "}]\n"
        "\n"
        "\n"
        "def run(messages):\n"
        '    return client.messages.create(model="claude-opus-4-1", max_tokens=1024,\n'
        "                                  tools=TOOLS, messages=messages)\n"
        "\n"
        "\n"
        "def delete_file(path):\n"
        "    os.remove(path)\n"
    ),
    # Excluded by default: tests and vendored code.
    "tests/test_llm.py": (
        "from openai import OpenAI\n"
        'out = OpenAI().chat.completions.create(model="gpt-4.1", messages=[])\n'
        "eval(out)\n"
    ),
    "node_modules/openai/index.js": 'const BASE = "https://api.openai.com/v1";\n',
    "README.md": "Calls `https://api.openai.com/v1` with gpt-4o.\n",
}

PLAIN_FILES = {
    "app.py": (
        "import subprocess\n"
        "from flask import request\n"
        "\n"
        "def run():\n"
        '    name = request.json["name"]\n'
        '    greeting = f"Hello {name}"\n'
        '    return subprocess.run(["echo", greeting])\n'
    ),
    "web/messages.js": "client.messages.create({ body: 'hi', to: '+15550100' });\n",
    "shop/models.py": 'class Meta:\n    model = "auth.User"\n',
    # A loopback base URL is an ordinary web app's, not a model server's (QC on UNVAR-91).
    "settings.py": 'API_BASE_URL = "http://localhost:8000"\n',
    "billing/client.py": (
        "import subprocess\n"
        "import requests\n"
        "from flask import request\n"
        'BASE_URL = "http://localhost:9000"\n'
        "\n"
        "def create_job(cursor):\n"
        '    name = request.json["name"]\n'
        '    payload = {"title": f"Job for {name}"}\n'
        '    resp = requests.post(BASE_URL + "/jobs", json=payload)\n'
        "    job = resp.json()\n"
        "    cursor.execute(f\"insert into jobs values ({job['id']})\")\n"
        '    subprocess.run(["notify", job["id"]])\n'
    ),
    "web/api.ts": ('import axios from "axios";\n'
                   'export const api = axios.create({ baseURL: "http://localhost:3000/api" });\n'),
    "playwright.config.ts": "export default { use: { baseURL: 'http://localhost:5173' } };\n",
    "search_indexes.py": ("from haystack import indexes\n"
                          "class NoteIndex(indexes.SearchIndex):\n    model = \"x\"\n"),
    "web/flags.js": "const model = 'o3';\nconst tier = 'o1';\n",
    # `/v1/messages` is an ordinary chat app's route too (second QC on UNVAR-91).
    "chat/send.py": (
        "import requests, subprocess\n"
        'BASE = "http://localhost:8000"\n'
        "def send(t):\n"
        '    resp = requests.post(BASE + "/v1/messages", json={"t": t})\n'
        "    job = resp.json()\n"
        '    subprocess.run(["notify", job["id"]])\n'
    ),
    "helpers.py": 'BASE_URL = "http://localhost:8000"\ndef OpenAI(x):\n    return x\n',
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
                       options={**DEFAULT_SCANNER_OPTIONS["ai_usage"], **options})


def _run(root: Path, files: dict[str, str], **options):
    ctx = _ctx(_write(root, files), **options)
    findings = AIUsageScanner().run(ctx)
    assert isinstance(ctx.inventory, AIUsage)
    return findings, ctx.inventory


def _rows(usage: AIUsage) -> set[tuple]:
    return {(s.provider, s.model, s.path, s.line, s.hosting) for s in usage.services}


def _tagged(findings, tag: str):
    return [f for f in findings if tag in f.tags]


def _where(finding) -> set[tuple[str, int | None]]:
    return {(e.path, e.line_start) for e in finding.evidence}


# --- acceptance 1: one row per SDK, raw HTTP and Ollama base URL ------------------------------

def test_sdk_raw_http_and_ollama_each_yield_a_row(tmp_path: Path):
    _, usage = _run(tmp_path, AI_FILES)
    assert _rows(usage) == {
        ("OpenAI", "gpt-4o-mini", "app/openai_chat.py", 12, "hosted"),
        ("Anthropic", "claude-sonnet-4-5", "svc/anthropic_http.js", 6, "hosted"),
        ("Ollama", "llama3.1:8b", "tools/local_llm.py", 8, "local"),
        ("Anthropic", "claude-opus-4-1", "agent/tools.py", 13, "hosted"),
    }
    calls = {(c.path, c.line) for c in usage.calls}
    assert calls == {("app/openai_chat.py", 11), ("svc/anthropic_http.js", 3),
                     ("tools/local_llm.py", 8), ("agent/tools.py", 13)}


def test_openai_sdk_pointed_at_a_local_server_is_that_server(tmp_path: Path):
    files = {"bot.py": (
        "from openai import OpenAI\n"
        'client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")\n'
        'reply = client.chat.completions.create(model="qwen2.5", messages=[], timeout=20)\n'
    ), "lm.ts": (
        'import OpenAI from "openai";\n'
        'const ai = new OpenAI({ baseURL: "http://127.0.0.1:8000/v1" });\n'
        'await ai.chat.completions.create({ model: "my-finetune", max_tokens: 50 });\n'
    )}
    findings, usage = _run(tmp_path, files)
    rows = {(s.provider, s.model, s.path, s.line, s.hosting, s.via) for s in usage.services}
    assert rows == {
        ("Ollama", "qwen2.5", "bot.py", 3, "local", "OpenAI SDK"),
        ("Local OpenAI-compatible server", "my-finetune", "lm.ts", 3, "local", "OpenAI SDK"),
    }
    assert findings == []


def test_dependencies_and_imports_without_a_model_id(tmp_path: Path):
    files = {
        "requirements.txt": "flask==3.0\nmistralai==1.0\n",
        "src/chain.py": "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n",
        "web/gen.ts": 'import { GoogleGenerativeAI } from "@google/generative-ai";\n',
    }
    _write(tmp_path, files)
    ctx = _ctx(tmp_path)
    from unvarnish.schemas.inventory import DependencyRecord
    ctx.dependencies = Dependencies(tool="t", dependencies=[
        DependencyRecord(ecosystem="PyPI", name="flask", constraint="==3.0",
                         manifest="requirements.txt"),
        DependencyRecord(ecosystem="PyPI", name="mistralai", constraint="==1.0",
                         manifest="requirements.txt"),
    ])
    AIUsageScanner().run(ctx)
    rows = {(s.provider, s.model, s.path, s.line, s.detected_by, s.via)
            for s in ctx.inventory.services}
    assert rows == {
        ("Mistral", None, "requirements.txt", 2, "dependency", None),
        ("OpenAI", None, "src/chain.py", 1, "import", "LangChain"),
        ("Google Gemini", None, "web/gen.ts", 1, "import", None),
    }


# --- acceptance 2: the prompt-injection review finding and the output sinks ------------------

def test_request_input_in_a_prompt_is_one_llm01_review_finding(tmp_path: Path):
    findings, _ = _run(tmp_path, AI_FILES)
    llm01 = _tagged(findings, "owasp-llm01")
    assert len(llm01) == 1
    assert "review" in llm01[0].tags and llm01[0].severity == Severity.medium
    assert _where(llm01[0]) == {("app/openai_chat.py", 10)}


def test_model_output_reaching_eval_or_subprocess_is_high(tmp_path: Path):
    findings, _ = _run(tmp_path, AI_FILES)
    sinks = _tagged(findings, "owasp-llm05")
    assert len(sinks) == 1 and sinks[0].severity == Severity.high
    assert _where(sinks[0]) == {("app/openai_chat.py", 16), ("tools/local_llm.py", 10)}


def test_output_into_sql_counts_only_when_built_into_the_query(tmp_path: Path):
    files = {"q.py": (
        "import anthropic\n"
        "client = anthropic.Anthropic(timeout=10)\n"
        'msg = client.messages.create(model="claude-haiku-4-5", max_tokens=100, messages=[])\n'
        "sql = msg.content[0].text\n"
        "cursor.execute(sql)\n"
        'cursor.execute("insert into notes values (?)", (sql,))\n'
        'cursor.execute(f"select * from t where name = \'{sql}\'")\n'
    )}
    findings, _ = _run(tmp_path, files)
    sinks = _tagged(findings, "owasp-llm05")
    assert len(sinks) == 1 and _where(sinks[0]) == {("q.py", 5), ("q.py", 7)}


def test_regex_exec_and_unrelated_names_are_not_sinks(tmp_path: Path):
    files = {"summ.js": (
        'import Anthropic from "@anthropic-ai/sdk";\n'
        "const client = new Anthropic({ timeout: 20000 });\n"
        "const msg = await client.messages.create({ model: 'claude-haiku-4-5', max_tokens: 9 });\n"
        "const text = msg.content[0].text;\n"
        "const m = /(\\d+)/.exec(text);\n"
        "execSync('ls -la');\n"
    )}
    findings, usage = _run(tmp_path, files)
    assert findings == [] and [(c.line, c.provider) for c in usage.calls] == [(3, "Anthropic")]


def test_unbounded_calls_and_tool_definitions(tmp_path: Path):
    findings, usage = _run(tmp_path, AI_FILES)
    unbounded = _tagged(findings, "owasp-llm10")
    assert len(unbounded) == 1 and unbounded[0].severity == Severity.low
    assert _where(unbounded[0]) == {("tools/local_llm.py", 8)}
    assert [(t.path, t.line, t.kind, t.name) for t in usage.tool_definitions] == [
        ("agent/tools.py", 8, "tool", "delete_file")]
    agency = _tagged(findings, "owasp-llm06")
    assert len(agency) == 1 and agency[0].severity == Severity.medium
    assert _where(agency[0]) == {("agent/tools.py", 8), ("agent/tools.py", 18)}


def test_tools_without_powerful_actions_are_recorded_without_a_finding(tmp_path: Path):
    files = {"agent.ts": (
        'import { generateText, tool } from "ai";\n'
        'import { openai } from "@ai-sdk/openai";\n'
        "const weather = tool({ description: 'weather', parameters: schema,\n"
        "  execute: async ({ city }) => lookup(city) });\n"
        'await generateText({ model: openai("gpt-4.1"), maxTokens: 200, tools: { weather } });\n'
    )}
    findings, usage = _run(tmp_path, files)
    assert [(t.line, t.kind, t.name) for t in usage.tool_definitions] == [(3, "tool", "weather")]
    assert _rows(usage) == {("OpenAI", "gpt-4.1", "agent.ts", 5, "hosted")}
    assert findings == []


# --- acceptance 3: nothing to report -----------------------------------------------------------

def test_a_tool_without_ai_usage_has_no_rows_and_no_findings(tmp_path: Path):
    findings, usage = _run(tmp_path, PLAIN_FILES)
    assert findings == [] and usage.services == [] and usage.calls == []
    assert usage.tool_definitions == []


def test_a_python_package_named_ai_is_not_the_vercel_ai_sdk(tmp_path: Path):
    files = {"app/main.py": "from ai.prompts import build\nimport ai\nx = build()\n",
             "ai/__init__.py": "", "web/chat.ts": 'import { generateText } from "ai";\n'}
    findings, usage = _run(tmp_path, files)
    assert {(s.provider, s.path) for s in usage.services} == {("Vercel AI SDK", "web/chat.ts")}
    assert findings == []


def test_a_large_handler_file_scans_in_linear_time(tmp_path: Path):
    import time

    handlers = "".join(
        f"def h{i}():\n    q{i} = request.args.get('q')\n    msg{i} = f'hi {{q{i}}}'\n"
        f"    log(msg{i})\n\n" for i in range(3000))
    body = ("from flask import request\nfrom openai import OpenAI\nclient = OpenAI()\n"
            + handlers + "r = client.chat.completions.create(model='gpt-4o', messages=[],"
            " max_tokens=5)\n")
    start = time.monotonic()
    findings, usage = _run(tmp_path, {"big.py": body})
    assert time.monotonic() - start < 20  # a whole-file pass per prompt line took minutes
    assert findings == [] and len(usage.calls) == 1


def test_a_loopback_base_url_with_a_model_path_is_a_local_server(tmp_path: Path):
    files = {"local.py": (
        "import requests\n"
        'BASE = "http://localhost:8080"\n'
        'r = requests.post(BASE + "/v1/chat/completions", json={"model": "qwen2.5"}, timeout=9)\n'
    )}
    findings, usage = _run(tmp_path, files)
    assert {(s.provider, s.model) for s in usage.services} == {
        ("Local OpenAI-compatible server", "qwen2.5")}
    assert [(c.line, c.provider) for c in usage.calls] == [(3, "Local OpenAI-compatible server")]
    assert findings == []


def test_reassigned_or_out_of_scope_names_are_not_model_output(tmp_path: Path):
    files = {"a.py": (
        "import subprocess\n"
        "from openai import OpenAI\n"
        "c = OpenAI(timeout=5)\n"
        "def a():\n"
        '    result = c.chat.completions.create(model="gpt-4o", messages=[])\n'
        "    return result\n"
        "\n"
        "def b(cmd):\n"
        "    result = build(cmd)\n"
        "    subprocess.run(result)\n"
        "\n"
        "def d(cmd):\n"
        "    subprocess.run(result)\n"
        "\n"
        "def e():\n"
        '    out = c.chat.completions.create(model="gpt-4o", messages=[])\n'
        "    if out.refusal:\n"
        '        out = "echo refused"\n'
        "    subprocess.run(out)\n"
    )}
    findings, _ = _run(tmp_path, files)
    sinks = _tagged(findings, "owasp-llm05")
    # Only the conditional reassignment leaves the output possibly reaching the shell.
    assert len(sinks) == 1 and _where(sinks[0]) == {("a.py", 19)}


CALL_LINE_SECRETS = [
    ('r = requests.post("https://generativelanguage.googleapis.com/v1beta/models/'
     'gemini-1.5-pro:generateContent?key={k}", json=p)', "AIzaSy" + _rand("gk", 33)),
    ('r = requests.post(url + "?key={k}", json=p)', "plainlowentropykey123"),
    ('r = requests.post(URL, headers={{"Ocp-Apim-Subscription-Key": "{k}"}}, json=p)',
     _rand("ocp", 32)),
    ('r = requests.post(URL, headers={{"X-Custom-Auth": "{k}"}}, json=p)', _rand("xca", 24)),
    ('r = httpx.post(URL, auth=("svc-user", "{k}"), json=p)', "Wq7!xPz93kLm"),
    ('r = requests.post("https://user:{k}@api.openai.com/v1/chat/completions", json=p)',
     "Sup3rS3cret"),
    ('resp = OpenAI("{k}").chat.completions.create(model="gpt-4o")', "zz" + _rand("pos", 24)),
    ('os.system("mysql -u root -p{k} db -e " + answer)', "S3cretPassw0rd"),
    ('os.environ["OPENAI_API_KEY"] = "{k}"', "abc123" + _rand("env", 20)),
    ("client = OpenAI(api_key = os.getenv('K', '{k}'))", "fallback" + _rand("fb", 14)),
    ('password: str = "{k}"; r = client.chat.completions.create(', "hunter2" + _rand("pw", 6)),
    ('cur.execute("INSERT INTO users VALUES (\'admin\', \'{k}\')")', "hunter2hunter2"),
    ('const r = await fetch(URL, {{ headers: {{ "api-key": "{k}" }} }})', _rand("js", 30)),
    ('os.system("PGPASSWORD={k} psql -c " + answer)', "hunter2"),
    ('subprocess.run(f"curl -u admin:{k} http://x -d {{answer}}", shell=True)', "hunter2"),
    ('os.system("sshpass -p {k} ssh host " + answer)', "hunter2"),
    ('os.system("sshpass -p \'{k}\' ssh host " + answer)', "hunter2"),
    ('r = requests.post(URL, json={{"password": pw, "pass": "{k}", "pin": "4821"}})', "hunter2"),
    ('r = requests.post(URL, json={{"user": "bob", "pin": "{k}"}})', "4821"),
    ('conn = psycopg2.connect("dbname=x user=bob password={k}"); cur.execute(answer)',
     "hunter2"),
    ('const r = await fetch(URL, {{headers: {{"x-api-key": KEY || "{k}"}}}})',
     "correcthorsebattery"),
    ('const key = API_KEY || "{k}";', "correcthorsebattery"),
    ('resp = OpenAI("{k}").chat.completions.create(model="gpt-4o")', "correcthorsebatterystaple"),
    ('r = requests.post(URL, headers={{"Authorization": "Bearer " + "{k}"}}, json=p)',
     "abcdefghijklmnop"),
    ('r = requests.post(URL, json=p, cookies={{"session": "{k}"}})', "correcthorsebattery"),
    ('r = requests.post(URL, json=p, headers=H)  # key is {k}', "hunter2hunter2x"),
    ('r = requests.post(URL, data="grant_type=password&username=bob&password={k}")', "hunter2"),
    # list-form command arguments: each flag and its value is its own element
    ('subprocess.run(["mysql", "-uroot", "-p{k}", "-e", sql])', "hunter2"),
    ('subprocess.run(["mysql", "-u", "root", "--password", "{k}", "-e", sql])', "hunter2"),
    ("subprocess.run(['sshpass', '-p', '{k}', 'ssh', 'db', sql])", "hunter2"),
    ('subprocess.run(["curl", "-u", "admin:{k}", "https://x.internal/run", "-d", sql])',
     "hunter2"),
    ('subprocess.run(["gpg", "--passphrase={k}", "-d", f])', "hunter2"),
    # names ending in pass, and a passphrase
    ('subprocess.run("DBPASS={k} ./run.sh " + sql, shell=True)', "hunter2"),
    ('subprocess.run("gpg --passphrase {k} -d f | " + sql, shell=True)', "hunter2"),
    ('r = requests.post(URL, json={{"dbpass": "{k}", "q": sql}})', "hunter2"),
    ('r = requests.post(URL, json={{"SMTPPASS": "{k}", "q": sql}})', "hunter2"),
]


def test_credentials_on_a_call_line_never_reach_an_excerpt():
    from unvarnish.scanners.ai_usage import scrub

    for template, key in CALL_LINE_SECRETS:
        line = template.format(k=key)
        out = scrub(line)
        assert key not in out, out
        assert "[redacted]" in out or "[comment removed]" in out, out
    kept = scrub('resp = client.chat.completions.create(model="gpt-4o-mini", max_tokens=300)')
    assert kept == 'resp = client.chat.completions.create(model="gpt-4o-mini", max_tokens=300)'
    assert "{question}" in scrub('prompt = f"Answer only with Python: {question}"')
    # a host name and a header name are kept: the line has no value to redact
    call = ('requests.post("https://generativelanguage.googleapis.com/v1beta/x", '
            'headers={"Ocp-Apim-Subscription-Key": k})')
    assert scrub(call) == call


def test_a_long_line_is_cut_before_it_is_scrubbed():
    from unvarnish.scanners.ai_usage import scrub

    key = "zz" + _rand("long", 30)
    line = 'r = client.chat.completions.create(model="gpt-4o", x="' + "a " * 700 + key + '")'
    assert key not in scrub(line) and len(scrub(line)) <= 1000
    cut = 'c = OpenAI(api_key="' + key  # a value cut short is still a value
    assert key not in scrub(cut)


def test_taint_follows_python_functions_and_statements(tmp_path: Path):
    files = {
        # A multi-line signature still opens a function: `result` ends with it.
        "sig.py": (
            "from openai import OpenAI\n"
            "c = OpenAI(timeout=5)\n"
            "def a(\n"
            "    x,\n"
            "):\n"
            '    result = c.chat.completions.create(model="gpt-4o", messages=[])\n'
            "    return result\n"
            "\n"
            "def b(result):\n"
            "    eval(result)\n"
        ),
        # A multi-line self-reassignment still reads the value; column-0 text in a string
        # does not end the function; an else branch does not replace the if branch's value.
        "keep.py": (
            "import re\n"
            "from openai import OpenAI\n"
            "c = OpenAI(timeout=5)\n"
            "def f(x):\n"
            '    text = c.chat.completions.create(model="gpt-4o", messages=[])\n'
            "    text = re.sub(\n"
            '        r"```", "", text)\n'
            '    note = """\n'
            "hello\n"
            '"""\n'
            "    eval(text)\n"
            "    if x:\n"
            '        cmd = c.chat.completions.create(model="gpt-4o", messages=[])\n'
            "    else:\n"
            '        cmd = "ls"\n'
            "    os.system(cmd)\n"
        ),
    }
    findings, _ = _run(tmp_path, files)
    sinks = _tagged(findings, "owasp-llm05")
    assert len(sinks) == 1 and _where(sinks[0]) == {("keep.py", 11), ("keep.py", 16)}


def test_javascript_function_bodies_are_statements(tmp_path: Path):
    files = {"a.ts": (
        'import OpenAI from "openai";\n'
        "const c = new OpenAI({ timeout: 5 });\n"
        "async function a() {\n"
        '  const result = await c.chat.completions.create({ model: "gpt-4o", messages: [] });\n'
        "  let code = result.choices[0].message.content;\n"
        "  code = code.trim();\n"
        "  eval(code);\n"
        "}\n"
    )}
    findings, _ = _run(tmp_path, files)
    assert _where(_tagged(findings, "owasp-llm05")[0]) == {("a.ts", 7)}


def test_request_input_reassigned_over_several_lines_is_still_request_input(tmp_path: Path):
    files = {"a.py": (
        "from flask import request\n"
        "from openai import OpenAI\n"
        "c = OpenAI(timeout=5)\n"
        "def f():\n"
        '    q = request.json["q"]\n'
        "    q = sanitize(\n"
        "        q)\n"
        '    prompt = f"Answer: {q}"\n'
        '    return c.chat.completions.create(model="gpt-4o", max_tokens=9,\n'
        '                                     messages=[{"role": "user", "content": prompt}])\n'
    )}
    findings, _ = _run(tmp_path, files)
    assert _where(_tagged(findings, "owasp-llm01")[0]) == {("a.py", 8)}


def test_many_rebinds_of_one_name_stay_linear(tmp_path: Path):
    import time

    body = "from openai import OpenAI\nc = OpenAI()\n" + "".join(
        "x = c.chat.completions.create(model='gpt-4o', max_tokens=5)\nx = 1\neval(x)\n"
        for _ in range(8000))
    start = time.monotonic()
    findings, _ = _run(tmp_path, {"kill.py": body})
    assert time.monotonic() - start < 20
    assert not _tagged(findings, "owasp-llm05")


def test_a_gemini_key_in_the_url_stays_out_of_the_findings(tmp_path: Path):
    key = "AIzaSy" + _rand("gemini-url", 33)
    files = {"g.py": (
        "import requests\n"
        'r = requests.post("https://generativelanguage.googleapis.com/v1beta/models/'
        f'gemini-1.5-pro:generateContent?key={key}", json={{}})\n'
    )}
    findings, usage = _run(tmp_path, files)
    assert findings and key not in json.dumps([f.model_dump(mode="json") for f in findings])
    assert key not in usage.model_dump_json()


def test_calls_before_a_minified_line_stay_fast(tmp_path: Path):
    import time

    body = ("import OpenAI from 'openai'\n"
            + "".join(f"const r{i} = await fetch(u{i}, {{\n" for i in range(30))
            + "var a=" + "x(y[z])," * 400_000 + "\n")
    start = time.monotonic()
    _run(tmp_path, {"big.js": body})
    assert time.monotonic() - start < 10  # each call's span scanned the 3 MB line: 30 s


# --- acceptance 5: tests and vendored code -----------------------------------------------------

def test_tests_vendored_and_docs_are_excluded_unless_tests_are_included(tmp_path: Path):
    findings, usage = _run(tmp_path, AI_FILES)
    paths = ({s.path for s in usage.services} | {c.path for c in usage.calls}
             | {e.path for f in findings for e in f.evidence})
    assert not {"tests/test_llm.py", "node_modules/openai/index.js", "README.md"} & paths
    findings, usage = AIUsageScanner().run(_ctx(tmp_path, include_tests=True)), None
    sinks = _tagged(findings, "owasp-llm05")
    assert ("tests/test_llm.py", 3) in _where(sinks[0])


# --- acceptance 6: redaction -------------------------------------------------------------------

def test_keys_beside_calls_never_reach_the_output(tmp_path: Path):
    findings, usage = _run(tmp_path, AI_FILES)
    blob = json.dumps([f.model_dump(mode="json") for f in findings]) + usage.model_dump_json()
    assert OPENAI_KEY not in blob and PLAIN_KEY not in blob
    assert not any("key" in f.title.lower() or "secret" in f.title.lower() for f in findings)


def test_registered_with_default_options_and_effort_bands():
    assert "ai_usage" in [s.name for s in builtin_scanners()]
    assert DEFAULT_SCANNER_OPTIONS["ai_usage"] == {"max_evidence": 25, "include_tests": False}
    assert set(EFFORT_RULES["ai_usage"]) == {"prompt_injection", "output_sink",
                                             "unbounded_calls", "agent_tools"}


# --- the pipeline: the artifact, the documents and extraction ----------------------------------

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


def _write_tool_model(ctx) -> None:
    """A tool.json as rollup_tool writes it, without a model call."""
    from tests.test_rollup_tool import TOOL
    from unvarnish.schemas.cost import Usage
    from unvarnish.schemas.toolmodel import ToolModel

    data = {k: v for k, v in json.loads(TOOL).items() if k != "candidate_findings"}
    data["capabilities"] = []
    tm = ToolModel(tool=ctx.tool, **data, backend="stub", model="stub", usage=Usage(),
                   prompt_version="test")
    write_artifact(ctx.paths.tool_model, tm, produced_by="rollup_tool", inputs_hash="")


def test_scan_writes_the_inventory_and_architecture_renders_it_without_a_model(engagement):
    from unvarnish.phases.render import RenderPhase

    assert engagement.config.models.default is None
    ctx = _engagement_run(engagement, "ai", AI_FILES, _scan_phases())
    usage = read_artifact(ctx.paths.ai_usage, AIUsage).data
    assert ("Ollama", "llama3.1:8b", "tools/local_llm.py", 8, "local") in _rows(usage)
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    assert "ai_usage" in scan.scanners_run and not scan.skipped
    _write_tool_model(ctx)
    assert PhaseRunner([RenderPhase()]).run(ctx)[0].status == PhaseStatus.ok
    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    section = arch.split("**AI services used (scanner)**", 1)[1].split("\n## ", 1)[0]
    assert "| Provider | Model | Location | Hosting |" in section
    assert "| Ollama | `llama3.1:8b` | `tools/local_llm.py:8` | local |" in section
    assert "| OpenAI | `gpt-4o-mini` | `app/openai_chat.py:12` | hosted |" in section
    assert "`agent/tools.py:8` (tool `delete_file`)" in section
    for doc in (arch, ctx.paths.findings_doc.read_text(encoding="utf-8")):
        assert OPENAI_KEY not in doc and PLAIN_KEY not in doc


def test_architecture_says_none_found_for_a_tool_without_ai(engagement):
    from unvarnish.phases.render import RenderPhase

    ctx = _engagement_run(engagement, "plain", PLAIN_FILES, _scan_phases())
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    assert not [f for f in scan.findings if f.scanner == "ai_usage"]
    _write_tool_model(ctx)
    PhaseRunner([RenderPhase()]).run(ctx)
    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    section = arch.split("**AI services used (scanner)**", 1)[1].split("\n## ", 1)[0]
    assert "| — | — | None found | — |" in section


def test_without_the_scanner_the_architecture_says_not_checked(engagement):
    from unvarnish.phases.render import RenderPhase

    ctx = _engagement_run(engagement, "old", PLAIN_FILES, _scan_phases(scanners=[]))
    assert not ctx.paths.ai_usage.exists()
    _write_tool_model(ctx)
    PhaseRunner([RenderPhase()]).run(ctx)
    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    assert "Not checked: the ai_usage scanner did not run" in arch


def test_comparison_risk_table_gains_the_ai_services_measure(engagement):
    from unvarnish.phases.compare import run_comparison

    _engagement_run(engagement, "ai", AI_FILES, _scan_phases())
    _engagement_run(engagement, "plain", PLAIN_FILES, _scan_phases())
    _engagement_run(engagement, "old", PLAIN_FILES, _scan_phases(scanners=[]))
    run_comparison(engagement)  # no model configured: the risk table is built from JSON
    doc = engagement.comparison_doc.read_text(encoding="utf-8")
    row = next(line for line in doc.splitlines() if line.startswith("| AI services used"))
    assert row == ("| AI services used | hosted: Anthropic, OpenAI; local: Ollama | none found "
                   "| not checked | ")


def test_model_calls_reach_extraction_as_scanner_notes(engagement):
    from tests.test_render_documents import _stub
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.phases.extract import ExtractPhase
    from unvarnish.phases.split import SplitPhase

    files = {"tools/local_llm.py": AI_FILES["tools/local_llm.py"],
             "lib/util.py": "A = 1\n"}
    ctx = _engagement_run(engagement, "ai", files, [*_scan_phases(), SplitPhase()])
    assert ai_hints(ctx.paths.ai_usage) == {"tools/local_llm.py": [8]}
    assert ai_hints(ctx.paths.root / "missing.json") == {}
    ctx.budget = BudgetTracker(None)
    stub = _stub()
    assert PhaseRunner([ExtractPhase(backend=stub)]).run(ctx)[0].status == PhaseStatus.ok
    msgs = [r.messages[-1].content for r in stub.requests if r.schema_name == "UnitExtraction"]
    llm = [m for m in msgs if "File: tools/local_llm.py" in m]
    other = [m for m in msgs if "File: lib/util.py" in m]
    assert llm and any("Scanner note" in m and "model" in m and "line 8" in m for m in llm)
    assert other and not any("Scanner note" in m for m in other)


def test_ai_hints_ignore_an_unreadable_artifact(tmp_path: Path):
    bad = tmp_path / "ai-usage.json"
    bad.write_text("{not json", encoding="utf-8")
    assert ai_hints(bad) == {}
