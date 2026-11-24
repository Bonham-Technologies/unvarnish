"""How a tool's own code uses AI: which model providers it sends data to, and four checks.

Records each AI SDK import, provider endpoint (raw HTTP included), model id and declared AI
dependency, classified hosted or local, as `inventory/ai-usage.json` (UNVAR-91). Four checks
follow the OWASP Top 10 for LLM applications: request input built into a prompt (LLM01, one
review finding), model output reaching eval/exec, a shell or SQL (LLM05, high), model calls
with no token cap or timeout (LLM10) and model-callable tools beside powerful actions (LLM06).
Heuristic, per file, for Python and JavaScript/TypeScript (endpoints and model ids in any
language); a false positive costs more than a miss. Offline and deterministic."""

from __future__ import annotations

import functools
import heapq
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.hardcoded_infra import COMMENT_LINE_RE
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.ai_usage import AICall, AIService, AIToolDefinition, AIUsage
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.plural import plural

NAME = "ai_usage"
MAX_FILE_BYTES = 5_000_000
MAX_LINE_CHARS = 4000  # longer lines are minified bundles
MAX_CALL_LINES = 40  # how far a call's argument list is followed
JS_LANGUAGES = {"javascript", "typescript", "tsx", "vue", "svelte"}


@dataclass(frozen=True)
class Provider:
    hosting: str = "hosted"
    gateway: bool = False  # serves other vendors' models: the model id does not name it
    framework: bool = False  # provider-agnostic orchestration; the model decides the provider


# --- the data tables: extend these, not the code ---------------------------------------------

PROVIDERS: dict[str, Provider] = {
    "OpenAI": Provider(), "Anthropic": Provider(), "Google Gemini": Provider(),
    "Mistral": Provider(), "Cohere": Provider(), "DeepSeek": Provider(), "xAI": Provider(),
    "Perplexity": Provider(),
    "Azure OpenAI": Provider(gateway=True), "Google Vertex AI": Provider(gateway=True),
    "AWS Bedrock": Provider(gateway=True), "Groq": Provider(gateway=True),
    "Together AI": Provider(gateway=True), "OpenRouter": Provider(gateway=True),
    "Replicate": Provider(gateway=True), "Hugging Face": Provider(gateway=True),
    "Ollama": Provider(hosting="local", gateway=True),
    "LM Studio": Provider(hosting="local", gateway=True),
    "Local OpenAI-compatible server": Provider(hosting="local", gateway=True),
    "LangChain": Provider(hosting="unknown", framework=True),
    "LlamaIndex": Provider(hosting="unknown", framework=True),
    "Vercel AI SDK": Provider(hosting="unknown", framework=True),
    "LiteLLM": Provider(hosting="unknown", framework=True),
    "Semantic Kernel": Provider(hosting="unknown", framework=True),
    "Haystack": Provider(hosting="unknown", framework=True),
    "CrewAI": Provider(hosting="unknown", framework=True),
    "AutoGen": Provider(hosting="unknown", framework=True),
}

# Import names (Python modules and JS package specifiers) -> (provider, via).
IMPORTS: dict[str, tuple[str, str | None]] = {
    "openai": ("OpenAI", None), "anthropic": ("Anthropic", None),
    "@anthropic-ai/sdk": ("Anthropic", None), "@anthropic-ai/bedrock-sdk": ("AWS Bedrock", None),
    "@anthropic-ai/vertex-sdk": ("Google Vertex AI", None),
    "google.generativeai": ("Google Gemini", None), "google.genai": ("Google Gemini", None),
    "@google/generative-ai": ("Google Gemini", None), "@google/genai": ("Google Gemini", None),
    "vertexai": ("Google Vertex AI", None), "google.cloud.aiplatform": ("Google Vertex AI", None),
    "@google-cloud/vertexai": ("Google Vertex AI", None),
    "mistralai": ("Mistral", None), "@mistralai/mistralai": ("Mistral", None),
    "cohere": ("Cohere", None), "cohere-ai": ("Cohere", None),
    "groq": ("Groq", None), "groq-sdk": ("Groq", None), "together": ("Together AI", None),
    "together-ai": ("Together AI", None), "replicate": ("Replicate", None),
    "ollama": ("Ollama", None), "@azure/openai": ("Azure OpenAI", None),
    "@aws-sdk/client-bedrock-runtime": ("AWS Bedrock", None),
    "huggingface_hub": ("Hugging Face", None), "@huggingface/inference": ("Hugging Face", None),
    # Framework adapters name their provider.
    "langchain_openai": ("OpenAI", "LangChain"), "@langchain/openai": ("OpenAI", "LangChain"),
    "langchain_anthropic": ("Anthropic", "LangChain"),
    "@langchain/anthropic": ("Anthropic", "LangChain"),
    "langchain_google_genai": ("Google Gemini", "LangChain"),
    "@langchain/google-genai": ("Google Gemini", "LangChain"),
    "langchain_google_vertexai": ("Google Vertex AI", "LangChain"),
    "langchain_mistralai": ("Mistral", "LangChain"), "langchain_cohere": ("Cohere", "LangChain"),
    "langchain_groq": ("Groq", "LangChain"), "langchain_aws": ("AWS Bedrock", "LangChain"),
    "langchain_ollama": ("Ollama", "LangChain"), "@langchain/ollama": ("Ollama", "LangChain"),
    "llama_index.llms.openai": ("OpenAI", "LlamaIndex"),
    "llama_index.llms.anthropic": ("Anthropic", "LlamaIndex"),
    "llama_index.llms.ollama": ("Ollama", "LlamaIndex"),
    "@ai-sdk/openai": ("OpenAI", "Vercel AI SDK"),
    "@ai-sdk/anthropic": ("Anthropic", "Vercel AI SDK"),
    "@ai-sdk/google": ("Google Gemini", "Vercel AI SDK"),
    "@ai-sdk/google-vertex": ("Google Vertex AI", "Vercel AI SDK"),
    "@ai-sdk/mistral": ("Mistral", "Vercel AI SDK"),
    "@ai-sdk/amazon-bedrock": ("AWS Bedrock", "Vercel AI SDK"),
    "ollama-ai-provider": ("Ollama", "Vercel AI SDK"),
    # Frameworks alone: the model, not the import, says where data goes.
    "langchain": ("LangChain", None), "langchain_core": ("LangChain", None),
    "langchain_community": ("LangChain", None), "@langchain/core": ("LangChain", None),
    "llama_index": ("LlamaIndex", None), "llamaindex": ("LlamaIndex", None),
    "ai": ("Vercel AI SDK", None), "litellm": ("LiteLLM", None),
    "semantic_kernel": ("Semantic Kernel", None), "haystack": ("Haystack", None),
    "crewai": ("CrewAI", None), "autogen": ("AutoGen", None),
    "autogen_agentchat": ("AutoGen", None),
}
# JavaScript package names that are ordinary Python package names (a local `ai/` package).
JS_ONLY_IMPORTS = {"ai", "llamaindex"}
# django-haystack (search indexes) shares the `haystack` name with deepset's framework.
DJANGO_HAYSTACK_RE = re.compile(
    r"^\s*(?:from\s+haystack(?:\s+import\s+|\.)|import\s+haystack\.)(?:indexes|query|forms"
    r"|views|generic_views|inputs|signals|backends|management|models|exceptions|constants"
    r"|fields|routers|admin|panels|apps)\b")
# Declared dependencies (lower case; PyPI names compared with "_" as "-").
PACKAGES: dict[str, str] = {
    **{name.replace("_", "-"): provider for name, (provider, _) in IMPORTS.items()
       if "." not in name},
    "google-generativeai": "Google Gemini", "google-genai": "Google Gemini",
    "google-cloud-aiplatform": "Google Vertex AI", "openai-agents": "OpenAI",
    "llama-index-llms-openai": "OpenAI", "llama-index-llms-anthropic": "Anthropic",
    "llama-index-llms-ollama": "Ollama", "llama-index": "LlamaIndex",
}
# Client class names that mark a provider reached through another vendor's SDK.
MARKERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:AzureOpenAI|AsyncAzureOpenAI|AzureChatOpenAI|azure_endpoint)\b"),
     "Azure OpenAI"),
    (re.compile(r"\b(?:AnthropicBedrock|ChatBedrock\w*|BedrockChat)\b"), "AWS Bedrock"),
    (re.compile(r"\b(?:AnthropicVertex|ChatVertexAI)\b"), "Google Vertex AI"),
]
# API hosts, matched in any text file (raw HTTP in any language).
_HOSTS: list[tuple[str, str]] = [
    (r"api\.openai\.com", "OpenAI"),
    (r"[\w-]+\.openai\.azure\.com", "Azure OpenAI"),
    (r"api\.anthropic\.com", "Anthropic"),
    (r"generativelanguage\.googleapis\.com", "Google Gemini"),
    (r"(?:[\w-]+-)?aiplatform\.googleapis\.com", "Google Vertex AI"),
    (r"api\.mistral\.ai", "Mistral"),
    (r"api\.cohere\.(?:ai|com)", "Cohere"),
    (r"api\.groq\.com", "Groq"),
    (r"api\.together\.(?:xyz|ai)", "Together AI"),
    (r"openrouter\.ai", "OpenRouter"),
    (r"api\.deepseek\.com", "DeepSeek"),
    (r"api\.x\.ai", "xAI"),
    (r"api\.perplexity\.ai", "Perplexity"),
    (r"api\.replicate\.com", "Replicate"),
    (r"(?:api-inference|router)\.huggingface\.co", "Hugging Face"),
    (r"bedrock-runtime(?:\.[\w-]+\.amazonaws\.com)?", "AWS Bedrock"),
    (r"[\w.-]+:11434", "Ollama"),
    (r"(?:localhost|127\.0\.0\.1):1234/v1", "LM Studio"),
    (r"OLLAMA_(?:HOST|BASE_URL|API_BASE)", "Ollama"),
]
HOSTS = [(re.compile(rf"(?<![\w.-]){p}(?![\w-])"), name) for p, name in _HOSTS]
LOCAL_BASE_RE = re.compile(
    r"(?i)base_?url[\"']?\s*[:=]\s*[\"']https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"host\.docker\.internal)\b")
LOCAL_SERVER = "Local OpenAI-compatible server"
# Every web app has a loopback base URL; one counts as a model server only beside another AI
# signal in the file (an SDK import or an OpenAI-compatible client), or with a model API path.
LOOPBACK_RE = re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]"
                         r"|host\.docker\.internal)\b")
LOCAL_AI_PATH_RE = re.compile(r"/v1/(?:chat/)?completions|/chat/completions|/v1/embeddings"
                              r"|/v1/messages")
CLIENT_RE = re.compile(r"(?<![\w.])(?:Async)?(?:Azure)?(?:OpenAI|ChatOpenAI|OpenAILike"
                       r"|OpenAIEmbeddings)\(")
BASE_KEY_RE = re.compile(r"(?i)base_?url[\"']?\s*[:=]")
# Model ids, matched whole against string literals; the first match names the provider.
_MODELS: list[tuple[str, str]] = [
    (r"(?:[a-z]{2}\.)?anthropic\.claude-[\w.:-]+", "AWS Bedrock"),
    (r"claude-[a-z0-9][\w.:@-]*", "Anthropic"),
    (r"gpt-(?:3\.5|4|5)[\w.:-]*|chatgpt-[\w.-]+|o[1345](?:-(?:mini|pro|preview)[\w.-]*)?"
     r"|text-embedding-(?:3|ada)[\w-]*|dall-e-[23]|whisper-1|tts-1(?:-hd)?|gpt-image-[\w.-]+",
     "OpenAI"),
    (r"(?:models/)?gemini-[\w.-]+", "Google Gemini"),
    (r"(?:open-)?(?:mistral|mixtral|codestral|ministral|pixtral|magistral|devstral)-[\w.-]+",
     "Mistral"),
    (r"command-(?:r|a|light|nightly)[\w.-]*|embed-(?:english|multilingual)-[\w.-]+", "Cohere"),
    (r"grok-[\w.-]+", "xAI"),
    (r"deepseek-(?:chat|reasoner|coder)[\w.-]*", "DeepSeek"),
]
MODELS = [(re.compile(p), name) for p, name in _MODELS]
STRING_RE = re.compile(r"""(["'`])([^"'`\s]{1,120})\1""")
MODEL_KEY_RE = re.compile(
    r"""(?i)\b\w*model(?:_?(?:name|id))?["']?\s*[:=]\s*(["'`]?)([A-Za-z0-9][\w.:/@-]{0,99})""")
MODEL_VALUE_RE = re.compile(r"[A-Za-z0-9][\w.:/@-]{0,99}")
# Values on a `model` line that are not model ids: Django's "auth.User", a class name.
NOT_MODEL_RE = re.compile(r"(?:\w+\.)?[A-Z][A-Za-z]*")
# A bare o-series id ("o1", "o3") is a model only on a `model` line in a file that uses AI.
BARE_O_RE = re.compile(r"o\d")

# Calls that send a request to a model: (pattern, providers one of which the file must use;
# None for any).
CALLS: list[tuple[re.Pattern[str], tuple[str, ...] | None]] = [
    (re.compile(r"\.chat\.completions\.(?:create|parse|stream)\(|\bChatCompletion\.a?create\("
                r"|\.responses\.(?:create|parse|stream)\("), None),
    (re.compile(r"\.messages\.(?:create|stream)\("),
     ("Anthropic", "AWS Bedrock", "Google Vertex AI")),
    (re.compile(r"\.generate_content(?:_async)?\(|\.generateContent(?:Stream)?\("),
     ("Google Gemini", "Google Vertex AI")),
    (re.compile(r"\bollama\.(?:chat|generate)\("), ("Ollama",)),
    (re.compile(r"(?<![\w.])(?:generateText|streamText|generateObject|streamObject)\("),
     ("Vercel AI SDK",)),
    (re.compile(r"\blitellm\.a?completion\("), ("LiteLLM",)),
    (re.compile(r"\.(?:converse|converse_stream|invoke_model)\("), ("AWS Bedrock",)),
    (re.compile(r"\b\w*(?:llm|chat|model|chain|agent)\w*\.a?invoke\(", re.I),
     ("LangChain", "LlamaIndex")),
]
HTTP_CALL_RE = re.compile(
    r"\b(?:requests|httpx|axios|aiohttp|http|session|client|\w+_session)\.(?:post|request)\("
    r"|(?<![\w.])fetch\(")
CAP_RE = re.compile(r"(?i)max_?(?:completion_?|output_?|new_?)?tokens|num_predict"
                    r"|max_tokens_to_sample")
SPREAD_RE = re.compile(r"\*\*[A-Za-z_]|\.\.\.[A-Za-z_]")
TIMEOUT_RE = re.compile(r"(?i)timeout|AbortSignal")

# Request input: web frameworks, serverless events and UI inputs.
REQUEST_RE = re.compile(
    r"\b(?:request|req)\.(?:json|form|args|values|data|body|query|params|get_json|query_params"
    r"|path_params|POST|GET|files|text)\b|\b(?:searchParams|formData)\.get\("
    r"|\bevent\[[\"']body[\"']\]|\bevent\.body\b|\bst\.(?:text_input|text_area|chat_input)\(")
ASSIGN_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?(?:\{([^}]*)\}|([A-Za-z_]\w*)(?:\s*:\s*[\w\[\], .|]+)?)"
    r"\s*=(?!=)\s*")
CALL_PREFIX_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?(?:\{([^}]*)\}|([A-Za-z_]\w*)(?:\s*:\s*[\w\[\], .|]+)?)"
    r"\s*=\s*(?:await\s+)?[\w.()\[\]]*$")
TRIPLE_RE = re.compile(r"(\bf)?(\"\"\"|''')|`")

# Where output must not go.
EXEC_RE = re.compile(
    r"(?<![\w.])(?:eval|exec)\(|\bos\.(?:system|popen)\(|\bsubprocess\.\w+\("
    r"|(?<![\w.])(?:execSync|execFile|execFileSync|spawn|spawnSync)\(|\bchild_process\.\w+\("
    r"|\bnew Function\(|\bvm\.run\w*\(")
SQL_RE = re.compile(r"\.(?:execute|executemany|executescript|raw|query|\$queryRawUnsafe"
                    r"|\$executeRawUnsafe)\(")
# Actions a model-callable tool should not reach unguarded.
ACTION_RE = re.compile(
    EXEC_RE.pattern + r"|\bos\.(?:remove|unlink|rmdir)\(|\bshutil\.rmtree\("
    r"|\bfs\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\(|(?<![\w.])(?:rmSync|unlinkSync)\("
    r"|(?i:\b(?:delete\s+from|drop\s+table|truncate\s+table|insert\s+into|update\s+\w+\s+set)\b)")
TOOL_RES: list[tuple[re.Pattern[str], str, str]] = [
    # (pattern, kind, where the name is: "after", "before", "def", "group")
    (re.compile(r"[\"']type[\"']\s*:\s*[\"']function[\"']"), "tool", "after"),
    (re.compile(r"[\"']?input_schema[\"']?\s*[:=]"), "tool", "before"),
    (re.compile(r"^\s*@(?:tool|function_tool)\b"), "tool", "def"),
    (re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*tool\(|\b(\w+)\s*:\s*tool\("), "tool",
     "group"),
    (re.compile(r"\bDynamicStructuredTool\(|\bStructuredTool\.from_function\("), "tool", "none"),
    (re.compile(r"\b(?:AgentExecutor|create_react_agent|create_tool_calling_agent"
                r"|create_openai_tools_agent|create_openai_functions_agent|initialize_agent)\("),
     "agent", "none"),
]
TOOL_NAME_RE = re.compile(r"[\"']name[\"']\s*:\s*[\"']([\w-]+)[\"']")
DEF_NAME_RE = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")

# Excerpt redaction (`scrub`). Each pattern is linear: no nested or adjacent unbounded repeats.
_QUOTED = r"([\"'`])((?:\\.|(?!\{q})[^\\\n])*)\{q}"
NAMED_VALUE_RE = re.compile(
    r"(?<![\w-])([\w-]+)([\"'\]]*(?:\s*:\s*[A-Za-z_][\w\[\]., |]{0,40}?)?\s*[:=]\s*"
    r"[rbufRBUF]{0,2})" + _QUOTED.format(q=3))
SECRET_NAME_RE = re.compile(r"(?i)key|auth|token|secret|passw|pwd|sig|credential|cookie")
URL_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@\"'`]+@")
URL_QUERY_RE = re.compile(r"([?&][\w.\-\[\]]+=)[^&#\s\"'`]+")
ENV_DEFAULT_RE = re.compile(
    r"((?:getenv|environ\.get|env\.get)\(\s*[^,()\n]{0,200},\s*[rbufRBUF]{0,2})"
    + _QUOTED.format(q=2)
    + r"|(process\.env\.\w+\s*(?:\|\||\?\?)\s*)" + _QUOTED.format(q=5))
AUTH_ARGS_RE = re.compile(r"(?i)(\bauth\s*[=:]\s*[(\[])[^)\]\n]*"
                          r"|(\b\w*(?:Basic|Digest|Proxy)Auth\w*\()[^)\n]*")
CLI_SECRET_RE = re.compile(r"(?<=\s)(-p)[^\s\"'`]+"
                           r"|(--?(?i:password|passwd|pass|pwd|token|api-?key|secret)[= ])"
                           r"[^\s\"'`]+")
STRING_LIT_RE = re.compile(_QUOTED.format(q=1))
LIT_TOKEN_RE = re.compile(r"[^\s/?&=:,;'\"`(){}\[\]<>|\\]{12,}")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
R = "[redacted]"


HOSTNAME_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}")


def _lit_token(m: re.Match[str]) -> str:
    """A key-shaped token inside a string literal: 12 or more characters with letters and
    digits, not a model id or a host name."""
    tok = m.group(0)
    shaped = re.search(r"[A-Za-z]", tok) and re.search(r"\d", tok)
    keep = model_provider(tok) is not None or HOSTNAME_RE.fullmatch(tok)
    return R if shaped and not keep else tok


def scrub(text: str) -> str:
    """An excerpt without credentials, by construction: the secrets rules' redaction, then
    URL userinfo and query values, the quoted value of any name that mentions a key, token,
    secret, password, signature, auth or cookie, env-lookup defaults, auth tuples and Basic
    auth arguments, password flags on a command line, and any key-shaped token inside a
    string literal (a positional key to a client) unless it is a model id. A key beside a call
    is the secrets scanner's finding, not ours."""
    text = redact_text(text)
    text = URL_USERINFO_RE.sub(lambda m: f"{m.group(1)}{R}@", text)
    text = URL_QUERY_RE.sub(lambda m: f"{m.group(1)}{R}", text)
    text = NAMED_VALUE_RE.sub(
        lambda m: (f"{m.group(1)}{m.group(2)}{m.group(3)}{R}{m.group(3)}"
                   if SECRET_NAME_RE.search(m.group(1)) else m.group(0)), text)
    text = ENV_DEFAULT_RE.sub(
        lambda m: (f"{m.group(1)}{m.group(2)}{R}{m.group(2)}" if m.group(1) is not None
                   else f"{m.group(4)}{m.group(5)}{R}{m.group(5)}"), text)
    text = AUTH_ARGS_RE.sub(lambda m: f"{m.group(1) or m.group(2)}{R}", text)
    text = CLI_SECRET_RE.sub(lambda m: f"{m.group(1) or m.group(2)}{R}", text)
    text = STRING_LIT_RE.sub(
        lambda m: m.group(1) + LIT_TOKEN_RE.sub(_lit_token, m.group(2)) + m.group(1), text)
    return BEARER_RE.sub(f"Bearer {R}", text)


def model_provider(value: str) -> str | None:
    return next((name for rx, name in MODELS if rx.fullmatch(value)), None)


@functools.lru_cache(maxsize=4096)
def _word(name: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w.]){re.escape(name)}\b")


def _targets(m: re.Match[str]) -> list[str]:
    """The names an assignment binds: one, or each in a destructuring `{ a, b: c }`."""
    if m.group(2):
        return [m.group(2)]
    out = []
    for part in (m.group(1) or "").split(","):
        part = part.split("=")[0].strip()
        part = part.split(":")[-1].strip()
        if re.fullmatch(r"[A-Za-z_]\w*", part):
            out.append(part)
    return out


TOKEN_RE = re.compile(r"(?<![\w.])\w+")


def _tokens(text: str) -> set[str]:
    """The names `_word(name)` would find in `text`: each whole word not after a dot."""
    return set(TOKEN_RE.findall(text))


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


Taint = dict[str, list[list[int]]]  # name -> [first line tainted, line it ends] intervals


def _live(taint: Taint, name: str, n: int, *, strict: bool) -> bool:
    """Whether `name` holds a tainted value on line `n`: bound before it (`strict`) or on it."""
    return any((s < n if strict else s <= n) and n < e for s, e in taint.get(name, ()))


def _span_end(text: str, start: int) -> int:
    """The index just past the parenthesis that closes the one at `start` (approximate:
    brackets in strings count)."""
    depth = 0
    for i in range(start, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


@dataclass
class _Signal:
    provider: str
    line: int
    kind: str  # "import", "endpoint"
    via: str | None = None


@dataclass
class _Call:
    line: int
    end_line: int
    text: str
    provider: str | None
    outputs: list[str]


@dataclass
class _File:
    path: str
    language: str | None
    lines: list[str]
    code: list[bool]  # False for comment lines and minified lines
    signals: list[_Signal] = field(default_factory=list)
    calls: list[_Call] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @functools.cached_property
    def assigns(self) -> list[tuple[int, list[str], set[str]]]:
        """(line, names bound, names read) for each assignment on a code line."""
        out = []
        for n, line in enumerate(self.lines, start=1):
            m = ASSIGN_RE.match(line) if self.code[n - 1] else None
            if m:
                out.append((n, _targets(m), _tokens(line[m.end():])))
        return out

    @functools.cached_property
    def touching(self) -> dict[str, list[int]]:
        """Each name -> the lines of the assignments that read or bind it."""
        out: dict[str, list[int]] = defaultdict(list)
        for n, targets, names in self.assigns:
            for name in names | set(targets):
                out[name].append(n)
        return out

    @functools.cached_property
    def assign_at(self) -> dict[int, tuple[list[str], set[str]]]:
        return {n: (targets, names) for n, targets, names in self.assigns}

    @functools.cached_property
    def scope_ends(self) -> list[int]:
        """For each line (index n - 1), the line that ends the Python function holding it, or
        past the file's end: a value bound in a function is not seen by the next one."""
        end = len(self.lines) + 1
        out = [end] * len(self.lines)
        if self.language != "python":
            return out
        stack: list[tuple[int, int]] = []  # (def indentation, def line)
        for n, line in enumerate(self.lines, start=1):
            if not line.strip() or not self.code[n - 1]:
                continue
            ind = _indent(line)
            while stack and ind <= stack[-1][0]:
                _, opened = stack.pop()
                for k in range(opened, n):
                    if out[k - 1] == end:  # an inner function already set its own lines
                        out[k - 1] = n
            if DEF_NAME_RE.match(line):
                stack.append((ind, n))
        return out

    def kills(self, n: int, since: int) -> bool:
        """Whether the assignment on line `n` replaces a value bound on line `since`: a whole
        statement (not a keyword argument inside a call) at the same or a lower indentation
        (not a branch that may not run)."""
        line = self.lines[n - 1].split("#")[0].rstrip()
        return (not line.endswith(",") and line.count(")") <= line.count("(")
                and _indent(line) <= _indent(self.lines[since - 1]))

    def span(self, line: int, col: int) -> tuple[str, int]:
        """The text of the call whose parenthesis is at (line, col), and its last line."""
        parts: list[str] = []
        size = 0
        for text in self.lines[line - 1:line - 1 + MAX_CALL_LINES]:
            parts.append(text[:col + MAX_LINE_CHARS - size] if parts else text)
            size += len(parts[-1]) + 1
            if size > col + MAX_LINE_CHARS:
                break
        chunk = "\n".join(parts)  # capped: a minified line after a call is not its argument
        start = col
        end = _span_end(chunk, start)
        return chunk[start:end], line + chunk[start:end].count("\n")


class AIUsageScanner:
    name = NAME
    category = Category.security

    def run(self, ctx: ScanContext) -> list[Finding]:
        self._ctx = ctx
        self._max = int(ctx.options.get("max_evidence", 25))
        include_tests = bool(ctx.options.get("include_tests", False))
        classes = {Classification.source, Classification.config}
        if include_tests:
            classes.add(Classification.test)
        allowed = {r.path for r in ctx.census.files
                   if not r.excluded and r.classification in classes
                   and r.bytes <= MAX_FILE_BYTES}
        usage = AIUsage(tool=ctx.tool)
        injections: list[Evidence] = []
        sinks: list[Evidence] = []
        unbounded: list[Evidence] = []
        agency: list[Evidence] = []
        agency_defs = 0
        agency_files: set[str] = set()
        for rec in ctx.census.files:
            if rec.path not in allowed:
                continue
            f = self._read(ctx.source_root, rec.path, rec.language)
            if f is None:
                continue
            self._signals(f)
            services = self._services(f)
            usage.services.extend(services)
            if not f.signals and not services:
                continue
            self._calls(f)
            bounded_file = self._bounded_file(f)
            for c in f.calls:
                bounded = bounded_file or bool(CAP_RE.search(c.text) or SPREAD_RE.search(c.text))
                usage.calls.append(AICall(path=f.path, line=c.line, provider=c.provider,
                                          bounded=bounded))
                if not bounded:
                    unbounded.append(self._evidence(f, c.line, c.provider))
            if not f.calls and not f.signals:
                continue
            injections += [self._evidence(f, n) for n in self._injections(f)]
            sinks += [self._evidence(f, n, note) for n, note in self._sinks(f)]
            defs = self._tool_definitions(f)
            usage.tool_definitions.extend(defs)
            actions = self._actions(f) if defs else []
            if actions:
                agency_defs += len(defs)
                agency_files.add(f.path)
                agency += [self._evidence(f, d.line, "tool definition") for d in defs]
                agency += [self._evidence(f, n, "powerful action") for n in actions]
        usage.services.extend(self._dependency_rows(ctx, usage, include_tests))
        usage.services.sort(key=lambda s: (s.path, s.line, s.provider, s.model or ""))
        ctx.inventory = usage
        return self._findings(injections, sinks, unbounded, agency, agency_defs,
                              len(agency_files))

    # --- reading and signals ---------------------------------------------------------------

    def _read(self, root: Path, path: str, language: str | None) -> _File | None:
        try:
            text = (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        lines = text.split("\n")
        code = [len(line) <= MAX_LINE_CHARS and not COMMENT_LINE_RE.match(line)
                for line in lines]
        return _File(path=path, language=language, lines=lines, code=code)

    def _signals(self, f: _File) -> None:
        local: list[int] = []  # lines with a loopback model server
        base: list[int] = []  # loopback base_url lines, counted only beside another signal
        loopback_names: dict[str, int] = {}  # names bound to a loopback URL -> their line
        for n, line in enumerate(f.lines, start=1):
            if not f.code[n - 1]:
                continue
            skip = f.language == "python" and DJANGO_HAYSTACK_RE.match(line)
            for module in [] if skip else self._imports(f.language, line):
                hit = _lookup_import(module, f.language)
                if hit:
                    f.signals.append(_Signal(hit[0], n, "import", hit[1]))
            for rx, provider in MARKERS:
                if rx.search(line):
                    f.signals.append(_Signal(provider, n, "endpoint"))
            hosted = False
            for rx, provider in HOSTS:
                if rx.search(line):
                    f.signals.append(_Signal(provider, n, "endpoint"))
                    hosted = True
            if hosted or not LOOPBACK_RE.search(line):
                continue
            if LOCAL_AI_PATH_RE.search(line):
                local.append(n)
            elif LOCAL_BASE_RE.search(line):
                base.append(n)
            a = ASSIGN_RE.match(line)
            if a:
                for name in _targets(a):
                    loopback_names.setdefault(name, n)
        # A loopback base URL counts beside another AI signal, or when a model API path or an
        # OpenAI-compatible client's base_url is built from it.
        ai_file = bool(f.signals) or any(
            f.code[i] and CLIENT_RE.search(line) for i, line in enumerate(f.lines))
        if ai_file:
            local += base
        if loopback_names:
            for i, line in enumerate(f.lines):
                if not f.code[i] or not (LOCAL_AI_PATH_RE.search(line)
                                         or ai_file and BASE_KEY_RE.search(line)):
                    continue
                local += [bound for name, bound in loopback_names.items()
                          if bound != i + 1 and name in _tokens(line)]
        for n in sorted(set(local)):
            f.signals.append(_Signal(LOCAL_SERVER, n, "endpoint"))

    @staticmethod
    def _imports(language: str | None, line: str) -> list[str]:
        if language == "python":
            m = re.match(r"^\s*(?:from\s+([\w.]+)\s+import\b|import\s+([\w.]+(?:\s*,\s*[\w.]+)*))",
                         line)
            if not m:
                return []
            return [m.group(1)] if m.group(1) else [p.strip() for p in m.group(2).split(",")]
        if language in JS_LANGUAGES:
            return re.findall(r"""(?:\bfrom\s+|\brequire\(\s*|\bimport\(\s*|^\s*import\s+)"""
                              r"""["']([^"']+)["']""", line)
        return []

    def _services(self, f: _File) -> list[AIService]:
        present: dict[str, _Signal] = {}
        for s in f.signals:
            present.setdefault(s.provider, s)
        frameworks = [p for p in present if PROVIDERS[p].framework]
        gateways = [p for p in present if PROVIDERS[p].gateway]
        endpoint_of = {s.provider for s in f.signals if s.kind == "endpoint"}
        rows: dict[tuple[str, str | None], AIService] = {}

        def add(provider: str, model: str | None, line: int, detected_by: str,
                via: str | None) -> None:
            key = (provider, model)
            if key not in rows:
                hosting = PROVIDERS[provider].hosting if provider in PROVIDERS else "hosted"
                rows[key] = AIService(provider=provider, model=model, hosting=hosting,
                                      path=f.path, line=line, via=via, detected_by=detected_by)

        for n, value, patterned in self._model_ids(f, bool(present)):
            provider: str | None
            via = None
            if patterned and patterned in endpoint_of:
                provider = patterned
            elif len(gateways) == 1:
                provider = gateways[0]
            elif patterned and patterned in present:
                provider, via = patterned, present[patterned].via
            elif patterned:
                provider, via = patterned, (frameworks[0] if frameworks else None)
            else:
                concrete = [p for p in present if not PROVIDERS[p].framework]
                provider = (concrete[0] if len(concrete) == 1
                            else frameworks[0] if not concrete and frameworks else None)
            if provider is not None:
                add(provider, value, n, "model id", via)
        modelled = {p for p, _ in rows}
        for provider, sig in present.items():
            if provider in modelled or (PROVIDERS[provider].framework and len(present) > 1):
                continue
            add(provider, None, sig.line, sig.kind, sig.via)
        # An SDK pointed at a gateway's endpoint (the OpenAI client at a local server) is
        # that gateway: the SDK's own row goes, and the gateway's rows say "via".
        endpoint_gateways = [g for g in gateways if g in endpoint_of]
        if endpoint_gateways:
            for provider, model in list(rows):
                sig = present.get(provider)
                if (model is None and sig is not None and sig.kind == "import"
                        and not PROVIDERS[provider].gateway and provider not in endpoint_of):
                    del rows[(provider, model)]
                    for other in rows.values():
                        if other.provider in endpoint_gateways and other.via is None:
                            other.via = f"{provider} SDK"
        return list(rows.values())

    def _model_ids(self, f: _File, signalled: bool) -> list[tuple[int, str, str | None]]:
        """(line, model id, provider its pattern names) for each model id in the file. Without
        a provider signal in the file, only ids on a `model` key line count."""
        out: list[tuple[int, str, str | None]] = []
        seen: set[str] = set()
        for n, line in enumerate(f.lines, start=1):
            if not f.code[n - 1]:
                continue
            found: list[tuple[str, str | None, bool]] = []
            for m in MODEL_KEY_RE.finditer(line):
                value, patterned = m.group(2), model_provider(m.group(2))
                if (m.group(1) or patterned) and not value.lower().startswith("http"):
                    found.append((value, patterned, True))
            if signalled:
                for m in STRING_RE.finditer(line):
                    patterned = model_provider(m.group(2))
                    if patterned:
                        found.append((m.group(2), patterned, False))
            for value, patterned, keyed in found:
                if (value in seen or not MODEL_VALUE_RE.fullmatch(value) or "://" in value
                        or redact_text(value) != value):
                    continue
                if patterned is None and (not signalled or NOT_MODEL_RE.fullmatch(value)):
                    continue
                if BARE_O_RE.fullmatch(value) and not (keyed and signalled):
                    continue
                seen.add(value)
                out.append((n, value, patterned))
        return out

    # --- calls -----------------------------------------------------------------------------

    def _calls(self, f: _File) -> None:
        present = {s.provider for s in f.signals} | {s.via for s in f.signals if s.via}
        concrete = sorted({s.provider for s in f.signals if not PROVIDERS[s.provider].framework})
        url_names: dict[str, str] = {}  # names bound to an AI endpoint -> its provider
        local_names: set[str] = set()  # names bound to a local server's base URL
        for s in f.signals:
            if s.kind == "endpoint":
                line = f.lines[s.line - 1]
                m = ASSIGN_RE.match(line)
                if m and not (s.provider == LOCAL_SERVER and not LOCAL_AI_PATH_RE.search(line)):
                    for name in _targets(m):
                        url_names[name] = s.provider
                elif m:
                    local_names.update(_targets(m))
        for n, line in enumerate(f.lines, start=1):
            if not f.code[n - 1]:
                continue
            for rx, needs in CALLS:
                m = rx.search(line)
                if m and (needs is None and present or needs and present & set(needs)):
                    provider = (needs[0] if needs and needs[0] in present
                                and not PROVIDERS[needs[0]].framework
                                else concrete[0] if len(concrete) == 1 else None)
                    self._add_call(f, n, line, m, provider)
                    break
            else:
                m = HTTP_CALL_RE.search(line)
                if m:
                    text, _ = f.span(n, m.end() - 1)
                    provider = self._http_target(text, url_names, local_names)
                    if provider:
                        self._add_call(f, n, line, m, provider)

    @staticmethod
    def _http_target(text: str, url_names: dict[str, str],
                     local_names: set[str] = frozenset()) -> str | None:
        for rx, provider in HOSTS:
            if rx.search(text):
                return provider
        for name, provider in url_names.items():
            if _word(name).search(text):
                return provider
        if LOCAL_AI_PATH_RE.search(text) and (LOOPBACK_RE.search(text)
                                              or not local_names.isdisjoint(_tokens(text))):
            return LOCAL_SERVER
        return None

    @staticmethod
    def _add_call(f: _File, n: int, line: str, m: re.Match[str], provider: str | None) -> None:
        text, end = f.span(n, m.end() - 1)
        pm = CALL_PREFIX_RE.match(line[:m.start()])
        f.calls.append(_Call(line=n, end_line=end, text=text, provider=provider,
                             outputs=_targets(pm) if pm else []))

    @staticmethod
    def _bounded_file(f: _File) -> bool:
        """A timeout anywhere in the file, or a token cap outside any call (on a client or in
        a shared options dict), bounds every call in it."""
        in_call = {n for c in f.calls for n in range(c.line, c.end_line + 1)}
        for n, line in enumerate(f.lines, start=1):
            if not f.code[n - 1]:
                continue
            if TIMEOUT_RE.search(line) or (n not in in_call and CAP_RE.search(line)):
                return True
        return False

    # --- data flow -------------------------------------------------------------------------

    @staticmethod
    def _propagate(f: _File, seeds: list[tuple[str, int]]) -> Taint:
        """Where names hold values derived from the seeds, by assignment, one file at a time:
        a value lives from the line it is bound until an unconditional reassignment from
        untainted values, or the end of its Python function. Lines are visited in order, only
        those whose assignments read or bind a tainted name, so the cost follows the names
        reached rather than the file's length (a whole-file pass per prompt line was
        quadratic)."""
        taint: Taint = {}
        seeded: dict[int, set[str]] = defaultdict(set)
        for name, line in seeds:
            seeded[line].add(name)
        heap = list(seeded)
        heapq.heapify(heap)
        last = 0

        def bind(name: str, n: int) -> None:
            spans = taint.setdefault(name, [])
            if spans and spans[-1][0] <= n < spans[-1][1]:
                return  # already live
            spans.append([n, f.scope_ends[n - 1] if n <= len(f.lines) else n + 1])
            for later in f.touching.get(name, ()):
                if later > n:
                    heapq.heappush(heap, later)

        while heap:
            n = heapq.heappop(heap)
            if n <= last:
                continue
            last = n
            for name in seeded.get(n, ()):
                bind(name, n)
            if n not in f.assign_at:
                continue
            targets, reads = f.assign_at[n]
            derived = any(_live(taint, r, n, strict=True) for r in reads)
            for t in targets:
                if t in seeded.get(n, ()):
                    continue
                if derived:
                    bind(t, n)
                elif _live(taint, t, n, strict=True) and f.kills(n, taint[t][-1][0]):
                    taint[t][-1][1] = n
        return taint

    def _injections(self, f: _File) -> list[int]:
        """Lines that build request input into text that reaches a model call (LLM01)."""
        if not f.calls:
            return []
        seeds: list[tuple[str, int]] = []
        for n, line in enumerate(f.lines, start=1):
            m = ASSIGN_RE.match(line)
            if m and f.code[n - 1] and REQUEST_RE.search(line[m.end():]):
                seeds += [(t, n) for t in _targets(m)]
        tainted = self._propagate(f, seeds)
        blocks = _string_blocks(f.lines)
        in_call = {n for c in f.calls for n in range(c.line, c.end_line + 1)}
        call_names = [(c.line, _tokens(c.text)) for c in f.calls]
        reaches: dict[tuple[str, int], bool] = {}
        out: list[int] = []
        for n, line in enumerate(f.lines, start=1):
            if not f.code[n - 1] and n not in blocks:
                continue
            names = [name for name in _tokens(line) if _live(tainted, name, n, strict=False)]
            if not _interpolates(line, names, n in blocks):
                continue
            if n in in_call:
                out.append(n)
                continue
            owner = blocks.get(n) or self._owner(f, n)
            if owner is None:
                continue
            if owner not in reaches:
                reach = self._propagate(f, [owner])
                reaches[owner] = any(
                    line_ >= owner[1] and any(_live(reach, r, line_, strict=False)
                                              for r in used)
                    for line_, used in call_names)
            if reaches[owner]:
                out.append(n)
        return out

    @staticmethod
    def _owner(f: _File, n: int) -> tuple[str, int] | None:
        """The name the statement holding line `n` assigns, looking back a few lines for a
        multi-line list or call."""
        for back in range(n, max(0, n - 15), -1):
            line = f.lines[back - 1]
            if not line.strip():
                return None
            m = ASSIGN_RE.match(line)
            if m:
                targets = _targets(m)
                return (targets[0], back) if targets else None
        return None

    def _sinks(self, f: _File) -> list[tuple[int, str]]:
        """Lines where model output reaches code execution, a shell or SQL text (LLM05)."""
        seeds = [(name, c.line) for c in f.calls for name in c.outputs]
        if not seeds:
            return []
        tainted = self._propagate(f, seeds)
        first = min(c.line for c in f.calls if c.outputs)
        out: list[tuple[int, str]] = []
        for n, line in enumerate(f.lines, start=1):
            if not f.code[n - 1] or n <= first:
                continue
            m = EXEC_RE.search(line)
            if m:
                args, _ = f.span(n, m.end() - 1)
                if any(_live(tainted, name, n, strict=True) for name in _tokens(args)):
                    out.append((n, "shell or code execution"))
                    continue
            m = SQL_RE.search(line)
            if m:
                args, _ = f.span(n, m.end() - 1)
                names = [name for name in _tokens(args) if _live(tainted, name, n, strict=True)]
                if any(re.match(rf"\(\s*{re.escape(name)}\s*[,)]", args) for name in names) \
                        or _interpolates(_first_argument(args), names, False):
                    out.append((n, "SQL text"))
        return out

    def _tool_definitions(self, f: _File) -> list[AIToolDefinition]:
        out: dict[int, AIToolDefinition] = {}
        for n, line in enumerate(f.lines, start=1):
            if not f.code[n - 1]:
                continue
            for rx, kind, where in TOOL_RES:
                m = rx.search(line)
                if m and n not in out:
                    out[n] = AIToolDefinition(path=f.path, line=n, kind=kind,
                                              name=_tool_name(f.lines, n, m, where))
        return list(out.values())

    @staticmethod
    def _actions(f: _File) -> list[int]:
        return [n for n, line in enumerate(f.lines, start=1)
                if f.code[n - 1] and ACTION_RE.search(line)]

    # --- dependencies ----------------------------------------------------------------------

    def _dependency_rows(self, ctx: ScanContext, usage: AIUsage,
                         include_tests: bool) -> list[AIService]:
        """A declared AI dependency the code never visibly uses: still a provider to name."""
        seen = {s.provider for s in usage.services}
        manifests = {r.path: r for r in ctx.census.files}
        out: list[AIService] = []
        for dep in ctx.dependencies.dependencies:
            provider = PACKAGES.get(dep.name.lower().replace("_", "-"))
            rec = manifests.get(dep.manifest)
            if (provider is None or provider in seen or PROVIDERS[provider].framework
                    or (dep.dev and not include_tests) or rec is None
                    or rec.classification in (Classification.test, Classification.vendored)):
                continue
            seen.add(provider)
            out.append(AIService(provider=provider, hosting=PROVIDERS[provider].hosting,
                                 path=dep.manifest, detected_by="dependency",
                                 line=_line_of_name(ctx.source_root / dep.manifest, dep.name)))
        return out

    # --- findings --------------------------------------------------------------------------

    def _evidence(self, f: _File, n: int, note: str | None = None) -> Evidence:
        line = f.lines[n - 1].strip()
        excerpt = scrub(line)[:200] if len(line) <= MAX_LINE_CHARS else None
        return Evidence(path=f.path, line_start=n, line_end=n, excerpt=excerpt or None,
                        note=note)

    def _finding(self, rule: str, severity: Severity, category: Category, title: str,
                 summary: str, impact: str, remediation: str, evidence: list[Evidence],
                 tags: list[str]) -> Finding:
        evidence = sorted(evidence, key=lambda e: (e.path, e.line_start or 0))
        if len(evidence) > self._max:
            summary += f" Showing the first {self._max}."
        return Finding(tool=self._ctx.tool, category=category, severity=severity, title=title,
                       summary=summary, impact=impact, remediation=remediation,
                       evidence=evidence[:self._max], source=Source.scanner, scanner=self.name,
                       tags=tags, **rule_effort(self._ctx, self.name, rule))

    def _findings(self, injections: list[Evidence], sinks: list[Evidence],
                  unbounded: list[Evidence], agency: list[Evidence],
                  agency_defs: int, agency_files: int) -> list[Finding]:
        out: list[Finding] = []
        if injections:
            n, files = len(injections), len({e.path for e in injections})
            out.append(self._finding(
                "prompt_injection", Severity.medium, Category.security,
                "Request input built into a model prompt",
                f"{plural(n, 'place')} in {plural(files, 'file')} "
                f"{'builds' if n == 1 else 'build'} request input into a prompt by "
                "concatenation or interpolation. This is a heuristic for review: whoever sends "
                "the request can write instructions the model may follow (OWASP LLM01, prompt "
                "injection). Model extraction, when configured, is asked to look at each model "
                "call.",
                "A user, or text they control such as an uploaded document, can override the "
                "instructions, extract the system prompt or other data in the context, or "
                "steer what the tool does with the answer.",
                "Keep instructions in the system prompt and pass user input as a separate "
                "message; give the model no more authority than the user has, and validate its "
                "output before acting on it.",
                injections, ["owasp-llm01", "review"]))
        if sinks:
            n = len(sinks)
            out.append(self._finding(
                "output_sink", Severity.high, Category.security,
                "Model output reaches code execution, a shell or SQL",
                f"{plural(n, 'place')} {'passes' if n == 1 else 'pass'} text a model returned "
                "to eval or exec, a shell or subprocess, or into the text of a SQL statement "
                "(OWASP LLM05, improper output handling).",
                "Anyone who can influence the model's input, through prompt injection, can run "
                "code or commands, or read and change the database, with the tool's privileges.",
                "Never execute model output: parse it into an allow-listed structure (an enum "
                "of actions, validated JSON), use parameterised queries, and run generated code "
                "only in a sandbox.",
                sinks, ["owasp-llm05"]))
        if unbounded:
            n, files = len(unbounded), len({e.path for e in unbounded})
            out.append(self._finding(
                "unbounded_calls", Severity.low, Category.reliability,
                "Model calls without a token limit or timeout",
                f"{plural(n, 'model call')} in {plural(files, 'file')} "
                f"{'has' if n == 1 else 'have'} no output-token limit (max_tokens or the "
                "provider's equivalent) and no timeout in the same file (OWASP LLM10, unbounded "
                "consumption).",
                "A long or stuck response holds a worker and runs up cost; anyone who can "
                "trigger calls repeatedly can exhaust the budget or the provider's quota.",
                "Set an output-token limit and a request timeout on every call, and rate-limit "
                "the endpoints that trigger them.",
                unbounded, ["owasp-llm10"]))
        if agency:
            out.append(self._finding(
                "agent_tools", Severity.medium, Category.security,
                "Model-callable tools beside powerful actions",
                f"{plural(agency_defs, 'tool or agent definition')} handed to a model "
                f"{'sits' if agency_defs == 1 else 'sit'} in {plural(agency_files, 'file')} "
                "with code that runs commands, evaluates code, deletes files or writes to a "
                "database. This is a heuristic for "
                "review: check which of these actions the model can trigger (OWASP LLM06, "
                "excessive agency).",
                "A model steered by prompt injection can take these actions with the tool's "
                "privileges and without a person approving them.",
                "Give each tool the narrowest permission it needs, keep destructive actions "
                "out of the model's reach or behind a person's confirmation, and log every "
                "tool call.",
                agency, ["owasp-llm06", "review"]))
        return out


def _lookup_import(module: str, language: str | None = None) -> tuple[str, str | None] | None:
    """The provider an import names: the module itself, or its nearest listed parent
    (`llama_index.llms.openai.base`, `@ai-sdk/openai/internal`). A JavaScript-only name in
    Python (`from ai.prompts import ...`) is the tool's own package."""
    sep = "/" if module.startswith("@") or "/" in module else "."
    parts = module.split(sep)
    for i in range(len(parts), 0, -1):
        name = sep.join(parts[:i])
        hit = IMPORTS.get(name)
        if hit:
            return None if language == "python" and name in JS_ONLY_IMPORTS else hit
    return None


def _string_blocks(lines: list[str]) -> dict[int, tuple[str, int]]:
    """Lines inside a multi-line f-string or template literal -> (the name the statement
    assigns, its first line). Approximate: quotes are not parsed."""
    out: dict[int, tuple[str, int]] = {}
    start: tuple[str, int] | None = None
    closer: str | None = None
    for n, line in enumerate(lines, start=1):
        if closer is not None:
            if start is not None:
                out[n] = start
            if line.count(closer) % 2 == 1:
                closer, start = None, None
            continue
        for m in TRIPLE_RE.finditer(line):
            token = m.group(2) or "`"
            if line.count(token) % 2 == 1:
                closer = token
                interpolating = token == "`" or bool(m.group(1))
                a = ASSIGN_RE.match(line)
                targets = _targets(a) if a else []
                start = (targets[0], n) if (interpolating and targets) else None
                break
    return out


def _interpolates(line: str, names: list[str], in_block: bool) -> bool:
    """Whether `line` builds one of `names`, or a request expression, into a string."""
    names = [name for name in names if name in line]
    if not names and not REQUEST_RE.search(line):
        return False
    refs = [rf"(?<![\w.]){re.escape(name)}\b" for name in names] + [REQUEST_RE.pattern]
    for w in refs:
        if re.search(rf"\$\{{[^}}]*(?:{w})", line):
            return True
        if (re.search(r"\bf[\"']", line) or in_block) and re.search(rf"\{{[^}}]*(?:{w})", line):
            return True
        if re.search(rf"[\"'`]\s*\+\s*(?:{w})|(?:{w})[\w.\[\]\"'()]*\s*\+\s*[\"'`]", line):
            return True
        if re.search(rf"\.format\([^)]*(?:{w})", line):
            return True
        if re.search(rf"[\"']\s*%\s*\(?[^)\n]*(?:{w})", line):
            return True
    return False


def _first_argument(args: str) -> str:
    """The first argument of a call's text `( ... )`, cut at the first top-level comma."""
    depth = 0
    for i, c in enumerate(args):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 1:
            return args[:i]
    return args


def _tool_name(lines: list[str], n: int, m: re.Match[str], where: str) -> str | None:
    if where == "group":
        return m.group(1) or m.group(2)
    if where == "def":
        for line in lines[n:n + 3]:
            d = DEF_NAME_RE.match(line)
            if d:
                return d.group(1)
        return None
    if where == "after":
        window = lines[n - 1:n + 6]
    elif where == "before":
        window = list(reversed(lines[max(0, n - 7):n]))
    else:
        return None
    for line in window:
        t = TOOL_NAME_RE.search(line)
        if t:
            return t.group(1)
    return None


def _line_of_name(path: Path, name: str) -> int:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError:
        return 1
    rx = re.compile(rf"(?<![\w@/.-]){re.escape(name)}(?![\w-])", re.I)
    return next((n for n, line in enumerate(lines, start=1) if rx.search(line)), 1)


def ai_hints(ai_usage: Path) -> dict[str, list[int]]:
    """Lines of model calls and tool definitions, by path, for extraction."""
    from unvarnish.artifacts import read_artifact

    if not ai_usage.exists():
        return {}
    try:
        usage = read_artifact(ai_usage, AIUsage).data
    except Exception:  # an unreadable artifact only loses the hints
        return {}
    hints: dict[str, set[int]] = defaultdict(set)
    for item in [*usage.calls, *usage.tool_definitions]:
        hints[item.path].add(item.line)
    return {p: sorted(lines) for p, lines in sorted(hints.items())}

