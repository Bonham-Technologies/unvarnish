"""Fixed remediation-effort bands for scanner findings (UNVAR-42).

Each rule a scanner reports has one band, whatever the finding's size: the band says what kind
of work the fix is, and the consultant adjusts it. `scanners.<scanner>.effort.<rule>` in
engagement.yaml replaces a band. The table is documented in docs/decisions.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unvarnish.schemas.finding import Effort, coerce_effort

if TYPE_CHECKING:
    from unvarnish.scanners.base import ScanContext

S, M, L, XL = Effort.S, Effort.M, Effort.L, Effort.XL

EFFORT_RULES: dict[str, dict[str, tuple[Effort, str]]] = {
    "secrets": {
        "credential": (S, "rotate one credential and move it to configuration"),
        "credential_history": (M, "rotate the credential, then rewrite history every clone "
                                  "must take"),
        "suppression": (S, "review each suppression entry"),
    },
    "oversized_files": {
        "inline_script": (M, "move inline scripts into their own files under a build step"),
        "file": (L, "split each file by responsibility"),
        "function": (M, "extract cohesive steps into tested functions"),
        "very_large_function": (L, "restructure a function far beyond any reviewable size"),
    },
    "hygiene": {
        "no_tests": (XL, "add a test suite and cover the main paths"),
        "no_ci": (M, "add a pipeline that runs tests and linting"),
        "no_readme": (S, "write a README"),
        "no_license": (S, "add an ownership or licence notice"),
        "no_linter": (S, "adopt the language's standard linter"),
        "todo_density": (M, "triage the markers into tracked issues"),
        "swallowed_errors": (M, "handle or surface each swallowed error"),
    },
    "bus_factor": {
        "single_author": (L, "pair a second maintainer and document the design"),
        "low_bus_factor": (M, "spread ownership through reviews"),
    },
    "dependencies": {
        "advisories": (S, "upgrade the package; more across a major version"),
        "unpinned": (S, "commit a lockfile or pin versions"),
        "licences": (M, "clear the licence with legal, or replace the package"),
    },
    "hardcoded_infra": {
        "url": (M, "move the values into configuration per environment"),
        "host": (M, "move the values into configuration per environment"),
        "ip": (M, "move the values into configuration per environment"),
        "path": (M, "move the values into configuration per environment"),
        "email": (S, "move the addresses into configuration"),
    },
    "vendored_bulk": {
        "vendored_directories": (M, "restore dependencies from the manifest at build time"),
        "binaries": (S, "move binaries to an artifact store or Git LFS"),
    },
    "generated_bulk": {
        "bulk_commits": (L, "review the largest unreviewed commits"),
    },
    "client_exposure": {
        "firebase_config": (S, "review the Security Rules and restrict the key"),
        "credentials_file": (S, "rotate the credentials and commit only an example file"),
        "policy_readable": (M, "scope the policy to the row's owner"),
        "policy_open": (M, "scope the policy to the row's owner"),
        "policy_without_check": (S, "add a with check expression"),
        "cors_any_origin": (S, "list the allowed origins"),
        "service_role_key": (M, "rotate the key and move privileged calls to the server"),
        "public_secret_var": (M, "rotate the value and read it only on the server"),
        "table_without_rls": (M, "enable row level security and write owner policies"),
        "rls_disabled": (M, "enable row level security and write owner policies"),
        "anon_key_open_tables": (L, "enable row level security with policies on every open "
                                    "table"),
        "unauthenticated_routes": (L, "confirm and add authentication across the handlers"),
    },
    "ai_usage": {
        "prompt_injection": (M, "keep user input out of the instructions and limit what the "
                                "answer can do"),
        "output_sink": (M, "parse the output into allowed actions instead of executing it"),
        "unbounded_calls": (S, "set a token limit and a timeout on each call"),
        "agent_tools": (M, "narrow each tool's permissions and confirm destructive actions"),
    },
    "end_of_life": {
        "past": (L, "move to a supported release, retest and update every place it is pinned"),
        "near": (L, "plan the move to a supported release before support ends"),
    },
    "hidden_text": {
        "rule_file": (S, "remove the characters and review what the file steered"),
        "bidi": (S, "remove the characters and add a CI check"),
        "tag": (S, "remove the characters and add a CI check"),
        "encoded_run": (M, "remove the payload and find how it got in"),
        "invisible": (S, "remove the characters"),
        "mcp_unpinned": (S, "pin each server to an exact version"),
    },
    "sast": {
        "rule": (M, "fix each flagged place and add a test that exercises it"),
        "suppression": (S, "review each suppression entry"),
    },
    "deployment_exposure": {
        "compose_database_port": (S, "drop the port mapping or bind it to localhost"),
        "compose_public_port": (S, "bind the port to localhost behind a proxy"),
        "compose_privileged": (M, "grant only the capabilities the service needs"),
        "compose_host_network": (M, "move the service to a bridge network"),
        "compose_docker_socket": (M, "remove the mount or put a socket proxy in front"),
        "compose_literal_password": (S, "rotate the credential and read it from a secret"),
        "compose_password_default": (S, "remove the fallback so a missing value stops the "
                                         "start"),
        "dockerfile_root_user": (S, "add an unprivileged user to the final stage"),
        "dockerfile_add_url": (S, "pin the download with a checksum"),
        "dockerfile_secret_literal": (S, "rotate the secret and pass it at run time"),
        "dockerfile_secret_build_arg": (M, "move the secret to a build secret mount"),
        "k8s_host_network": (M, "expose the pod through a Service instead"),
        "k8s_privileged": (M, "grant only the capabilities the container needs"),
        "k8s_no_limits": (S, "set memory and CPU limits per container"),
        "k8s_latest_image": (S, "pin each image to a version or digest"),
        "tf_open_ingress": (M, "restrict the source ranges to known networks"),
        "tf_public_storage": (M, "make the storage private and serve files through signed "
                                 "URLs"),
    },
}


def rule_effort(ctx: ScanContext, scanner: str, rule: str) -> dict[str, Any]:
    """The `effort` and `effort_note` fields for a finding of `scanner`'s `rule`."""
    band, why = EFFORT_RULES[scanner][rule]
    override = (ctx.options.get("effort") or {}).get(rule)
    if override:
        band = Effort(override)
        why = f"{why}; band set by scanners.{scanner}.effort.{rule}"
    return {"effort": band, "effort_note": f"{why} (scanner rule {scanner}.{rule})"}


def validate_effort_overrides(scanners: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Check and normalise every `scanners.<name>.effort` mapping: a typo must fail the
    configuration, not a scanner. Rules are checked for built-in scanners only."""
    for name, options in scanners.items():
        overrides = options.get("effort") if isinstance(options, dict) else None
        if overrides is None:
            continue
        if not isinstance(overrides, dict):
            raise ValueError(f"scanners.{name}.effort must map rule names to bands")
        clean: dict[str, str] = {}
        for rule, band in overrides.items():
            known = EFFORT_RULES.get(name)
            if known is not None and rule not in known:
                raise ValueError(f"scanners.{name}.effort: unknown rule {rule!r}; rules: "
                                 + ", ".join(known))
            value = coerce_effort(band)
            if value not in {e.value for e in Effort}:
                raise ValueError(f"scanners.{name}.effort.{rule}: {band!r} is not a band "
                                 "(S, M, L, XL)")
            clean[str(rule)] = str(value)
        options["effort"] = clean
    return scanners
