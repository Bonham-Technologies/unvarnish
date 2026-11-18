# Security Policy

## Supported Versions

Only the latest release and the current default branch receive security fixes.

## Reporting a Vulnerability

Please **do not** open a public issue for security problems. Report privately via
[GitHub Security Advisories](https://github.com/Bonham-Technologies/Unvarnish/security/advisories/new).

Include reproduction steps and the version you tested. You should hear back
within a few business days; please allow a reasonable window for a fix before
public disclosure.

## Scope notes

In scope: the unvarnish CLI and Python package, its Docker image and site kit, and how it handles client source code, credentials, and model API keys (secret redaction, offline operation, prompt-injection resistance). Out of scope: vulnerabilities in the code Unvarnish reviews (report those to the code's owner), third-party tools bundled in the image (gitleaks, osv-scanner, pandoc) unless Unvarnish uses them unsafely, and model providers' services.
