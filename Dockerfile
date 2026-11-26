# Unvarnish: portable image with the export toolchain. Engagement mounted at /engagement.

# Tool images, pinned by tag and digest. They are named stages because Dependabot's docker
# updater reads only FROM lines; a COPY --from=<image> pin would never be bumped.
# Scanners: gitleaks (secrets) and osv-scanner (dependency advisories).
FROM zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
FROM ghcr.io/google/osv-scanner:v2.7.1@sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde AS osv-scanner
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# weasyprint itself comes from PyPI below; these are the libraries it loads (pango, harfbuzz).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git pandoc graphviz libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
        fonts-dejavu-core fonts-inter fonts-liberation2 \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner

# Optional offline advisory database, e.g. --build-arg OSV_ECOSYSTEMS="PyPI npm Go"
ARG OSV_ECOSYSTEMS=""
ENV OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv
RUN mkdir -p /opt/osv/osv-scalibr && for eco in $OSV_ECOSYSTEMS; do \
        mkdir -p "/opt/osv/osv-scalibr/$eco" && \
        python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" \
            "https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip" \
            "/opt/osv/osv-scalibr/$eco/all.zip" || exit 1; \
    done && if [ -n "$OSV_ECOSYSTEMS" ]; then date -u +%Y-%m-%d > /opt/osv/DATE; fi \
    && chmod -R a+rX /opt/osv

COPY --from=uv /uv /usr/local/bin/uv

# The PDF engine, pinned and hash-checked in docker/weasyprint.txt, in a venv of its own so its
# libraries never meet Unvarnish's. Debian's weasyprint (62.3) hides every link in a tagged
# (PDF/UA) file; 66.0 and later leave them clickable (UNVAR-22).
COPY docker/weasyprint.txt /tmp/weasyprint.txt
RUN uv venv --python /usr/local/bin/python3 /opt/weasyprint \
    && uv pip install --python /opt/weasyprint --compile-bytecode \
        --require-hashes -r /tmp/weasyprint.txt \
    && ln -s /opt/weasyprint/bin/weasyprint /usr/local/bin/weasyprint \
    && weasyprint --version && rm -rf /tmp/weasyprint.txt /root/.cache
WORKDIR /app
# Dependencies first, so a source change does not reinstall them.
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
RUN uv sync --frozen --no-dev --no-install-project && rm -rf /root/.cache
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable && rm -rf /root/.cache
ENV PATH="/app/.venv/bin:${PATH}" UNVARNISH_CONFIG_DIR=/engagement/.unvarnish HOME=/tmp \
    UNVARNISH_IN_DOCKER=1

# Tree-sitter grammars: the language pack downloads them from GitHub at first use, which an
# air-gapped run or --network none cannot do. Fetch them at build time into a fixed directory
# any --user can read, and drop the bundle they were unpacked from (UNVAR-45).
ENV TREE_SITTER_LANGUAGE_PACK_CACHE_DIR=/opt/tree-sitter
RUN unvarnish grammars fetch \
    && rm -rf /opt/tree-sitter/tree-sitter-language-pack/*/bundles \
    && chmod -R a+rX /opt/tree-sitter

# End-of-life dates for the end_of_life scanner: the bundle `unvarnish eol refresh` writes, so a
# --network none run checks runtimes offline (UNVAR-44). EOL_DATA=fetch, the default, fails the
# build when any product cannot be downloaded (refresh writes nothing then); EOL_DATA=skip builds
# without it, and runs report end of life as "not checked". The bundle carries its own date.
ARG EOL_DATA=fetch
ENV UNVARNISH_EOL_DIR=/opt/eol
RUN case "$EOL_DATA" in \
        fetch) unvarnish eol refresh --dir "$UNVARNISH_EOL_DIR" ;; \
        skip) mkdir -p "$UNVARNISH_EOL_DIR" ;; \
        *) echo "error: EOL_DATA must be fetch or skip, not '$EOL_DATA'" >&2; exit 1 ;; \
    esac && chmod -R a+rX "$UNVARNISH_EOL_DIR"

# Exploit data for dependency advisories (CISA KEV and EPSS): the bundle `unvarnish vulndata
# refresh` writes, beside the end-of-life bundle, where a run looks when UNVARNISH_VULNDATA_DIR
# is unset, so one mount over /opt/eol refreshes both (UNVAR-101). EXPLOIT_DATA=fetch, the
# default, fails the build when either feed cannot be downloaded (refresh writes nothing then);
# EXPLOIT_DATA=skip builds without it, and runs report exploit data as "not checked".
ARG EXPLOIT_DATA=fetch
RUN case "$EXPLOIT_DATA" in \
        fetch) unvarnish vulndata refresh --dir "$UNVARNISH_EOL_DIR" ;; \
        skip) mkdir -p "$UNVARNISH_EOL_DIR" ;; \
        *) echo "error: EXPLOIT_DATA must be fetch or skip, not '$EXPLOIT_DATA'" >&2; exit 1 ;; \
    esac && chmod -R a+rX "$UNVARNISH_EOL_DIR"

# No volume declaration: it would silently hide a missing -v; the CLI warns instead.
WORKDIR /engagement
ENTRYPOINT ["unvarnish"]
CMD ["--help"]
