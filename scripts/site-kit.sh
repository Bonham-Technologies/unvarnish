#!/usr/bin/env bash
# Build the air-gapped site kit: an Unvarnish image with every common ecosystem's offline
# advisory database, the end-of-life data bundle and the exploit data bundle (CISA KEV and
# EPSS), saved as a tarball with checksums, a runbook, and an example on-prem engagement
# config. Run on a machine with internet access; carry dist/site-kit-<version>/ to the client
# site.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)}"
ECOSYSTEMS="PyPI npm Go Maven crates.io NuGet RubyGems Packagist"
OUT="dist/site-kit-$VERSION"
IMAGE="unvarnish:$VERSION"

mkdir -p "$OUT"
echo "Building $IMAGE with end-of-life data, exploit data and offline advisories for:" \
    "$ECOSYSTEMS"
docker build --build-arg OSV_ECOSYSTEMS="$ECOSYSTEMS" --build-arg EOL_DATA=fetch \
    --build-arg EXPLOIT_DATA=fetch \
    --label "org.opencontainers.image.version=$VERSION" \
    --label "org.opencontainers.image.revision=$(git rev-parse --short HEAD)" \
    -t "$IMAGE" .

echo "Checking the image"
docker run --rm --network none --entrypoint sh "$IMAGE" -c '
    unvarnish --help >/dev/null &&
    gitleaks version >/dev/null && osv-scanner --version >/dev/null &&
    pandoc --version >/dev/null && dot -V 2>/dev/null &&
    unvarnish grammars status &&
    test -s /opt/osv/DATE && echo "advisory database dated $(cat /opt/osv/DATE)" &&
    eol=$(python -c "from unvarnish.analysis.eol import bundle_date; print(bundle_date() or \"\")") &&
    if [ -n "$eol" ]; then echo "end-of-life data dated $eol"; else
        echo "error: no readable end-of-life bundle in $UNVARNISH_EOL_DIR" >&2; exit 1; fi &&
    exploit=$(python -c "from unvarnish.analysis.vulndata import bundle_date; print(bundle_date() or \"\")") &&
    if [ -n "$exploit" ]; then echo "exploit data dated $exploit"; else
        echo "error: no readable exploit data bundle in $UNVARNISH_EOL_DIR" >&2; exit 1; fi &&
    unvarnish doctor'

echo "Saving the image"
docker save "$IMAGE" | gzip > "$OUT/unvarnish-$VERSION.tar.gz"
cp docs/site-kit.md "$OUT/RUNBOOK.md"
cp examples/engagement-onprem.yaml "$OUT/engagement-onprem.yaml"
(cd "$OUT" && if command -v sha256sum >/dev/null; then sha256sum ./*; else shasum -a 256 ./*; fi \
    | grep -v SHA256SUMS > SHA256SUMS)
echo "Site kit written to $OUT:"
ls -lh "$OUT"
