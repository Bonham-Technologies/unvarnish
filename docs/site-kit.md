# Unvarnish site kit: running at an air-gapped client site

The kit holds everything needed to vet tools on a network with no internet access:

| File | What it is |
|---|---|
| `unvarnish-<version>.tar.gz` | The Docker image: Unvarnish with its tree-sitter grammars, gitleaks, osv-scanner, pandoc, Graphviz, offline advisory databases for PyPI, npm, Go, Maven, crates.io, NuGet, RubyGems, and Packagist, endoflife.date's end-of-life dates for runtimes and frameworks, and CISA's known exploited vulnerabilities with FIRST's EPSS scores |
| `engagement-onprem.yaml` | Model settings for the client's own model server |
| `SHA256SUMS` | Checksums for the files above |
| `RUNBOOK.md` | This page |

Build it on a connected machine with `scripts/site-kit.sh` (about 2 GB). The advisory databases,
the end-of-life data and the exploit data are dated: the build prints every date, then runs
`unvarnish doctor` in the image, and reports state the dates beside the vulnerability,
end-of-life and known-exploited counts.

## 1. Before you go

- Confirm the client has a model server that speaks the OpenAI chat-completions protocol (vLLM,
  Ollama, LM Studio, or a gateway), its URL, the model name, and its context length.
- Confirm a machine at the site with Docker, 8 GB of RAM free, and disk for the image plus about
  twice the size of the code under review.
- Check the image with no network; it lists every data set's date and age and every tool, and
  exits 1 if anything a run needs is missing:

      docker run --rm --network none unvarnish:<version> doctor

- Rebuild the kit if its advisory database, end-of-life data or exploit data is more than a few
  weeks old (see "Refresh the end-of-life and exploit data" below for the data alone). Exploit
  data more than 30 days old is noted in every findings document
  (`scanners.dependencies.max_data_age_days`). End-of-life data more than
  90 days old is flagged in every findings document: a note under "Not analysed" and on the
  end-of-life row. Set `scanners.end_of_life.max_data_age_days` in the engagement file to
  change the limit.

## 2. At the site

Check and load the image:

    sha256sum -c SHA256SUMS            # macOS: shasum -a 256 -c SHA256SUMS
    docker load < unvarnish-<version>.tar.gz

Check the model server from the same machine (adjust the URL):

    curl http://llm.client.internal:8000/v1/models

Make sure the server's context length is at least 16k tokens and matches
`capabilities.context_window`. Ollama defaults to 4,096 and silently truncates longer prompts:
start it with `OLLAMA_CONTEXT_LENGTH=32768`. vLLM takes `--max-model-len`.

## 3. Run an engagement

Every command runs in the image through a small shell function (it works in bash and zsh);
`E` is the engagement folder on the host.

    E=$PWD/acme-2026-10
    mkdir -p "$E"
    u() { docker run --rm --user "$(id -u):$(id -g)" -v "$E:/engagement" unvarnish:<version> "$@"; }
    u init /engagement --client "Acme" --consultant "Your firm"

Copy the `backends`, `models`, `pipeline`, and `scanners` sections of `engagement-onprem.yaml`
into `$E/engagement.yaml` and set the URL, model, and context window. If the server needs a key,
add `-e ONPREM_LLM_KEY` to the `docker run` in `u` and export the key in the shell.

Add each tool. Copy its source into the engagement's reach first; tools added by path must be
inside a mounted folder:

    u add expense-bot --repo /engagement/incoming/expense-bot
    u add timesheets --files /engagement/incoming/timesheets

Check the model and estimate the work, then run:

    u config check
    u run --dry-run
    u run
    u compare            # when there are two or more tools

`u status` shows progress; a stopped run resumes where it left off with `u run`.

## 4. How long it takes

| Server | Speed |
|---|---|
| CPU only (8-core Intel, 14B model) | 4 to 13 minutes a unit; a 1,000-line tool takes about 4 hours |
| One modern GPU (14B to 32B model) | seconds a unit; a 1,000-line tool takes minutes |

`unvarnish run --dry-run` prints the unit count. On CPU-only servers set
`timeout_s: 7200` and `pipeline.concurrency: 1`.

## 5. Deliverables

    u export             # DOCX, HTML, and PDF under exports/
    u ask "Which tools write to the payroll database?"

The documents are in `$E/tools/<tool>/docs/` and `$E/comparison/`, and the exports in
`$E/exports/`. The engagement folder contains a full copy of each tool's source and its
analysis: keep it on the client's systems unless the engagement letter says otherwise, and
carry out only the exports.

## 6. Refresh the end-of-life and exploit data

The image holds the end-of-life bundle (`/opt/eol/endoflife.json`) and the exploit data bundle
(`/opt/eol/vulndata.gz`); findings show their dates. To see the dates before a run, with no
network:

    docker run --rm --network none unvarnish:<version> doctor

To refresh them without rebuilding the kit, on a connected machine with the image loaded, write
both into one folder (a mount over `/opt/eol` hides both of the image's bundles):

    mkdir -p eol
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/eol:/eol" unvarnish:<version> \
        eol refresh --dir /eol
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/eol:/eol" unvarnish:<version> \
        vulndata refresh --dir /eol

Each exits 1 and writes nothing if any download fails; run it again. Carry the `eol` folder to
the site, set `EOL=` to its full path, add `-v "$EOL:/opt/eol:ro"` to the `docker run` in `u`,
check with `u doctor`, and run `u run` again: the new dates rerun the inventory and scan.

## 7. If something goes wrong

| Symptom | Fix |
|---|---|
| `config check` reports an error | Wrong URL, model name, or key; the message names which |
| Units recorded as failed with "no reply within" | Raise `timeout_s`, then `unvarnish run` again |
| Dependency vulnerabilities "not checked" for an ecosystem | The kit lacks that ecosystem's database; rebuild with it |
| End-of-life row says "older than the 90-day limit: refresh it" | The end-of-life data is older than `max_data_age_days`; findings still use it, but releases and end-of-life dates since then are missing; see section 6 |
| End-of-life "not checked (no end-of-life data bundle)" | The image was built with `EOL_DATA=skip`, or a `-v` over `/opt/eol` holds no `endoflife.json`; see section 6 |
| Exploit data "not checked (no exploit data bundle)" | The image was built with `EXPLOIT_DATA=skip`, or a `-v` over `/opt/eol` holds no `vulndata.gz`; see section 6 |
| Not sure what the image holds | `u doctor` lists each data set's date and each tool, offline |
| Prose sections say "No model-written text" | The model call failed or was refused; tables are still correct |
