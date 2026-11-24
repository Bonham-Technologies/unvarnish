# Roadmap

What we are working on, what comes next, and what shipped recently. It is refreshed by
hand from our tracker each week; dates are not promises.

## Now

- unvarnish.com moves onto the shared Bonham Technologies design system.
- The public sample report on unvarnish.com is re-recorded from the current release, so
  it shows tagged PDFs, plural wording and the accessibility fixes below.

## Next

- Fewer false positives from the hardcoded-infrastructure scanner: attribute access such
  as `if config.internal:` is no longer read as a hostname.
- A clear architecture section when a tool has no module map, instead of an empty diagram.
- `status` says when a run stopped because the model server was unreachable, not because
  of the budget, and the error names the server.
- Evidence rows are unique per line, so the 25-row cap shows more real locations.
- `config check` explains scanners-only runs instead of printing an empty table.
- Plural wording in every phase summary and status line.
- A working install line in the README for the public repository.
- CI builds the Docker image on every change that affects it.
- Smaller polish: no placeholder dashes in document headers, a clearer `add --link`
  hint, and more tests around the engagement lock.

## Recently shipped

- Tagged PDF exports that keep links clickable; the image ships weasyprint 70.
- HTML and PDF exports carry the consultant as author.
- One error line per configuration problem instead of a traceback.
- Re-audits match grouped scanner findings across reviews.
- gitleaks runs in an empty folder, so a stray ignore file can't hide findings.
- Plural words in command-line and error messages.
- The Anthropic backend drops an unsupported temperature instead of crashing.
- `add --files` and `add --link` say clearly when a path does not exist.
- unvarnish.com rebuilt, and the docs brought up to date for the public repository.
