# unvarnish.com

The product site: static HTML and one stylesheet, no build step and no JavaScript. Decided in
BORG-70: the site lives here in `site/`, deployed by its own Vercel project, and the demo at
launch is a recorded walkthrough plus static sample output, with no live model calls.

| File | What it is |
|---|---|
| `index.html` | The writeup: what Unvarnish finds, who it is for, how it works, how to run it, licence |
| `demo/index.html` | The walkthrough: a real run on OWASP NodeGoat, command by command |
| `demo/nodegoat-findings.{md,html,pdf}` | The findings document that run wrote, and its HTML and PDF exports, unedited |
| `site.css` | Styles, built on the Bonham Technologies design system (see Design, below) |
| `fonts/` | Archivo and IBM Plex Mono (Latin subsets), self-hosted, with their SIL Open Font Licence texts |
| `og-image.png`, `favicon.svg` | Link-preview image (1200×630) and icon, both drawn from the stripped-layers motif |
| `robots.txt`, `sitemap.xml` | Crawling |
| `vercel.json` | Security headers and CSP, and the ignored-build step |
| `.vercelignore` | Keeps this README off the deployed site |

## Design (UNVAR-74)

The site follows the Bonham Technologies design system, the one bonham.tech uses: Daylight
and Night themes, Archivo for text and IBM Plex Mono for code and figures only, square
corners, hairlines in place of shadows, and safety orange (`--signal-fill`) as the one action
colour, on one primary button per view.

- **Themes.** Daylight is the default; Night follows the reader's system setting
  (`prefers-color-scheme`). There is no toggle, because the site has no JavaScript. Keep both
  token blocks at the top of `site.css` in step.
- **Unvarnish's own identity** (owner's choice, 2026-11-17): no accent colour at all.
  `--product-accent` is the ink itself, so the page is ink, paper and one orange button. The
  motif is "stripped layers": coats cut back one by one to a solid base, under the hero, in
  `favicon.svg` and in `og-image.png`. Use it once per page.
- **The parent's own motifs stay on bonham.tech.** No mountains, ridgeline, contours or forest
  green here; those belong to the parent brand.
- **Fonts are self-hosted** and the CSP allows no font service (`font-src 'self'`), so the
  page makes no third-party request. Each family needs its licence text beside it.
- **Numbers** only where the order is real: the pipeline steps and the walkthrough.

`og-image.png` is a 1200×630 render of the lockup, the headline and the motif; redraw it if
the headline changes.

`tests/test_site.py` checks every internal link and anchor, the page metadata, the headers,
the sitemap, that the fonts are self-hosted and both themes are present, that the demo's
numbers match its report, and that no page links the GitHub
repository while `LICENSE` is still the proprietary notice.

## Guardrails (BORG-70)

- Every change under `site/` is `ap-owner-merge`, whoever wrote it, and autopilot never
  merges a PR from a fork or from anyone but the owner or Dependabot
  (`.claude/rules/autopilot.local.md`).
- `vercel.json` skips a deploy unless `site/` changed
  (`ignoreCommand: git diff --quiet HEAD^ HEAD -- .`, run from the project root `site/`).
- The Vercel project holds no secrets or environment variables, and the site needs none.

## Owner steps before it goes live

1. Create the Vercel project from `Bonham-Technologies/unvarnish` with **Root Directory**
   `site`, framework preset **Other**, no build command, output directory `.`.
2. Production branch `main` only; keep **Git Fork Protection** on.
3. Add `unvarnish.com` and `www.unvarnish.com` to the project (redirect `www` to the apex);
   set the DNS records Vercel shows at Porkbun, and turn on the registrar lock.
4. Confirm the Vercel plan: Hobby is for non-commercial use, so a product site likely needs
   Pro (about $20 a month per seat).
5. GitHub: require approval before workflows run for outside contributors; passkeys or 2FA on
   GitHub, Vercel and Porkbun.
6. After the first deploy, check that `https://unvarnish.com/README.md` returns 404
   (`.vercelignore` keeps it off the site) and that the response headers match `vercel.json`.

## Since launch

The repository went public on 2026-11-18 (UNVAR-37). The licence section and both footers link
`https://github.com/Bonham-Technologies/unvarnish`, and
`test_every_page_links_the_public_repository` keeps it that way.

## Refreshing the demo

The demo was recorded on 2026-11-14 with Unvarnish at `main`, gitleaks 8.30.1 and
osv-scanner 2.7.1 on PATH (the versions the Dockerfile pins), pandoc 3.1.3 and WeasyPrint 61.1
for the exports, `UNVARNISH_EOL_DIR` pointing at a bundle `unvarnish eol refresh` wrote that
day, no model configured, and `scanners.dependencies.offline: false`:

    unvarnish eol refresh --dir "$UNVARNISH_EOL_DIR"
    unvarnish init nodegoat-review --client "Demo client" --consultant "Unvarnish demo"
    cd nodegoat-review     # set scanners.dependencies.offline: false in engagement.yaml
    unvarnish add nodegoat --repo https://github.com/OWASP/NodeGoat.git
    unvarnish run
    unvarnish status
    unvarnish export --format html --format pdf --doc findings

Copy `tools/nodegoat/docs/findings.md` and the two exports into `demo/`, paste the new
terminal output and the report's summary, remediation outlook and first critical finding
into `demo/index.html`, and update the four numbers in `index.html`'s demo section;
`tests/test_site.py` fails until they match the report. It also fails when the scanner table
in `index.html` no longer lists exactly the registered scanners. Advisory counts grow as new
advisories are published, so a rerun will not reproduce these numbers exactly.

## Checking it locally

    python3 -m http.server -d site 8000

The 2026-11-06 checks (axe-core 4.10 and Lighthouse 12.6, desktop and an iPhone 13 viewport):
axe found no violations on either page, and Lighthouse scored accessibility 100 on both. The
exported findings HTML, published as produced, has three axe findings that are the export's
own: links told apart by colour only (UNVAR-23), and no `main` landmark.
