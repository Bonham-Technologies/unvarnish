# Bonham Technologies export style

A neutral starting point for branded exports. Unvarnish already uses this style by default;
this folder is the copy to change. Point an engagement at it in `engagement.yaml`:

    report:
      branding:
        reference_docx: /path/to/branding/bonham/reference.docx
        html_css: /path/to/branding/bonham/report.css

Relative paths resolve against the engagement folder.

## HTML and PDF (`report.css`)

- **Colours:** change the variables at the top (`--accent` for headings and rules, `--ink` for
  text, `--wash` for table headers and quotes).
- **Fonts:** change `--font`. Exports run offline, so a font must be installed where
  `unvarnish export` runs (the Docker image has Inter, Liberation, and DejaVu). To add one to the
  image, install its package in the Dockerfile's `apt-get` line.
- **Header and footer:** the `@page` block sets the running title (top left), "Confidential"
  (top right), and page numbers (bottom right). Change the text there.
- **Logo:** put `logo.png` next to this file and add to the `@page` block:
  `@top-left { content: url("logo.png"); }` (PDF), or for HTML add
  `body::before { content: url("logo.png"); display: block; margin-bottom: 1em; }`.
- **Tables:** keep the `tbody th` rules. HTML exports mark the first column of summary
  tables as row headers (`<th scope="row">`), and those rules make them look like data
  cells instead of column headers.
- **Paper size:** `size: Letter` in `@page`; use `A4` outside North America.

## Word (`reference.docx`)

Open it in Word and change the styles, not the text (pandoc uses only the styles, headers,
footers, and page setup): Normal, Heading 1 to 4, Block Text (the grey quote box), and Table
(the header row). Add a logo in the header, change the footer text, save under the same name.
To rebuild it from code instead, edit the constants in `scripts/build-reference-docx.py` and run
`uv run --with python-docx python scripts/build-reference-docx.py branding/bonham/reference.docx`.
