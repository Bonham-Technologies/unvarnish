-- Structure for screen readers in HTML exports. pandoc.py runs this filter for --format html
-- only, after inert-html.lua (whose pass would turn the raw <main> markers below into text);
-- Word and PDF never see it, so their output stays exactly as it was.
--
-- 1. The report goes inside <main>, so assistive technology can jump to it.
-- 2. Every column header gets scope="col".
-- 3. In summary tables, the first cell of each body row becomes <th scope="row">. A summary
--    table is one whose first column header names a row label: the severity counts in
--    findings.md and the Measure and Layer tables (Measure | Value, per-tool measures in the
--    comparison, Layer | Value). Lists of findings, files or systems keep plain data cells:
--    their first column is an item, not a label for the row.
--    report.css styles these row headers like the data cells they replace.
local ROW_LABEL_HEADERS = { Severity = true, Measure = true, Layer = true }

function Table(tbl)
  local head = tbl.head.rows
  if #head == 0 or #head[1].cells == 0 then return nil end
  for _, row in ipairs(head) do
    for _, cell in ipairs(row.cells) do cell.attributes.scope = "col" end
  end
  local first = pandoc.utils.stringify(head[1].cells[1].contents)
  if ROW_LABEL_HEADERS[first] then
    for _, body in ipairs(tbl.bodies) do
      body.row_head_columns = 1
      for _, row in ipairs(body.body) do
        if #row.cells > 0 then row.cells[1].attributes.scope = "row" end
      end
    end
  end
  return tbl
end

function Pandoc(doc)
  doc.blocks:insert(1, pandoc.RawBlock("html", "<main>"))
  doc.blocks:insert(pandoc.RawBlock("html", "</main>"))
  return doc
end
