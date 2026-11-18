-- Turn raw HTML into visible text. Model-written and scanned fields come from the client's
-- untrusted code; a quoted <script> or List<String> must never become markup. The gfm reader
-- in pandoc 3.1 keeps raw HTML even with -raw_html, so this filter is the guarantee.
local function is_html(el)
  return el.format == "html" or el.format == "html5" or el.format == "html4"
end

function RawInline(el)
  if is_html(el) then return pandoc.Str(el.text) end
end

function RawBlock(el)
  if is_html(el) then return pandoc.Para({pandoc.Str((el.text:gsub("%s+$", "")))}) end
end

-- Images and links in model-written text must not reach outside the document. pandoc embeds
-- every image it can read (--embed-resources, Word, weasyprint), so a Markdown image pointing
-- at ~/.ssh/id_rsa or a remote URL would be read at export time. Only the diagrams that
-- prepare_markdown writes into the export's images/ directory may load (pandoc runs in the
-- export's work directory, so the path is checked there); any other image shows its alt
-- text. Links keep only http, https and mailto targets and in-document #anchors: a path such
-- as /etc/passwd or //host/share would resolve to a live file: link in the PDF.
local DIAGRAM_SRC = "^images/[%w_-]+%.[%a]+$"
local LINK_SCHEMES = { http = true, https = true, mailto = true }

local function inert(inlines, target)
  local text = pandoc.utils.stringify(inlines)
  if text == "" then return pandoc.Str(target) end
  if text == target then return inlines end
  local out = pandoc.List(inlines)
  out:insert(pandoc.Str(" (" .. target .. ")"))
  return out
end

local function is_diagram(src)
  if not src:match(DIAGRAM_SRC) or src:match("%.%.") then return false end
  local f = io.open(src, "rb")
  if f == nil then return false end
  f:close()
  return true
end

function Image(el)
  if is_diagram(el.src) then return nil end
  return inert(el.caption, el.src)
end

function Link(el)
  -- Browsers ignore whitespace and control characters inside a scheme, so drop them first.
  local target = el.target:gsub("[%c%s]", ""):lower()
  if target:sub(1, 1) == "#" then return nil end
  local scheme = target:match("^([%a][%w+.-]*):")
  if scheme ~= nil and LINK_SCHEMES[scheme] then return nil end
  return inert(el.content, el.target)
end
