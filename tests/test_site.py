"""The unvarnish.com static site under site/ (UNVAR-38): links resolve, pages carry the
metadata and headers the launch needs, and the demo's numbers match its published report."""

import json
import re
from datetime import date, timedelta
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
PAGES = ["index.html", "demo/index.html"]
SITE_URL = "https://unvarnish.com"

pytestmark = pytest.mark.skipif(not SITE.exists(), reason="needs the repository checkout")


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.meta: dict[str, str] = {}
        self.canonical: str | None = None
        self.lang: str | None = None
        self.h1 = 0
        self.inline_scripts: list[str] = []
        self._script_type: str | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "html":
            self.lang = a.get("lang")
        if tag == "h1":
            self.h1 += 1
        if tag == "meta":
            key = a.get("property") or a.get("name")
            if key:
                self.meta[key] = a.get("content", "")
        if tag == "link" and a.get("rel") == "canonical":
            self.canonical = a.get("href")
        for attr in ("href", "src"):
            if a.get(attr) and not (tag == "link" and a.get("rel") in ("preconnect", "canonical")):
                self.links.append(a[attr])
        if tag == "script":
            self._script_type = a.get("type", "text/javascript")

    def handle_data(self, data):
        if self._script_type and data.strip():
            self.inline_scripts.append(self._script_type)

    def handle_endtag(self, tag):
        if tag == "script":
            self._script_type = None


def _parse(rel: str) -> _Page:
    page = _Page()
    page.feed((SITE / rel).read_text(encoding="utf-8"))
    return page


def _resolve(rel: str, href: str) -> Path:
    path = urlparse(href).path
    if not path:
        return SITE / rel
    target = SITE / path.lstrip("/") if path.startswith("/") else (SITE / rel).parent / path
    return target / "index.html" if path.endswith("/") else target


@pytest.mark.parametrize("rel", PAGES)
def test_every_internal_link_resolves(rel):
    page = _parse(rel)
    for href in page.links:
        parsed = urlparse(href)
        if parsed.scheme in ("http", "https", "mailto"):
            continue
        assert _resolve(rel, href).is_file(), f"{rel}: {href} does not exist"
        if parsed.fragment:
            target = _resolve(rel, href)
            ids = page.ids if target == SITE / rel else _parse(str(target.relative_to(SITE))).ids
            assert parsed.fragment in ids, f"{rel}: #{parsed.fragment} has no target"


@pytest.mark.parametrize("rel", PAGES)
def test_pages_carry_launch_metadata(rel):
    page = _parse(rel)
    assert page.lang == "en" and page.h1 == 1
    assert page.canonical and page.canonical.startswith(SITE_URL + "/")
    for key in ("description", "og:title", "og:description", "og:image", "og:url",
                "twitter:card", "viewport"):
        assert page.meta.get(key), f"{rel}: missing {key}"
    assert page.meta["og:url"] == page.canonical
    image = urlparse(page.meta["og:image"]).path
    assert (SITE / image.lstrip("/")).is_file()
    # The CSP allows scripts from 'self' only: no inline JavaScript, data blocks are fine.
    assert all(t == "application/ld+json" for t in page.inline_scripts)


def test_og_image_is_the_size_the_pages_declare():
    data = (SITE / "og-image.png").read_bytes()
    width, height = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    assert (width, height) == (1200, 630)


def test_sitemap_and_robots_list_only_real_pages():
    robots = (SITE / "robots.txt").read_text(encoding="utf-8")
    assert f"Sitemap: {SITE_URL}/sitemap.xml" in robots
    locs = re.findall(r"<loc>([^<]+)</loc>", (SITE / "sitemap.xml").read_text(encoding="utf-8"))
    assert f"{SITE_URL}/" in locs and f"{SITE_URL}/demo/" in locs
    for loc in locs:
        assert loc.startswith(SITE_URL + "/")
        assert _resolve("index.html", urlparse(loc).path).is_file(), loc


def test_vercel_config_sets_security_headers_and_skips_unrelated_deploys():
    config = json.loads((SITE / "vercel.json").read_text(encoding="utf-8"))
    headers = {h["key"]: h["value"] for h in config["headers"][0]["headers"]}
    assert config["headers"][0]["source"] == "/(.*)"
    csp = headers["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "object-src 'none'",
                      "base-uri 'self'", "frame-ancestors 'none'"):
        assert directive in csp
    assert "unsafe-eval" not in csp and "script-src 'self' 'unsafe-inline'" not in csp
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "max-age=63072000" in headers["Strict-Transport-Security"]
    assert headers["Referrer-Policy"] and headers["Permissions-Policy"]
    # Guardrail from BORG-70: deploy only when site/ changed; the project holds no env vars.
    assert config["ignoreCommand"] == "git diff --quiet HEAD^ HEAD -- ."
    assert "env" not in config and "build" not in config


def test_internal_notes_are_not_served():
    # With Root Directory site/, every file in it is public unless .vercelignore drops it;
    # README.md holds the owner's setup notes, which are not for the public site.
    ignored = (SITE / ".vercelignore").read_text(encoding="utf-8").split()
    assert "README.md" in ignored


def test_every_page_links_the_public_repository():
    # The repository went public on 2026-11-18 (UNVAR-37): every page's footer links it, and
    # it is the only Bonham Technologies repository the pages link (the demo also links the
    # project it scanned).
    for rel in PAGES:
        text = (SITE / rel).read_text(encoding="utf-8")
        assert 'href="https://github.com/Bonham-Technologies/unvarnish"' in text, rel
        assert "will be published" not in text and "once it goes public" not in text, rel
        ours = re.findall(r'href="(https://github\.com/bonham-technologies/[^"]*)"', text, re.I)
        assert set(ours) == {"https://github.com/Bonham-Technologies/unvarnish"}, rel


def test_demo_numbers_match_the_published_report():
    report = (SITE / "demo/nodegoat-findings.md").read_text(encoding="utf-8")
    total, critical = re.search(r"(\d+) finding\(s\): (\d+) critical", report).groups()
    history = re.search(r"\| Secrets \(current / history only\) \| \d+ / (\d+) \|", report)[1]
    commits = re.search(r"\| Commits · authors · active days \| (\d+) ·", report)[1]
    index = (SITE / "index.html").read_text(encoding="utf-8")
    stats = dict(re.findall(r"<dt>([^<]+)</dt><dd>(\d+)</dd>", index))
    assert stats == {"findings": total, "critical": critical,
                     "secrets only in history": history, "commits read": commits}
    demo = (SITE / "demo/index.html").read_text(encoding="utf-8")
    assert re.search(rf"all\s+{total}\s+findings", demo)
    for name in ("nodegoat-findings.html", "nodegoat-findings.pdf"):
        assert (SITE / "demo" / name).stat().st_size > 10_000


def test_scanner_table_lists_every_registered_scanner():
    # UNVAR-55: the site said "Eight scanners" after client_exposure and end_of_life shipped.
    from unvarnish.scanners import load_scanners

    index = (SITE / "index.html").read_text(encoding="utf-8")
    section = re.search(r'<section id="finds".*?</section>', index, re.S)[0]
    listed = re.findall(r"<tr><td><code>([a-z_]+)</code></td>", section)
    registered = [s.name for s in load_scanners()]
    assert len(listed) == len(set(listed)), f"a scanner is listed twice: {listed}"
    assert sorted(listed) == sorted(registered)
    words = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine",
             "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen",
             "Seventeen", "Eighteen", "Nineteen", "Twenty"]
    assert len(registered) < len(words), f"no count word for {len(registered)} scanners"
    assert f"{words[len(registered)]} scanners run" in section


def test_security_txt_names_a_contact_that_expires_within_a_year():
    # BORG-96: bonham-ops `bin/seo-check` SITE-3 (RFC 9116) failed on the live site with a 404.
    text = (SITE / ".well-known" / "security.txt").read_text(encoding="utf-8")
    assert re.search(r"^Contact: mailto:\S+@bonham\.tech$", text, re.M)
    expires = re.search(r"^Expires: (\d{4}-\d{2}-\d{2})T", text, re.M)
    assert expires
    assert date.today() < date.fromisoformat(expires[1]) <= date.today() + timedelta(days=366)
    assert f"Canonical: {SITE_URL}/.well-known/security.txt" in text


def test_every_sitemap_page_names_itself_as_canonical():
    # BORG-96: `bin/seo-check` SEO-9 failed on demo/nodegoat-findings.html (no canonical tag).
    locs = re.findall(r"<loc>([^<]+)</loc>", (SITE / "sitemap.xml").read_text(encoding="utf-8"))
    for loc in locs:
        path = urlparse(loc).path
        page = _parse(str(_resolve("index.html", path).relative_to(SITE)))
        assert page.canonical == loc, f"{loc}: canonical is {page.canonical}"
