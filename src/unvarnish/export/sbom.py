"""A CycloneDX 1.6 SBOM per tool, from dependencies.json and its stored advisories (UNVAR-93).

Written by Unvarnish itself, with no osv-scanner call, so it works offline. Components are the
declared dependencies (purl, exact version or the manifest's constraint, manifest path), then
the packages osv-scanner resolved online and the packages advisories name that no manifest
declares. Licences appear only as deps.dev declared them in online mode; otherwise the
document says, in its metadata, that they were not checked."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from urllib.parse import quote

import unvarnish
from unvarnish.analysis.licences import cyclonedx_licences, ecosystem, normal_name, package_key
from unvarnish.schemas.inventory import Dependencies, DependencyRecord

SPEC_VERSION = "1.6"
PURL_TYPES = {"pypi": "pypi", "npm": "npm", "cargo": "cargo", "go": "golang", "maven": "maven"}
EXACT_RE = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+][\w.]+)?$")
FULL_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.]+)?$")
RATINGS = {"critical", "high", "medium", "low", "info", "none"}


def exact_version(rec: DependencyRecord) -> str | None:
    """The version a manifest constraint pins exactly, or None for a range or no version."""
    c = (rec.constraint or "").strip()
    if rec.ecosystem == "pypi":
        c = c.removeprefix("===").removeprefix("==") if c.startswith("==") or (
            EXACT_RE.match(c)) else ""  # Poetry: a bare version is exact
    elif rec.ecosystem == "cargo":
        c = c[1:].strip() if c.startswith("=") else ""  # a bare Cargo version means ^version
    elif rec.ecosystem == "npm":
        c = c.removeprefix("=")
        if not FULL_RE.match(c):
            return None  # "1" or "1.2" is a range in npm
    elif rec.ecosystem == "maven" and any(t in c for t in "[(,$"):
        return None
    return c if c and EXACT_RE.match(c) else None


def _seg(text: str) -> str:
    return quote(text, safe=".-_~")


def purl(eco: str, name: str, version: str | None) -> str | None:
    """The package URL for a package in one of the manifest parser's ecosystems."""
    kind = PURL_TYPES.get(eco)
    if kind is None or not name:
        return None
    if eco == "pypi":
        parts = [normal_name(eco, name)]
    elif eco == "maven" and ":" in name:
        parts = name.split(":", 1)
    elif eco == "go":
        parts = name.split("/")
    elif eco == "npm" and name.startswith("@") and "/" in name:
        parts = name.split("/", 1)
    else:
        parts = [name]
    out = f"pkg:{kind}/" + "/".join(_seg(p) for p in parts)
    return out + (f"@{_seg(version)}" if version else "")


def _group_name(eco: str, name: str) -> tuple[str | None, str]:
    if eco == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        return group, artifact
    if eco == "npm" and name.startswith("@") and "/" in name:
        scope, _, rest = name.partition("/")
        return scope, rest
    return None, name


def _props(**values: str | None) -> list[dict]:
    return [{"name": f"unvarnish:{k}", "value": v} for k, v in values.items() if v]


def _component(eco: str, name: str, version: str | None, manifest: str, *,
               constraint: str | None = None, dev: bool = False, scope: bool = True,
               licences: list[str] | None = None, ref: str) -> dict:
    group, short = _group_name(eco, name)
    comp: dict = {"type": "library", "bom-ref": ref}
    if group:
        comp["group"] = group
    comp["name"] = short
    if version:
        comp["version"] = version
    if scope:
        comp["scope"] = "optional" if dev else "required"
    if licences:
        comp["licenses"] = cyclonedx_licences(licences)
    url = purl(eco, name, version)
    if url:
        comp["purl"] = url
    comp["properties"] = _props(manifest=manifest, constraint=constraint, ecosystem=eco)
    return comp


class _Refs:
    """Unique bom-refs: a component's purl and manifest, numbered if a manifest repeats it."""

    def __init__(self) -> None:
        self.seen: set[str] = set()

    def new(self, base: str) -> str:
        ref, n = base, 2
        while ref in self.seen:
            ref, n = f"{base}#{n}", n + 1
        self.seen.add(ref)
        return ref


def licence_status(deps: Dependencies, offline: bool) -> str:
    """"checked (...)" or "not checked (<why>)": the SBOM's metadata and the export's note."""
    if deps.licences_checked:
        return "checked (deps.dev, through osv-scanner)"
    why = deps.licences_note or ("offline mode" if offline else "not looked up")
    return f"not checked ({why})"


def cyclonedx_document(tool: str, deps: Dependencies, *, timestamp: datetime,
                       offline: bool = True) -> dict:
    refs = _Refs()
    components: list[dict] = []
    direct: list[str] = []
    # (ecosystem, normalised name, folder) -> the bom-ref of the component it joins
    by_key: dict[tuple[str, str, str], str] = {}
    resolved: dict[tuple[str, str, str], set[str]] = {}
    for p in deps.packages:
        resolved.setdefault(package_key(p.ecosystem, p.name, p.manifest), set()).add(p.version)
    for rec in deps.dependencies:
        key = package_key(rec.ecosystem, rec.name, rec.manifest)
        version = exact_version(rec)
        if version is None and len(resolved.get(key, ())) == 1:
            version = next(iter(resolved[key]))  # the one version the lockfile resolved
        ref = refs.new(f"{purl(rec.ecosystem, rec.name, None) or rec.name}?manifest="
                       f"{rec.manifest}")
        components.append(_component(rec.ecosystem, rec.name, version, rec.manifest,
                                     constraint=rec.constraint, dev=rec.dev,
                                     licences=rec.licences, ref=ref))
        by_key.setdefault(key, ref)
        direct.append(ref)
    by_version: dict[tuple[str, str, str, str], str] = {}

    def extra(eco_osv: str, name: str, version: str, manifest: str,
              licences: list[str] | None) -> str:
        eco = ecosystem(eco_osv)
        vkey = (*package_key(eco, name, manifest), version)
        if vkey not in by_version:
            ver = version if version and version != "?" else None
            ref = refs.new(f"{purl(eco, name, ver) or name}?manifest={manifest}")
            components.append(_component(eco, name, ver, manifest, scope=False,
                                         licences=licences, ref=ref))
            by_version[vkey] = ref
        return by_version[vkey]

    for p in deps.packages:
        if package_key(p.ecosystem, p.name, p.manifest) not in by_key:
            extra(p.ecosystem, p.name, p.version, p.manifest, p.licences)

    vulns: dict[str, dict] = {}
    for a in deps.advisories:
        vid = str(a.get("id") or "?")
        eco, name = a.get("ecosystem", "?"), a.get("package", "?")
        manifest, version = a.get("manifest") or ".", str(a.get("version") or "?")
        ref = by_key.get(package_key(eco, name, manifest)) or extra(
            eco, name, version, manifest, None)
        v = vulns.get(vid)
        if v is None:
            v = vulns[vid] = _vulnerability(vid, a)
        affect = {"ref": ref}
        if version != "?":
            affect["versions"] = [{"version": version, "status": "affected"}]
        if affect not in v["affects"]:
            v["affects"].append(affect)

    tool_ref = refs.new(f"unvarnish:tool/{tool}")
    doc: dict = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "unvarnish",
                                      "version": unvarnish.__version__}]},
            "component": {"type": "application", "bom-ref": tool_ref, "name": tool},
            "properties": _props(
                licences=licence_status(deps, offline),
                advisories=("checked (osv-scanner)" if deps.advisories_checked else
                            f"not checked ({deps.advisories_note or 'unknown reason'})"),
                advisories_note=deps.advisories_note if deps.advisories_checked else None,
                exploit_data=(f"dated {deps.exploit_data_date}" if deps.exploit_data_date
                              else None)),
        },
        "components": components,
        "dependencies": [{"ref": tool_ref, "dependsOn": list(dict.fromkeys(direct))}],
    }
    if vulns:
        doc["vulnerabilities"] = list(vulns.values())
    return doc


def _vulnerability(vid: str, a: dict) -> dict:
    v: dict = {"bom-ref": f"vulnerability:{vid}", "id": vid,
               "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{quote(vid)}"}}
    aliases = [str(i) for i in a.get("ids") or [] if i and i != vid]
    if aliases:
        v["references"] = [{"id": i, "source": {
            "name": "OSV", "url": f"https://osv.dev/vulnerability/{quote(i)}"}}
            for i in dict.fromkeys(aliases)]
    severity = str(a.get("severity") or "").lower()
    if severity in RATINGS:
        rating: dict = {"severity": severity, "method": "other"}
        if a.get("kev"):
            rating["justification"] = ("listed in CISA's Known Exploited Vulnerabilities "
                                       "catalog, so rated critical")
        v["ratings"] = [rating]
    if a.get("summary"):
        v["description"] = str(a["summary"])
    v["affects"] = []
    props = {}
    if "kev" in a:
        props["kev"] = "true" if a.get("kev") else "false"
        props["kev_date_added"] = a.get("kev_date_added")
        if a.get("epss") is not None:
            props["epss"] = str(a["epss"])
            props["epss_percentile"] = str(a.get("epss_percentile"))
    if props:
        v["properties"] = _props(**props)
    return v
