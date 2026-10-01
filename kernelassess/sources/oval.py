"""SUSE OVAL patch feed: download, cache and extract kernel advisories.

The patch-class OVAL feed (``suse.linux.enterprise.server.<major>-patch.xml.gz``)
is SUSE's machine-readable form of every released maintenance update. Each
definition carries the SUSE-SU advisory ID, issue date, severity, the CVEs
with SUSE and NVD CVSS scores, the affected product CPEs and the fixed RPM
versions. We stream it once and keep only kernel advisories in a compact
JSON index, rebuilt whenever the feed changes.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

from ..kernel import KNOWN_FLAVORS

log = logging.getLogger(__name__)

OVAL_BASE = "https://ftp.suse.com/pub/projects/security/oval/"
INDEX_SCHEMA = 1

_NS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
_KERNEL_RE = re.compile(
    r"^kernel-(?P<flavor>[a-z0-9_]+)-(?P<version>\d+\.\d+(?:\.\d+)?)-(?P<release>\d{6}(?:\.\d+)+) is installed$"
)
_CVE_LINE_RE = re.compile(r"^\s*-\s*((?:CVE-\d{4}-\d{4,}[,\s]*)+):\s*(.+?)\s*$")
_BULLET_RE = re.compile(r"^\s*-\s+(.+?)\s*$")
_BSC_RE = re.compile(r"\s*\((?:bsc|bnc|jsc)#[^)]*\)\.?\s*$")
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def feed_url(major: str) -> str:
    return f"{OVAL_BASE}suse.linux.enterprise.server.{major}-patch.xml.gz"


def download(url: str, cache_dir: Path, session: requests.Session | None = None) -> tuple[Path, bool]:
    """Fetch ``url`` into ``cache_dir`` using a conditional GET. Returns (path, changed)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / url.rsplit("/", 1)[-1]
    meta_path = target.with_suffix(target.suffix + ".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() and target.exists() else {}

    headers = {}
    if meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]

    s = session or requests.Session()
    with s.get(url, headers=headers, stream=True, timeout=(15, 300)) as r:
        if r.status_code == 304:
            log.info("Feed unchanged: %s", url)
            return target, False
        r.raise_for_status()
        tmp = target.with_suffix(target.suffix + ".part")
        with tmp.open("wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
        tmp.replace(target)
        meta_path.write_text(json.dumps({
            "url": url,
            "etag": r.headers.get("ETag"),
            "last_modified": r.headers.get("Last-Modified"),
        }))
    log.info("Downloaded %s", url)
    return target, True


def _split_description(text: str) -> tuple[dict[str, str], list[str]]:
    """Return ({CVE: summary}, [non-security fix lines]) from an advisory description."""
    cve_summaries: dict[str, str] = {}
    other: list[str] = []
    in_non_security = False
    for line in text.splitlines():
        low = line.lower()
        if "were fixed" in low:
            in_non_security = "non-security" in low
            continue
        m = _CVE_LINE_RE.match(line)
        if m:
            for cve_id in _CVE_ID_RE.findall(m[1]):
                cve_summaries.setdefault(cve_id, _BSC_RE.sub("", m[2]))
            continue
        if in_non_security:
            b = _BULLET_RE.match(line)
            if b:
                other.append(_BSC_RE.sub("", b[1]))
    return cve_summaries, other


def component_of(summary: str | None) -> str | None:
    """Kernel fix summaries follow the commit-subject style ``subsystem: driver: text``."""
    if not summary or ": " not in summary:
        return None
    head = summary.split(": ")[0].strip()
    if 0 < len(head) <= 40 and " " not in head.strip():
        return head
    return None


def _parse_cvss(attr: str | None) -> tuple[float | None, str | None]:
    if not attr:
        return None, None
    score, _, vector = attr.partition("/")
    try:
        return float(score), vector or None
    except ValueError:
        return None, None


def _definition_to_advisory(defn: ET.Element) -> dict | None:
    kernels: dict[str, dict] = {}
    for crit in defn.iter(f"{_NS}criterion"):
        m = _KERNEL_RE.match(crit.get("comment", ""))
        if m and m["flavor"] in KNOWN_FLAVORS:
            kernels[m["flavor"]] = {"version": m["version"], "release": m["release"]}
    if not kernels:
        return None

    md = defn.find(f"{_NS}metadata")
    adv = md.find(f"{_NS}advisory")
    advisory_id = url = None
    for ref in md.findall(f"{_NS}reference"):
        if ref.get("source") == "SUSE-SU":
            advisory_id, url = ref.get("ref_id"), ref.get("ref_url")
            break

    description = (md.findtext(f"{_NS}description") or "").strip()
    summaries, non_security = _split_description(description)

    cves: dict[str, dict] = {}
    for c in adv.findall(f"{_NS}cve") if adv is not None else []:
        text = c.text or ""
        m = _CVE_ID_RE.search(text)
        if not m:
            continue
        entry = cves.setdefault(m[0], {"id": m[0]})
        score, vector = _parse_cvss(c.get("cvss3"))
        side = "nvd" if "nvd.nist.gov" in (c.get("href") or "") else "suse"
        entry[f"{side}_impact"] = c.get("impact")
        entry[f"{side}_cvss3"] = score
        entry[f"{side}_vector"] = vector
        if side == "suse":
            entry["url"] = c.get("href")
    for cve_id, entry in cves.items():
        entry["summary"] = summaries.get(cve_id)
        entry["component"] = component_of(entry["summary"])

    def _date(tag: str) -> str | None:
        el = adv.find(f"{_NS}{tag}") if adv is not None else None
        return el.get("date") if el is not None else None

    title = (md.findtext(f"{_NS}title") or "").strip()
    return {
        "oval_id": defn.get("id"),
        # "ga" entries list CVEs already fixed in the GA media kernel: a baseline, not an update.
        "kind": "ga" if advisory_id is None and "on GA media" in title else "update",
        "id": advisory_id,
        "url": url,
        "title": title,
        "severity": adv.findtext(f"{_NS}severity") if adv is not None else None,
        "issued": _date("issued"),
        "updated": _date("updated"),
        "platforms": [p.text for p in md.iter(f"{_NS}platform")],
        "cpes": [c.text for c in adv.iter(f"{_NS}cpe")] if adv is not None else [],
        "kernels": kernels,
        "cves": sorted(cves.values(), key=lambda e: e["id"]),
        "non_security_fixes": non_security,
        "description": description,
    }


def extract_kernel_advisories(feed_path: Path) -> list[dict]:
    """Stream the OVAL feed and return every definition that ships a kernel package."""
    advisories: list[dict] = []
    container = None
    with gzip.open(feed_path, "rb") as f:
        for event, elem in ET.iterparse(f, events=("start", "end")):
            if event == "start":
                if elem.tag == f"{_NS}definitions":
                    container = elem
                continue
            if elem.tag == f"{_NS}definition":
                adv = _definition_to_advisory(elem)
                if adv:
                    advisories.append(adv)
                if container is not None:
                    container.clear()
            elif elem.tag == f"{_NS}definitions":
                break  # tests/objects/states follow; we only need definitions
    return _merge_duplicates(advisories)


def _merge_duplicates(advisories: list[dict]) -> list[dict]:
    """SUSE emits one definition per product family (e.g. LTSS and SAP) for the
    same advisory; fold them into one record with the union of products."""
    merged: dict[str, dict] = {}
    for adv in advisories:
        key = adv["id"] or adv["oval_id"]
        if key not in merged:
            merged[key] = adv
            continue
        into = merged[key]
        for field in ("platforms", "cpes"):
            into[field] = list(dict.fromkeys(into[field] + adv[field]))
        into["kernels"] = {**adv["kernels"], **into["kernels"]}
    return sorted(merged.values(), key=lambda a: (a["issued"] or "", a["id"] or ""))


def load_index(major: str, cache_dir: Path, refresh: bool = True,
               session: requests.Session | None = None) -> dict:
    """Return the kernel advisory index for SLE ``major``, rebuilding it if the feed changed."""
    url = feed_url(major)
    index_path = cache_dir / f"kernel-index-sle{major}.json"
    feed_path = cache_dir / url.rsplit("/", 1)[-1]

    changed = False
    if refresh or not feed_path.exists():
        feed_path, changed = download(url, cache_dir, session)

    if index_path.exists() and not changed:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if index.get("schema") == INDEX_SCHEMA:
            return index

    log.info("Building kernel index from %s (this takes a minute)", feed_path.name)
    meta_path = feed_path.with_suffix(feed_path.suffix + ".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    index = {
        "schema": INDEX_SCHEMA,
        "source": url,
        "source_last_modified": meta.get("last_modified"),
        "advisories": extract_kernel_advisories(feed_path),
    }
    index_path.write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")
    return index
