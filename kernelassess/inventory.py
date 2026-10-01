"""Fleet inventory (CSV) loading, validation and hostname masking.

Expected CSV header (case-insensitive, extra columns ignored)::

    hostname,os,version,kernel,architecture,platform

Real hostnames never leave this module's caller: every host gets a stable
pseudonym (HOST-0001, ...) and the mapping is written only to a local file.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

_SLES_NAMES = {
    "sles": "SLES",
    "suse linux enterprise server": "SLES",
    "sles_sap": "SLES",
    "sles for sap": "SLES",
    "suse linux enterprise server for sap applications": "SLES",
}
_VERSION_RE = re.compile(r"^\s*(?P<major>\d+)(?:\s*[-.\s]\s*(?:sp\s*)?(?P<sp>\d+))?\s*$", re.I)


@dataclass
class Host:
    host_id: str
    hostname: str
    os_raw: str
    version_raw: str
    kernel: str
    architecture: str | None
    platform: str | None
    product: str | None = None
    major: str | None = None
    service_pack: int | None = None
    issues: list[str] = field(default_factory=list)

    def public_input(self) -> dict:
        """Input fields safe to include in reports / send onwards (no hostname)."""
        return {
            "os": self.os_raw,
            "version": self.version_raw,
            "kernel": self.kernel,
            "architecture": self.architecture,
            "platform": self.platform,
        }


def _normalise_product(os_raw: str) -> str | None:
    return _SLES_NAMES.get(os_raw.strip().lower())


def _parse_version(version_raw: str) -> tuple[str | None, int | None]:
    m = _VERSION_RE.match(version_raw.replace("SP", " SP").replace("sp", " sp"))
    if not m:
        return None, None
    return m["major"], int(m["sp"]) if m["sp"] is not None else 0


def load_inventory(path: Path) -> list[Host]:
    with path.open(newline="", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        rows = list(csv.DictReader(f, dialect=dialect))

    hosts: list[Host] = []
    for i, row in enumerate(rows, start=1):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        if not any(row.values()):
            continue
        h = Host(
            host_id=f"HOST-{i:04d}",
            hostname=row.get("hostname", ""),
            os_raw=row.get("os", ""),
            version_raw=row.get("version", ""),
            kernel=row.get("kernel", ""),
            architecture=row.get("architecture") or None,
            platform=row.get("platform") or None,
        )
        h.product = _normalise_product(h.os_raw)
        if not h.product:
            h.issues.append(f"Unsupported or unrecognised OS: {h.os_raw!r}")
        h.major, h.service_pack = _parse_version(h.version_raw)
        if h.major is None:
            h.issues.append(f"Unrecognised version: {h.version_raw!r}")
        if not h.kernel:
            h.issues.append("Kernel version missing")
        hosts.append(h)
    return hosts


def masking_map(hosts: list[Host]) -> dict[str, str]:
    return {h.host_id: h.hostname for h in hosts}
