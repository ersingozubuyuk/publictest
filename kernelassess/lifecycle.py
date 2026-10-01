"""Product lifecycle lookup from the bundled SUSE lifecycle table."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from importlib import resources

import yaml

from . import NOT_AVAILABLE

GENERAL = "General Support"
LTSS = "LTSS"
EOL = "End of Life"


@dataclass
class Lifecycle:
    product: str
    version: str
    service_pack: int
    fcs: dt.date | None
    general_end: dt.date | None
    ltss_end: dt.date | None
    product_general_end: dt.date | None
    product_ltss_end: dt.date | None
    source: str
    retrieved: str

    def phase(self, on: dt.date) -> str:
        if self.general_end and on <= self.general_end:
            return GENERAL
        if self.ltss_end and on <= self.ltss_end:
            return LTSS
        if self.general_end or self.ltss_end:
            return EOL
        return NOT_AVAILABLE

    def current_phase_end(self, on: dt.date) -> dt.date | None:
        phase = self.phase(on)
        return {GENERAL: self.general_end, LTSS: self.ltss_end}.get(phase)

    def to_dict(self, on: dt.date) -> dict:
        end = self.current_phase_end(on)
        return {
            "product": f"{self.product} {self.version} SP{self.service_pack}",
            "phase": self.phase(on),
            "fcs": _iso(self.fcs),
            "general_support_end": _iso(self.general_end),
            "ltss_end": _iso(self.ltss_end),
            "product_general_end": _iso(self.product_general_end),
            "product_ltss_end": _iso(self.product_ltss_end),
            "current_phase_end": _iso(end),
            "days_to_phase_end": (end - on).days if end else None,
            # LTSS is a separately purchased subscription; we cannot see entitlements.
            "ltss_subscription": "Not Verified" if self.phase(on) == LTSS else None,
            "source": self.source,
            "source_retrieved": self.retrieved,
        }


def _iso(d: dt.date | None) -> str:
    return d.isoformat() if d else NOT_AVAILABLE


def _load() -> dict:
    with resources.files(__package__).joinpath("data/lifecycle.yaml").open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def lookup(product: str, version: str, service_pack: int) -> Lifecycle | None:
    data = _load()
    prod = data["products"].get(product, {}).get(str(version))
    if not prod:
        return None
    rel = prod["releases"].get(str(service_pack))
    if not rel:
        return None
    return Lifecycle(
        product=product,
        version=str(version),
        service_pack=service_pack,
        fcs=rel.get("fcs"),
        general_end=rel.get("general_end"),
        ltss_end=rel.get("ltss_end"),
        product_general_end=prod.get("product_general_end"),
        product_ltss_end=prod.get("product_ltss_end"),
        source=data["source"],
        retrieved=str(data["retrieved"]),
    )


def latest_service_pack(product: str, version: str) -> int | None:
    prod = _load()["products"].get(product, {}).get(str(version))
    if not prod:
        return None
    return max(int(sp) for sp in prod["releases"])
