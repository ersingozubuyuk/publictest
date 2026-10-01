"""Run an assessment over an inventory and persist the results (shared by CLI and web)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .analysis import assess_host, fleet_summary
from .inventory import Host, masking_map
from .sources import oval


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def run(hosts: list[Host], cache: Path, out: Path, on: dt.date, refresh: bool,
        indexes: dict[str, dict] | None = None) -> dict:
    """Assess ``hosts`` and write host JSONs, fleet summary and the private masking map to ``out``."""
    indexes = {} if indexes is None else indexes
    results = []
    for h in hosts:
        major = h.major or "15"
        if major not in indexes:
            indexes[major] = oval.load_index(major, cache, refresh=refresh)
        results.append(assess_host(h, indexes[major], on))

    for r in results:
        write_json(out / "hosts" / f"{r['host_id']}.json", r)
    summary = fleet_summary(results, on)
    write_json(out / "fleet-summary.json", summary)
    # Stays local: the only place real hostnames are written.
    write_json(out / "private" / "masking-map.json", masking_map(hosts))
    return summary
