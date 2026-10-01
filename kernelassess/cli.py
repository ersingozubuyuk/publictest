"""Command line entry point.

    kernelassess fetch                       # download / refresh SUSE data
    kernelassess assess inventory.csv -o out # analyse a fleet
    kernelassess web                         # test dashboard (needs the [web] extra)
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import sys
from pathlib import Path

from . import runner
from .inventory import load_inventory
from .sources import oval

DEFAULT_CACHE = Path(os.environ.get("KERNELASSESS_DATA", ".")) / "cache"


def cmd_fetch(args) -> int:
    for major in args.major:
        index = oval.load_index(major, args.cache, refresh=True)
        print(f"SLE {major}: {len(index['advisories'])} kernel advisories indexed "
              f"(feed last modified {index.get('source_last_modified')})")
    return 0


def cmd_assess(args) -> int:
    on = dt.date.fromisoformat(args.date) if args.date else dt.date.today()
    hosts = load_inventory(args.inventory)
    if not hosts:
        print("Inventory is empty", file=sys.stderr)
        return 1

    summary = runner.run(hosts, args.cache, args.out, on, refresh=not args.offline)
    for row in summary["hosts"]:
        print(f"{row['host_id']}  {row['kernel']:<32} {row['lifecycle_phase']:<16} "
              f"behind={row['releases_behind']!s:<3} CVE={row['missing_cves']!s:<5} "
              f"C={row['critical']} H={row['high']} M={row['medium']} L={row['low']}"
              + (f"  issues={row['issues']}" if row["issues"] else ""))
    print(f"\nWrote {len(hosts)} host reports to {args.out}")
    return 0


def cmd_web(args) -> int:
    import uvicorn

    uvicorn.run("kernelassess.web.app:app", host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="kernelassess", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cache", type=Path, default=DEFAULT_CACHE, help="data cache directory")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download/refresh SUSE security data")
    f.add_argument("--major", nargs="+", default=["15"], help="SLE major versions (default: 15)")
    f.set_defaults(func=cmd_fetch)

    a = sub.add_parser("assess", help="assess a fleet inventory CSV")
    a.add_argument("inventory", type=Path)
    a.add_argument("-o", "--out", type=Path, default=Path("out"))
    a.add_argument("--date", help="assessment date (YYYY-MM-DD), default today")
    a.add_argument("--offline", action="store_true", help="use cached data without checking for updates")
    a.set_defaults(func=cmd_assess)

    w = sub.add_parser("web", help="run the test dashboard")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8080)
    w.set_defaults(func=cmd_web)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
