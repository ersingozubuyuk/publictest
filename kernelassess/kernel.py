"""SUSE kernel version parsing and ordering.

A SLES kernel as reported by ``uname -r`` looks like::

    6.4.0-150600.23.25-default
    │     │      │  │   └─ flavor
    │     │      │  └───── maintenance update counter
    │     │      └──────── kernel branch (stable within an SP)
    │     └─────────────── codestream: 15 06 00 -> SLE 15 SP6
    └───────────────────── upstream base version

The matching RPM carries one more rebuild component (``150600.23.25.1``).
Maintenance releases are identified by ``<branch>.<update>`` (e.g. ``23.25``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_UNAME_RE = re.compile(
    r"^(?P<upstream>\d+\.\d+(?:\.\d+)?)"
    r"-(?P<codestream>\d{6})\.(?P<branch>\d+)\.(?P<update>\d+)(?:\.(?P<rebuild>\d+))?"
    r"-(?P<flavor>[a-z0-9_]+)$"
)

KNOWN_FLAVORS = {"default", "64kb", "rt", "azure", "zfcpdump", "kvmsmall", "preempt", "debug"}


class KernelParseError(ValueError):
    pass


@total_ordering
@dataclass(frozen=True)
class KernelRelease:
    upstream: str
    codestream: int
    branch: int
    update: int
    flavor: str
    rebuild: int | None = None

    @classmethod
    def parse(cls, text: str) -> "KernelRelease":
        m = _UNAME_RE.match(text.strip())
        if not m:
            raise KernelParseError(f"Unrecognised SUSE kernel version: {text!r}")
        return cls(
            upstream=m["upstream"],
            codestream=int(m["codestream"]),
            branch=int(m["branch"]),
            update=int(m["update"]),
            flavor=m["flavor"],
            rebuild=int(m["rebuild"]) if m["rebuild"] else None,
        )

    @classmethod
    def from_rpm(cls, version: str, release: str, flavor: str) -> "KernelRelease":
        """Build from RPM version/release, e.g. ('6.4.0', '150600.23.25.1', 'default')."""
        parts = release.split(".")
        if len(parts) < 3 or not all(p.isdigit() for p in parts[:3]):
            raise KernelParseError(f"Unrecognised SUSE kernel release: {release!r}")
        return cls(
            upstream=version,
            codestream=int(parts[0]),
            branch=int(parts[1]),
            update=int(parts[2]),
            flavor=flavor,
            rebuild=int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None,
        )

    # Ordering ignores the rebuild counter and flavor: uname never shows the
    # rebuild, and the same maintenance release ships every flavor.
    @property
    def key(self) -> tuple[int, int, int]:
        return (self.codestream, self.branch, self.update)

    def __lt__(self, other: "KernelRelease") -> bool:
        return self.key < other.key

    def __eq__(self, other: object) -> bool:
        return isinstance(other, KernelRelease) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)

    @property
    def sle_major(self) -> int:
        return self.codestream // 10000

    @property
    def sle_sp(self) -> int:
        return (self.codestream // 100) % 100

    @property
    def maintenance_release(self) -> str:
        return f"{self.branch}.{self.update}"

    @property
    def uname(self) -> str:
        return f"{self.upstream}-{self.codestream}.{self.branch}.{self.update}-{self.flavor}"

    def __str__(self) -> str:
        return self.uname

