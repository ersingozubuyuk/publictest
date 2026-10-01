import datetime as dt
from pathlib import Path

import pytest

from kernelassess.analysis import assess_host, classify_cve
from kernelassess.inventory import load_inventory
from kernelassess.kernel import KernelParseError, KernelRelease
from kernelassess.sources.oval import _split_description, component_of


def test_parse_uname():
    k = KernelRelease.parse("6.4.0-150600.23.25-default")
    assert (k.upstream, k.sle_major, k.sle_sp, k.maintenance_release, k.flavor) == ("6.4.0", 15, 6, "23.25", "default")


def test_uname_equals_rpm_release():
    assert KernelRelease.parse("6.4.0-150600.23.25-default") == KernelRelease.from_rpm("6.4.0", "150600.23.25.1", "default")
    assert KernelRelease.parse("6.4.0-150600.23.25-default") < KernelRelease.from_rpm("6.4.0", "150600.23.100.1", "default")


@pytest.mark.parametrize("bad", ["6.4.0-garbage", "6.4.0-150600.23-default", ""])
def test_parse_rejects_bad(bad):
    with pytest.raises(KernelParseError):
        KernelRelease.parse(bad)


def test_split_description():
    text = """The following security issues were fixed:

- CVE-2024-57841,CVE-2026-53260: net: fix memory leak in tcp_conn_request() (bsc#1235944 bsc#1269731).
- CVE-2023-0160: Fixed deadlock flaw in BPF (bsc#1209657).

The following non-security bugs were fixed:

- ext4: fix something (bsc#1).
"""
    cves, other = _split_description(text)
    assert cves["CVE-2026-53260"] == "net: fix memory leak in tcp_conn_request()"
    assert cves["CVE-2023-0160"] == "Fixed deadlock flaw in BPF"
    assert other == ["ext4: fix something"]
    assert component_of(cves["CVE-2024-57841"]) == "net"
    assert component_of(cves["CVE-2023-0160"]) is None


def test_classify_prefers_suse_then_nvd():
    assert classify_cve({"suse_impact": "medium", "suse_cvss3": 5.5, "nvd_impact": "high"}) == ("Medium", 5.5, "SUSE")
    assert classify_cve({"nvd_cvss3": 9.8}) == ("Critical", 9.8, "NVD")
    assert classify_cve({}) == ("Unknown", None, "Unknown")


def _adv(n, release, issued, cves):
    return {"kind": "update", "id": f"SUSE-SU-{n}", "url": None, "title": "t", "severity": "Important",
            "issued": issued, "cpes": ["cpe:/o:suse:sles:15:sp6"], "non_security_fixes": [],
            "kernels": {"default": {"version": "6.4.0", "release": release}},
            "cves": [{"id": c, "suse_impact": "high", "suse_cvss3": 7.8, "summary": None, "component": None} for c in cves]}


def test_assess_host_gap(tmp_path: Path):
    inv = tmp_path / "inv.csv"
    inv.write_text("hostname,os,version,kernel,architecture,platform\n"
                   "real-name,SLES,15 SP6,6.4.0-150600.23.25-default,ppc64le,IBM Power\n")
    host = load_inventory(inv)[0]
    index = {"source": "x", "advisories": [
        _adv(1, "150600.23.25.1", "2024-10-09", ["CVE-2024-1"]),
        _adv(2, "150600.23.30.1", "2024-12-13", ["CVE-2024-2", "CVE-2024-1"]),
        _adv(3, "150600.23.33.1", "2025-01-17", ["CVE-2024-2", "CVE-2025-3"]),
    ]}
    r = assess_host(host, index, dt.date(2026, 10, 1))
    assert "real-name" not in str(r)
    assert r["version"]["maintenance_gap"] == {"releases_behind": 2, "days_behind": 100}
    assert r["version"]["latest"]["maintenance_release"] == "23.33"
    cves = {c["cve"]: c for c in r["security"]["missing_cves"]}
    assert set(cves) == {"CVE-2024-1", "CVE-2024-2", "CVE-2025-3"}
    assert cves["CVE-2024-2"]["fixed_release"] == "23.30"
    assert cves["CVE-2024-2"]["also_fixed_in"] == ["23.33"]
    assert cves["CVE-2024-1"]["previously_addressed"] is True
    assert r["lifecycle"]["phase"] == "LTSS"
    assert r["ibm_power"]["hmc_compatibility"] == "Not Verified"
