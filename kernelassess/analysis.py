"""Per-host kernel security & lifecycle analysis.

Everything here is deterministic and derived only from the declared versions
plus official SUSE data. Anything we cannot establish is reported as
Unknown / Not Available / Not Verified rather than guessed.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter

from . import NOT_AVAILABLE, NOT_VERIFIED, UNKNOWN, __version__, lifecycle
from .inventory import Host
from .kernel import KernelParseError, KernelRelease

SEVERITIES = ("Critical", "High", "Medium", "Low", UNKNOWN)
ASSESSMENT_METHOD = "Offline version-based analysis (no server access)"

_IMPACT_MAP = {
    "critical": "Critical",
    "important": "High",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
}


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return None


def classify_cve(cve: dict) -> tuple[str, float | None, str]:
    """Return (severity, cvss3, source). SUSE's own rating wins, NVD is the fallback."""
    for side, label in (("suse", "SUSE"), ("nvd", "NVD")):
        score = cve.get(f"{side}_cvss3")
        sev = _IMPACT_MAP.get((cve.get(f"{side}_impact") or "").lower()) or _severity_from_score(score)
        if sev:
            return sev, score, label
    return UNKNOWN, None, UNKNOWN


def _releases_for(index: dict, kernel: KernelRelease, sp: int) -> list[tuple[KernelRelease, dict]]:
    """Kernel maintenance updates shipped for this SP codestream and flavor, oldest first."""
    sp_suffix = f":{kernel.sle_major}:sp{sp}"
    out = []
    for adv in index["advisories"]:
        if adv["kind"] != "update" or not any(c.endswith(sp_suffix) for c in adv["cpes"]):
            continue
        pkg = adv["kernels"].get(kernel.flavor)
        if not pkg:
            continue
        rel = KernelRelease.from_rpm(pkg["version"], pkg["release"], kernel.flavor)
        if rel.codestream == kernel.codestream and rel.branch == kernel.branch:
            out.append((rel, adv))
    out.sort(key=lambda p: p[0])
    return out


def _release_row(rel: KernelRelease, adv: dict) -> dict:
    return {
        "maintenance_release": rel.maintenance_release,
        "kernel": rel.uname,
        "advisory": adv["id"] or NOT_AVAILABLE,
        "advisory_url": adv["url"],
        "issued": adv["issued"] or UNKNOWN,
        "severity": adv["severity"] or UNKNOWN,
        "cve_count": len(adv["cves"]),
    }


def assess_host(host: Host, index: dict, on: dt.date) -> dict:
    result: dict = {
        "host_id": host.host_id,
        "tool_version": __version__,
        "input": host.public_input(),
        "issues": list(host.issues),
        "not_verified": [],
    }
    sources = [{"name": "SUSE OVAL patch feed (SUSE Security Announcements, CVE ratings)",
                "url": index.get("source"), "retrieved": index.get("source_last_modified") or UNKNOWN}]

    # --- Kernel format & consistency -------------------------------------------------
    try:
        kernel = KernelRelease.parse(host.kernel)
        format_ok = True
    except KernelParseError as e:
        result["issues"].append(str(e))
        kernel, format_ok = None, False

    sp = host.service_pack
    if kernel is not None:
        if host.major and str(kernel.sle_major) != host.major:
            result["issues"].append(
                f"Kernel codestream indicates SLE {kernel.sle_major}, inventory says {host.major}")
        if sp is not None and kernel.sle_sp != sp:
            result["issues"].append(
                f"Kernel codestream indicates SP{kernel.sle_sp}, inventory says SP{sp}; using kernel codestream")
        sp = kernel.sle_sp

    result["system"] = {
        "os": host.product or host.os_raw or UNKNOWN,
        "service_pack": f"SP{sp}" if sp is not None else UNKNOWN,
        "kernel": host.kernel or UNKNOWN,
        "kernel_flavor": kernel.flavor if kernel else UNKNOWN,
        "upstream_version": kernel.upstream if kernel else UNKNOWN,
        "architecture": host.architecture or UNKNOWN,
        "platform": host.platform or UNKNOWN,
        "assessment_date": on.isoformat(),
        "assessment_method": ASSESSMENT_METHOD,
    }

    # --- Lifecycle ---------------------------------------------------------------------
    lc = lifecycle.lookup(host.product or "", host.major or "", sp) if sp is not None else None
    if lc:
        result["lifecycle"] = lc.to_dict(on)
        latest_sp = lifecycle.latest_service_pack(lc.product, lc.version)
        result["lifecycle"]["latest_service_pack"] = f"SP{latest_sp}" if latest_sp is not None else UNKNOWN
        result["lifecycle"]["service_pack_upgrade_recommended"] = bool(latest_sp is not None and sp < latest_sp)
        sources.append({"name": "SUSE Product Lifecycle", "url": lc.source, "retrieved": lc.retrieved})
        if lc.phase(on) == lifecycle.LTSS:
            result["not_verified"].append("LTSS subscription entitlement")
    else:
        result["lifecycle"] = {"phase": NOT_AVAILABLE}

    if kernel is None or sp is None:
        result["validation"] = {"kernel_format_valid": format_ok}
        result["sources"] = sources
        return result

    # --- Version intelligence ------------------------------------------------------------
    releases = _releases_for(index, kernel, sp)
    installed_entry = next(((r, a) for r, a in releases if r == kernel), None)
    newer = [(r, a) for r, a in releases if r > kernel]
    latest = releases[-1] if releases else None

    result["validation"] = {
        "kernel_format_valid": format_ok,
        "installed_release_published_by_suse": installed_entry is not None,
    }
    if installed_entry is None:
        result["not_verified"].append(
            "Installed kernel not found among SUSE maintenance releases (custom/PTF build or older branch)")

    timeline = []
    for r, a in releases:
        row = _release_row(r, a)
        row["status"] = "installed" if r == kernel else ("missing" if r > kernel else "superseded")
        timeline.append(row)

    installed_date = installed_entry[1]["issued"] if installed_entry else None
    latest_date = latest[1]["issued"] if latest else None
    days_behind = None
    if newer and installed_date and latest_date:
        days_behind = (dt.date.fromisoformat(latest_date) - dt.date.fromisoformat(installed_date)).days
    elif not newer and installed_entry:
        days_behind = 0

    # The kernel is cumulative: SUSE's recommended target within an SP is the newest update.
    recommended = latest if newer else None
    result["version"] = {
        "installed": _release_row(*installed_entry) if installed_entry else {
            "maintenance_release": kernel.maintenance_release, "kernel": kernel.uname,
            "advisory": NOT_AVAILABLE, "issued": UNKNOWN},
        "recommended": _release_row(*recommended) if recommended else "Already on latest",
        "latest": _release_row(*latest) if latest else NOT_AVAILABLE,
        "maintenance_gap": {
            "releases_behind": len(newer),
            "days_behind": days_behind if days_behind is not None else UNKNOWN,
        },
        "timeline": timeline,
    }

    # --- Security ---------------------------------------------------------------------
    applied_cves = {c["id"] for r, a in releases if r <= kernel for c in a["cves"]}
    missing_cves: dict[str, dict] = {}
    missing_advisories = []
    for r, a in newer:
        missing_advisories.append({
            **_release_row(r, a),
            "title": a["title"],
            "non_security_fix_count": len(a["non_security_fixes"]),
        })
        for c in a["cves"]:
            if c["id"] in missing_cves:
                missing_cves[c["id"]]["also_fixed_in"].append(r.maintenance_release)
                continue
            sev, score, sev_src = classify_cve(c)
            missing_cves[c["id"]] = {
                "cve": c["id"],
                "cvss3": score if score is not None else NOT_AVAILABLE,
                "severity": sev,
                "severity_source": sev_src,
                "fixed_release": r.maintenance_release,
                "fixed_kernel": r.uname,
                "advisory": a["id"] or NOT_AVAILABLE,
                "component": c.get("component") or UNKNOWN,
                "summary": c.get("summary") or NOT_AVAILABLE,
                "url": c.get("url") or f"https://www.suse.com/security/cve/{c['id']}/",
                # Listed again after a fix the host already has: a follow-up fix by SUSE.
                "previously_addressed": c["id"] in applied_cves,
                "also_fixed_in": [],
            }

    counts = Counter(c["severity"] for c in missing_cves.values())
    result["security"] = {
        "missing_advisory_count": len(missing_advisories),
        "missing_cve_count": len(missing_cves),
        "by_severity": {s: counts.get(s, 0) for s in SEVERITIES},
        "missing_advisories": missing_advisories,
        "missing_cves": sorted(missing_cves.values(),
                               key=lambda c: (SEVERITIES.index(c["severity"]),
                                              -(c["cvss3"] if isinstance(c["cvss3"], float) else 0),
                                              c["cve"])),
    }
    result["not_verified"].append(
        "Per-architecture CVE applicability (SUSE OVAL does not distinguish architectures)")

    # --- What changed: raw material for the narrative layer ----------------------------
    result["changes"] = [
        {
            "maintenance_release": r.maintenance_release,
            "advisory": a["id"] or NOT_AVAILABLE,
            "issued": a["issued"] or UNKNOWN,
            "top_components": Counter(
                c["component"] for c in a["cves"] if c.get("component")).most_common(8),
            "non_security_fixes": a["non_security_fixes"],
        }
        for r, a in newer
    ]

    # --- IBM Power ----------------------------------------------------------------------
    arch = (host.architecture or "").lower()
    platform = (host.platform or "").lower()
    if arch == "ppc64le" or "power" in platform:
        result["ibm_power"] = {
            "architecture_ppc64le": "Yes" if arch == "ppc64le" else (UNKNOWN if not arch else "No"),
            "firmware_compatibility": NOT_VERIFIED,
            "hmc_compatibility": NOT_VERIFIED,
            "vios_compatibility": NOT_VERIFIED,
            "powervm_compatibility": NOT_VERIFIED,
            "live_partition_mobility": NOT_VERIFIED,
            "note": "Requires on-system data (lsmcode, HMC/VIOS levels); cannot be verified offline.",
        }

    result["sources"] = sources
    return result


def fleet_summary(results: list[dict], on: dt.date) -> dict:
    rows = []
    unique: dict[str, str] = {}
    for r in results:
        sec = r.get("security", {})
        ver = r.get("version", {})
        by_sev = sec.get("by_severity", {})
        for c in sec.get("missing_cves", []):
            unique[c["cve"]] = c["severity"]
        rows.append({
            "host_id": r["host_id"],
            "kernel": r["input"]["kernel"],
            "service_pack": r.get("system", {}).get("service_pack", UNKNOWN),
            "lifecycle_phase": r.get("lifecycle", {}).get("phase", NOT_AVAILABLE),
            "releases_behind": ver.get("maintenance_gap", {}).get("releases_behind", UNKNOWN),
            "days_behind": ver.get("maintenance_gap", {}).get("days_behind", UNKNOWN),
            "missing_advisories": sec.get("missing_advisory_count", UNKNOWN),
            "missing_cves": sec.get("missing_cve_count", UNKNOWN),
            **{s.lower(): by_sev.get(s, 0) for s in SEVERITIES},
            "issues": len(r["issues"]),
        })
    totals = Counter(unique.values())
    return {
        "assessment_date": on.isoformat(),
        "host_count": len(results),
        "hosts": rows,
        "fleet_unique_missing_cves": len(unique),
        "fleet_unique_missing_cves_by_severity": {s: totals.get(s, 0) for s in SEVERITIES},
    }
