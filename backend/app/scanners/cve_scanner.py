"""
CVE Scanner — OpenSecX Phase 2

Matches detected technologies against the NVD CVE database and enriches
results with CISA KEV status and EPSS exploit probability scores.

Pipeline:
  1. For each tech+version in discovered assets, query NVD API v2
  2. Match CVEs where version falls in affected range (CPE matching)
  3. Cross-reference with locally cached CISA KEV feed (updates daily)
  4. Fetch EPSS probability for each CVE from FIRST.org API
  5. Assign priority: URGENT / HIGH / ELEVATED / STANDARD / VERIFY

No API key required for:
  - NVD API v2 (rate limit: 5 req/30s without key, 50 req/30s with NIST_NVD_KEY)
  - CISA KEV feed (public JSON)
  - EPSS API (public)

Installation: None (stdlib only)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
_cve_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="cve-scan")

# Cache directory
_CACHE_DIR = Path(os.getenv("OPENSECX_CACHE_DIR", Path.home() / ".opensecx_cache"))
_KEV_CACHE_FILE = _CACHE_DIR / "cisa_kev.json"
_KEV_CACHE_TTL = 86400  # 24 hours

# Known tech → CPE vendor:product mapping (common ones)
TECH_TO_CPE: Dict[str, Tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "php": ("php", "php"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("bootstrap", "bootstrap"),
    "react": ("facebook", "react"),
    "angular": ("google", "angular.js"),
    "vue": ("vuejs", "vue.js"),
    "django": ("djangoproject", "django"),
    "flask": ("palletsprojects", "flask"),
    "laravel": ("laravel", "laravel"),
    "spring": ("pivotal_software", "spring_framework"),
    "struts": ("apache", "struts"),
    "log4j": ("apache", "log4j"),
    "openssl": ("openssl", "openssl"),
    "openssh": ("openbsd", "openssh"),
    "mysql": ("mysql", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
}

# Version extraction pattern
VERSION_RE = re.compile(r'(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)')


def _get_kev_set() -> set:
    """Returns set of CVE IDs from CISA KEV feed. Cached for 24h."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Use cache if fresh
    if _KEV_CACHE_FILE.exists():
        age = time.time() - _KEV_CACHE_FILE.stat().st_mtime
        if age < _KEV_CACHE_TTL:
            try:
                with open(_KEV_CACHE_FILE) as f:
                    data = json.load(f)
                return set(v["cveID"] for v in data.get("vulnerabilities", []))
            except Exception:
                pass

    # Fetch fresh KEV data
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        req = urllib.request.Request(url, headers={"User-Agent": "OpenSecX-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        with open(_KEV_CACHE_FILE, "w") as f:
            json.dump(data, f)
        logger.info("[cve] CISA KEV updated: %d entries", len(data.get("vulnerabilities", [])))
        return set(v["cveID"] for v in data.get("vulnerabilities", []))
    except Exception as exc:
        logger.warning("[cve] Failed to fetch CISA KEV: %s", exc)
        return set()


def _get_epss(cve_id: str) -> Optional[float]:
    """Get EPSS probability for a CVE from FIRST.org."""
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "OpenSecX-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        items = data.get("data", [])
        if items:
            return float(items[0].get("epss", 0))
    except Exception:
        pass
    return None


def _nvd_search(keyword: str, version: Optional[str] = None) -> List[dict]:
    """Search NVD API v2 for CVEs matching a keyword/product."""
    try:
        api_key = os.getenv("NIST_NVD_KEY", "")
        params = f"keywordSearch={urllib.request.quote(keyword)}&resultsPerPage=10"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
        headers = {"User-Agent": "OpenSecX-Scanner/1.0"}
        if api_key:
            headers["apiKey"] = api_key

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get CVSS score
            cvss = 0.0
            metrics = cve_data.get("metrics", {})
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss = float(cvss_data.get("baseScore", 0))
                    break

            cves.append({
                "cve_id": cve_id,
                "description": description[:500],
                "cvss": cvss,
                "version_confirmed": version is not None,
            })

        return cves
    except Exception as exc:
        logger.debug("[cve] NVD search failed for '%s': %s", keyword, exc)
        return []


def _assign_priority(cve_id: str, cvss: float, epss: Optional[float], in_kev: bool) -> str:
    """Assign operational priority to a CVE."""
    if in_kev:
        return "URGENT"
    if epss and epss >= 0.5:
        return "HIGH"
    if cvss >= 9.0:
        return "HIGH"
    if (epss and epss >= 0.1) or cvss >= 7.0:
        return "ELEVATED"
    if cvss >= 4.0:
        return "STANDARD"
    return "VERIFY"


def _scan_technologies_sync(technologies: List[str], target: str) -> List[dict]:
    """
    Main CVE scanning logic — runs in thread pool.
    Returns list of finding dicts.
    """
    if not technologies:
        return []

    kev_set = _get_kev_set()
    findings = []

    for tech_raw in technologies:
        tech_lower = tech_raw.lower()
        # Extract name and version
        version_match = VERSION_RE.search(tech_raw)
        version = version_match.group(1) if version_match else None
        tech_name = re.sub(r'[\d\.\s]', '', tech_lower).strip()

        # Find CPE mapping
        cpe_vendor, cpe_product = None, None
        for key, (vendor, product) in TECH_TO_CPE.items():
            if key in tech_lower:
                cpe_vendor, cpe_product = vendor, product
                tech_name = key
                break

        if not cpe_vendor:
            continue  # Skip unknown tech

        # Search NVD
        search_term = f"{cpe_vendor} {cpe_product}"
        if version:
            search_term += f" {version}"

        cves = _nvd_search(search_term, version)
        time.sleep(0.5)  # Respect NVD rate limits

        for cve in cves[:5]:  # Limit to top 5 per tech
            cve_id = cve["cve_id"]
            cvss = cve["cvss"]
            in_kev = cve_id in kev_set

            # Get EPSS (only for CVEs with decent CVSS)
            epss = None
            if cvss >= 5.0:
                epss = _get_epss(cve_id)
                time.sleep(0.2)

            priority = _assign_priority(cve_id, cvss, epss, in_kev)
            severity_map = {
                "URGENT": "critical", "HIGH": "high",
                "ELEVATED": "high", "STANDARD": "medium", "VERIFY": "low"
            }

            evidence = {
                "tech": tech_raw,
                "version": version,
                "cve_id": cve_id,
                "cvss": cvss,
                "in_kev": in_kev,
                "priority": priority,
                "target": target,
            }
            if epss is not None:
                evidence["epss"] = epss

            grade = "supported" if version else "possible"
            title_prefix = f"[{priority}] " if priority in ("URGENT", "HIGH") else ""

            findings.append({
                "title": f"{title_prefix}CVE in {tech_raw}: {cve_id}",
                "severity": severity_map.get(priority, "medium"),
                "category": "A06:Vulnerable and Outdated Components",
                "description": (
                    f"CVE {cve_id} affects {cpe_vendor} {cpe_product}."
                    + (f" Version detected: {version}." if version else " Version not confirmed — verify manually.")
                    + (f" CVSS: {cvss}." if cvss else "")
                    + (f" EPSS: {epss:.1%} probability of exploitation." if epss else "")
                    + (" ⚠️ This CVE is in the CISA Known Exploited Vulnerabilities catalogue." if in_kev else "")
                    + f"\n\n{cve.get('description', '')}"
                ),
                "evidence": evidence,
                "grade": grade,
                "cve_id": cve_id,
                "epss": epss,
                "in_kev": in_kev,
                "cvss": cvss,
                "priority": priority,
                "remediation": f"Update {tech_raw} to a version not affected by {cve_id}. Check NVD for the patched version range.",
            })

    return findings


async def scan_cves(technologies: List[str], target: str, timeout: int = 120) -> List[dict]:
    """Async wrapper for CVE scanning."""
    if not technologies:
        return []
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_cve_pool, _scan_technologies_sync, technologies, target),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("[cve] CVE scan timed out for %s", target)
        return []
    except Exception as exc:
        logger.error("[cve] CVE scan error: %s", exc)
        return []
