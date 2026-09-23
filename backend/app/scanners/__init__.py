"""
OpenSecX Scanner Plugin Package — Phase 1

Each scanner adapter in this package follows the BaseScannerAdapter interface.
Adapters run real external tools as subprocesses or HTTP calls and return
normalized Asset records. They never return fake/simulated data.

Available adapters:
    - CrtShScanner       — certificate transparency logs via crt.sh API
    - WhoisScanner       — WHOIS/RDAP data via python-whois
    - SubfinderScanner   — passive subdomain discovery (requires subfinder binary)
    - DnsxScanner        — DNS resolution (requires dnsx binary)
    - HttpxScanner       — HTTP/HTTPS probing (requires httpx binary)
    - NmapScanner        — port/service discovery (requires nmap binary)
"""
from app.scanners.base import BaseScannerAdapter, ScannerResult, AdapterStatus

__all__ = [
    "BaseScannerAdapter",
    "ScannerResult",
    "AdapterStatus",
]
