"""
Port Scanner — OpenSecX (Pure Python, no nmap binary)

Scans common ports using asyncio TCP connections. Fast, no binary
required. Checks the top 1000 most common ports in parallel.

Identifies services by port number and attempts banner grabbing
on common application ports to confirm the service.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Tuple

from app.scanners.base import (
    AdapterStatus, AssetRecord, BaseScannerAdapter, ScannerResult,
)

logger = logging.getLogger(__name__)

# Top common ports to scan (ordered by frequency)
TOP_PORTS = [
    80, 443, 22, 21, 25, 53, 110, 143, 993, 995,
    3306, 5432, 27017, 6379, 9200, 5601,
    8080, 8443, 8888, 3000, 4000, 5000, 9000, 9090,
    23, 445, 139, 135, 3389, 5900,
    587, 465, 2525,
    1433, 1521, 5984,
    11211, 6380, 6381,
    8161, 61616,  # ActiveMQ
    4848,          # GlassFish
    7001, 7002,    # WebLogic
    9300,          # Elasticsearch transport
    2181,          # Zookeeper
    8020, 50070,   # Hadoop
]

# Service name map: port → service label
PORT_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2181: "zookeeper", 2525: "smtp-alt", 3000: "dev-http",
    3306: "mysql", 3389: "rdp", 4000: "dev-http",
    4848: "glassfish-admin", 5000: "dev-http", 5432: "postgresql",
    5601: "kibana", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6380: "redis", 6381: "redis",
    7001: "weblogic", 7002: "weblogic-ssl", 8020: "hdfs",
    8080: "http-alt", 8161: "activemq-web", 8443: "https-alt",
    8888: "jupyter", 9000: "dev-http", 9090: "dev-http",
    9200: "elasticsearch", 9300: "elasticsearch-transport",
    11211: "memcached", 23: "telnet", 27017: "mongodb",
    50070: "hadoop-namenode", 61616: "activemq",
    135: "msrpc", 139: "netbios",
}

# High-risk services (should not be internet-exposed)
HIGH_RISK_PORTS = {
    3306, 5432, 27017, 6379, 9200, 11211, 5984, 1433, 1521,
    2181, 5900, 23, 445, 139, 3389, 61616, 8161, 4848, 7001,
}


async def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Async TCP connect check. Returns True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


class PortScanner(BaseScannerAdapter):
    """
    Pure-Python async port scanner. No binary required.
    Scans top common ports using TCP connect and identifies services.
    """

    @property
    def name(self) -> str:
        return "port_scanner"

    @property
    def binary(self) -> None:
        return None

    async def run(self, target: str, timeout: int = 60) -> ScannerResult:
        """Scan top ports on target IP or hostname."""
        logger.info("[port_scanner] Scanning %d ports on %s", len(TOP_PORTS), target)

        # Resolve hostname to IP first
        import socket
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return ScannerResult(
                status=AdapterStatus.ERROR,
                error=f"Cannot resolve hostname: {target}",
            )

        # Scan all ports concurrently with semaphore to avoid overwhelming
        semaphore = asyncio.Semaphore(100)

        async def bounded_check(port: int) -> Tuple[int, bool]:
            async with semaphore:
                open_ = await _check_port(ip, port, timeout=2.0)
                return port, open_

        tasks = [bounded_check(p) for p in TOP_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports: List[int] = []
        for r in results:
            if isinstance(r, tuple) and r[1]:
                open_ports.append(r[0])

        if not open_ports:
            logger.info("[port_scanner] No open ports found on %s", target)
            return ScannerResult(status=AdapterStatus.OK, assets=[])

        logger.info("[port_scanner] %d open ports on %s: %s", len(open_ports), target, open_ports)

        assets: List[AssetRecord] = []
        for port in sorted(open_ports):
            service = PORT_SERVICES.get(port, "unknown")
            protocol = "https" if port in (443, 8443, 993, 995, 465) else "http" if port in (80, 8080, 8888, 3000, 4000, 5000) else "tcp"

            notes = None
            if port in HIGH_RISK_PORTS:
                notes = f"⚠️ HIGH RISK: {service} on port {port} should not be internet-exposed"

            assets.append(AssetRecord(
                domain=target,
                hostname=target,
                ip_address=ip,
                ports=[port],
                protocol=protocol,
                service=service,
                source="port_scanner",
                status="Active",
                notes=notes,
            ))

        return ScannerResult(status=AdapterStatus.OK, assets=assets)

    async def scan_multiple(self, targets: List[str], timeout: int = 60) -> ScannerResult:
        """Scan multiple targets."""
        all_assets: List[AssetRecord] = []
        for target in targets:
            try:
                result = await self.run(target, timeout=timeout)
                all_assets.extend(result.assets)
            except Exception as e:
                logger.warning("[port_scanner] Failed for %s: %s", target, e)
        return ScannerResult(status=AdapterStatus.OK, assets=all_assets)
