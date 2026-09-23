"""
Base scanner adapter interface — OpenSecX Phase 1

All scanner adapters must implement BaseScannerAdapter. This enforces a
consistent contract: every adapter checks for tool availability, runs the
real tool, parses real output, and returns normalized AssetRecord objects.

Adapters MUST NOT return fabricated data. If a tool is unavailable,
the adapter returns AdapterStatus.UNAVAILABLE and an empty asset list.
"""
from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class AdapterStatus(str, Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"  # Binary/service not installed
    ERROR = "error"              # Tool ran but encountered an error
    TIMEOUT = "timeout"          # Tool exceeded its time limit


@dataclass
class AssetRecord:
    """
    Normalized asset record produced by every scanner adapter.
    Maps directly to the Asset SQLAlchemy model fields.
    """
    domain: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    ports: Optional[List[int]] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    technologies: Optional[List[str]] = None
    dns_records: Optional[dict] = None
    certificate: Optional[dict] = None
    source: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    status: str = "Active"
    notes: Optional[str] = None


@dataclass
class ScannerResult:
    """
    Result container returned by every scanner adapter.

    Attributes:
        status:   Whether the adapter ran successfully, was unavailable, etc.
        assets:   List of normalized AssetRecord objects from real tool output.
        error:    Human-readable error message when status is ERROR or TIMEOUT.
        raw:      Raw tool output (stdout) for debugging. Not stored in DB.
        tool_version: Version string reported by the tool, if available.
    """
    status: AdapterStatus
    assets: List[AssetRecord] = field(default_factory=list)
    error: Optional[str] = None
    raw: Optional[str] = None
    tool_version: Optional[str] = None


class BaseScannerAdapter(ABC):
    """
    Abstract base class for all OpenSecX scanner adapters.

    Subclasses implement:
        - name       : short tool name (e.g. "subfinder")
        - binary     : executable name to check with shutil.which()
        - run()      : async method that executes the tool and returns ScannerResult
    """

    DEFAULT_TIMEOUT: int = 120  # seconds

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this scanner (e.g. 'subfinder')."""
        ...

    @property
    def binary(self) -> Optional[str]:
        """
        Name of the system binary this adapter requires.
        Return None for adapters that use HTTP or Python libraries only.
        """
        return None

    def is_available(self) -> bool:
        """Return True if the required binary is installed on PATH."""
        if self.binary is None:
            return True  # HTTP/library-based adapters are always available
        return shutil.which(self.binary) is not None

    @abstractmethod
    async def run(self, target: str, timeout: int = DEFAULT_TIMEOUT) -> ScannerResult:
        """
        Execute the scanner against target and return a ScannerResult.

        Args:
            target:  Domain name or IP address to scan.
            timeout: Maximum seconds to wait for tool completion.

        Returns:
            ScannerResult with real data from the tool.
            If the tool is unavailable, return ScannerResult(status=AdapterStatus.UNAVAILABLE).
            Never return fabricated asset data.
        """
        ...

    async def _run_subprocess(
        self,
        cmd: List[str],
        timeout: int,
    ) -> tuple[int, str, str]:
        """
        Helper: run a subprocess command asynchronously.

        Returns:
            (returncode, stdout, stderr)

        Raises:
            asyncio.TimeoutError if command exceeds timeout.
        """
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise
