"""
Data models for network nodes, scan results, and alerts.
"""

from dataclasses import dataclass, field, asdict
from typing import Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class NetworkNode:
    """Represents a discovered network host with all its properties."""
    
    ip: str
    mac: str
    hostname: str
    status: str  # "active" | "unreachable"
    open_ports: list[int]
    os_hint: str
    hardening_status: str  # "pending" | "success" | "failed" | "skipped"
    last_seen: str  # ISO-8601 UTC timestamp
    traceroute_hops: list[str]  # Ordered list of hop IPs to this node

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NetworkNode":
        """Reconstruct from dictionary."""
        return cls(
            ip=d.get("ip", "unknown"),
            mac=d.get("mac", "unknown"),
            hostname=d.get("hostname", "unknown"),
            status=d.get("status", "unreachable"),
            open_ports=d.get("open_ports", []),
            os_hint=d.get("os_hint", "unknown"),
            hardening_status=d.get("hardening_status", "pending"),
            last_seen=d.get("last_seen", ""),
            traceroute_hops=d.get("traceroute_hops", [])
        )


@dataclass
class AlertPayload:
    """Represents an alert to be sent via webhook."""
    
    alert_type: str  # "NODE_DISAPPEARED" | "HARDENING_FAILED" | "NEW_NODE"
    node_ip: str
    node_mac: str
    timestamp: str  # ISO-8601 UTC
    message: str
    severity: str  # "INFO" | "WARNING" | "CRITICAL"
    trace: str = ""  # Full Python traceback if applicable

    def to_dict(self) -> dict[str, Any]:
        """Convert AlertPayload to a dictionary suitable for JSON serialization.
        
        Returns:
            dict: Dictionary representation of the AlertPayload
        """
        return asdict(self)


@dataclass
class ScanResult:
    """Represents the complete result of a network scan."""
    
    scan_time: str  # ISO-8601 UTC timestamp
    cidr: str  # The subnet that was scanned
    total_hosts_found: int
    nodes: list[NetworkNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert ScanResult to a dictionary suitable for JSON serialization.
        
        Returns:
            dict: Dictionary representation of the ScanResult with all nested nodes
        """
        return {
            "scan_time": self.scan_time,
            "cidr": self.cidr,
            "total_hosts_found": self.total_hosts_found,
            "nodes": [node.to_dict() for node in self.nodes]
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanResult":
        """Reconstruct a ScanResult from a dictionary.
        
        Args:
            d: Dictionary containing ScanResult fields
            
        Returns:
            ScanResult: Reconstructed ScanResult instance
        """
        nodes = [NetworkNode.from_dict(node_dict) for node_dict in d.get("nodes", [])]
        return cls(
            scan_time=d.get("scan_time", ""),
            cidr=d.get("cidr", ""),
            total_hosts_found=d.get("total_hosts_found", 0),
            nodes=nodes
        )
