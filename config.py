"""
Configuration management using environment variables.
"""

import os
import logging
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class Configuration:
    """Centralized configuration for NetCartographer."""
    
    TARGET_CIDR: str = field(default_factory=lambda: os.getenv("TARGET_CIDR", "192.168.1.0/24"))
    GATEWAY_IP: str = field(default_factory=lambda: os.getenv("GATEWAY_IP", "192.168.1.1"))
    SCAN_INTERFACE: str = field(default_factory=lambda: os.getenv("SCAN_INTERFACE", "eth0"))
    SCAN_PORTS: list[int] = field(default_factory=lambda: [
        int(p) for p in os.getenv("SCAN_PORTS", "22,80,443,161,8080").split(",")
    ])
    PORT_SCAN_TIMEOUT: float = field(default_factory=lambda: float(os.getenv("PORT_SCAN_TIMEOUT", "1.5")))
    ARP_TIMEOUT: float = field(default_factory=lambda: float(os.getenv("ARP_TIMEOUT", "2.0")))
    TRACEROUTE_MAX_HOPS: int = field(default_factory=lambda: int(os.getenv("TRACEROUTE_MAX_HOPS", "15")))
    TRACEROUTE_TIMEOUT: float = field(default_factory=lambda: float(os.getenv("TRACEROUTE_TIMEOUT", "2.0")))
    DAEMON_INTERVAL: int = field(default_factory=lambda: int(os.getenv("DAEMON_INTERVAL", "60")))
    STATE_FILE: str = field(default_factory=lambda: os.getenv("STATE_FILE", "/tmp/net_cartographer_state.json"))
    LOG_FILE: str = field(default_factory=lambda: os.getenv("LOG_FILE", "/var/log/net_cartographer.log"))
    WEBHOOK_URL: str = field(default_factory=lambda: os.getenv("WEBHOOK_URL", "http://localhost:9000/webhook"))
    ANSIBLE_SSH_USER: str = field(default_factory=lambda: os.getenv("ANSIBLE_SSH_USER", "ubuntu"))
    ANSIBLE_SSH_KEY: str = field(default_factory=lambda: os.getenv("ANSIBLE_SSH_KEY", "~/.ssh/id_rsa"))
    OUTPUT_DIR: str = field(default_factory=lambda: os.getenv("OUTPUT_DIR", "./output"))
    TOPOLOGY_HTML: str = field(default_factory=lambda: os.getenv("TOPOLOGY_HTML", "./output/topology.html"))

    def __post_init__(self) -> None:
        """Create output directory if it doesn't exist."""
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        logger.info(f"Configuration loaded. Output directory: {self.OUTPUT_DIR}")


# Global CONFIG instance
CONFIG = Configuration()
