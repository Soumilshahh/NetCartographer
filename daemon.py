"""
Continuous network monitoring daemon with change detection and alerting.
"""

import os
import json
import time
import logging
import traceback
from datetime import datetime
from typing import Optional
from logging.handlers import RotatingFileHandler

import requests

from models import NetworkNode, AlertPayload, ScanResult
from config import CONFIG

logger = logging.getLogger(__name__)


def load_state(state_file: str) -> dict[str, NetworkNode]:
    """Load previous network state from JSON file."""
    if not os.path.exists(state_file):
        logger.info(f"No previous state file found at {state_file}")
        return {}
    
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        state = {}
        for ip, node_dict in data.items():
            state[ip] = NetworkNode.from_dict(node_dict)
        
        logger.info(f"Loaded state with {len(state)} nodes from {state_file}")
        return state
        
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse state file {state_file}: {e}")
        return {}
    except Exception as e:
        logger.warning(f"Failed to load state file {state_file}: {e}")
        return {}


def save_state(state_file: str, nodes: list[NetworkNode]) -> None:
    """Save network state to JSON file atomically."""
    try:
        # Build state dictionary
        state = {node.ip: node.to_dict() for node in nodes}
        
        # Write to temporary file
        temp_file = state_file + ".tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        
        # Atomic replace
        os.replace(temp_file, state_file)
        
        logger.info(f"Saved state with {len(nodes)} nodes to {state_file}")
        
    except Exception as e:
        logger.error(f"Failed to save state to {state_file}: {e}\n{traceback.format_exc()}")


def diff_states(
    previous: dict[str, NetworkNode],
    current: list[NetworkNode]
) -> tuple[list[NetworkNode], list[NetworkNode], list[NetworkNode]]:
    """Compare previous and current network states to detect changes.
    
    Args:
        previous: Dict of IP -> NetworkNode from previous scan
        current: List of NetworkNode objects from current scan
        
    Returns:
        tuple: (new_nodes, disappeared_nodes, unchanged_nodes)
    """
    previous_ips = set(previous.keys())
    current_ips = set(node.ip for node in current)
    
    new_ips = current_ips - previous_ips
    disappeared_ips = previous_ips - current_ips
    unchanged_ips = current_ips & previous_ips
    
    # Build result lists
    current_by_ip = {node.ip: node for node in current}
    
    new_nodes = [current_by_ip[ip] for ip in new_ips]
    disappeared_nodes = [previous[ip] for ip in disappeared_ips]
    unchanged_nodes = [current_by_ip[ip] for ip in unchanged_ips]
    
    logger.info(f"State diff: {len(new_nodes)} new, {len(disappeared_nodes)} disappeared, {len(unchanged_nodes)} unchanged")
    
    return new_nodes, disappeared_nodes, unchanged_nodes


def post_webhook(payload: AlertPayload, webhook_url: str) -> bool:
    """POST an alert payload to the configured webhook URL.
    
    Args:
        payload: AlertPayload to send
        webhook_url: HTTP endpoint to POST to
        
    Returns:
        bool: True if POST succeeded (HTTP 2xx), False otherwise
    """
    try:
        response = requests.post(
            webhook_url,
            json=payload.to_dict(),
            timeout=5.0
        )
        
        if 200 <= response.status_code < 300:
            logger.info(f"Webhook alert sent successfully: {payload.alert_type} for {payload.node_ip}")
            return True
        else:
            logger.warning(f"Webhook POST failed with status {response.status_code}: {response.text}")
            return False
            
    except requests.RequestException as e:
        logger.error(f"Webhook POST failed: {e}")
        return False


def build_alert(
    alert_type: str,
    node: NetworkNode,
    message: str,
    severity: str,
    trace: str = ""
) -> AlertPayload:
    """Construct an AlertPayload for a network event.
    
    Args:
        alert_type: Type of alert ("NODE_DISAPPEARED", "HARDENING_FAILED", "NEW_NODE")
        node: NetworkNode that triggered the alert
        message: Human-readable description
        severity: "INFO" | "WARNING" | "CRITICAL"
        trace: Optional Python traceback string
        
    Returns:
        AlertPayload: Constructed alert ready to send
    """
    return AlertPayload(
        alert_type=alert_type,
        node_ip=node.ip,
        node_mac=node.mac,
        timestamp=datetime.utcnow().isoformat() + "Z",
        message=message,
        severity=severity,
        trace=trace
    )


def setup_file_logging(log_file: str) -> None:
    """Add a RotatingFileHandler to the root logger.
    
    Creates parent directories if they don't exist. Configures rotation
    at 10MB with 5 backup files.
    
    Args:
        log_file: Path to the log file
    """
    try:
        # Create parent directories
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        # Create rotating file handler
        handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8"
        )
        
        # Set formatter
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )
        handler.setFormatter(formatter)
        
        # Add to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        
        logger.info(f"File logging configured: {log_file}")
        
    except Exception as e:
        logger.error(f"Failed to setup file logging: {e}\n{traceback.format_exc()}")


class NetworkDaemon:
    """Continuous network monitoring with change detection and alerts."""
    
    def __init__(self, config) -> None:
        """Initialize daemon with configuration."""
        self.config = config
        self.running = False
        logger.info("NetworkDaemon initialized")
    
    def run(self) -> None:
        """Start the daemon's main loop.
        
        Runs continuously until stop() is called. Each cycle:
        1. Scans the network
        2. Compares with previous state
        3. Sends alerts for changes
        4. Hardens new nodes
        5. Updates visualization
        6. Sleeps for configured interval
        """
        import scanner
        import hardener
        import visualizer
        
        self.running = True
        logger.info("NetworkDaemon starting main loop")
        
        while self.running:
            try:
                logger.info("===== Starting daemon scan cycle =====")
                
                # Step 1: Scan the network
                scan_result = scanner.discover_network(
                    cidr=self.config.TARGET_CIDR,
                    interface=self.config.SCAN_INTERFACE,
                    ports=self.config.SCAN_PORTS,
                    arp_timeout=self.config.ARP_TIMEOUT,
                    port_timeout=self.config.PORT_SCAN_TIMEOUT,
                    traceroute_max_hops=self.config.TRACEROUTE_MAX_HOPS,
                    traceroute_timeout=self.config.TRACEROUTE_TIMEOUT
                )
                
                # Step 2: Load previous state and compare
                previous_state = load_state(self.config.STATE_FILE)
                new_nodes, disappeared_nodes, unchanged_nodes = diff_states(
                    previous_state,
                    scan_result.nodes
                )
                
                # Step 3: Handle disappeared nodes
                for node in disappeared_nodes:
                    logger.error(f"Node {node.ip} has DISAPPEARED from network")
                    
                    alert = build_alert(
                        alert_type="NODE_DISAPPEARED",
                        node=node,
                        message=f"Node {node.ip} ({node.hostname}) is no longer reachable",
                        severity="CRITICAL"
                    )
                    post_webhook(alert, self.config.WEBHOOK_URL)
                
                # Step 4: Handle new nodes
                for node in new_nodes:
                    logger.info(f"New node detected: {node.ip}")
                    
                    alert = build_alert(
                        alert_type="NEW_NODE",
                        node=node,
                        message=f"New node discovered: {node.ip} ({node.hostname})",
                        severity="INFO"
                    )
                    post_webhook(alert, self.config.WEBHOOK_URL)
                    
                    # Trigger hardening for new node
                    logger.info(f"Triggering hardening for new node {node.ip}")
                    
                    single_node_result = ScanResult(
                        scan_time=scan_result.scan_time,
                        cidr=scan_result.cidr,
                        total_hosts_found=1,
                        nodes=[node]
                    )
                    
                    hardener.apply_hardening_to_scan(single_node_result)
                    
                    # Check if hardening failed
                    if node.hardening_status == "failed":
                        logger.error(f"Hardening FAILED for new node {node.ip}")
                        
                        alert = build_alert(
                            alert_type="HARDENING_FAILED",
                            node=node,
                            message=f"Security hardening failed for {node.ip}",
                            severity="CRITICAL"
                        )
                        post_webhook(alert, self.config.WEBHOOK_URL)
                
                # Step 5: Save updated state
                save_state(self.config.STATE_FILE, scan_result.nodes)
                
                # Step 6: Update visualization
                try:
                    graph = visualizer.build_topology(
                        scan_result.nodes,
                        self.config.GATEWAY_IP
                    )
                    visualizer.render_html(
                        graph,
                        self.config.TOPOLOGY_HTML
                    )
                except Exception as e:
                    logger.error(f"Visualization update failed: {e}\n{traceback.format_exc()}")
                
                # Step 7: Sleep until next cycle
                logger.info(f"Cycle complete. Sleeping {self.config.DAEMON_INTERVAL}s")
                time.sleep(self.config.DAEMON_INTERVAL)
                
            except Exception as e:
                logger.error(f"Daemon cycle failed: {e}\n{traceback.format_exc()}")
                logger.info(f"Sleeping {self.config.DAEMON_INTERVAL}s before retry")
                time.sleep(self.config.DAEMON_INTERVAL)
        
        logger.info("NetworkDaemon stopped")
    
    def stop(self) -> None:
        """Request daemon shutdown."""
        logger.info("Daemon stop requested")
        self.running = False
