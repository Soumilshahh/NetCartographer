"""
Ansible automation for security hardening of discovered hosts.
"""

import os
import json
import yaml
import logging
import shutil
import tempfile
import traceback
from typing import Optional

import ansible_runner

from models import NetworkNode, ScanResult

logger = logging.getLogger(__name__)


def build_inventory(nodes: list[NetworkNode], ssh_user: str, ssh_key: str) -> dict:
    """Build Ansible inventory from discovered nodes."""
    inventory = {
        "all": {
            "hosts": {}
        }
    }
    
    for node in nodes:
        if node.status == "active":
            inventory["all"]["hosts"][node.ip] = {
                "ansible_host": node.ip,
                "ansible_user": ssh_user,
                "ansible_ssh_private_key_file": ssh_key,
                "ansible_ssh_common_args": "-o StrictHostKeyChecking=no"
            }
    
    active_count = len(inventory["all"]["hosts"])
    logger.info(f"Built Ansible inventory with {active_count} active hosts")
    
    return inventory


def generate_hardening_playbook() -> str:
    """Generate Ansible hardening playbook as YAML string."""
    playbook = [
        {
            "hosts": "all",
            "become": True,
            "gather_facts": True,
            "tasks": [
                {
                    "name": "Update apt package cache",
                    "apt": {
                        "update_cache": True,
                        "cache_valid_time": 3600
                    }
                },
                {
                    "name": "Upgrade all packages to latest",
                    "apt": {
                        "upgrade": "dist",
                        "autoremove": True
                    }
                },
                {
                    "name": "Install UFW firewall",
                    "apt": {
                        "name": "ufw",
                        "state": "present"
                    }
                },
                {
                    "name": "Set UFW default policy to deny incoming",
                    "community.general.ufw": {
                        "direction": "incoming",
                        "policy": "deny"
                    }
                },
                {
                    "name": "Allow SSH through UFW",
                    "community.general.ufw": {
                        "rule": "allow",
                        "port": "22",
                        "proto": "tcp"
                    }
                },
                {
                    "name": "Enable UFW",
                    "community.general.ufw": {
                        "state": "enabled"
                    }
                },
                {
                    "name": "Disable root SSH login",
                    "lineinfile": {
                        "path": "/etc/ssh/sshd_config",
                        "regexp": "^PermitRootLogin",
                        "line": "PermitRootLogin no",
                        "state": "present",
                        "backup": True
                    }
                },
                {
                    "name": "Disable SSH password authentication",
                    "lineinfile": {
                        "path": "/etc/ssh/sshd_config",
                        "regexp": "^PasswordAuthentication",
                        "line": "PasswordAuthentication no",
                        "state": "present",
                        "backup": True
                    }
                },
                {
                    "name": "Restart SSH service to apply changes",
                    "service": {
                        "name": "sshd",
                        "state": "restarted"
                    }
                }
            ]
        }
    ]
    
    yaml_content = yaml.dump(playbook, default_flow_style=False, sort_keys=False)
    logger.debug("Generated hardening playbook")
    
    return yaml_content


def run_hardening(
    nodes: list[NetworkNode],
    ssh_user: str,
    ssh_key: str,
    output_dir: str
) -> dict[str, str]:
    """Execute the Ansible hardening playbook against all active nodes.
    
    Creates a temporary directory with inventory and playbook files, runs
    ansible-runner, and returns the result status for each node.
    
    Args:
        nodes: List of NetworkNode objects to harden
        ssh_user: SSH username for connections
        ssh_key: Path to SSH private key
        output_dir: Directory for Ansible output artifacts
        
    Returns:
        dict: Mapping of node IP -> "success" | "failed"
    """
    result_map: dict[str, str] = {}
    
    # Get list of active nodes
    active_nodes = [node for node in nodes if node.status == "active"]
    
    if not active_nodes:
        logger.info("No active nodes to harden")
        return result_map
    
    logger.info(f"Starting hardening for {len(active_nodes)} active nodes")
    
    temp_dir = None
    
    try:
        # Create temporary working directory
        temp_dir = tempfile.mkdtemp(prefix="ansible_")
        logger.debug(f"Created temporary Ansible directory: {temp_dir}")
        
        # Create necessary subdirectories
        inventory_dir = os.path.join(temp_dir, "inventory")
        project_dir = os.path.join(temp_dir, "project")
        os.makedirs(inventory_dir, exist_ok=True)
        os.makedirs(project_dir, exist_ok=True)
        
        # Write inventory file
        inventory = build_inventory(active_nodes, ssh_user, ssh_key)
        inventory_file = os.path.join(inventory_dir, "hosts.json")
        
        with open(inventory_file, "w", encoding="utf-8") as f:
            json.dump(inventory, f, indent=2)
        
        logger.debug(f"Wrote inventory to {inventory_file}")
        
        # Write playbook file
        playbook_content = generate_hardening_playbook()
        playbook_file = os.path.join(project_dir, "hardening.yml")
        
        with open(playbook_file, "w", encoding="utf-8") as f:
            f.write(playbook_content)
        
        logger.debug(f"Wrote playbook to {playbook_file}")
        
        # Run ansible-runner
        logger.info("Executing Ansible playbook...")
        
        runner = ansible_runner.run(
            private_data_dir=temp_dir,
            playbook="hardening.yml",
            inventory=inventory_file,
            verbosity=1
        )
        
        # Check execution status
        if runner.status == "successful":
            logger.info("Ansible playbook execution: SUCCESSFUL")
            
            for node in active_nodes:
                result_map[node.ip] = "success"
        else:
            logger.error(f"Ansible playbook execution: {runner.status.upper()}")
            
            # Try to get stdout for debugging
            try:
                if hasattr(runner, 'stdout') and runner.stdout:
                    stdout_content = runner.stdout.read()
                    logger.error(f"Ansible stdout:\n{stdout_content}")
            except Exception as e:
                logger.error(f"Could not read Ansible stdout: {e}")
            
            for node in active_nodes:
                result_map[node.ip] = "failed"
    
    except Exception as e:
        logger.error(f"Hardening execution failed: {e}\n{traceback.format_exc()}")
        
        # Mark all nodes as failed
        for node in active_nodes:
            result_map[node.ip] = "failed"
    
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e}")
    
    logger.info(f"Hardening complete. Results: {result_map}")
    return result_map


def apply_hardening_to_scan(scan_result: ScanResult) -> ScanResult:
    """Apply hardening to all nodes in a scan result and update their statuses.
    
    This is a thin wrapper around run_hardening() that updates the NetworkNode
    hardening_status fields based on execution results.
    
    Args:
        scan_result: ScanResult containing nodes to harden
        
    Returns:
        ScanResult: Updated scan result with hardening statuses applied
    """
    from config import CONFIG
    
    logger.info("Applying hardening to scan results")
    
    # Run hardening
    hardening_results = run_hardening(
        nodes=scan_result.nodes,
        ssh_user=CONFIG.ANSIBLE_SSH_USER,
        ssh_key=CONFIG.ANSIBLE_SSH_KEY,
        output_dir=CONFIG.OUTPUT_DIR
    )
    
    # Update node statuses
    for node in scan_result.nodes:
        if node.ip in hardening_results:
            node.hardening_status = hardening_results[node.ip]
            logger.info(f"Node {node.ip} hardening status: {node.hardening_status}")
    
    return scan_result
