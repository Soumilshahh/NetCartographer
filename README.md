# NetCartographer

Network discovery and security hardening tool that maps your network topology and automatically hardens Linux hosts using Ansible.

## Features

- **Network Discovery**: ARP scanning, port scanning, OS fingerprinting, traceroute
- **Topology Visualization**: Interactive HTML graphs showing network layout
- **Security Hardening**: Automated Ansible playbooks for system updates, firewall setup, and SSH hardening  
- **Continuous Monitoring**: Daemon mode with alerts for network changes

All scanning is done with Scapy and raw Python - no dependencies on nmap or other external tools.

## Quick Start

```bash
# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install community.general

# Configure
cp .env.example .env
nano .env

# Run scan (requires root for raw sockets)
sudo venv/bin/python main.py scan
```

## Requirements

- Python 3.11+
- Linux (tested on Ubuntu 22.04)
- Root privileges for raw sockets
- Ansible (for hardening)
- SSH access to target hosts

## Usage

### Scan Mode

Run a one-time scan:

```bash
sudo venv/bin/python main.py scan
```

### Daemon Mode

Continuous monitoring with alerts:

```bash
sudo venv/bin/python main.py daemon
```

### Visualization

Regenerate HTML from saved data:

```bash
python main.py visualize --input ./output/scan_result.json
```

## Architecture

The project is organized into focused modules:

- `scanner.py` - Network discovery (ARP, ports, traceroute, OS detection)
- `hardener.py` - Ansible automation for security hardening
- `visualizer.py` - NetworkX/Pyvis topology rendering
- `daemon.py` - Continuous monitoring and alerts
- `models.py` - Data structures  
- `config.py` - Configuration management
- `main.py` - CLI entry point

## Configuration

All settings via `.env` file:

```bash
TARGET_CIDR=192.168.1.0/24
GATEWAY_IP=192.168.1.1
SCAN_INTERFACE=eth0
SCAN_PORTS=22,80,443,161,8080
ANSIBLE_SSH_USER=ubuntu
ANSIBLE_SSH_KEY=~/.ssh/id_rsa
```

See `.env.example` for full options.

## Security Notes

- Requires root for raw socket operations
- Only scan networks you own/have permission for
- Protect SSH private keys
- Review Ansible playbooks before running

## Testing

Use VMs for testing without real hardware. See SETUP.md for details.

