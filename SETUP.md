# NetCartographer Setup Guide

## Prerequisites

- **Python 3.11+**
- **Linux OS** (tested on Ubuntu 22.04)
- **Ansible** installed system-wide:
  ```bash
  sudo apt update
  sudo apt install ansible
  ```
- **SSH key pair** generated and public key deployed to target hosts:
  ```bash
  ssh-keygen -t rsa -b 4096
  ssh-copy-id user@target-host
  ```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Soumilshahh/netcartographer.git
cd netcartographer
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install Ansible Community Collection

The hardening playbook uses the `community.general.ufw` module:

```bash
ansible-galaxy collection install community.general
```

## Configuration

### 1. Create Configuration File

Copy the example configuration and customize it:

```bash
cp .env.example .env
nano .env
```

### 2. Environment Variables

Create a `.env` file with the following variables:

```bash
# Network Scanning Configuration
TARGET_CIDR=192.168.1.0/24          # Subnet to scan
GATEWAY_IP=192.168.1.1              # Network gateway IP
SCAN_INTERFACE=eth0                 # Network interface to use
SCAN_PORTS=22,80,443,161,8080       # TCP ports to scan (comma-separated)

# Timeout Configuration
PORT_SCAN_TIMEOUT=1.5               # Per-port TCP timeout (seconds)
ARP_TIMEOUT=2.0                     # ARP reply timeout (seconds)
TRACEROUTE_MAX_HOPS=15              # Maximum traceroute hops
TRACEROUTE_TIMEOUT=2.0              # Per-hop traceroute timeout (seconds)

# Daemon Configuration
DAEMON_INTERVAL=60                  # Seconds between daemon scan cycles
STATE_FILE=/tmp/net_cartographer_state.json
LOG_FILE=/var/log/net_cartographer.log

# Webhook Alerts
WEBHOOK_URL=http://localhost:9000/webhook

# Ansible Configuration
ANSIBLE_SSH_USER=ubuntu             # SSH username for target hosts
ANSIBLE_SSH_KEY=~/.ssh/id_rsa       # Path to SSH private key

# Output Configuration
OUTPUT_DIR=./output
TOPOLOGY_HTML=./output/topology.html
```

### Variable Descriptions

| Variable | Description | Default |
|----------|-------------|---------|
| `TARGET_CIDR` | Network range to scan in CIDR notation | `192.168.1.0/24` |
| `GATEWAY_IP` | Network gateway (root node in topology) | `192.168.1.1` |
| `SCAN_INTERFACE` | Network interface for raw socket operations | `eth0` |
| `SCAN_PORTS` | Comma-separated list of TCP ports to scan | `22,80,443,161,8080` |
| `PORT_SCAN_TIMEOUT` | Timeout for each port probe (seconds) | `1.5` |
| `ARP_TIMEOUT` | Timeout for ARP replies (seconds) | `2.0` |
| `TRACEROUTE_MAX_HOPS` | Maximum hops for traceroute | `15` |
| `TRACEROUTE_TIMEOUT` | Per-hop traceroute timeout (seconds) | `2.0` |
| `DAEMON_INTERVAL` | Seconds between daemon scan cycles | `60` |
| `STATE_FILE` | Path to persistent state file | `/tmp/net_cartographer_state.json` |
| `LOG_FILE` | Path to daemon log file | `/var/log/net_cartographer.log` |
| `WEBHOOK_URL` | HTTP endpoint for alert webhooks | `http://localhost:9000/webhook` |
| `ANSIBLE_SSH_USER` | SSH username for Ansible | `ubuntu` |
| `ANSIBLE_SSH_KEY` | Path to SSH private key | `~/.ssh/id_rsa` |
| `OUTPUT_DIR` | Directory for output files | `./output` |
| `TOPOLOGY_HTML` | Path to topology visualization HTML | `./output/topology.html` |

## Running

**IMPORTANT:** NetCartographer requires root privileges for raw socket operations (ARP, ICMP, traceroute).

### Mode 1: One-Shot Scan

Perform a single network scan, apply hardening, and generate topology:

```bash
sudo venv/bin/python main.py scan
```

Output:
- `./output/scan_result.json` - Complete scan results in JSON
- `./output/topology.html` - Interactive network topology visualization

### Mode 2: Continuous Daemon

Run continuous monitoring with alerts and automatic hardening:

```bash
sudo venv/bin/python main.py daemon
```

The daemon will:
- Scan the network every `DAEMON_INTERVAL` seconds
- Detect new and disappeared nodes
- Send webhook alerts for changes
- Automatically harden new nodes
- Update topology visualization
- Log to `LOG_FILE`

Press `Ctrl+C` to stop gracefully.

### Mode 3: Visualize Only

Regenerate topology from saved scan data (no root required):

```bash
venv/bin/python main.py visualize --input ./output/scan_result.json
```

### Additional Options

**Enable verbose debug logging:**

```bash
sudo venv/bin/python main.py scan --verbose
```

**Use custom config file:**

```bash
sudo venv/bin/python main.py scan --config /path/to/custom.env
```

## Testing Without Real Hardware

You can test NetCartographer using local virtual machines.

### Option 1: Vagrant Testing Environment

Create a `Vagrantfile`:

```ruby
Vagrant.configure("2") do |config|
  # Network configuration
  private_network = "192.168.56"
  
  # VM 1: Ubuntu server
  config.vm.define "server1" do |server|
    server.vm.box = "ubuntu/jammy64"
    server.vm.hostname = "server1"
    server.vm.network "private_network", ip: "#{private_network}.10"
    
    server.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
      vb.cpus = 1
    end
    
    # Install SSH key
    server.vm.provision "shell", inline: <<-SHELL
      mkdir -p /home/vagrant/.ssh
      cat /vagrant/id_rsa.pub >> /home/vagrant/.ssh/authorized_keys
    SHELL
  end
  
  # VM 2: Ubuntu server
  config.vm.define "server2" do |server|
    server.vm.box = "ubuntu/jammy64"
    server.vm.hostname = "server2"
    server.vm.network "private_network", ip: "#{private_network}.11"
    
    server.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
      vb.cpus = 1
    end
    
    server.vm.provision "shell", inline: <<-SHELL
      mkdir -p /home/vagrant/.ssh
      cat /vagrant/id_rsa.pub >> /home/vagrant/.ssh/authorized_keys
    SHELL
  end
end
```

Start the test environment:

```bash
# Copy your SSH public key
cp ~/.ssh/id_rsa.pub ./

# Start VMs
vagrant up

# Configure NetCartographer for the test network
cat > .env << EOF
TARGET_CIDR=192.168.56.0/24
GATEWAY_IP=192.168.56.1
SCAN_INTERFACE=vboxnet0
ANSIBLE_SSH_USER=vagrant
ANSIBLE_SSH_KEY=~/.ssh/id_rsa
EOF

# Run scan
sudo venv/bin/python main.py scan
```

### Option 2: Docker Testing Environment

Create a Docker Compose network with multiple containers:

```yaml
version: '3.8'

services:
  host1:
    image: ubuntu:22.04
    container_name: test_host1
    networks:
      testnet:
        ipv4_address: 172.20.0.10
    command: sleep infinity
    
  host2:
    image: ubuntu:22.04
    container_name: test_host2
    networks:
      testnet:
        ipv4_address: 172.20.0.11
    command: sleep infinity

networks:
  testnet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

Note: Docker networks have limitations for raw socket operations. Vagrant is recommended for full-featured testing.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                  main.py                                     │
│                        (Entry Point & CLI Interface)                         │
└──────────────┬─────────────────┬─────────────────┬─────────────────┬────────┘
               │                 │                 │                 │
               │                 │                 │                 │
       ┌───────▼────────┐ ┌──────▼───────┐ ┌──────▼──────┐ ┌────────▼────────┐
       │   scanner.py   │ │  hardener.py │ │ visualizer.py│ │   daemon.py    │
       │                │ │               │ │             │ │                 │
       │  • ARP Sweep   │ │ • Ansible     │ │• NetworkX   │ │ • Continuous    │
       │  • Port Scan   │ │   Inventory   │ │  Topology   │ │   Monitoring    │
       │  • Traceroute  │ │ • Playbook    │ │• Pyvis HTML │ │ • State Diff    │
       │  • OS Detect   │ │   Generation  │ │  Rendering  │ │ • Webhooks      │
       │  • DNS Lookup  │ │ • Hardening   │ │             │ │ • Auto-harden   │
       └────────┬───────┘ └───────┬───────┘ └──────┬──────┘ └────────┬────────┘
                │                 │                │                  │
                │                 │                │                  │
         ┌──────▼─────────────────▼────────────────▼──────────────────▼─────┐
         │                          models.py                                │
         │              (NetworkNode, ScanResult, AlertPayload)              │
         └──────────────────────────────┬────────────────────────────────────┘
                                        │
                                        │
                                 ┌──────▼──────┐
                                 │  config.py  │
                                 │ (CONFIG obj)│
                                 └─────────────┘
```

### Data Flow

1. **Scan Mode:**
   ```
   main.py → scanner.py → models.py → hardener.py → visualizer.py → output files
   ```

2. **Daemon Mode:**
   ```
   main.py → daemon.py → [continuous loop]
                 ├─→ scanner.py → models.py
                 ├─→ state diff & alerts
                 ├─→ hardener.py (for new nodes)
                 └─→ visualizer.py
   ```

3. **Visualize Mode:**
   ```
   main.py → load JSON → visualizer.py → topology.html
   ```

## Troubleshooting

### Permission Denied Errors

**Problem:** `PermissionError: Operation not permitted`

**Solution:** Ensure you're running with sudo for scan/daemon modes.

### No Hosts Discovered

**Problem:** ARP sweep returns 0 hosts

**Solutions:**
- Verify `SCAN_INTERFACE` is correct: `ip link show`
- Check you're on the same subnet as `TARGET_CIDR`
- Ensure firewall isn't blocking ARP packets

### Ansible Hardening Fails

**Problem:** Hardening status shows "failed" for all nodes

**Solutions:**
- Verify SSH key is deployed: `ssh -i ~/.ssh/id_rsa ubuntu@target-host`
- Check `ANSIBLE_SSH_USER` matches actual username on target
- Ensure target hosts are Debian/Ubuntu (playbook uses apt)
- Check Ansible is installed: `ansible --version`

### UFW Module Not Found

**Problem:** Ansible error about missing `community.general.ufw`

**Solution:** Install the collection:
```bash
ansible-galaxy collection install community.general
```

## Security Considerations

1. **Root Privileges:** Required for raw sockets. Run only on trusted networks.
2. **SSH Keys:** Protect your private keys. Never commit them to version control.
3. **Webhook URL:** If using external webhooks, ensure HTTPS and authentication.
4. **Hardening Playbook:** Review and customize the playbook for your environment.
5. **Network Scanning:** Obtain permission before scanning networks you don't own.


