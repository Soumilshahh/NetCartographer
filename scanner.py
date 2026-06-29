"""
Network scanning and discovery module.

Implements ARP scanning, port scanning, traceroute, and OS fingerprinting
using Scapy and raw sockets.
"""

import socket
import logging
import traceback
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Optional

from scapy.all import ARP, Ether, IP, ICMP, UDP, sr1, srp
from netaddr import IPNetwork

from config import CONFIG
from models import NetworkNode, ScanResult

logger = logging.getLogger(__name__)


def arp_sweep(cidr: str, interface: str, timeout: float) -> dict[str, str]:
    """Send ARP requests across CIDR range and collect MAC addresses."""
    logger.info(f"Starting ARP sweep on {cidr} via interface {interface}")
    ip_to_mac: dict[str, str] = {}
    
    try:
        # Enumerate host IPs in CIDR range
        network = IPNetwork(cidr)
        target_ips = list(network)
        
        # Remove network and broadcast addresses
        if len(target_ips) > 2:
            target_ips = target_ips[1:-1]
        
        for ip in target_ips:
            try:
                # Build and send ARP request
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip))
                answered, _ = srp(pkt, iface=interface, timeout=timeout, verbose=False, retry=0)
                
                # Extract replies
                for sent, received in answered:
                    replied_ip = received[ARP].psrc
                    replied_mac = received[Ether].src
                    ip_to_mac[replied_ip] = replied_mac
                    logger.info(f"ARP: Discovered {replied_ip} -> {replied_mac}")
                    
            except Exception as e:
                logger.debug(f"ARP sweep error for {ip}: {e}")
                continue
                
    except PermissionError as e:
        logger.critical("ARP sweep requires root privileges for raw socket operations")
        raise
    except Exception as e:
        logger.error(f"ARP sweep failed: {e}\n{traceback.format_exc()}")
    
    logger.info(f"ARP sweep complete. Discovered {len(ip_to_mac)} hosts")
    return ip_to_mac


def read_proc_arp() -> dict[str, str]:
    """Read kernel ARP cache from /proc/net/arp."""
    ip_to_mac: dict[str, str] = {}
    arp_file = "/proc/net/arp"
    
    try:
        with open(arp_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        # Skip header
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3]
                
                # Skip incomplete entries
                if mac != "00:00:00:00:00:00":
                    ip_to_mac[ip] = mac
                    logger.debug(f"/proc/net/arp: {ip} -> {mac}")
                    
    except FileNotFoundError:
        logger.warning(f"{arp_file} not found (non-Linux system?)")
    except Exception as e:
        logger.warning(f"Failed to read {arp_file}: {e}")
    
    return ip_to_mac


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup with 2-second timeout."""
    def _resolve() -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            return "unknown"
    
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_resolve)
            result = future.result(timeout=2.0)
            if result != "unknown":
                logger.debug(f"Resolved {ip} -> {result}")
            return result
    except TimeoutError:
        logger.debug(f"DNS resolution timeout for {ip}")
        return "unknown"
    except Exception as e:
        logger.debug(f"DNS resolution failed for {ip}: {e}")
        return "unknown"


def os_hint_from_ttl(ttl: int) -> str:
    """Guess OS based on TTL value."""
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    elif ttl >= 32:
        return "Network Device (Router/Switch)"
    else:
        return "Unknown"


def get_icmp_ttl(ip: str, timeout: float) -> Optional[int]:
    """Send ICMP echo and extract TTL from reply."""
    try:
        pkt = IP(dst=ip, ttl=64) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=False)
        
        if reply is not None and reply.haslayer(IP):
            ttl = reply[IP].ttl
            logger.debug(f"ICMP TTL from {ip}: {ttl}")
            return ttl
    except Exception as e:
        logger.debug(f"ICMP TTL probe failed for {ip}: {e}")
    
    return None


def scan_ports(ip: str, ports: list[int], timeout: float) -> list[int]:
    """Scan TCP ports using parallel socket connections."""
    def _check_port(port: int) -> Optional[int]:
        """Check if a single port is open."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                return port
        except socket.error:
            # Ignore socket errors - port is closed or unreachable
            pass
        finally:
            if sock:
                sock.close()
        
        return None
    
    open_ports: list[int] = []
    
    try:
        with ThreadPoolExecutor(max_workers=len(ports)) as executor:
            futures = {executor.submit(_check_port, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
        
        open_ports.sort()
        
        if open_ports:
            logger.info(f"Host {ip}: open ports {open_ports}")
        else:
            logger.debug(f"Host {ip}: no open ports found")
            
    except Exception as e:
        logger.warning(f"Port scan failed for {ip}: {e}")
    
    return open_ports


def traceroute_to_host(target_ip: str, max_hops: int, timeout: float) -> list[str]:
    """UDP-based traceroute using incrementing TTL values."""
    hops: list[str] = []
    reached = False
    
    try:
        for ttl in range(1, max_hops + 1):
            # Send UDP probe with incrementing TTL
            pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434 + ttl)
            reply = sr1(pkt, timeout=timeout, verbose=False)
            
            if reply is None:
                hops.append("*")
                continue
            
            if reply.haslayer(ICMP):
                hop_ip = reply[IP].src
                hops.append(hop_ip)
                
                # Check if we reached the destination
                icmp_type = reply[ICMP].type
                
                # Type 0 = echo reply, Type 3 = destination unreachable (port unreachable means we reached it)
                if icmp_type == 0 or icmp_type == 3:
                    reached = True
                    break
                
                # Type 11 = time exceeded (normal traceroute hop)
                if icmp_type == 11:
                    continue
            elif reply.haslayer(IP):
                # Got a reply without ICMP layer
                hop_ip = reply[IP].src
                hops.append(hop_ip)
                reached = True
                break
        
        logger.debug(f"Traceroute to {target_ip}: {' -> '.join(hops)}")
        
    except Exception as e:
        logger.debug(f"Traceroute to {target_ip} failed: {e}")
    
    return hops


def discover_network(
    cidr: str,
    interface: str,
    ports: list[int],
    arp_timeout: float,
    port_timeout: float,
    traceroute_max_hops: int,
    traceroute_timeout: float
) -> ScanResult:
    """Run complete network discovery scan."""
    scan_start = datetime.utcnow()
    logger.info(f"Starting network discovery: {cidr}")
    
    # Discover hosts via ARP
    arp_hosts = arp_sweep(cidr, interface, arp_timeout)
    proc_hosts = read_proc_arp()
    
    # Merge results
    all_hosts = {**proc_hosts, **arp_hosts}
    
    logger.info(f"Total unique hosts discovered: {len(all_hosts)}")
    
    # Build NetworkNode for each host
    nodes: list[NetworkNode] = []
    
    for ip, mac in all_hosts.items():
        try:
            logger.info(f"Scanning host {ip}...")
            
            # Gather host information
            hostname = resolve_hostname(ip)
            
            ttl = get_icmp_ttl(ip, arp_timeout)
            os_hint = os_hint_from_ttl(ttl) if ttl is not None else "unknown"
            
            open_ports = scan_ports(ip, ports, port_timeout)
            
            traceroute_hops = traceroute_to_host(ip, traceroute_max_hops, traceroute_timeout)
            
            # Create node
            node = NetworkNode(
                ip=ip,
                mac=mac,
                hostname=hostname,
                status="active",
                open_ports=open_ports,
                os_hint=os_hint,
                hardening_status="pending",
                last_seen=datetime.utcnow().isoformat() + "Z",
                traceroute_hops=traceroute_hops
            )
            
            nodes.append(node)
            logger.info(f"Host {ip} scan complete: {hostname} ({os_hint})")
            
        except Exception as e:
            logger.error(f"Failed to scan host {ip}: {e}\n{traceback.format_exc()}")
            
            # Create minimal node for unreachable hosts
            node = NetworkNode(
                ip=ip,
                mac=mac,
                hostname="unknown",
                status="unreachable",
                open_ports=[],
                os_hint="unknown",
                hardening_status="pending",
                last_seen=datetime.utcnow().isoformat() + "Z",
                traceroute_hops=[]
            )
            nodes.append(node)
    
    # Build and save scan result
    scan_result = ScanResult(
        scan_time=scan_start.isoformat() + "Z",
        cidr=cidr,
        total_hosts_found=len(nodes),
        nodes=nodes
    )
    
    # Save to disk
    output_file = f"{CONFIG.OUTPUT_DIR}/scan_result.json"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(scan_result.to_dict(), f, indent=2)
        logger.info(f"Scan results saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save scan results: {e}\n{traceback.format_exc()}")
    
    logger.info("Network discovery scan complete")
    return scan_result
