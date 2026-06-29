"""
NetCartographer - Network Discovery and Hardening System

Main entry point with three modes:
- scan: Run network scan with hardening
- daemon: Continuous monitoring
- visualize: Regenerate topology from saved data
"""

import sys
import os
import json
import logging
import argparse
import signal
from typing import Optional

from dotenv import load_dotenv

# Import all modules
from config import CONFIG
from models import ScanResult, NetworkNode
import scanner
import hardener
import visualizer
import daemon

# Setup basic logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)

logger = logging.getLogger(__name__)


def check_root_privileges() -> None:
    """Check if running as root (required for raw socket operations)."""
    try:
        if os.geteuid() != 0:
            print("=" * 80)
            print("ERROR: NetCartographer requires root privileges for raw socket operations.")
            print("Please run with sudo:")
            print(f"  sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}")
            print("=" * 80)
            sys.exit(1)
    except AttributeError:
        # os.geteuid() doesn't exist on Windows
        logger.warning("Root privilege check skipped (non-Unix system)")


def print_scan_summary(scan_result: ScanResult) -> None:
    """Print formatted summary of scan results."""
    print("\n" + "=" * 100)
    print("NETWORK SCAN SUMMARY")
    print("=" * 100)
    print(f"Scan Time: {scan_result.scan_time}")
    print(f"Target CIDR: {scan_result.cidr}")
    print(f"Total Hosts Found: {scan_result.total_hosts_found}")
    print("=" * 100)
    
    # Table header
    header = f"{'IP Address':<17} | {'Hostname':<22} | {'OS Hint':<10} | {'Open Ports':<12} | {'Hardening':<14}"
    separator = "-" * 100
    
    print(header)
    print(separator)
    
    # Table rows
    for node in scan_result.nodes:
        ip = node.ip[:16]
        hostname = node.hostname[:21] if node.hostname else "unknown"
        os_hint = node.os_hint[:9] if node.os_hint else "unknown"
        
        ports_str = ",".join(str(p) for p in node.open_ports[:3])
        if len(node.open_ports) > 3:
            ports_str += "..."
        ports_str = ports_str[:11] if ports_str else "none"
        
        hardening = node.hardening_status[:13]
        
        row = f"{ip:<17} | {hostname:<22} | {os_hint:<10} | {ports_str:<12} | {hardening:<14}"
        print(row)
    
    print("=" * 100)
    print(f"\nResults saved to: {CONFIG.OUTPUT_DIR}/scan_result.json")
    print(f"Topology HTML: {CONFIG.TOPOLOGY_HTML}")
    print()


def mode_scan(args: argparse.Namespace) -> None:
    """Run network scan, apply hardening, and generate visualization."""
    logger.info("Starting one-shot scan mode")
    
    # Perform network discovery
    scan_result = scanner.discover_network(
        cidr=CONFIG.TARGET_CIDR,
        interface=CONFIG.SCAN_INTERFACE,
        ports=CONFIG.SCAN_PORTS,
        arp_timeout=CONFIG.ARP_TIMEOUT,
        port_timeout=CONFIG.PORT_SCAN_TIMEOUT,
        traceroute_max_hops=CONFIG.TRACEROUTE_MAX_HOPS,
        traceroute_timeout=CONFIG.TRACEROUTE_TIMEOUT
    )
    
    # Apply hardening
    logger.info("Applying security hardening to discovered nodes")
    scan_result = hardener.apply_hardening_to_scan(scan_result)
    
    # Save updated results
    output_file = f"{CONFIG.OUTPUT_DIR}/scan_result.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(scan_result.to_dict(), f, indent=2)
    logger.info(f"Updated scan results saved to {output_file}")
    
    # Build and render topology
    logger.info("Generating topology visualization")
    graph = visualizer.build_topology(scan_result.nodes, CONFIG.GATEWAY_IP)
    visualizer.render_html(graph, CONFIG.TOPOLOGY_HTML)
    
    # Print summary
    print_scan_summary(scan_result)


def mode_daemon(args: argparse.Namespace) -> None:
    """Run continuous monitoring daemon until interrupted."""
    logger.info("Starting daemon mode")
    
    # Setup file logging
    daemon.setup_file_logging(CONFIG.LOG_FILE)
    
    # Create daemon instance
    network_daemon = daemon.NetworkDaemon(CONFIG)
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, stopping daemon")
        network_daemon.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Daemon started. Press Ctrl+C to stop.")
    print("NetCartographer daemon started. Monitoring network...")
    print(f"Scan interval: {CONFIG.DAEMON_INTERVAL} seconds")
    print(f"Log file: {CONFIG.LOG_FILE}")
    print("Press Ctrl+C to stop.")
    
    # Run daemon
    network_daemon.run()
    
    logger.info("Daemon stopped")


def mode_visualize(args: argparse.Namespace) -> None:
    """Regenerate topology visualization from saved scan data."""
    logger.info(f"Loading scan results from {args.input}")
    
    # Load scan result
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        scan_result = ScanResult.from_dict(data)
        logger.info(f"Loaded {len(scan_result.nodes)} nodes from {args.input}")
        
    except FileNotFoundError:
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in input file: {e}")
        sys.exit(1)
    
    # Build and render topology
    logger.info("Generating topology visualization")
    graph = visualizer.build_topology(scan_result.nodes, CONFIG.GATEWAY_IP)
    visualizer.render_html(graph, CONFIG.TOPOLOGY_HTML)
    
    print(f"Topology visualization generated: {CONFIG.TOPOLOGY_HTML}")


def main() -> None:
    """Main entry point with argument parsing and mode dispatch."""
    parser = argparse.ArgumentParser(
        description="NetCartographer - Network Discovery and Hardening System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py scan
  sudo python3 main.py daemon
  python3 main.py visualize --input ./output/scan_result.json
        """
    )
    
    # Global arguments
    parser.add_argument(
        "--config",
        type=str,
        help="Path to .env configuration file"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="mode", help="Operating mode")
    
    # Scan mode
    parser_scan = subparsers.add_parser(
        "scan",
        help="Perform one-shot network scan with hardening"
    )
    
    # Daemon mode
    parser_daemon = subparsers.add_parser(
        "daemon",
        help="Run continuous monitoring daemon"
    )
    
    # Visualize mode
    parser_visualize = subparsers.add_parser(
        "visualize",
        help="Regenerate visualization from saved scan data"
    )
    parser_visualize.add_argument(
        "--input",
        type=str,
        default="./output/scan_result.json",
        help="Path to scan_result.json file (default: ./output/scan_result.json)"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Load custom config file if specified
    if args.config:
        load_dotenv(args.config)
        logger.info(f"Loaded configuration from {args.config}")
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Verbose logging enabled")
    
    # Check if mode was specified
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    
    # Check root privileges for scan and daemon modes
    if args.mode in ["scan", "daemon"]:
        check_root_privileges()
    
    # Dispatch to appropriate mode
    if args.mode == "scan":
        mode_scan(args)
    elif args.mode == "daemon":
        mode_daemon(args)
    elif args.mode == "visualize":
        mode_visualize(args)


if __name__ == "__main__":
    main()
