"""
Network topology visualization using NetworkX and Pyvis.
"""

import logging
from typing import Any

import networkx as nx
from pyvis.network import Network

from models import NetworkNode

logger = logging.getLogger(__name__)


def build_topology(nodes: list[NetworkNode], gateway_ip: str) -> nx.Graph:
    """Build NetworkX graph from network nodes."""
    logger.info(f"Building topology graph with gateway {gateway_ip}")
    
    G = nx.Graph()
    
    # Add gateway as root node
    G.add_node(gateway_ip, role="gateway", ip=gateway_ip)
    
    # Add all discovered nodes
    for node in nodes:
        G.add_node(
            node.ip,
            ip=node.ip,
            mac=node.mac,
            status=node.status,
            open_ports=str(node.open_ports),
            os_hint=node.os_hint,
            hardening_status=node.hardening_status,
            hostname=node.hostname
        )
        
        # Determine edge based on traceroute data
        edge_added = False
        
        if node.traceroute_hops and len(node.traceroute_hops) > 0:
            # First hop after local machine
            first_hop = node.traceroute_hops[0]
            
            if first_hop != "*":
                if first_hop == gateway_ip:
                    # Direct connection to gateway
                    G.add_edge(gateway_ip, node.ip)
                    edge_added = True
                else:
                    # Connection through intermediate hop
                    # For simplicity, still connect to gateway if hop is not in our node list
                    if first_hop in [n.ip for n in nodes]:
                        G.add_edge(first_hop, node.ip)
                        edge_added = True
        
        # Fallback: connect directly to gateway if no traceroute info
        if not edge_added:
            G.add_edge(gateway_ip, node.ip)
    
    logger.info(f"Topology graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def get_node_color(node_attrs: dict[str, Any]) -> str:
    """Determine node display color based on status."""
    if node_attrs.get("role") == "gateway":
        return "#4A90D9"  # Blue
    
    if node_attrs.get("status") == "unreachable":
        return "#E74C3C"  # Red
    
    hardening = node_attrs.get("hardening_status")
    if hardening == "success":
        return "#2ECC71"  # Green
    elif hardening == "failed":
        return "#E74C3C"  # Red
    elif hardening == "pending":
        return "#F39C12"  # Orange
    
    return "#95A5A6"  # Grey


def render_html(
    G: nx.Graph,
    output_path: str,
    title: str = "NetCartographer — Live Topology"
) -> None:
    """Render NetworkX graph as interactive HTML using Pyvis."""
    logger.info(f"Rendering topology to {output_path}")
    
    # Create Pyvis network
    net = Network(
        height="900px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#eaeaea",
        heading=title
    )
    
    # Add nodes
    for node_id, attrs in G.nodes(data=True):
        # Build label
        ip = attrs.get("ip", node_id)
        hostname = attrs.get("hostname", "")
        label = f"{ip}\n{hostname}"
        
        # Determine color and size
        color = get_node_color(attrs)
        size = 30 if attrs.get("role") == "gateway" else 20
        
        # Build tooltip
        title_tooltip = (
            f"IP: {attrs.get('ip', '?')}\n"
            f"MAC: {attrs.get('mac', '?')}\n"
            f"OS: {attrs.get('os_hint', '?')}\n"
            f"Ports: {attrs.get('open_ports', '[]')}\n"
            f"Hardening: {attrs.get('hardening_status', '?')}"
        )
        
        net.add_node(
            node_id,
            label=label,
            color=color,
            size=size,
            title=title_tooltip
        )
    
    # Add edges
    for edge in G.edges():
        net.add_edge(edge[0], edge[1])
    
    # Set physics options for clean layout
    net.set_options("""
    {
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -8000,
          "springLength": 200
        },
        "stabilization": { "iterations": 200 }
      }
    }
    """)
    
    # Write to file
    net.write_html(output_path)
    logger.info(f"Topology HTML written to {output_path}")
