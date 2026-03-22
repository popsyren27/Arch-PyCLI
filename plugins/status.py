"""
System Status Plugin
Usage: status [health | memory | cpu | full]
"""
import logging
from typing import Dict, Any
from core.hal import HAL
from core.network import NETWORK_NODE


def _validate_subcommand(subcommand: str) -> bool:
    """Input validation to prevent command injection."""
    valid_commands = {"health", "memory", "cpu", "full", ""}
    return subcommand.lower() in valid_commands


def execute(context: Dict[str, Any], *args) -> str:
    """
    Reports system health and resource metrics.
    
    Args:
        context: Dict containing health data
        *args: optional subcommand (health|memory|cpu|full)
    
    Returns:
        Formatted system status string
    """
    # Input validation
    if not context or "health" not in context:
        raise ValueError("ERR_MISSING_HEALTH_CONTEXT")
    
    subcommand = args[0].lower() if args else "full"
    
    # Validate subcommand safely
    if not _validate_subcommand(subcommand):
        return f"ERR_INVALID_SUBCOMMAND: '{subcommand}'. Use: health|memory|cpu|full"
    
    health = context["health"]
    
    # Generate status output
    output = []
    output.append(f"Node ID: {NETWORK_NODE.node_id}")
    output.append(f"Status: {health['status']}")
    
    if subcommand in ["memory", "full"]:
        output.append(f"Memory Pressure: {health['memory_pressure']:.1f}%")
    
    if subcommand in ["cpu", "full"]:
        output.append(f"CPU Utilization: {health['cpu_utilization']:.1f}%")
    
    if subcommand in ["health", "full"]:
        output.append(f"Internal Latency: {health['internal_latency']:.6f}s")
        output.append(f"Timestamp: {health['timestamp']:.2f}")
    
    if subcommand == "full":
        output.append(f"HAL CPU Cores: {HAL.CPU_CORES}")
        output.append(f"HAL Total RAM: {HAL.TOTAL_RAM / (1024**3):.2f} GB")
    
    return "\n".join(output)
