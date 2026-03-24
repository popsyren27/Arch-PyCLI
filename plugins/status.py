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

    health = context.get("health", {})
    
    # Generate status output
    output = []
    output.append(f"Node ID: {NETWORK_NODE.node_id}")
    output.append(f"Status: {health.get('status', 'UNKNOWN')}")

    if subcommand in ["memory", "full"]:
        mem = float(health.get('memory_pressure', 0.0))
        output.append(f"Memory Pressure: {mem:.1f}%")

    if subcommand in ["cpu", "full"]:
        cpu = float(health.get('cpu_utilization', 0.0))
        output.append(f"CPU Utilization: {cpu:.1f}%")

    if subcommand in ["health", "full"]:
        lat = float(health.get('internal_latency', 0.0))
        ts = float(health.get('timestamp', 0.0))
        output.append(f"Internal Latency: {lat:.6f}s")
        output.append(f"Timestamp: {ts:.2f}")
    
    if subcommand == "full":
        try:
            cores = int(getattr(HAL, 'CPU_CORES', 0))
            total_ram = float(getattr(HAL, 'TOTAL_RAM', 0))
            output.append(f"HAL CPU Cores: {cores}")
            output.append(f"HAL Total RAM: {total_ram / (1024**3):.2f} GB")
        except Exception:
            output.append("HAL: data unavailable")
    
    return "\n".join(output)
