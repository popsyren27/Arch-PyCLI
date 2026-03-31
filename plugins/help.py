"""
Help Plugin for Arch-PyCLI.

This plugin provides help and documentation for all available commands.

Features:
- List all available commands
- Show command details
- Search commands by name
- Group commands by category

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, List, Optional


# =============================================================================
# CONFIGURATION
# =============================================================================

# Debug configuration
DEBUG_PREFIX: str = "[HELP_PLUGIN]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging."""
    global _is_debug_mode
    _is_debug_mode = enabled


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# SETUP LOGGING
# =============================================================================

_logger: logging.Logger = logging.getLogger("HELP_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[HELP_PLUGIN] Help plugin initialized")


# =============================================================================
# CATEGORIES
# =============================================================================

CATEGORIES: Dict[str, str] = {
    "system": "System Commands",
    "security": "Security & Encryption",
    "network": "Network & Communication",
    "storage": "Storage & Files",
    "tools": "Utilities & Tools",
    "fun": "Entertainment",
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _ensure_health(context: Dict[str, Any]) -> None:
    """Ensure health context is valid."""
    health: Optional[Dict[str, Any]] = context.get("health")
    
    if not isinstance(health, dict):
        _logger.error("[HELP_PLUGIN] Invalid health context")
        raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
    
    if health.get("status") == "CRITICAL":
        _logger.warning("[HELP_PLUGIN] System in CRITICAL state")
        raise RuntimeError("ERR_SYSTEM_INSTABILITY")


def _get_command_info() -> Dict[str, Dict[str, Any]]:
    """
    Get information about all available commands.
    
    Returns:
        Dictionary mapping command names to their info
    """
    # Import loader to get registered commands
    try:
        from core.loader import KERNEL_LOADER
        
        commands = {}
        
        # Get commands from loader
        if hasattr(KERNEL_LOADER, 'commands'):
            for name, info in KERNEL_LOADER.commands.items():
                if isinstance(info, dict):
                    commands[name] = {
                        "name": name,
                        "description": info.get("description", "No description"),
                        "plugin": info.get("plugin", name),
                        "version": info.get("version", "?"),
                    }
                elif hasattr(info, 'plugin_meta'):
                    meta = getattr(info, 'plugin_meta', {})
                    commands[name] = {
                        "name": name,
                        "description": meta.get("description", "No description"),
                        "plugin": name,
                        "version": meta.get("version", "?"),
                    }
        
        return commands
        
    except ImportError:
        return {}


def _get_builtin_help() -> Dict[str, Dict[str, Any]]:
    """
    Get help info for builtin commands.
    
    Returns:
        Dictionary of builtin commands
    """
    return {
        "help": {
            "name": "help",
            "description": "Show help information for commands",
            "category": "system",
            "usage": "help [command]",
            "examples": ["help", "help echo", "help status"],
        },
        "exit": {
            "name": "exit",
            "description": "Exit the CLI",
            "category": "system",
            "usage": "exit",
            "examples": ["exit", "quit"],
        },
        "clear": {
            "name": "clear",
            "description": "Clear the terminal screen",
            "category": "system",
            "usage": "clear",
            "examples": ["clear"],
        },
        "history": {
            "name": "history",
            "description": "Show command history",
            "category": "system",
            "usage": "history [limit]",
            "examples": ["history", "history 20"],
        },
    }


def _build_full_help() -> Dict[str, Dict[str, Any]]:
    """
    Build complete help information.
    
    Returns:
        Dictionary of all commands with full info
    """
    help_info = _get_builtin_help()
    
    # Add plugin commands
    commands = _get_command_info()
    for name, info in commands.items():
        if name not in help_info:
            # Try to determine category from name
            category = "tools"
            if name in ("echo",):
                category = "tools"
            elif name in ("net",):
                category = "network"
            elif name in ("vault", "file_manager"):
                category = "storage"
            elif name in ("trap",):
                category = "security"
            elif name in ("status",):
                category = "system"
            elif name in ("calc", "game"):
                category = "fun"
            
            help_info[name] = {
                "name": info.get("name", name),
                "description": info.get("description", "No description"),
                "category": category,
                "version": info.get("version", "?"),
            }
    
    return help_info


def _format_command_list(commands: Dict[str, Dict[str, Any]], category: Optional[str] = None) -> str:
    """
    Format command list for display.
    
    Args:
        commands: Dictionary of commands
        category: Optional category filter
    
    Returns:
        Formatted string
    """
    lines = []
    
    if category:
        cat_name = CATEGORIES.get(category, category.title())
        lines.append(f"\n{'='*60}")
        lines.append(f"  {cat_name}")
        lines.append(f"{'='*60}\n")
        
        filtered = {k: v for k, v in commands.items() if v.get("category") == category}
    else:
        lines.append(f"\n{'='*60}")
        lines.append(f"  Arch-PyCLI Command Reference")
        lines.append(f"{'='*60}\n")
        filtered = commands
    
    if not filtered:
        lines.append("  No commands found.")
        return "\n".join(lines)
    
    # Sort by name
    for name in sorted(filtered.keys()):
        info = filtered[name]
        desc = info.get("description", "No description")
        
        # Truncate long descriptions
        if len(desc) > 50:
            desc = desc[:47] + "..."
        
        lines.append(f"  {name:<15} {desc}")
    
    return "\n".join(lines)


def _format_command_detail(name: str, info: Dict[str, Any]) -> str:
    """
    Format detailed help for a command.
    
    Args:
        name: Command name
        info: Command info dictionary
    
    Returns:
        Formatted detail string
    """
    lines = []
    
    lines.append(f"\n{'─'*60}")
    lines.append(f"  Command: {name}")
    lines.append(f"{'─'*60}\n")
    
    lines.append(f"  Description:")
    lines.append(f"    {info.get('description', 'No description')}\n")
    
    if "usage" in info:
        lines.append(f"  Usage:")
        lines.append(f"    {info['usage']}\n")
    
    if "examples" in info:
        lines.append(f"  Examples:")
        for ex in info["examples"]:
            lines.append(f"    {ex}")
        lines.append("")
    
    if "version" in info:
        lines.append(f"  Version: {info['version']}")
    
    if "category" in info:
        cat = info["category"]
        cat_name = CATEGORIES.get(cat, cat.title())
        lines.append(f"  Category: {cat_name}")
    
    lines.append(f"\n{'─'*60}")
    
    return "\n".join(lines)


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "help",
    "description": "Show help information for commands.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "help [command|category]",
    "examples": [
        "help",
        "help echo",
        "help system",
        "help --list"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Help plugin execution function.
    
    Provides help for commands:
        - help: Show all commands
        - help <command>: Show detailed help for command
        - help <category>: Show commands in category
    
    Categories: system, security, network, storage, tools, fun
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments
    
    Returns:
        Help information string
    
    Raises:
        RuntimeError: If health context is invalid
    """
    # =====================================================================
    # CONTEXT VALIDATION
    # =====================================================================
    
    _ensure_health(context)
    
    # No args - show general help
    if not args:
        return _show_general_help()
    
    # =====================================================================
    # PARSE ARGUMENTS
    # =====================================================================
    
    cmd: str = str(args[0]).lower().strip()
    cmd_args: tuple = args[1:]
    
    _debug_log("Help for: %s", cmd)
    
    # =====================================================================
    # HANDLE FLAGS
    # =====================================================================
    
    if cmd in ("--list", "-l", "list", "all"):
        return _show_all_commands()
    
    if cmd in ("--categories", "cats", "categories"):
        return _show_categories()
    
    if cmd in ("--search", "-s", "search"):
        if cmd_args:
            return _search_commands(str(cmd_args[0]))
        return "ERR_USAGE: help search <pattern>"
    
    # =====================================================================
    # HANDLE CATEGORIES
    # =====================================================================
    
    if cmd in CATEGORIES:
        commands = _build_full_help()
        return _format_command_list(commands, category=cmd)
    
    # =====================================================================
    # HANDLE SPECIFIC COMMAND
    # =====================================================================
    
    commands = _build_full_help()
    
    # Check if command exists
    if cmd in commands:
        return _format_command_detail(cmd, commands[cmd])
    
    # Fuzzy search
    matches = [k for k in commands.keys() if cmd in k.lower()]
    
    if matches:
        if len(matches) == 1:
            return _format_command_detail(matches[0], commands[matches[0]])
        
        lines = [f"\nDid you mean one of these?\n"]
        for m in matches[:5]:
            lines.append(f"  • {m}: {commands[m].get('description', '')[:50]}")
        return "\n".join(lines)
    
    # Not found
    return f"ERR_COMMAND_NOT_FOUND: {cmd}\nType 'help' to see all available commands."


def _show_general_help() -> str:
    """Show general help."""
    commands = _build_full_help()
    
    # Group by category
    lines = []
    
    lines.append(f"""
╔══════════════════════════════════════════════════════════════╗
║                    Arch-PyCLI Help                          ║
╠══════════════════════════════════════════════════════════════╣
║  Type 'help <command>' for detailed info                   ║
║  Type 'help <category>' for commands in a category         ║
║  Type 'help --list' for a list of all commands             ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Show categories
    lines.append("Categories:")
    for key, name in CATEGORIES.items():
        count = sum(1 for c in commands.values() if c.get("category") == key)
        lines.append(f"  {name:<20} ({count} commands)")
    
    lines.append("")
    lines.append("Quick Commands:")
    
    # Show a few key commands
    key_commands = ["help", "echo", "status", "net", "vault", "calc", "game"]
    for cmd_name in key_commands:
        if cmd_name in commands:
            desc = commands[cmd_name].get("description", "")[:45]
            lines.append(f"  {cmd_name:<12} {desc}")
    
    lines.append("")
    lines.append("Type 'help --list' for all commands.")
    
    return "\n".join(lines)


def _show_all_commands() -> str:
    """Show all commands."""
    commands = _build_full_help()
    
    lines = [f"\n{'='*60}"]
    lines.append(f"  All Available Commands ({len(commands)} total)")
    lines.append(f"{'='*60}\n")
    
    for name in sorted(commands.keys()):
        info = commands[name]
        desc = info.get("description", "No description")
        if len(desc) > 45:
            desc = desc[:42] + "..."
        
        cat = info.get("category", "?")
        cat_name = CATEGORIES.get(cat, cat)
        
        lines.append(f"  {name:<14} {desc:<45} [{cat_name}]")
    
    lines.append(f"\n{'='*60}")
    lines.append(f"Total: {len(commands)} commands")
    lines.append(f"{'='*60}")
    
    return "\n".join(lines)


def _show_categories() -> str:
    """Show all categories."""
    commands = _build_full_help()
    
    lines = [f"\n{'='*60}"]
    lines.append(f"  Command Categories")
    lines.append(f"{'='*60}\n")
    
    for key, name in CATEGORIES.items():
        count = sum(1 for c in commands.values() if c.get("category") == key)
        lines.append(f"  {name}:")
        lines.append(f"    {count} command{'s' if count != 1 else ''}")
        
        # List commands in category
        cat_commands = [k for k, v in commands.items() if v.get("category") == key]
        if cat_commands:
            lines.append(f"    Commands: {', '.join(sorted(cat_commands))}")
        lines.append("")
    
    lines.append(f"{'='*60}")
    
    return "\n".join(lines)


def _search_commands(pattern: str) -> str:
    """Search for commands matching a pattern."""
    commands = _build_full_help()
    
    pattern_lower = pattern.lower()
    matches = []
    
    for name, info in commands.items():
        # Search in name and description
        if (pattern_lower in name.lower() or
            pattern_lower in info.get("description", "").lower()):
            matches.append((name, info))
    
    if not matches:
        return f"No commands found matching '{pattern}'"
    
    lines = [f"\nSearch results for '{pattern}' ({len(matches)} found):\n"]
    
    for name, info in sorted(matches, key=lambda x: x[0]):
        desc = info.get("description", "No description")
        lines.append(f"  {name}: {desc[:50]}")
    
    return "\n".join(lines)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
