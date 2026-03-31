"""
Arch-PyCLI Main Entry Point.

This is the main entry point for the Arch-PyCLI framework, providing an
interactive command-line interface with plugin-based command execution and
AI chatbot integration.

Features:
- Interactive CLI with command dispatch
- Plugin-based architecture
- Network node support
- AI chatbot integration (llama.cpp compatible)
- Secure startup sequence
- Graceful shutdown handling
- Comprehensive error handling
- Command similarity detection for AI vs command disambiguation

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional

# Import core modules
from core.config import PyArchConfig, setup_logger
from core.hal import HAL
from core.loader import KERNEL_LOADER
from core.network import DistributedNode
from core.security import SEC_KERNEL

# Import network module for global node access
import core.network as core_network

# Import AI module
from core.ai import (
    AIClient,
    AIResponse,
    get_ai_client,
    find_similar_commands,
    calculate_similarity,
    is_command_like,
    Message,
    DEFAULT_HOST as AI_HOST,
    DEFAULT_PORT as AI_PORT,
)


# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION: str = "0.1.0-alpha (Pseudo-Arch)"
SHUTDOWN_TIMEOUT: float = 5.0  # Seconds to wait for graceful shutdown
COMMAND_SIMILARITY_THRESHOLD: float = 0.8  # 80% similarity threshold


# =============================================================================
# MAIN KERNEL CLASS
# =============================================================================

class ArchKernel:
    """
    Main kernel class for Arch-PyCLI.
    
    This class orchestrates the startup, CLI loop, and shutdown sequence.
    
    Attributes:
        is_running: Whether the kernel is currently running
        version: Version string
        config: Configuration object
        logger: Logger instance
        ai_client: AI client for chatbot functionality
        chat_history: Chat history for context
    """
    
    def __init__(self, config: Optional[PyArchConfig] = None) -> None:
        """
        Initialize the kernel.
        
        Args:
            config: Optional configuration object
        """
        self.is_running: bool = False
        self.version: str = VERSION
        self.config: PyArchConfig = config or PyArchConfig.from_env(
            node_id=f"kernel_{int(time.time())}"
        )
        self.logger: logging.Logger = setup_logger(self.config.node_id)
        self._shutdown_requested: bool = False
        
        # AI chatbot settings
        self.ai_enabled: bool = False
        self.ai_client: Optional[AIClient] = None
        self.chat_history: List[Message] = []
        self.ai_host: str = AI_HOST
        self.ai_port: int = AI_PORT
        
        # System prompt for AI
        self.ai_system_prompt: str = """You are ArchBot, a helpful AI assistant running on the Arch-PyCLI framework.
You help users with various tasks including:
- Answering questions
- Having conversations
- Providing explanations
- Helping with problems

Keep responses concise and friendly. If asked about system commands, you can suggest using the 'help' command to see available commands."""
        
        self.logger.info(
            "[KERNEL] Arch-PyCLI v%s initializing...",
            self.version
        )
    
    def _init_ai(self) -> bool:
        """
        Initialize AI client.
        
        Returns:
            True if AI is available, False otherwise
        """
        try:
            self.ai_client = get_ai_client(
                host=self.ai_host,
                port=self.ai_port
            )
            
            # Test connection
            success, msg = self.ai_client.test_connection()
            
            if success:
                self.ai_enabled = True
                self.logger.info("[KERNEL] AI enabled: %s", msg)
                print(f"\n🤖 AI: {msg}")
                return True
            else:
                self.logger.warning("[KERNEL] AI unavailable: %s", msg)
                return False
                
        except Exception as e:
            self.logger.warning("[KERNEL] AI initialization failed: %s", e)
            return False
    
    def _get_available_commands(self) -> List[str]:
        """
        Get list of available command names.
        
        Returns:
            List of command names
        """
        try:
            return KERNEL_LOADER.get_command_names()
        except Exception:
            return []
    
    def _is_command_input(self, user_input: str) -> bool:
        """
        Check if input looks like a command.
        
        A command is identified by:
        1. Starting with a known command name
        2. Being similar (>80%) to a known command name
        
        Args:
            user_input: User input string
        
        Returns:
            True if input is a command
        """
        if not user_input:
            return False
        
        stripped = user_input.strip()
        
        # Get first word as potential command
        parts = stripped.split()
        if not parts:
            return False
        
        first_word = parts[0].lower()
        commands = self._get_available_commands()
        
        # Check if exact match
        if first_word in commands:
            return True
        
        # Check similarity to any command
        for cmd in commands:
            if is_command_like(first_word, cmd, threshold=COMMAND_SIMILARITY_THRESHOLD):
                return True
        
        return False
    
    def _find_similar_command_suggestion(self, user_input: str) -> Optional[str]:
        """
        Find a similar command suggestion if input is not clearly a command.
        
        Args:
            user_input: User input string
        
        Returns:
            Suggested command or None
        """
        stripped = user_input.strip()
        parts = stripped.split()
        
        if not parts:
            return None
        
        first_word = parts[0].lower()
        commands = self._get_available_commands()
        
        # Find most similar command
        matches = find_similar_commands(
            first_word,
            commands,
            threshold=0.5  # Lower threshold for suggestions
        )
        
        if matches and matches[0][1] >= 0.6:  # 60% similarity for suggestion
            return matches[0][0]
        
        return None
    
    def _handle_ai_chat(self, user_input: str) -> str:
        """
        Handle AI chatbot interaction.
        
        Args:
            user_input: User message
        
        Returns:
            AI response string
        """
        if not self.ai_enabled or self.ai_client is None:
            return "AI is not available. Please start an LLM server on localhost:8080"
        
        try:
            # Add user message to history
            self.chat_history.append(Message(
                role="user",
                content=user_input
            ))
            
            # Get AI response
            response = self.ai_client.chat(
                message=user_input,
                system_prompt=self.ai_system_prompt,
                history=self.chat_history[-10:]  # Keep last 10 messages for context
            )
            
            if response.error:
                return f"AI Error: {response.error}"
            
            # Add assistant response to history
            self.chat_history.append(Message(
                role="assistant",
                content=response.content
            ))
            
            # Trim history if too long
            if len(self.chat_history) > 50:
                self.chat_history = self.chat_history[-50:]
            
            return response.content
            
        except Exception as e:
            self.logger.exception("[KERNEL] AI chat failed")
            return f"AI Error: {e}"
    
    def boot_sequence(self) -> None:
        """
        Execute the boot sequence.
        
        This performs system initialization including:
        1. Hardware validation (HAL health check)
        2. Plugin loading
        3. Network node setup
        4. AI initialization (optional)
        
        Raises:
            RuntimeError: If boot fails
        """
        self.logger.info("[KERNEL] Starting boot sequence...")
        
        try:
            # =================================================================
            # STEP 1: Hardware Validation
            # =================================================================
            self.logger.info("[KERNEL] Phase 1: Hardware validation")
            
            try:
                health_report: Dict[str, Any] = HAL.get_health_report(force_refresh=True)
                
                self.logger.info(
                    "[KERNEL] HAL: %s cores | memory %.1f%% | latency %.6fs",
                    HAL.CPU_CORES,
                    health_report.get('memory_pressure', 0),
                    health_report.get('internal_latency', 0)
                )
                
                # Check for critical hardware state
                if health_report.get('status') == "CRITICAL":
                    self.logger.error("[KERNEL] Hardware failure detected on boot!")
                    raise RuntimeError("Hardware Failure on Boot")
                    
            except Exception as e:
                self.logger.warning(
                    "[KERNEL] HAL health check warning: %s",
                    e
                )
                # Continue boot even if HAL fails - we have fallbacks
            
            # =================================================================
            # STEP 2: Plugin Loading
            # =================================================================
            self.logger.info("[KERNEL] Phase 2: Plugin loading")
            
            try:
                loaded_count: int = KERNEL_LOADER.bootstrap()
                
                # Verify loader is properly initialized
                if not isinstance(KERNEL_LOADER.commands, dict):
                    raise RuntimeError("Loader Initialization Failure")
                
                commands: List[str] = KERNEL_LOADER.get_command_names()
                self.logger.info(
                    "[KERNEL] Commands Loaded: %s",
                    commands
                )
                
            except Exception as e:
                self.logger.error("[KERNEL] Plugin loading failed: %s", e)
                raise RuntimeError(f"Plugin Loading Failure: {e}") from e
            
            # =================================================================
            # STEP 3: Network Setup
            # =================================================================
            self.logger.info("[KERNEL] Phase 3: Network initialization")
            
            try:
                node_kwargs: Dict[str, Any] = {
                    'host': self.config.host,
                    'port': self.config.port,
                    'use_tls': self.config.network_use_tls,
                    'certfile': self.config.network_certfile,
                    'keyfile': self.config.network_keyfile,
                    'cafile': self.config.network_cafile,
                    'require_client_cert': self.config.network_require_client_cert,
                    'verify_server': self.config.network_verify_server,
                }
                
                # Create distributed node
                node: DistributedNode = DistributedNode(**node_kwargs)
                
                # Replace module global so plugins can access it
                core_network.NETWORK_NODE = node
                
                # Start the node
                node.start_node()
                
                self.logger.info(
                    "[KERNEL] Node ID: %s Active on %s:%d",
                    node.node_id,
                    self.config.host,
                    self.config.port
                )
                
            except Exception as e:
                self.logger.warning(
                    "[KERNEL] Network initialization failed: %s",
                    e
                )
                self.logger.warning("[KERNEL] Continuing in local-only mode")
            
            # =================================================================
            # STEP 4: AI Setup (Optional)
            # =================================================================
            self.logger.info("[KERNEL] Phase 4: AI initialization")
            
            if self.ai_enabled:
                self._init_ai()
            
            # =================================================================
            # BOOT COMPLETE
            # =================================================================
            self.is_running = True
            self.logger.info(
                "[KERNEL] Boot sequence complete. System ready."
            )
            
        except Exception as e:
            self.logger.exception("[KERNEL] Boot sequence failed: %s", e)
            sys.exit(1)
    
    def run_cli(self) -> None:
        """
        Run the interactive CLI loop.
        
        This loop:
        1. Displays a prompt
        2. Reads user input
        3. Dispatches commands or AI chat
        4. Handles errors
        """
        self.logger.info(
            "[KERNEL] Entering interactive CLI; type 'help' or 'exit'"
        )
        
        # Print welcome banner
        ai_status = "🤖 AI Ready" if self.ai_enabled else "⚙️ CLI Mode"
        print(f"\n{'='*50}")
        print(f"  Arch-PyCLI v{self.version}")
        print(f"  {ai_status}")
        print(f"{'='*50}")
        print("\nType commands or chat with AI!")
        print("Type 'ai on/off' to toggle AI mode\n")
        
        while self.is_running and not self._shutdown_requested:
            try:
                # =================================================================
                # PREPARE PROMPT
                # =================================================================
                
                # Get current health for prompt
                health: Dict[str, Any] = HAL.get_health_report()
                
                # Get node info
                node: Optional[Any] = getattr(core_network, 'NETWORK_NODE', None)
                node_id: str = getattr(node, 'node_id', 'unknown')
                
                # Calculate memory pressure
                try:
                    mem_pressure: int = int(health.get('memory_pressure', 0))
                except (TypeError, ValueError):
                    mem_pressure = 0
                
                # Build prompt
                ai_indicator = "🤖" if self.ai_enabled else "💬"
                prompt: str = f"({ai_indicator}@{node_id})-[{mem_pressure}%] # "
                
                # =================================================================
                # READ INPUT
                # =================================================================
                
                sys.stdout.write(prompt)
                sys.stdout.flush()
                line: str = sys.stdin.readline()
                
                # Handle EOF
                if not line:
                    self.logger.info("[KERNEL] EOF received, shutting down")
                    break
                
                # Parse command
                cmd_input: str = line.strip()
                
                # Skip empty input
                if not cmd_input:
                    continue
                
                # Handle exit commands
                if cmd_input.lower() in ('exit', 'quit', 'shutdown', 'halt'):
                    self.logger.info(
                        "[KERNEL] Exit command received: %s",
                        cmd_input
                    )
                    self.is_running = False
                    break
                
                # Handle AI toggle commands
                if cmd_input.lower() == "ai on":
                    if not self.ai_enabled:
                        if self._init_ai():
                            print("🤖 AI enabled!")
                        else:
                            print("⚠️ AI not available. Start an LLM server on localhost:8080")
                    else:
                        print("🤖 AI is already enabled!")
                    continue
                
                if cmd_input.lower() == "ai off":
                    self.ai_enabled = False
                    print("⚙️ AI disabled. CLI mode only.")
                    continue
                
                # Handle AI toggle with host/port
                if cmd_input.lower().startswith("ai "):
                    parts = cmd_input.split()
                    if len(parts) >= 3:
                        try:
                            self.ai_host = parts[1]
                            self.ai_port = int(parts[2])
                            self.ai_enabled = False  # Reset to force reinit
                            if self._init_ai():
                                print(f"🤖 AI enabled on {self.ai_host}:{self.ai_port}!")
                            else:
                                print(f"⚠️ AI not available on {self.ai_host}:{self.ai_port}")
                        except ValueError:
                            print("Usage: ai <host> <port>")
                    continue
                
                # =================================================================
                # DISPATCH COMMAND
                # =================================================================
                
                # Parse command
                parts: List[str] = cmd_input.split()
                if not parts:
                    continue
                
                cmd_name: str = parts[0]
                args: List[str] = parts[1:]
                
                # Validate command name (alphanumeric + underscore only)
                if not cmd_name.replace('_', '').isalnum():
                    # Not a valid command name - try AI if enabled
                    if self.ai_enabled:
                        response = self._handle_ai_chat(cmd_input)
                        print(f"\n{response}\n")
                    else:
                        print("AI features unavailable. Type 'help' for available commands.")
                    continue
                
                # Check if this looks like a chat message (AI mode only)
                if self.ai_enabled and not self._is_command_input(cmd_input):
                    # This looks like natural language - use AI
                    response = self._handle_ai_chat(cmd_input)
                    print(f"\n{response}\n")
                    
                    # Show command suggestion if similar
                    suggestion = self._find_similar_command_suggestion(cmd_input)
                    if suggestion:
                        print(f"(If you meant the '{suggestion}' command, type it directly)\n")
                    continue
                
                # Build execution context
                context: Dict[str, Any] = {
                    "health": health,
                    "user": "root",
                    "node_id": node_id,
                }
                
                # Dispatch command
                result: Any = KERNEL_LOADER.dispatch(cmd_name, context, *args)
                
                # Print result
                print(f"{result}\n")
                
            except KeyboardInterrupt:
                self.logger.info("[KERNEL] Interrupt received")
                print("\nUse 'exit' to shutdown cleanly")
                continue
                
            except Exception as e:
                self.logger.exception("[KERNEL] Runtime error during CLI")
                print(f"Runtime Error: {e}")
        
        # Shutdown
        self.shutdown()
    
    def shutdown(self) -> None:
        """
        Perform graceful shutdown.
        
        This method:
        1. Stops the network node
        2. Wipes sensitive data
        3. Logs shutdown completion
        """
        self.logger.info("[KERNEL] Shutdown initiated...")
        
        # Stop network node
        try:
            node: Optional[Any] = getattr(core_network, 'NETWORK_NODE', None)
            if node is not None:
                try:
                    if hasattr(node, 'stop'):
                        node.stop(timeout=SHUTDOWN_TIMEOUT)
                    self.logger.info("[KERNEL] Network node stopped")
                except Exception as e:
                    self.logger.warning(
                        "[KERNEL] Failed to stop network node: %s",
                        e
                    )
        except Exception:
            pass
        
        # Wipe master key
        try:
            if SEC_KERNEL is not None:
                if hasattr(SEC_KERNEL, '_master_key'):
                    master_key = getattr(SEC_KERNEL, '_master_key', b'')
                    if master_key:
                        try:
                            SEC_KERNEL._wipe_memory(master_key)
                            self.logger.info("[KERNEL] Master key wiped")
                        except Exception:
                            pass
        except Exception:
            pass
        
        self.logger.info("[KERNEL] System halted")
        sys.exit(0)


# =============================================================================
# ARGUMENT PARSING
# =============================================================================

def _parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Arch-PyCLI - Python-based command-line framework with AI chatbot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Start with defaults
  python main.py --host 0.0.0.0         # Listen on all interfaces
  python main.py --port 9001              # Use custom port
  python main.py --tls --certfile cert.pem # Enable TLS
  python main.py --ai-host localhost:8080 # Connect to AI server
  python main.py --debug                   # Enable debug logging
        """
    )
    
    # Network options
    network_group = parser.add_argument_group('Network Options')
    network_group.add_argument(
        "--host",
        help="Listen host (default: 127.0.0.1)"
    )
    network_group.add_argument(
        "--port",
        type=int,
        help="Listen port (default: 8888)"
    )
    
    # AI options
    ai_group = parser.add_argument_group('AI Options')
    ai_group.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI chatbot (requires LLM server)"
    )
    ai_group.add_argument(
        "--ai-host",
        help="AI server host (default: localhost)"
    )
    ai_group.add_argument(
        "--ai-port",
        type=int,
        help="AI server port (default: 8080)"
    )
    
    # TLS options
    tls_group = parser.add_argument_group('TLS Options')
    tls_group.add_argument(
        "--tls",
        action="store_true",
        help="Enable TLS for network"
    )
    tls_group.add_argument(
        "--certfile",
        help="TLS certificate file path"
    )
    tls_group.add_argument(
        "--keyfile",
        help="TLS private key file path"
    )
    tls_group.add_argument(
        "--cafile",
        help="TLS CA certificate file path"
    )
    tls_group.add_argument(
        "--no-verify",
        action="store_true",
        help="Do not verify peer certificates"
    )
    
    # Debug options
    debug_group = parser.add_argument_group('Debug Options')
    debug_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    debug_group.add_argument(
        "--node-id",
        help="Custom node ID"
    )
    
    return parser.parse_args()


# =============================================================================
# SIGNAL HANDLING
# =============================================================================

def _handle_signal(signum: int, frame: Any) -> None:
    """
    Handle termination signals.
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    signal_name: str = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
    
    print(f"\n[SIGNAL] Received {signal_name}, initiating shutdown...")
    
    if 'os_kernel' in globals():
        os_kernel.logger.info("[SIGNAL] Signal %s received", signal_name)
        os_kernel.shutdown()


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Parse arguments
    args: argparse.Namespace = _parse_args()
    
    # Initialize kernel with configuration
    os_kernel: ArchKernel = ArchKernel()
    
    # Apply CLI argument overrides to config
    try:
        if args.host:
            os_kernel.config.host = args.host
        
        if args.port:
            if not (1 <= args.port <= 65535):
                print(f"Error: Port must be between 1 and 65535")
                sys.exit(1)
            os_kernel.config.port = args.port
        
        if args.tls:
            os_kernel.config.network_use_tls = True
        
        if args.certfile:
            os_kernel.config.network_certfile = args.certfile
        
        if args.keyfile:
            os_kernel.config.network_keyfile = args.keyfile
        
        if args.cafile:
            os_kernel.config.network_cafile = args.cafile
        
        if args.no_verify:
            os_kernel.config.network_verify_server = False
        
        if args.node_id:
            os_kernel.config.node_id = args.node_id
        
        # AI options
        if args.ai:
            os_kernel.ai_enabled = True
        
        if args.ai_host:
            os_kernel.ai_host = args.ai_host
        
        if args.ai_port:
            os_kernel.ai_port = args.ai_port
        
    except Exception as e:
        os_kernel.logger.exception("[KERNEL] Failed to apply CLI overrides")
        print(f"Error applying configuration: {e}")
        sys.exit(1)
    
    # Setup signal handlers for graceful shutdown
    try:
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except (ValueError, OSError) as e:
        os_kernel.logger.warning(
            "[KERNEL] Signal handlers not available: %s",
            e
        )
    
    # Print startup banner
    print(f"\n{'='*50}")
    print(f"  Arch-PyCLI v{VERSION}")
    print(f"  Secure CLI Framework")
    print(f"{'='*50}\n")
    
    # Execute boot sequence
    os_kernel.boot_sequence()
    
    # Run CLI
    os_kernel.run_cli()
