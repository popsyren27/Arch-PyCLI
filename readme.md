# Arch-PyCLI

## Overview

Arch-PyCLI is a Python-based command-line framework that implements a modular plugin system, an encrypted communication layer, an AI chatbot integration, and a security-oriented execution environment.

**Important**: This is NOT an operating system. It is NOT a kernel in the traditional sense. It is a CLI framework with components structured to resemble kernel-like separation of concerns.

The project is experimental and intended for learning, prototyping, and exploration of system-like architecture patterns in Python.

---

## Features

### Core Architecture
- **Interactive Command-Line Interface** - User-friendly CLI with health-aware prompts
- **Plugin-Based Command System** - Dynamic loading of Python modules from a plugins directory
- **Thread-Safe Operations** - All modules use proper locking for concurrent access
- **Comprehensive Error Handling** - Fallback chains and graceful degradation

### Security
- **AES-GCM Encryption** - Industry-standard authenticated encryption for files and network
- **KDF Key Derivation** - Scrypt (PBKDF2 fallback) for master key generation
- **Token-Based Authentication** - Short-lived tokens with TTL and rate limiting
- **Memory Secure Wiping** - Attempts to minimize sensitive data lifetime in RAM
- **Path Traversal Prevention** - Storage paths validated to prevent escape

### Networking
- **TCP Distributed Node** - Node-to-node command routing with encrypted payloads
- **TLS/SSL Support** - Full mTLS capability with certificate verification
- **Connection Limits** - Configurable maximum concurrent connections
- **Idle Connection Cleanup** - Automatic timeout enforcement

### Storage
- **Encrypted File Storage** - AES-GCM encryption at rest in `.vault` directory
- **Atomic Write Operations** - Prevents corruption on crashes
- **Streaming Support** - Memory-efficient handling of large files
- **Thread-Safe Access** - File locking for concurrent operations

---

## Architecture

The system is organized into the following core components:

### Core Modules

| Module | Description |
|--------|-------------|
| `core/security.py` | Encryption, key management, token validation, rate limiting |
| `core/network.py` | TCP server, connection handling, remote command dispatch |
| `core/secure_store.py` | Encrypted file storage with atomic operations |
| `core/file_manager.py` | File operations wrapper (delegates to secure_store) |
| `core/loader.py` | Plugin discovery, validation, and command dispatch |
| `core/hal.py` | Hardware monitoring, health checks, caching |
| `core/config.py` | Configuration management with env var support |
| `core/session.py` | Session tracking, command history, timeout management |
| `core/ai.py` | AI chatbot integration with LLM servers (llama.cpp compatible) |

### Plugin System

| Plugin | Description |
|--------|-------------|
| `echo` | Text echoing with optional typing animation |
| `status` | System health and resource metrics |
| `net` | Token generation and remote command execution |
| `vault` | Secure key-value storage |
| `file_manager` | Directory listing and file operations |
| `calc` | Calculator with arithmetic, functions, unit conversions |
| `game` | Number guessing game with high scores and multiple difficulties |
| `help` | Help system with categories, search, and command details |

---

## Installation

### Requirements
- Python 3.9 or higher
- pip

### Dependencies

Install required packages:

```bash
pip install -r requirements.txt
```

**Core Dependencies:**
- `cryptography>=3.4` - For AES-GCM encryption and KDF
- `psutil>=5.8.0` - For hardware monitoring (optional but recommended)

**Optional Dependencies:**
- `keyring` - For OS keyring integration (optional)

---

## Quick Start

### Basic Usage

```bash
# Create virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate   # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run the interactive kernel
python main.py
```

### Command Line Options

```bash
# Listen on all interfaces
python main.py --host 0.0.0.0 --port 9001

# Enable TLS
python main.py --tls --certfile ./cert.pem --keyfile ./key.pem

# Custom node ID
python main.py --node-id my_custom_node

# Enable debug logging
python main.py --debug
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYARCH_HOST` | `127.0.0.1` | Listen host |
| `PYARCH_PORT` | `8888` | Listen port |
| `PYARCH_PLUGIN_DIR` | `plugins` | Plugin directory |
| `PYARCH_NETWORK_USE_TLS` | `false` | Enable TLS |
| `PYARCH_NETWORK_CERTFILE` | - | TLS certificate path |
| `PYARCH_NETWORK_KEYFILE` | - | TLS key path |
| `PYARCH_NETWORK_CAFILE` | - | CA certificate path |
| `PYARCH_NETWORK_REQUIRE_CLIENT_CERT` | `false` | Require client certs |
| `PYARCH_NETWORK_VERIFY_SERVER` | `true` | Verify server certs |

### Example: Docker Deployment

```bash
PYARCH_HOST=0.0.0.0 \
PYARCH_PORT=9001 \
PYARCH_NETWORK_USE_TLS=true \
PYARCH_NETWORK_CERTFILE=/certs/cert.pem \
PYARCH_NETWORK_KEYFILE=/certs/key.pem \
python main.py
```

---

## TLS / Certificates

For local testing, generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

**Important**: When using self-signed certs for local testing, set `PYARCH_NETWORK_VERIFY_SERVER=false` or pass `--no-verify` so the client does not reject the cert.

---

## Plugin Development

### Plugin Structure

```python
"""
My Custom Plugin for Arch-PyCLI.
"""

from typing import Any, Dict

# Plugin metadata (optional)
PLUGIN_META = {
    "name": "my_plugin",
    "description": "Description of what this plugin does",
    "version": "0.1.0",
    "author": "Your Name",
    "usage": "my_plugin [args]",
}

def execute(context: Dict[str, Any], *args) -> str:
    """
    Main plugin function.
    
    Args:
        context: Execution context with 'health' dict and metadata
        *args: Command arguments
    
    Returns:
        Result string
    """
    # Validate health context
    health = context.get("health", {})
    if health.get("status") == "CRITICAL":
        return "ERR_SYSTEM_INSTABILITY"
    
    # Process arguments
    message = " ".join(str(arg) for arg in args)
    
    return f"Result: {message}"
```

### Plugin Requirements

1. **File Name**: Must be `*.py` in the plugins directory
2. **Execute Function**: Must have `execute(context, *args)` function
3. **Signature**: First parameter must accept context dict

### Built-in Plugins

#### Echo Plugin
```bash
echo hello world
echo -t hello  # With typing animation
```

#### Status Plugin
```bash
status            # Full status
status health     # Health metrics
status memory     # Memory usage
status cpu       # CPU usage
```

#### Net Plugin
```bash
net auth                    # Generate access token
net send 127.0.0.1 9001 <token> echo hello  # Remote command
net send -a 127.0.0.1 9001 <token> status   # Async send
```

#### Vault Plugin
```bash
vault set api_key my_secret_value
vault get api_key
```

#### File Manager Plugin
```bash
file_manager list
file_manager read myfile.txt
file_manager write myfile.txt Hello World
file_manager create newfile.txt Content
file_manager delete myfile.txt
file_manager rename old.txt new.txt
file_manager exists myfile.txt
```

#### Calc Plugin
```bash
calc 2 + 2           # Basic arithmetic
calc sqrt(16)        # Square root
calc sin(45)         # Trigonometric functions
calc 5!              # Factorial
calc 10 % 3          # Modulo
calc convert 100 km to mi  # Unit conversion
calc m+ 42           # Memory operations
calc history         # View calculation history
```

#### Game Plugin
```bash
game start          # Start new game (medium difficulty)
game start hard    # Start with hard difficulty
game guess 50      # Make a guess
game hint          # Get a hint (costs 1 attempt)
game scores        # View high scores
```

#### Help Plugin
```bash
help               # Show general help
help echo          # Show help for specific command
help --list        # List all commands
help --categories  # Show all categories
help network       # Commands in a category
help --search calc # Search for commands
```

---

## AI Chatbot

Arch-PyCLI includes AI chatbot integration with local LLM servers (like llama.cpp).

### Setup
1. Start your LLM server (e.g., llama.cpp) on localhost:8080
2. Enable AI with the `ai on` command

### Commands
```bash
ai on              # Enable AI chatbot
ai off             # Disable AI chatbot (CLI mode only)
ai localhost 8080  # Connect to different AI server
```

### Usage
When AI is enabled:
- Type naturally to chat with the AI
- Commands are automatically detected (80% similarity threshold)
- Similar commands are suggested if input looks like a command

### Example
```bash
(🤖@kernel_xxx)-[0%] # Hello, how are you?
AI: I'm doing well, thanks for asking! How can I help you today?

(🤖@kernel_xxx)-[0%] # What time is it?
AI: I don't have access to real-time clock data, but you can use the 
'status' command to see system information.

(🤖@kernel_xxx)-[0%] # stat
status: System running normally | CPU: 4 cores | Memory: 45%
```

---

## Security Notes

### Key Management
- Master key is derived using Scrypt (PBKDF2 fallback) from passphrase or hardware fingerprint
- Keys are NEVER stored in plaintext
- Memory wiping attempts to minimize key lifetime in RAM

### Token Security
- Tokens are short-lived (default: 15 minutes)
- Rate limiting prevents token generation abuse (50/minute max)
- Automatic token cleanup prevents memory growth

### Network Security
- All network payloads are AES-GCM encrypted
- TLS provides transport layer security
- Connection limits prevent resource exhaustion

### Production Recommendations
1. Use valid CA-signed certificates
2. Enable `require_client_cert` for mutual TLS
3. Keep backups of your master key export
4. Use the OS keyring for passphrase storage when possible
5. Monitor token generation rate

---

## Troubleshooting

### "psutil not available" Warning
This is normal if psutil is not installed. The system will use fallback values for hardware metrics.

### "File logging unavailable" Warning
This occurs in read-only filesystems. Logging will continue to stdout.

### Connection Refused Errors
- Ensure the target node is running
- Check that the port is correct
- Verify the token is valid and not expired

### Plugin Load Failures
- Check that plugin files are valid Python
- Verify the `execute` function signature
- Enable debug mode (`--debug`) for detailed logs

---

## File Structure

```
Arch-PyCLI/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── readme.md              # This file
├── .gitignore            # Git ignore rules
├── core/
│   ├── config.py         # Configuration management
│   ├── file_manager.py   # File operations wrapper
│   ├── hal.py           # Hardware abstraction layer
│   ├── loader.py        # Plugin loader
│   ├── network.py       # Network node
│   ├── secure_store.py  # Encrypted storage
│   ├── security.py      # Security kernel
│   └── session.py       # Session management
├── plugins/
│   ├── calc.py         # Calculator plugin
│   ├── echo.py         # Echo plugin
│   ├── file_manager.py  # File manager plugin
│   ├── game.py         # Game plugin
│   ├── help.py         # Help plugin
│   ├── net.py         # Network plugin
│   ├── status.py       # Status plugin
│   ├── trap.py         # Trap plugin (security)
│   └── vault.py        # Vault plugin
└── .vault/              # Encrypted storage directory (created at runtime)
```

---

## Development

### Running Tests
```bash
# Coming soon
pytest tests/
```

### Code Style
- Follow PEP 8 guidelines
- Use type annotations for all public functions
- Add docstrings for all public APIs
- Enable debug mode to verify logging

---

## License

This project is for educational and experimental purposes.

---

## Credits

Developed as a learning project for exploring system-like architecture patterns in Python.
