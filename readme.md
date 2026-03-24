# Arch-PyCLI

## Overview

Arch-PyCLI is a Python-based command-line framework that implements a modular plugin system, an encrypted communication layer, and a basic security-oriented execution environment.

It is not an operating system. It is not a kernel in the traditional sense. It is a CLI framework with components structured to resemble kernel-like separation of concerns.

The project is experimental and intended for learning, prototyping, and exploration of system-like architecture patterns in Python.

## Features

- Interactive command-line interface
- Plugin-based command system
- Dynamic loading of Python modules from a plugins directory
- AES-GCM encryption for sensitive operations
- Token-based authentication for network execution
- TCP-based remote command execution
- Basic system monitoring via a hardware abstraction layer
- Separation of concerns across core modules

## Architecture

The system is organized into the following core components:

- Loader  
  Responsible for discovering and loading plugins at runtime. Maps plugin commands to callable functions.

- Security Kernel  
  Handles encryption, decryption, and token validation. Uses AES-GCM and PBKDF2 for key derivation.

- HAL (Hardware Abstraction Layer)  
  Collects system metrics such as CPU usage, memory usage, and system uptime using psutil.

- Network Node  
  Provides a TCP server that accepts encrypted requests, validates tokens, executes commands via the loader, and returns encrypted responses.

- Plugins  
  Independent Python modules that define executable commands. Each plugin exposes a standard interface expected by the loader.

## Installation

Requirements:
- Python 3.9+
- pip

## File Manager Plugin

A core-backed plugin exposes simple file operations to the CLI. The plugin entrypoint is `plugins/file_manager.py` and the core implementation is `core/file_manager.py`.

Basic usage via the interactive CLI (examples):

- List directory: `file_manager list [path]`
- Read file: `file_manager read <path>`
- Create file: `file_manager create <path> [content]`
- Write file: `file_manager write <path> <content>`
- Delete file: `file_manager delete <path> [-r|--recursive]`
- Rename: `file_manager rename <src> <dst>`
- Exists check: `file_manager exists <path>`

Notes:
- Operations are constrained to the project workspace root for safety.
- The plugin requires the runtime `context` (passed by the loader) which must include a `health` dict; the CLI automatically supplies this.
- Errors from filesystem operations are surfaced as runtime errors prefixed with `FM_ERROR:`.

## Quick Start

- Create a virtual environment and install dependencies (if any):

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt  # if you maintain dependencies
```

- Run the interactive kernel:

```bash
python main.py
```

You can pass CLI overrides for network/TLS settings:

```bash
python main.py --host 0.0.0.0 --port 9001 --tls --certfile ./cert.pem --keyfile ./key.pem
```

## Configuration (Environment Variables)

You can control runtime behavior via environment variables. Supported variables:

- `PYARCH_HOST` — listen host (default 127.0.0.1)
- `PYARCH_PORT` — listen port (default from config)
- `PYARCH_PLUGIN_DIR` — plugin folder
- `PYARCH_NETWORK_USE_TLS` — enable TLS (true/1/yes)
- `PYARCH_NETWORK_CERTFILE` — path to TLS certificate (PEM)
- `PYARCH_NETWORK_KEYFILE` — path to TLS private key (PEM)
- `PYARCH_NETWORK_CAFILE` — optional CA bundle for client verification
- `PYARCH_NETWORK_REQUIRE_CLIENT_CERT` — require client certs (true/1/yes)
- `PYARCH_NETWORK_VERIFY_SERVER` — client verifies server certs by default; set to false to disable

## TLS / Test Certificates

For local testing you can generate a self-signed certificate with OpenSSL:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

When using self-signed certs for local testing, set `PYARCH_NETWORK_VERIFY_SERVER=false` or pass `--no-verify` to `main.py` so the client does not reject the cert.

## Secure Storage

Sensitive files and plugin vault entries are stored encrypted under the hidden folder `.vault` in the repository root. Files are encrypted with AES-GCM and a KDF-bound master key.

APIs:
- `core/secure_store.py` — read/write/encrypted streaming helpers
- `core/security.py` — key derivation, AES-GCM helpers, token utilities

## Notes & Security

- The system uses AES-GCM for on-disk and in-flight payload encryption, and issues short-lived tokens for remote execution.
- For production or networked deployments, use valid CA-signed certificates and enable `require_client_cert` if mutual TLS is desired.
- Keep backups of your master key or use the provided `export_master_blob`/`import_master_blob` flows (see `core/security.py`) to avoid lockout if hardware changes.