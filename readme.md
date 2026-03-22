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
