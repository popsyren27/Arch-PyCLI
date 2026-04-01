"""
AI Module for Arch-PyCLI.

This module provides integration with local LLM servers (like llama.cpp).

Features:
- HTTP API client for LLM inference
- Async request support
- Streaming response support
- Conversation context
- Configurable endpoint

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class AIError(Exception):
    """Base exception for AI errors."""
    pass


class AIConnectionError(AIError):
    """Raised when connection to LLM server fails."""
    pass


class AIInferenceError(AIError):
    """Raised when inference fails."""
    pass


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_HOST: str = "localhost"
DEFAULT_PORT: int = 8080
DEFAULT_TIMEOUT: float = 60.0
DEFAULT_MODEL: str = ""
DEFAULT_MAX_TOKENS: int = 4096
DEFAULT_TEMPERATURE: float = 0.7
DEFAULT_STREAM: bool = False


# =============================================================================
# SETUP LOGGING
# =============================================================================

_logger: logging.Logger = logging.getLogger("AI_MODULE")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[AI_MODULE] AI module initialized")


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Message:
    """Represents a chat message."""
    role: str  # "user", "assistant", "system"
    content: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class AIResponse:
    """Represents an AI response."""
    content: str
    model: str
    tokens: int
    duration_ms: float
    done: bool = True
    error: Optional[str] = None


# =============================================================================
# SIMILARITY HELPER
# =============================================================================

def calculate_similarity(str1: str, str2: str) -> float:
    """
    Calculate similarity between two strings using SequenceMatcher.
    
    Args:
        str1: First string
        str2: Second string
    
    Returns:
        Similarity ratio between 0.0 and 1.0
    """
    return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()


def is_command_like(input_str: str, command: str, threshold: float = 0.8) -> bool:
    """
    Check if input string is similar to a command.
    
    Args:
        input_str: Input string to check
        command: Command to compare against
        threshold: Similarity threshold (default: 0.8 = 80%)
    
    Returns:
        True if input is similar to command
    """
    similarity = calculate_similarity(input_str, command)
    return similarity >= threshold


def find_similar_commands(input_str: str, commands: List[str], threshold: float = 0.8) -> List[tuple]:
    """
    Find commands similar to input string.
    
    Args:
        input_str: Input string to check
        commands: List of available commands
        threshold: Similarity threshold
    
    Returns:
        List of (command, similarity) tuples sorted by similarity
    """
    results = []
    for cmd in commands:
        sim = calculate_similarity(input_str, cmd)
        if sim >= threshold * 0.5:  # Include even lower matches for suggestions
            results.append((cmd, sim))
    
    return sorted(results, key=lambda x: x[1], reverse=True)


# =============================================================================
# AI CLIENT CLASS
# =============================================================================

class AIClient:
    """
    Client for local LLM inference server.
    
    Provides chat completion via HTTP API compatible with OpenAI-style endpoints.
    
    Attributes:
        host: Server host
        port: Server port
        model: Model name
        timeout: Request timeout in seconds
    
    Example:
        >>> client = AIClient(host="localhost", port=8080)
        >>> response = client.chat("Hello, how are you?")
        >>> print(response.content)
    """
    
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE
    ) -> None:
        """
        Initialize AI client.
        
        Args:
            host: Server host (default: localhost)
            port: Server port (default: 8080)
            model: Model name (empty for default)
            timeout: Request timeout in seconds
            max_tokens: Maximum tokens to generate
            temperature: Generation temperature
        """
        self.host = host
        self.port = port
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature
        
        self._url = f"http://{host}:{port}/v1/chat/completions"
        self._session: Optional[Any] = None
        
        _logger.info(
            "[AI_CLIENT] Initialized (host=%s:%d, model=%s)",
            host,
            port,
            model or "default"
        )
    
    def _get_session(self):
        """Get or create HTTP session."""
        if self._session is None:
            try:
                import requests
                self._session = requests.Session()
                self._session.headers.update({
                    "Content-Type": "application/json"
                })
            except ImportError:
                import urllib.request
                self._session = None
        return self._session
    
    def chat(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        history: Optional[List[Message]] = None
    ) -> AIResponse:
        """
        Send a chat message and get a response.
        
        Args:
            message: User message
            system_prompt: Optional system prompt
            history: Optional conversation history
        
        Returns:
            AIResponse object
        
        Raises:
            AIConnectionError: If connection fails
            AIInferenceError: If inference fails
        """
        start_time = time.time()
        
        # Build messages
        messages = []
        
        # System prompt
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })
        
        # History
        if history:
            for msg in history:
                messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        # Current message
        messages.append({
            "role": "user",
            "content": message
        })
        
        # Build request
        payload = {
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": False
        }
        
        if self.model:
            payload["model"] = self.model
        
        try:
            # Try using requests if available
            session = self._get_session()
            if session is not None:
                response = session.post(
                    self._url,
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()
            else:
                # Fallback to urllib
                import urllib.request
                import urllib.error
                
                req = urllib.request.Request(
                    self._url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers={"Content-Type": "application/json"},
                    method='POST'
                )
                
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
            
            # Parse response
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0]["message"]["content"]
                model = data.get("model", self.model or "unknown")
                usage = data.get("usage", {})
                tokens = usage.get("completion_tokens", len(content.split()))
                
                duration_ms = (time.time() - start_time) * 1000
                
                _logger.info(
                    "[AI_CLIENT] Response: %d tokens in %.2fms",
                    tokens,
                    duration_ms
                )
                
                return AIResponse(
                    content=content,
                    model=model,
                    tokens=tokens,
                    duration_ms=duration_ms,
                    done=True
                )
            else:
                raise AIInferenceError("Invalid response format")
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            _logger.exception("[AI_CLIENT] Inference failed")
            
            return AIResponse(
                content="",
                model=self.model or "unknown",
                tokens=0,
                duration_ms=duration_ms,
                done=False,
                error=str(e)
            )
    
    def test_connection(self) -> tuple:
        """
        Test connection to LLM server.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Try models endpoint first
            try:
                import requests
                resp = requests.get(
                    f"http://{self.host}:{self.port}/v1/models",
                    timeout=5
                )
                if resp.ok:
                    models = resp.json()
                    model_names = [m.get("id", "unknown") for m in models.get("data", [])]
                    return True, f"Connected. Models: {', '.join(model_names[:3])}"
            except Exception:
                pass
            
            # Try a simple completion
            response = self.chat("Hi", max_tokens=10)
            if response.error:
                return False, f"Connection failed: {response.error}"
            
            return True, f"Connected. Model: {response.model}"
        
        except Exception as e:
            return False, f"Connection failed: {e}"


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

# Lazy-loaded client
_ai_client: Optional[AIClient] = None


def get_ai_client(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    **kwargs
) -> AIClient:
    """
    Get or create the global AI client.
    
    Args:
        host: Server host
        port: Server port
        **kwargs: Additional client arguments
    
    Returns:
        AIClient instance
    """
    global _ai_client
    
    if _ai_client is None:
        _ai_client = AIClient(host=host, port=port, **kwargs)
    
    return _ai_client


def reset_ai_client() -> None:
    """Reset the global AI client."""
    global _ai_client
    _ai_client = None


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "AIClient",
    "AIResponse",
    "Message",
    "AIError",
    "AIConnectionError",
    "AIInferenceError",
    "get_ai_client",
    "reset_ai_client",
    "calculate_similarity",
    "is_command_like",
    "find_similar_commands",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
]
