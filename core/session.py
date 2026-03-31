"""
Session Manager Module for Arch-PyCLI.

This module provides session tracking, command history, and session timeout management.

Features:
- Session creation and lifecycle management
- Command history per session
- Session timeout handling
- Idle time tracking
- Session statistics
- Thread-safe operations

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class SessionError(Exception):
    """Base exception for session errors."""
    pass


class SessionNotFoundError(SessionError):
    """Raised when session is not found."""
    pass


class SessionExpiredError(SessionError):
    """Raised when session has expired."""
    pass


class SessionLockedError(SessionError):
    """Raised when session is locked."""
    pass


# =============================================================================
# ENUMS
# =============================================================================

class SessionState(Enum):
    """Session state enumeration."""
    ACTIVE = "active"
    IDLE = "idle"
    LOCKED = "locked"
    EXPIRED = "expired"
    TERMINATED = "terminated"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CommandEntry:
    """Represents a single command in history."""
    command: str
    timestamp: datetime
    duration_ms: float
    result_status: str
    error_message: Optional[str] = None


@dataclass
class Session:
    """
    Represents a user session.
    
    Attributes:
        session_id: Unique session identifier
        user: Username
        created_at: Session creation time
        last_activity: Last activity timestamp
        state: Current session state
        command_history: List of executed commands
        idle_timeout: Idle timeout in seconds
        max_history: Maximum commands to keep in history
        metadata: Additional session metadata
    """
    session_id: str
    user: str
    created_at: datetime
    last_activity: datetime
    state: SessionState = SessionState.ACTIVE
    command_history: List[CommandEntry] = field(default_factory=list)
    idle_timeout: int = 300  # 5 minutes default
    max_history: int = 1000   # Max commands to keep
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def idle_time(self) -> float:
        """Get seconds since last activity."""
        return (datetime.now() - self.last_activity).total_seconds()
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return self.state in (SessionState.EXPIRED, SessionState.TERMINATED)
    
    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.state == SessionState.ACTIVE


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_IDLE_TIMEOUT: int = 300      # 5 minutes
DEFAULT_MAX_HISTORY: int = 1000      # Max commands per session
DEFAULT_SESSION_TTL: int = 86400      # 24 hours
CLEANUP_INTERVAL: int = 60          # Cleanup check interval (seconds)
MAX_SESSIONS: int = 100             # Maximum concurrent sessions


# =============================================================================
# SETUP LOGGING
# =============================================================================

_logger: logging.Logger = logging.getLogger("SESSION_MANAGER")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[SESSION_MANAGER] Session manager initialized")


# =============================================================================
# SESSION MANAGER CLASS
# =============================================================================

class SessionManager:
    """
    Manages user sessions, command history, and timeouts.
    
    This class provides:
    - Session creation and lifecycle management
    - Command history tracking
    - Idle timeout detection
    - Session cleanup
    - Statistics collection
    
    Thread-safe for concurrent access.
    
    Example:
        >>> manager = SessionManager()
        >>> session = manager.create_session("user1")
        >>> manager.record_command(session.session_id, "echo hello", "OK")
        >>> history = manager.get_history(session.session_id)
    """
    
    def __init__(
        self,
        idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
        max_history: int = DEFAULT_MAX_HISTORY,
        max_sessions: int = MAX_SESSIONS,
        session_ttl: int = DEFAULT_SESSION_TTL
    ) -> None:
        """
        Initialize the session manager.
        
        Args:
            idle_timeout: Default idle timeout in seconds
            max_history: Maximum commands per session history
            max_sessions: Maximum concurrent sessions
            session_ttl: Session time-to-live in seconds
        """
        self._sessions: Dict[str, Session] = {}
        self._sessions_lock: threading.RLock = threading.RLock()
        
        self._idle_timeout: int = idle_timeout
        self._max_history: int = max_history
        self._max_sessions: int = max_sessions
        self._session_ttl: int = session_ttl
        
        # Cleanup thread
        self._cleanup_running: bool = True
        self._cleanup_thread: Optional[threading.Thread] = None
        self._start_cleanup_thread()
        
        _logger.info(
            "[SESSION_MANAGER] Initialized (idle=%ds, max_history=%d, max_sessions=%d)",
            self._idle_timeout,
            self._max_history,
            self._max_sessions
        )
    
    # =========================================================================
    # SESSION LIFECYCLE
    # =========================================================================
    
    def create_session(
        self,
        user: str,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Session:
        """
        Create a new session.
        
        Args:
            user: Username for the session
            session_id: Optional custom session ID
            metadata: Optional session metadata
        
        Returns:
            Created Session object
        
        Raises:
            SessionError: If max sessions reached
        """
        with self._sessions_lock:
            # Check max sessions
            if len(self._sessions) >= self._max_sessions:
                _logger.warning(
                    "[SESSION_MANAGER] Max sessions reached (%d)",
                    self._max_sessions
                )
                raise SessionError(f"Maximum sessions ({self._max_sessions}) reached")
            
            # Generate session ID if not provided
            if session_id is None:
                session_id = self._generate_session_id(user)
            
            # Check if session already exists
            if session_id in self._sessions:
                _logger.info(
                    "[SESSION_MANAGER] Reconnecting existing session: %s",
                    session_id
                )
                session = self._sessions[session_id]
                session.state = SessionState.ACTIVE
                session.last_activity = datetime.now()
                return session
            
            # Create new session
            now = datetime.now()
            session = Session(
                session_id=session_id,
                user=user,
                created_at=now,
                last_activity=now,
                state=SessionState.ACTIVE,
                idle_timeout=self._idle_timeout,
                max_history=self._max_history,
                metadata=metadata or {}
            )
            
            self._sessions[session_id] = session
            
            _logger.info(
                "[SESSION_MANAGER] Created session: %s (user=%s)",
                session_id,
                user
            )
            
            return session
    
    def get_session(self, session_id: str) -> Session:
        """
        Get a session by ID.
        
        Args:
            session_id: Session ID
        
        Returns:
            Session object
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            if session_id not in self._sessions:
                raise SessionNotFoundError(f"Session not found: {session_id}")
            
            return self._sessions[session_id]
    
    def get_session_safe(self, session_id: str) -> Optional[Session]:
        """
        Get a session by ID, returning None if not found.
        
        Args:
            session_id: Session ID
        
        Returns:
            Session object or None
        """
        try:
            return self.get_session(session_id)
        except SessionNotFoundError:
            return None
    
    def terminate_session(self, session_id: str) -> None:
        """
        Terminate a session.
        
        Args:
            session_id: Session ID to terminate
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            if session_id not in self._sessions:
                raise SessionNotFoundError(f"Session not found: {session_id}")
            
            session = self._sessions[session_id]
            session.state = SessionState.TERMINATED
            
            _logger.info(
                "[SESSION_MANAGER] Terminated session: %s",
                session_id
            )
    
    def remove_session(self, session_id: str) -> None:
        """
        Remove a session entirely.
        
        Args:
            session_id: Session ID to remove
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            if session_id not in self._sessions:
                raise SessionNotFoundError(f"Session not found: {session_id}")
            
            del self._sessions[session_id]
            
            _logger.info(
                "[SESSION_MANAGER] Removed session: %s",
                session_id
            )
    
    # =========================================================================
    # SESSION STATE MANAGEMENT
    # =========================================================================
    
    def touch_session(self, session_id: str) -> None:
        """
        Update session's last activity time.
        
        Args:
            session_id: Session ID
        
        Raises:
            SessionNotFoundError: If session not found
            SessionExpiredError: If session is expired
        """
        with self._sessions_lock:
            session = self.get_session(session_id)
            
            if session.is_expired:
                raise SessionExpiredError(f"Session expired: {session_id}")
            
            session.last_activity = datetime.now()
            
            # Transition from IDLE to ACTIVE if needed
            if session.state == SessionState.IDLE:
                session.state = SessionState.ACTIVE
                _logger.debug(
                    "[SESSION_MANAGER] Session %s resumed from idle",
                    session_id
                )
    
    def lock_session(self, session_id: str) -> None:
        """
        Lock a session.
        
        Args:
            session_id: Session ID
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            session = self.get_session(session_id)
            session.state = SessionState.LOCKED
            
            _logger.info(
                "[SESSION_MANAGER] Locked session: %s",
                session_id
            )
    
    def unlock_session(self, session_id: str) -> None:
        """
        Unlock a session.
        
        Args:
            session_id: Session ID
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            session = self.get_session(session_id)
            
            if session.state != SessionState.LOCKED:
                raise SessionLockedError(f"Session not locked: {session_id}")
            
            session.state = SessionState.ACTIVE
            session.last_activity = datetime.now()
            
            _logger.info(
                "[SESSION_MANAGER] Unlocked session: %s",
                session_id
            )
    
    def set_idle_timeout(self, session_id: str, timeout: int) -> None:
        """
        Set session's idle timeout.
        
        Args:
            session_id: Session ID
            timeout: New timeout in seconds
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            session = self.get_session(session_id)
            session.idle_timeout = timeout
            
            _logger.debug(
                "[SESSION_MANAGER] Session %s idle timeout set to %ds",
                session_id,
                timeout
            )
    
    # =========================================================================
    # COMMAND HISTORY
    # =========================================================================
    
    def record_command(
        self,
        session_id: str,
        command: str,
        result_status: str,
        duration_ms: float = 0.0,
        error_message: Optional[str] = None
    ) -> None:
        """
        Record a command execution.
        
        Args:
            session_id: Session ID
            command: Command that was executed
            result_status: Result status (OK, ERROR, etc.)
            duration_ms: Execution duration in milliseconds
            error_message: Optional error message
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            session = self.get_session(session_id)
            
            # Update last activity
            session.last_activity = datetime.now()
            
            # Create command entry
            entry = CommandEntry(
                command=command,
                timestamp=datetime.now(),
                duration_ms=duration_ms,
                result_status=result_status,
                error_message=error_message
            )
            
            # Add to history
            session.command_history.append(entry)
            
            # Trim history if needed
            if len(session.command_history) > session.max_history:
                session.command_history = session.command_history[-session.max_history:]
            
            _logger.debug(
                "[SESSION_MANAGER] Recorded command for %s: %s (%s)",
                session_id,
                command[:50],
                result_status
            )
    
    def get_history(
        self,
        session_id: str,
        limit: Optional[int] = None,
        since: Optional[datetime] = None
    ) -> List[CommandEntry]:
        """
        Get command history for a session.
        
        Args:
            session_id: Session ID
            limit: Maximum number of entries to return
            since: Only return entries after this time
        
        Returns:
            List of CommandEntry objects
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            session = self.get_session(session_id)
            
            history = session.command_history
            
            # Filter by time if specified
            if since is not None:
                history = [e for e in history if e.timestamp >= since]
            
            # Apply limit
            if limit is not None:
                history = history[-limit:]
            
            return history
    
    def clear_history(self, session_id: str) -> int:
        """
        Clear command history for a session.
        
        Args:
            session_id: Session ID
        
        Returns:
            Number of entries cleared
        
        Raises:
            SessionNotFoundError: If session not found
        """
        with self._sessions_lock:
            session = self.get_session(session_id)
            count = len(session.command_history)
            session.command_history.clear()
            
            _logger.info(
                "[SESSION_MANAGER] Cleared %d entries for session %s",
                count,
                session_id
            )
            
            return count
    
    def search_history(
        self,
        session_id: str,
        pattern: str,
        case_sensitive: bool = False
    ) -> List[CommandEntry]:
        """
        Search command history for a pattern.
        
        Args:
            session_id: Session ID
            pattern: Search pattern
            case_sensitive: Whether search is case-sensitive
        
        Returns:
            List of matching CommandEntry objects
        """
        with self._sessions_lock:
            session = self.get_session_safe(session_id)
            if session is None:
                return []
            
            results = []
            search_in = str.casefold if not case_sensitive else lambda x: x
            
            for entry in session.command_history:
                if search_in(pattern) in search_in(entry.command):
                    results.append(entry)
            
            return results
    
    # =========================================================================
    # SESSION QUERIES
    # =========================================================================
    
    def get_active_sessions(self) -> List[Session]:
        """
        Get all active sessions.
        
        Returns:
            List of active Session objects
        """
        with self._sessions_lock:
            return [
                s for s in self._sessions.values()
                if s.is_active
            ]
    
    def get_idle_sessions(self) -> List[Session]:
        """
        Get all idle sessions.
        
        Returns:
            List of idle Session objects
        """
        with self._sessions_lock:
            idle = []
            for s in self._sessions.values():
                if s.state == SessionState.ACTIVE and s.idle_time >= s.idle_timeout:
                    idle.append(s)
            return idle
    
    def get_user_sessions(self, user: str) -> List[Session]:
        """
        Get all sessions for a user.
        
        Args:
            user: Username
        
        Returns:
            List of Session objects for the user
        """
        with self._sessions_lock:
            return [
                s for s in self._sessions.values()
                if s.user == user
            ]
    
    def get_all_sessions(self) -> List[Session]:
        """
        Get all sessions.
        
        Returns:
            List of all Session objects
        """
        with self._sessions_lock:
            return list(self._sessions.values())
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get session manager statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self._sessions_lock:
            now = datetime.now()
            
            active = sum(1 for s in self._sessions.values() if s.is_active)
            idle = sum(1 for s in self._sessions.values() if s.state == SessionState.IDLE)
            locked = sum(1 for s in self._sessions.values() if s.state == SessionState.LOCKED)
            expired = sum(1 for s in self._sessions.values() if s.is_expired)
            
            total_commands = sum(len(s.command_history) for s in self._sessions.values())
            
            return {
                "total_sessions": len(self._sessions),
                "active_sessions": active,
                "idle_sessions": idle,
                "locked_sessions": locked,
                "expired_sessions": expired,
                "total_commands": total_commands,
                "max_sessions": self._max_sessions,
                "idle_timeout": self._idle_timeout,
                "session_ttl": self._session_ttl,
            }
    
    # =========================================================================
    # CLEANUP
    # =========================================================================
    
    def _start_cleanup_thread(self) -> None:
        """Start the background cleanup thread."""
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="SessionCleanup"
        )
        self._cleanup_thread.start()
        _logger.info("[SESSION_MANAGER] Cleanup thread started")
    
    def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self._cleanup_running:
            try:
                self._cleanup_expired()
                self._mark_idle_sessions()
            except Exception as e:
                _logger.exception("[SESSION_MANAGER] Cleanup error")
            
            time.sleep(CLEANUP_INTERVAL)
    
    def _cleanup_expired(self) -> None:
        """Remove expired sessions."""
        with self._sessions_lock:
            now = datetime.now()
            expired = []
            
            for session_id, session in self._sessions.items():
                # Check session TTL
                age = (now - session.created_at).total_seconds()
                if age > self._session_ttl:
                    expired.append(session_id)
                    continue
                
                # Check if explicitly terminated
                if session.state == SessionState.TERMINATED:
                    expired.append(session_id)
            
            for session_id in expired:
                del self._sessions[session_id]
                _logger.debug(
                    "[SESSION_MANAGER] Cleaned up expired session: %s",
                    session_id
                )
    
    def _mark_idle_sessions(self) -> None:
        """Mark idle sessions."""
        with self._sessions_lock:
            for session in self._sessions.values():
                if session.state == SessionState.ACTIVE:
                    if session.idle_time >= session.idle_timeout:
                        session.state = SessionState.IDLE
                        _logger.info(
                            "[SESSION_MANAGER] Session %s marked idle",
                            session.session_id
                        )
    
    def shutdown(self) -> None:
        """Shutdown the session manager."""
        _logger.info("[SESSION_MANAGER] Shutting down...")
        
        self._cleanup_running = False
        
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=5.0)
        
        with self._sessions_lock:
            self._sessions.clear()
        
        _logger.info("[SESSION_MANAGER] Shutdown complete")
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _generate_session_id(self, user: str) -> str:
        """Generate a unique session ID."""
        timestamp = int(time.time() * 1000)
        import random
        random_suffix = random.randint(1000, 9999)
        return f"{user}_{timestamp}_{random_suffix}"
    
    def __enter__(self) -> "SessionManager":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.shutdown()


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

SESSION_MANAGER: SessionManager = SessionManager()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "SessionManager",
    "SESSION_MANAGER",
    "Session",
    "SessionState",
    "CommandEntry",
    "SessionError",
    "SessionNotFoundError",
    "SessionExpiredError",
    "SessionLockedError",
]
