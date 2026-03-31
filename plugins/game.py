"""
Game Plugin for Arch-PyCLI.

This plugin provides simple CLI games for entertainment.

Features:
- Number guessing game
- High scores tracking
- Multiple difficulty levels
- ASCII art feedback

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import random
import sys
from typing import Any, Dict, List, Optional


# =============================================================================
# CONFIGURATION
# =============================================================================

# Debug configuration
DEBUG_PREFIX: str = "[GAME_PLUGIN]"
_is_debug_mode: bool = False

# Game settings
MAX_GUESSES: int = 10
DEFAULT_DIFFICULTY: str = "medium"


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

_logger: logging.Logger = logging.getLogger("GAME_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[GAME_PLUGIN] Game plugin initialized")


# =============================================================================
# GAME STATE
# =============================================================================

class GameState:
    """Maintains game state and high scores."""
    
    def __init__(self) -> None:
        """Initialize game state."""
        self.current_number: Optional[int] = None
        self.attempts: int = 0
        self.max_attempts: int = MAX_GUESSES
        self.difficulty: str = DEFAULT_DIFFICULTY
        self.in_game: bool = False
        self.high_scores: Dict[str, List[int]] = {
            "easy": [],
            "medium": [],
            "hard": []
        }
        self._max_high_scores: int = 10
    
    def reset(self) -> None:
        """Reset current game state."""
        self.current_number = None
        self.attempts = 0
        self.in_game = False
    
    def get_hint(self, guess: int) -> str:
        """
        Get hint for a guess.
        
        Args:
            guess: User's guess
        
        Returns:
            Hint string
        """
        if self.current_number is None:
            return "No game in progress"
        
        diff = self.current_number - guess
        
        if diff == 0:
            return "🎯 CORRECT!"
        
        # Direction
        direction = "higher" if diff > 0 else "lower"
        
        # Magnitude
        magnitude = abs(diff)
        
        if magnitude <= 2:
            return f"🔥 Burning hot! Go {direction}!"
        elif magnitude <= 5:
            return f"☀️ Very warm! Go {direction}!"
        elif magnitude <= 10:
            return f"🌤️ Warm! Go {direction}."
        elif magnitude <= 20:
            return f"🌿 Cool. Go {direction}."
        else:
            return f"❄️ Cold! Go {direction}!"


# Global state
_state = GameState()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _ensure_health(context: Dict[str, Any]) -> None:
    """Ensure health context is valid."""
    health: Optional[Dict[str, Any]] = context.get("health")
    
    if not isinstance(health, dict):
        _logger.error("[GAME_PLUGIN] Invalid health context")
        raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
    
    if health.get("status") == "CRITICAL":
        _logger.warning("[GAME_PLUGIN] System in CRITICAL state")
        raise RuntimeError("ERR_SYSTEM_INSTABILITY")


def _get_number_range() -> tuple:
    """
    Get number range based on difficulty.
    
    Returns:
        Tuple of (min, max)
    """
    ranges = {
        "easy": (1, 50),
        "medium": (1, 100),
        "hard": (1, 500),
        "impossible": (1, 1000)
    }
    return ranges.get(_state.difficulty, (1, 100))


def _start_new_game(difficulty: str) -> str:
    """
    Start a new guessing game.
    
    Args:
        difficulty: Game difficulty
    
    Returns:
        Welcome message
    """
    _state.difficulty = difficulty
    _state.reset()
    
    min_num, max_num = _get_number_range()
    _state.current_number = random.randint(min_num, max_num)
    _state.max_attempts = {
        "easy": 15,
        "medium": 10,
        "hard": 7,
        "impossible": 5
    }.get(difficulty, 10)
    _state.in_game = True
    _state.attempts = 0
    
    _logger.info(
        "[GAME_PLUGIN] New game started: %s (range: %d-%d)",
        difficulty,
        min_num,
        max_num
    )
    
    return f"""
╔══════════════════════════════════════════════════════════╗
║              🎮 NUMBER GUESSING GAME 🎮                 ║
╠══════════════════════════════════════════════════════════╣
║  Difficulty: {difficulty.upper():<40}║
║  Range: {min_num} to {max_num}{" " * (38 - len(str(max_num)) - len(str(min_num)))}║
║  Max attempts: {_state.max_attempts}{" " * (38 - len(str(_state.max_attempts)))}║
╠══════════════════════════════════════════════════════════╣
║  Type 'guess <number>' to make a guess                 ║
║  Type 'hint' for a hint (costs 1 attempt)              ║
║  Type 'quit' to end the game                          ║
╚══════════════════════════════════════════════════════════╝
"""


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "game",
    "description": "CLI games including number guessing with high scores.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "game [start|guess|hint|scores|help]",
    "examples": [
        "game start easy",
        "game start hard",
        "game guess 50",
        "game hint",
        "game scores",
        "game help"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Game plugin execution function.
    
    Provides CLI games:
        - start [easy|medium|hard|impossible]: Start new game
        - guess <number>: Make a guess
        - hint: Get a hint (costs 1 attempt)
        - scores: View high scores
        - help: Show help
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments
    
    Returns:
        Game result string
    
    Raises:
        RuntimeError: If health context is invalid
        ValueError: If game arguments are invalid
    """
    # =====================================================================
    # CONTEXT VALIDATION
    # =====================================================================
    
    _ensure_health(context)
    
    # No args - show help
    if not args:
        return _show_help()
    
    # =====================================================================
    # PARSE COMMAND
    # =====================================================================
    
    cmd: str = str(args[0]).lower().strip()
    cmd_args: tuple = args[1:]
    
    _debug_log("Command: %s, Args: %s", cmd, cmd_args)
    
    # =====================================================================
    # COMMAND HANDLERS
    # =====================================================================
    
    if cmd in ("start", "new", "play"):
        return _handle_start(cmd_args)
    
    if cmd in ("guess", "g", "guess"):
        return _handle_guess(cmd_args)
    
    if cmd in ("hint", "h"):
        return _handle_hint()
    
    if cmd in ("scores", "highscores", "high_scores", "leaderboard"):
        return _handle_scores()
    
    if cmd in ("quit", "q", "exit", "end"):
        return _handle_quit()
    
    if cmd in ("help", "--help", "-h"):
        return _show_help()
    
    if cmd in ("rules", "info"):
        return _show_rules()
    
    # Unknown command
    return f"ERR_UNKNOWN_COMMAND: {cmd}\nType 'game help' for available commands."


def _handle_start(args: tuple) -> str:
    """Handle start command."""
    difficulty = args[0].lower() if args else DEFAULT_DIFFICULTY
    
    valid_difficulties = ["easy", "medium", "hard", "impossible"]
    if difficulty not in valid_difficulties:
        return f"ERR_INVALID_DIFFICULTY: {difficulty}\nValid: {', '.join(valid_difficulties)}"
    
    return _start_new_game(difficulty)


def _handle_guess(args: tuple) -> str:
    """Handle guess command."""
    if not _state.in_game:
        return "No game in progress. Type 'game start' to begin!"
    
    if not args:
        return "ERR_USAGE: guess <number>"
    
    try:
        guess = int(args[0])
    except ValueError:
        return f"ERR_INVALID_GUESS: {args[0]} is not a number"
    
    min_num, max_num = _get_number_range()
    
    if guess < min_num or guess > max_num:
        return f"ERR_OUT_OF_RANGE: Guess must be between {min_num} and {max_num}"
    
    _state.attempts += 1
    remaining = _state.max_attempts - _state.attempts
    
    # Correct guess!
    if guess == _state.current_number:
        _state.in_game = False
        
        # Update high scores
        _state.high_scores[_state.difficulty].append(_state.attempts)
        _state.high_scores[_state.difficulty].sort()
        if len(_state.high_scores[_state.difficulty]) > _state._max_high_scores:
            _state.high_scores[_state.difficulty] = _state.high_scores[_state.difficulty][: _state._max_high_scores]
        
        # Calculate score
        base_score = 1000
        difficulty_multiplier = {
            "easy": 1,
            "medium": 2,
            "hard": 5,
            "impossible": 10
        }.get(_state.difficulty, 1)
        bonus = remaining * 50 * difficulty_multiplier
        score = base_score * difficulty_multiplier + bonus
        
        _logger.info(
            "[GAME_PLUGIN] Game won in %d attempts (difficulty: %s)",
            _state.attempts,
            _state.difficulty
        )
        
        return f"""
╔══════════════════════════════════════════════════════════╗
║                    🎉 YOU WIN! 🎉                        ║
╠══════════════════════════════════════════════════════════╣
║  The number was: {_state.current_number:<40}║
║  Attempts: {_state.attempts:<46}║
║  Remaining: {remaining:<45}║
║  Difficulty: {_state.difficulty.upper():<41}║
║  Score: {score:<47}║
╚══════════════════════════════════════════════════════════╝

Type 'game start' to play again!
"""
    
    # Wrong guess
    hint = _state.get_hint(guess)
    
    if remaining <= 0:
        _state.in_game = False
        return f"""
╔══════════════════════════════════════════════════════════╗
║                   💔 GAME OVER 💔                        ║
╠══════════════════════════════════════════════════════════╣
║  The number was: {_state.current_number:<40}║
║  You ran out of attempts!                                ║
╚══════════════════════════════════════════════════════════╝

Type 'game start' to try again!
"""
    
    return f"""
{hint}
Guess #{_state.attempts}: {guess}
Attempts remaining: {remaining}

Min: {min_num} | Max: {max_num}
"""


def _handle_hint() -> str:
    """Handle hint command."""
    if not _state.in_game:
        return "No game in progress. Type 'game start' to begin!"
    
    _state.attempts += 1
    remaining = _state.max_attempts - _state.attempts
    
    if remaining <= 0:
        _state.in_game = False
        return f"""
💔 GAME OVER - You ran out of attempts!
The number was: {_state.current_number}

Type 'game start' to try again!
"""
    
    # Generate hint
    num = _state.current_number
    hints = []
    
    # Parity hint
    if num % 2 == 0:
        hints.append("Number is even")
    else:
        hints.append("Number is odd")
    
    # Divisibility hints
    if num % 5 == 0:
        hints.append("Divisible by 5")
    if num % 3 == 0:
        hints.append("Divisible by 3")
    
    # Range hint
    min_num, max_num = _get_number_range()
    quarter = (max_num - min_num) // 4
    
    if num <= min_num + quarter:
        hints.append("In the lower quarter")
    elif num >= max_num - quarter:
        hints.append("In the upper quarter")
    else:
        hints.append("In the middle half")
    
    hint_text = "\n  • ".join(hints)
    
    return f"""
💡 HINT (costs 1 attempt)
Remaining attempts: {remaining}
───────────────
  • {hint_text}
───────────────
"""


def _handle_scores() -> str:
    """Handle scores command."""
    lines = ["╔══════════════════════════════════════════════════════════╗"]
    lines.append("║                    🏆 HIGH SCORES 🏆                     ║")
    lines.append("╠══════════════════════════════════════════════════════════╣")
    
    for difficulty in ["easy", "medium", "hard", "impossible"]:
        scores = _state.high_scores.get(difficulty, [])
        lines.append(f"║  {difficulty.upper():<12} │ ", end="")
        
        if not scores:
            lines.append("No scores yet" + " " * 30 + "║")
        else:
            score_str = f"Best: {scores[0]} attempts"
            lines.append(score_str + " " * (38 - len(score_str)) + "║")
    
    lines.append("╚══════════════════════════════════════════════════════════╝")
    lines.append("\nFewer attempts = better score!")
    
    return "\n".join(lines)


def _handle_quit() -> str:
    """Handle quit command."""
    if _state.in_game:
        _state.in_game = False
        return f"""
Game ended. The number was: {_state.current_number}
Better luck next time!
"""
    return "No game in progress."


def _show_help() -> str:
    """Show game help."""
    return """Game Plugin Help
================

COMMANDS:
  game start [difficulty]  - Start a new game
  game guess <number>     - Make a guess
  game hint               - Get a hint (costs 1 attempt)
  game scores             - View high scores
  game quit               - Quit current game
  game help               - Show this help

DIFFICULTIES:
  easy      - Range 1-50, 15 attempts
  medium    - Range 1-100, 10 attempts (default)
  hard      - Range 1-500, 7 attempts
  impossible - Range 1-1000, 5 attempts

EXAMPLES:
  game start hard
  game guess 50
  game hint
  game scores

TIPS:
  - Use hints wisely! They cost 1 attempt.
  - Pay attention to hot/cold feedback.
  - Even/odd and divisibility hints can help narrow down.
"""


def _show_rules() -> str:
    """Show game rules."""
    return """Number Guessing Game Rules
===========================

1. The computer picks a random number within the range.
2. You have a limited number of attempts to guess it.
3. After each guess, you'll get feedback:
   🔥 Burning hot - Very close!
   ☀️ Very warm   - Close
   🌤️ Warm        - Getting warmer
   🌿 Cool        - Getting colder
   ❄️ Cold        - Far off

4. You can ask for a HINT, but it costs 1 attempt.
   Hints include: parity, divisibility, range position.

5. Win by guessing the number within the attempts limit.

6. Your score is based on:
   - Difficulty (harder = more points)
   - Fewer attempts = higher score
   - Remaining attempts bonus

GOOD LUCK! 🍀
"""


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
