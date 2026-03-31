"""
Calc Plugin for Arch-PyCLI.

This plugin provides a calculator with arithmetic operations and functions.

Features:
- Basic arithmetic (+, -, *, /, //, %, **)
- Mathematical functions (sqrt, sin, cos, tan, log, etc.)
- Unit conversions
- Expression evaluation
- Memory operations (M+, M-, MR, MC)
- History of calculations

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import cmath
import logging
import math
import sys
from typing import Any, Dict, List, Optional, Union


# =============================================================================
# CONFIGURATION
# =============================================================================

# Debug configuration
DEBUG_PREFIX: str = "[CALC_PLUGIN]"
_is_debug_mode: bool = False

# Calculation limits
MAX_EXPRESSION_LENGTH: int = 1000
MAX_RESULT_DECIMALS: int = 10
MEMORY_SLOTS: int = 10


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

_logger: logging.Logger = logging.getLogger("CALC_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[CALC_PLUGIN] Calc plugin initialized")


# =============================================================================
# CALCULATOR STATE
# =============================================================================

class CalculatorState:
    """
    Maintains calculator state including memory and history.
    
    Attributes:
        memory: Memory slots for storing values
        history: List of past calculations
        last_result: Last calculation result
        angle_mode: Angle mode ('deg' or 'rad')
    """
    
    def __init__(self) -> None:
        """Initialize calculator state."""
        self.memory: List[Optional[float]] = [None] * MEMORY_SLOTS
        self.current_memory: int = 0
        self.history: List[str] = []
        self.last_result: Optional[float] = None
        self.angle_mode: str = "deg"  # 'deg' or 'rad'
        self._max_history: int = 50
    
    def _format_result(self, value: Union[float, complex]) -> str:
        """
        Format a result for display.
        
        Args:
            value: Result value
        
        Returns:
            Formatted string
        """
        if isinstance(value, complex):
            if value.imag == 0:
                return self._format_result(value.real)
            real = self._format_result(value.real)
            imag = self._format_result(abs(value.imag))
            sign = "+" if value.imag >= 0 else "-"
            return f"{real}{sign}{imag}i"
        
        if math.isnan(value):
            return "NaN"
        
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        
        # Round to max decimals
        rounded = round(value, MAX_RESULT_DECIMALS)
        
        # Remove trailing zeros
        formatted = f"{rounded:f}".rstrip('0').rstrip('.')
        
        return formatted
    
    def _add_to_history(self, expression: str, result: str) -> None:
        """Add calculation to history."""
        entry = f"{expression} = {result}"
        self.history.append(entry)
        
        # Trim history if needed
        if len(self.history) > self._max_history:
            self.history = self.history[-self._max_history:]


# Global state
_state = CalculatorState()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _ensure_health(context: Dict[str, Any]) -> None:
    """
    Ensure health context is valid.
    
    Args:
        context: Execution context
    
    Raises:
        RuntimeError: If health context is invalid
    """
    health: Optional[Dict[str, Any]] = context.get("health")
    
    if not isinstance(health, dict):
        _logger.error("[CALC_PLUGIN] Invalid health context")
        raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
    
    if health.get("status") == "CRITICAL":
        _logger.warning("[CALC_PLUGIN] System in CRITICAL state")
        raise RuntimeError("ERR_SYSTEM_INSTABILITY")


def _safe_eval(expression: str) -> Union[float, complex]:
    """
    Safely evaluate a mathematical expression.
    
    Args:
        expression: Mathematical expression
    
    Returns:
        Result of evaluation
    
    Raises:
        ValueError: If expression is invalid
    """
    # Whitelist of allowed functions
    allowed_names = {
        "sin": lambda x: math.sin(math.radians(x) if _state.angle_mode == "deg" else x),
        "cos": lambda x: math.cos(math.radians(x) if _state.angle_mode == "deg" else x),
        "tan": lambda x: math.tan(math.radians(x) if _state.angle_mode == "deg" else x),
        "asin": lambda x: math.degrees(math.asin(x)) if _state.angle_mode == "deg" else math.asin(x),
        "acos": lambda x: math.degrees(math.acos(x)) if _state.angle_mode == "deg" else math.acos(x),
        "atan": lambda x: math.degrees(math.atan(x)) if _state.angle_mode == "deg" else math.atan(x),
        "sinh": math.sinh,
        "cosh": math.cosh,
        "tanh": math.tanh,
        "sqrt": math.sqrt,
        "cbrt": lambda x: x ** (1/3),
        "log": math.log10,
        "ln": math.log,
        "log2": math.log2,
        "exp": math.exp,
        "abs": abs,
        "ceil": math.ceil,
        "floor": math.floor,
        "round": round,
        "factorial": math.factorial,
        "gcd": math.gcd,
        "pow": pow,
        "max": max,
        "min": min,
        # Constants
        "pi": math.pi,
        "e": math.e,
        "tau": math.tau,
        "phi": (1 + math.sqrt(5)) / 2,  # Golden ratio
        # Complex number support
        "csqrt": cmath.sqrt,
        "cexp": cmath.exp,
        "clog": cmath.log,
        "phase": cmath.phase,
        "polar": lambda x: (abs(x), cmath.phase(x)),
        "rect": lambda r, theta: cmath.rect(r, theta),
    }
    
    # Check expression length
    if len(expression) > MAX_EXPRESSION_LENGTH:
        raise ValueError("ERR_EXPRESSION_TOO_LONG")
    
    # Validate characters (only allow safe math characters)
    import re
    safe_pattern = r'^[\d\s+\-*/().,%^sqrtloglnsinastancoshsinexpceilfloorabsfactorialgcodpowmaxminpiephitaupolargcdcbrt]+$'
    clean_expr = expression.replace('**', '^').replace('×', '*').replace('÷', '/')
    
    # More permissive pattern for actual use
    allowed_chars = set("0123456789.+-*/()^% ,sqrtloglnsinacostaneexpsqrtpi e")
    for char in clean_expr:
        if char.isalnum():
            continue
        if char in allowed_chars or char.isspace():
            continue
        raise ValueError(f"ERR_INVALID_CHARACTER: {char}")
    
    # Replace ^ with ** for Python evaluation
    clean_expr = clean_expr.replace('^', '**')
    
    # Handle implicit multiplication (2pi -> 2*pi)
    clean_expr = re.sub(r'(\d)([a-zA-Z(])', r'\1*\2', clean_expr)
    clean_expr = re.sub(r'([a-zA-Z)])(\d)', r'\1*\2', clean_expr)
    clean_expr = re.sub(r'(\))(\()', r'\1*\2', clean_expr)
    
    # Evaluate using limited safe namespace
    try:
        result = eval(clean_expr, {"__builtins__": {}}, allowed_names)
    except ZeroDivisionError:
        raise ValueError("ERR_DIVISION_BY_ZERO")
    except Exception as e:
        _logger.debug("[CALC_PLUGIN] Evaluation error: %s", e)
        raise ValueError(f"ERR_EVALUATION_ERROR: {e}")
    
    return result


def _convert_units(value: float, from_unit: str, to_unit: str) -> float:
    """
    Convert between units.
    
    Args:
        value: Value to convert
        from_unit: Source unit
        to_unit: Target unit
    
    Returns:
        Converted value
    """
    # Length conversions (to meters)
    length_to_m = {
        "m": 1, "meter": 1, "meters": 1,
        "km": 1000, "kilometer": 1000, "kilometers": 1000,
        "cm": 0.01, "centimeter": 0.01, "centimeters": 0.01,
        "mm": 0.001, "millimeter": 0.001, "millimeters": 0.001,
        "mi": 1609.344, "mile": 1609.344, "miles": 1609.344,
        "ft": 0.3048, "foot": 0.3048, "feet": 0.3048,
        "in": 0.0254, "inch": 0.0254, "inches": 0.0254,
        "yd": 0.9144, "yard": 0.9144, "yards": 0.9144,
    }
    
    # Weight conversions (to grams)
    weight_to_g = {
        "g": 1, "gram": 1, "grams": 1,
        "kg": 1000, "kilogram": 1000, "kilograms": 1000,
        "mg": 0.001, "milligram": 0.001, "milligrams": 0.001,
        "lb": 453.592, "lbs": 453.592, "pound": 453.592, "pounds": 453.592,
        "oz": 28.3495, "ounce": 28.3495, "ounces": 28.3495,
    }
    
    # Temperature conversions
    def celsius_to_fahrenheit(c): return c * 9/5 + 32
    def fahrenheit_to_celsius(f): return (f - 32) * 5/9
    def celsius_to_kelvin(c): return c + 273.15
    def kelvin_to_celsius(k): return k - 273.15
    
    from_u = from_unit.lower().strip()
    to_u = to_unit.lower().strip()
    
    # Try length conversion
    if from_u in length_to_m and to_u in length_to_m:
        meters = value * length_to_m[from_u]
        return meters / length_to_m[to_u]
    
    # Try weight conversion
    if from_u in weight_to_g and to_u in weight_to_g:
        grams = value * weight_to_g[from_u]
        return grams / weight_to_g[to_u]
    
    # Temperature conversions
    temp_units = {"c", "celsius", "f", "fahrenheit", "k", "kelvin"}
    if from_u in temp_units and to_u in temp_units:
        # Convert to celsius first
        if from_u in ("f", "fahrenheit"):
            c = fahrenheit_to_celsius(value)
        elif from_u in ("k", "kelvin"):
            c = kelvin_to_celsius(value)
        else:
            c = value
        
        # Convert from celsius to target
        if to_u in ("f", "fahrenheit"):
            return celsius_to_fahrenheit(c)
        elif to_u in ("k", "kelvin"):
            return celsius_to_kelvin(c)
        else:
            return c
    
    raise ValueError(f"ERR_UNSUPPORTED_CONVERSION: {from_u} -> {to_u}")


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "calc",
    "description": "Calculator with arithmetic, functions, and unit conversions.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "calc [expr|func] [args]",
    "examples": [
        "calc 2 + 2",
        "calc sqrt(16)",
        "calc 5!",
        "calc 10 % 3",
        "calc sin(45)",
        "calc convert 100 km to mi",
        "calc m+ 42",
        "calc mr",
        "calc history",
        "calc mode deg"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Calc plugin execution function.
    
    Provides calculator operations:
        - Arithmetic expressions: +, -, *, /, //, %, **
        - Functions: sqrt, sin, cos, tan, log, ln, exp, etc.
        - Constants: pi, e, tau, phi
        - Memory: m+, m-, mr, mc, ms
        - Convert: Unit conversions
        - Mode: deg/rad toggle
        - History: View calculation history
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments
    
    Returns:
        Calculation result string
    
    Raises:
        RuntimeError: If health context is invalid
        ValueError: If expression is invalid
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
    # MEMORY OPERATIONS
    # =====================================================================
    
    if cmd == "m+":
        return _handle_m_plus(cmd_args)
    
    if cmd == "m-":
        return _handle_m_minus(cmd_args)
    
    if cmd in ("mr", "recall"):
        return _handle_mr()
    
    if cmd in ("mc", "clear"):
        return _handle_mc()
    
    if cmd in ("ms", "store"):
        return _handle_ms(cmd_args)
    
    # =====================================================================
    # MODE COMMANDS
    # =====================================================================
    
    if cmd == "mode":
        return _handle_mode(cmd_args)
    
    if cmd in ("deg", "degrees"):
        _state.angle_mode = "deg"
        return "Angle mode: degrees"
    
    if cmd in ("rad", "radians"):
        _state.angle_mode = "rad"
        return "Angle mode: radians"
    
    # =====================================================================
    # HISTORY
    # =====================================================================
    
    if cmd == "history":
        return _handle_history()
    
    if cmd == "clearh":
        _state.history.clear()
        return "History cleared"
    
    # =====================================================================
    # CONVERT COMMAND
    # =====================================================================
    
    if cmd == "convert":
        return _handle_convert(cmd_args)
    
    if cmd == "units":
        return _show_units()
    
    # =====================================================================
    # LAST RESULT
    # =====================================================================
    
    if cmd == "ans":
        if _state.last_result is None:
            return "No previous result"
        return _state._format_result(_state.last_result)
    
    if cmd == "last":
        return _handle_history(limit=1)
    
    # =====================================================================
    # EXPRESSION EVALUATION
    # =====================================================================
    
    # Join all args as expression
    expression: str = " ".join(str(a) for a in args)
    
    try:
        result = _safe_eval(expression)
        formatted = _state._format_result(result)
        _state.last_result = result
        _state._add_to_history(expression, formatted)
        
        _logger.info("[CALC_PLUGIN] %s = %s", expression, formatted)
        
        return formatted
        
    except ValueError as e:
        _logger.warning("[CALC_PLUGIN] Calculation error: %s", e)
        return str(e)
    
    except Exception as e:
        _logger.exception("[CALC_PLUGIN] Unexpected error")
        return f"ERR_CALCULATION_ERROR: {e}"


def _show_help() -> str:
    """Show calculator help."""
    return """Calc Plugin Help
=================

USAGE:
  calc <expression>     - Evaluate expression
  calc <function>       - Use built-in function
  calc <command>       - Run calculator command

ARITHMETIC:
  +        Addition
  -        Subtraction
  *        Multiplication
  /        Division
  //       Integer division
  %        Modulo
  ** or ^  Power

FUNCTIONS:
  sqrt(x)    Square root
  cbrt(x)    Cube root
  sin(x)     Sine
  cos(x)     Cosine
  tan(x)     Tangent
  log(x)     Base-10 log
  ln(x)      Natural log
  exp(x)     e^x
  abs(x)     Absolute value
  ceil(x)    Ceiling
  floor(x)   Floor
  factorial(x) Factorial

CONSTANTS:
  pi       3.14159...
  e        2.71828...
  tau      6.28318...
  phi      Golden ratio (1.618...)

MEMORY:
  m+ <n>      Add to memory
  m- <n>      Subtract from memory
  mr          Recall memory
  mc          Clear memory
  ms <slot>   Store in memory slot

CONVERSIONS:
  convert <value> <unit> to <unit>
  units        Show available units

MODE:
  deg         Set degrees mode
  rad         Set radians mode
  mode        Show current mode

HISTORY:
  history     Show calculation history
  clearh      Clear history
  ans         Show last result

EXAMPLES:
  calc 2 + 2
  calc sqrt(16) * 2
  calc sin(30)
  calc 5!
  calc convert 100 km to mi
  calc m+ 42
  calc mr
"""


def _show_units() -> str:
    """Show available unit conversions."""
    return """Available Unit Conversions
==========================

LENGTH (metric prefixes work):
  m, km, cm, mm, mi, ft, in, yd

WEIGHT/MASS:
  g, kg, mg, lb, oz

TEMPERATURE:
  c, celsius, f, fahrenheit, k, kelvin

EXAMPLES:
  calc convert 100 km to mi
  calc convert 32 f to c
  calc convert 1 kg to lb
"""


# =====================================================================
# COMMAND HANDLERS
# =====================================================================

def _handle_m_plus(args: tuple) -> str:
    """Handle M+ command."""
    if not args:
        if _state.last_result is not None:
            val = _state.last_result
        else:
            return "ERR_NO_VALUE"
    else:
        try:
            val = float(args[0])
        except ValueError:
            return f"ERR_INVALID_VALUE: {args[0]}"
    
    current = _state.memory[_state.current_memory]
    _state.memory[_state.current_memory] = (current or 0) + val
    return f"M+{_state._format_result(val)} -> {_state._format_result(_state.memory[_state.current_memory])}"


def _handle_m_minus(args: tuple) -> str:
    """Handle M- command."""
    if not args:
        if _state.last_result is not None:
            val = _state.last_result
        else:
            return "ERR_NO_VALUE"
    else:
        try:
            val = float(args[0])
        except ValueError:
            return f"ERR_INVALID_VALUE: {args[0]}"
    
    current = _state.memory[_state.current_memory]
    _state.memory[_state.current_memory] = (current or 0) - val
    return f"M-{_state._format_result(val)} -> {_state._format_result(_state.memory[_state.current_memory])}"


def _handle_mr() -> str:
    """Handle MR (memory recall) command."""
    val = _state.memory[_state.current_memory]
    if val is None:
        return "Memory is empty"
    return _state._format_result(val)


def _handle_mc() -> str:
    """Handle MC (memory clear) command."""
    _state.memory = [None] * MEMORY_SLOTS
    _state.current_memory = 0
    return "Memory cleared"


def _handle_ms(args: tuple) -> str:
    """Handle MS (memory store) command."""
    if not args:
        return "ERR_USAGE: ms <slot>"
    
    try:
        slot = int(args[0])
        if not (0 <= slot < MEMORY_SLOTS):
            return f"ERR_INVALID_SLOT (0-{MEMORY_SLOTS-1})"
        
        val = _state.last_result if len(args) == 1 else float(args[1])
        _state.memory[slot] = val
        _state.current_memory = slot
        return f"Stored in M{slot}: {_state._format_result(val)}"
        
    except ValueError:
        return f"ERR_INVALID_VALUE: {args[0]}"


def _handle_mode(args: tuple) -> str:
    """Handle mode command."""
    if not args:
        return f"Angle mode: {_state.angle_mode}"
    
    mode = str(args[0]).lower()
    if mode in ("deg", "degrees"):
        _state.angle_mode = "deg"
        return "Angle mode: degrees"
    elif mode in ("rad", "radians"):
        _state.angle_mode = "rad"
        return "Angle mode: radians"
    else:
        return f"ERR_INVALID_MODE: {mode} (use 'deg' or 'rad')"


def _handle_history(limit: Optional[int] = None) -> str:
    """Handle history command."""
    history = _state.history
    if limit:
        history = history[-limit:]
    
    if not history:
        return "No history"
    
    lines = [f"History ({len(_state.history)} total):"]
    for i, entry in enumerate(history, 1):
        lines.append(f"  {i}. {entry}")
    
    return "\n".join(lines)


def _handle_convert(args: tuple) -> str:
    """Handle unit conversion."""
    if len(args) < 4:
        return "ERR_USAGE: convert <value> <from_unit> to <to_unit>"
    
    try:
        value = float(args[0])
    except ValueError:
        return f"ERR_INVALID_VALUE: {args[0]}"
    
    from_unit = str(args[1])
    
    # Find 'to' keyword
    to_index = None
    for i, arg in enumerate(args[2:], 2):
        if str(arg).lower() == "to":
            to_index = i
            break
    
    if to_index is None:
        return "ERR_USAGE: convert <value> <from_unit> to <to_unit>"
    
    to_unit = str(args[to_index + 1]) if to_index + 1 < len(args) else ""
    
    if not to_unit:
        return "ERR_USAGE: convert <value> <from_unit> to <to_unit>"
    
    try:
        result = _convert_units(value, from_unit, to_unit)
        formatted = _state._format_result(result)
        return f"{value} {from_unit} = {formatted} {to_unit}"
        
    except ValueError as e:
        return str(e)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
