"""Sandboxed Code Executor. Run agent-written Python code inside a
hardened subprocess jail.

Public API:
    execute(code, ...) -> ExecutionResult
    execute_file(path, ...) -> ExecutionResult
    SandboxConfig, ExecutionResult, ValidationError
"""

from .errors import SandboxError, ValidationError
from .executor import ExecutionResult, SandboxConfig, execute, execute_file
from .validator import ALLOWED_MODULES, validate_source

__all__ = [
    "ALLOWED_MODULES",
    "ExecutionResult",
    "SandboxConfig",
    "SandboxError",
    "ValidationError",
    "execute",
    "execute_file",
    "validate_source",
]

__version__ = "0.1.0"
