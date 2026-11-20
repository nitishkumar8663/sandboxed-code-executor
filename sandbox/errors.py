"""Error types for the sandboxed code executor."""


class SandboxError(Exception):
    """Base class for sandbox errors."""


class ValidationError(SandboxError):
    """Submitted code failed static (AST) validation.

    Attributes:
        violations: human-readable list of what was rejected and why.
    """

    def __init__(self, violations):
        self.violations = list(violations)
        super().__init__(
            "code rejected by AST validation:\n" + "\n".join(f"  - {v}" for v in self.violations)
        )
