"""Static (AST) validation of submitted Python code.

This is layer 1 of 2. It runs in the parent process *before* anything is
executed, and rejects code that is not even allowed to reach the jail.
Layer 2 is the runtime audit hook in :mod:`sandbox.launcher`, which
enforces the same policy on live behaviour (open paths, sockets, imports)
in case a construct slips past this static check.

Policy
------
Imports: allowlist only. A module is importable iff its top-level name is
in :data:`ALLOWED_MODULES`. Everything else (``os``, ``sys``,
``subprocess``, ``socket``, ``ctypes``, ``pathlib``, ``urllib``, ...) is
rejected. Relative imports are rejected.

Banned builtins: ``eval``, ``exec``, ``compile``, ``__import__``,
``breakpoint``, ``getattr``, ``setattr``, ``delattr``, ``hasattr``,
``globals``, ``locals``, ``vars``. ``getattr``/``setattr`` are banned
because they are the classic route to dunder access via strings
(``getattr(x, "__class__")``). ``open`` is ALLOWED. The runtime hook
restricts which paths it may touch.

Dunder abuse: any attribute or name starting with ``__`` (other than the
module-level ``__name__``) is rejected: ``x.__class__``,
``x.__subclasses__()``, ``__builtins__``, etc.

Size limits: source > ``MAX_SOURCE_BYTES`` or an AST with more than
``MAX_AST_NODES`` nodes is rejected, so a hostile submission cannot DoS
the validator itself.

What this does NOT do: it cannot see through dynamically built strings
(``eval("...")`` is banned, but a string passed to an allowed function is
opaque). That is why the runtime audit hook exists as layer 2.
"""

import ast

MAX_SOURCE_BYTES = 65_536
MAX_AST_NODES = 20_000

# Pure-computation / data-handling stdlib modules. No I/O beyond open(),
# no processes, no network, no introspection, no dynamic code loading.
ALLOWED_MODULES = frozenset(
    {
        "array",
        "base64",
        "binascii",
        "bisect",
        "calendar",
        "collections",
        "copy",
        "csv",
        "dataclasses",
        "datetime",
        "decimal",
        "email",
        "enum",
        "fractions",
        "functools",
        "hashlib",
        "heapq",
        "hmac",
        "html",
        "ipaddress",
        "itertools",
        "json",
        "math",
        "operator",
        "pprint",
        "random",
        "re",
        "secrets",
        "statistics",
        "string",
        "struct",
        "textwrap",
        "time",
        "typing",
        "unicodedata",
        "uuid",
        "xml",
        "zlib",
    }
)

# Builtins that must never be callable from submitted code.
BANNED_BUILTINS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "breakpoint",
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
        "globals",
        "locals",
        "vars",
    }
)


class _Checker(ast.NodeVisitor):
    def __init__(self):
        self.violations = []
        self._nodes = 0

    def visit(self, node):
        self._nodes += 1
        if self._nodes > MAX_AST_NODES:
            self.violations.append(
                f"AST node count exceeds limit ({MAX_AST_NODES})"
            )
            return  # stop descending; already over the limit
        super().visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top not in ALLOWED_MODULES:
                self.violations.append(
                    f"line {node.lineno}: import of '{alias.name}' is not allowed "
                    f"(top-level module '{top}' is not on the import allowlist)"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.level > 0:
            self.violations.append(
                f"line {node.lineno}: relative imports are not allowed"
            )
        elif node.module is not None:
            top = node.module.split(".")[0]
            if top not in ALLOWED_MODULES:
                self.violations.append(
                    f"line {node.lineno}: import from '{node.module}' is not allowed "
                    f"(top-level module '{top}' is not on the import allowlist)"
                )
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            if node.id in BANNED_BUILTINS:
                self.violations.append(
                    f"line {node.lineno}: use of builtin '{node.id}' is not allowed"
                )
            elif node.id.startswith("__") and node.id != "__name__":
                self.violations.append(
                    f"line {node.lineno}: dunder name '{node.id}' is not allowed"
                )
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr.startswith("__"):
            self.violations.append(
                f"line {node.lineno}: dunder attribute '.{node.attr}' is not allowed"
            )
        self.generic_visit(node)


def validate_source(source):
    """Validate Python source. Returns a list of violations (empty = OK).

    Raises ValueError if the source is not a string, SyntaxError if it
    does not parse. Both are reported as violations, never raised to the
    caller of :func:`execute`.
    """
    violations = []
    if not isinstance(source, str):
        return ["submitted code must be a string"]
    if len(source.encode("utf-8", "replace")) > MAX_SOURCE_BYTES:
        return [
            f"source exceeds size limit ({MAX_SOURCE_BYTES} bytes, "
            f"got {len(source.encode('utf-8', 'replace'))})"
        ]
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"syntax error: {exc}"]
    checker = _Checker()
    checker.visit(tree)
    violations.extend(checker.violations)
    return violations
