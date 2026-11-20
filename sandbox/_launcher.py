"""In-jail launcher (layer 2 of 2).

The parent (:mod:`sandbox.executor`) starts this script as
``python3 -I -S -u _launcher.py <code_path> <run_dir>`` with cwd set to a
fresh per-run directory. The launcher installs a :func:`sys.addaudithook`
*before* the submitted code runs, then executes the code. The hook is the
runtime enforcement for everything the static AST check cannot see:

* ``open``: reads are allowed only under the run directory, the stdlib,
  or ``/dev/null``; writes/creates are allowed only under the run
  directory. A symlink inside the run dir pointing outside is caught
  because paths are resolved with :func:`os.path.realpath` first.
* ``import``: an import of a denied top-level module (``os``, ``sys``,
  ``subprocess``, ``socket``, …) is refused **when the importer is the
  submitted code itself**. Imports performed by stdlib internals are
  allowed: the stdlib routinely imports ``sys`` (e.g. ``re`` ->
  ``sre_compile`` -> ``sys``) and occasionally ``os`` (e.g. ``uu``), so a
  blanket runtime ban would break every non-trivial allowlisted module.
  The hook tells the two apart by walking the Python stack to the frame
  that issued the import: the first frame that is neither frozen
  importlib machinery nor this launcher. If that frame is the submitted
  code file, the import is the user's; anything else is stdlib-internal.
* ``socket.*``, ``subprocess.Popen``, ``os.*``, ``pty.spawn``,
  ``ctypes.*``: refused outright, with one carve-out: ``os.listdir``
  is allowed for directories under the run dir or the stdlib, because
  the import system itself scans package directories with it (finding
  ``json.decoder`` inside ``/usr/lib/python3.12/json``). Listing
  anywhere else stays blocked. Submitted code cannot import ``os``
  anyway (AST allowlist), so these events should never fire from user
  code; the hook is belt-and-braces.

The hook cannot be removed from Python code (there is no API for it),
and the modules that could remove it from C (``ctypes``) or bypass it
(``os``, ``subprocess``) are themselves blocked.

Deliberate gap, documented in the README: ``compile``/``exec`` audit
events are NOT blocked here, because the launcher itself needs
``compile``/``exec`` to run the submitted code. Dynamic code execution
(``eval``/``exec``/``compile``) is therefore enforced only statically
by the AST validator. If you run the executor with ``validate=False``
you lose that layer. That flag exists only for testing the hook itself.
"""

import os
import sys
import sysconfig
import traceback

# Top-level modules that may never be imported *by submitted code*, even
# if the AST check is bypassed. Deliberately NOT including `io`: stdlib
# internals need it, and io.open is covered by the "open" audit event.
# `uu` is included because it re-exports the real `os` module as `uu.os`.
DENIED_IMPORTS = frozenset(
    {
        "asyncio",
        "code",
        "codeop",
        "concurrent",
        "ctypes",
        "gc",
        "http",
        "importlib",
        "inspect",
        "multiprocessing",
        "os",
        "pathlib",
        "pkgutil",
        "pty",
        "resource",
        "runpy",
        "sandbox",
        "selectors",
        "shutil",
        "signal",
        "socket",
        "socketserver",
        "ssl",
        "subprocess",
        "sys",
        "threading",
        "urllib",
        "uu",
        "venv",
        "webbrowser",
        "zipimport",
        "ftplib",
        "smtplib",
        "telnetlib",
    }
)

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
_WRITE_MODES = frozenset("wax+")

_LAUNCHER_FILE = os.path.realpath(__file__)


def _importer_is_user_code(code_path):
    """True if the frame that issued the current import is the user code.

    Walks the stack newest-first, skipping this launcher's own frames
    and frozen importlib machinery; the first remaining frame is the
    importer. Returns False when no such frame can be identified
    (fail-open only for stdlib-internal imports, never for user code:
    a user-code import always has the user file on the stack).
    """
    for frame in reversed(traceback.extract_stack()):
        filename = frame.filename
        if filename.startswith("<frozen"):
            continue
        if os.path.realpath(filename) == _LAUNCHER_FILE:
            continue
        return os.path.realpath(filename) == code_path
    return False


def _build_hook(run_dir, allowed_read_dirs, code_path):
    code_path = os.path.realpath(code_path)

    def hook(event, args):
        if event == "open":
            path = args[0]
            if isinstance(path, int):
                # Opening by fd: no legitimate use inside the jail.
                raise PermissionError("sandbox: opening by file descriptor is blocked")
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            real = os.path.realpath(os.path.abspath(path))
            if real == "/dev/null":
                return
            mode = args[1] if len(args) > 1 else ""
            flags = args[2] if len(args) > 2 else 0
            is_write = False
            if isinstance(mode, str):
                is_write = any(c in mode for c in _WRITE_MODES)
            if isinstance(flags, int):
                is_write = is_write or bool(flags & _WRITE_FLAGS)
            if is_write:
                if not (real == run_dir or real.startswith(run_dir + os.sep)):
                    raise PermissionError(
                        f"sandbox: write outside the run directory is blocked: {path}"
                    )
            else:
                ok = real == run_dir or real.startswith(run_dir + os.sep)
                if not ok:
                    ok = any(
                        real == d or real.startswith(d + os.sep)
                        for d in allowed_read_dirs
                    )
                if not ok:
                    raise PermissionError(
                        f"sandbox: read outside the run directory is blocked: {path}"
                    )
            return
        if event == "import":
            module = args[0]
            top = module.split(".")[0] if isinstance(module, str) else ""
            if top in DENIED_IMPORTS and _importer_is_user_code(code_path):
                raise PermissionError(
                    f"sandbox: import of '{module}' is blocked"
                )
            return
        if event == "os.listdir":
            # The import system scans package directories with os.listdir
            # (e.g. finding json.decoder inside /usr/lib/python3.12/json).
            # Allow it only for directories under the run dir or the stdlib;
            # listing anywhere else (/, /etc, $HOME, ...) stays blocked.
            path = args[0] if args else None
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            if isinstance(path, str):
                real = os.path.realpath(os.path.abspath(path))
                ok = real == run_dir or real.startswith(run_dir + os.sep)
                if not ok:
                    ok = any(
                        real == d or real.startswith(d + os.sep)
                        for d in allowed_read_dirs
                    )
                if ok:
                    return
            raise PermissionError(f"sandbox: {event} is blocked")
        if (
            event.startswith("socket.")
            or event.startswith("os.")
            or event.startswith("ctypes.")
            or event in ("subprocess.Popen", "pty.spawn")
        ):
            raise PermissionError(f"sandbox: {event} is blocked")
        # Everything else (including "compile"/"exec", see module docstring)
        # is left to the AST validator.

    return hook


def main(argv):
    code_path, run_dir = argv[1], argv[2]
    run_dir = os.path.realpath(run_dir)
    stdlib = os.path.realpath(sysconfig.get_path("stdlib"))
    platstdlib = os.path.realpath(sysconfig.get_path("platstdlib"))
    allowed_read_dirs = [stdlib, platstdlib]

    sys.dont_write_bytecode = True
    sys.addaudithook(_build_hook(run_dir, allowed_read_dirs, code_path))
    # Drop the launcher's own directory from sys.path: submitted code must
    # only see its run directory and the stdlib.
    sys.path = [run_dir, stdlib, platstdlib]

    with open(code_path, "rb") as f:
        source = f.read()
    code = compile(source, code_path, "exec")
    globs = {"__name__": "__main__", "__file__": code_path}
    try:
        exec(code, globs)
    except SystemExit as exc:
        if exc.code is None:
            raise SystemExit(0)
        if isinstance(exc.code, int):
            raise SystemExit(exc.code)
        print(exc.code, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv)
