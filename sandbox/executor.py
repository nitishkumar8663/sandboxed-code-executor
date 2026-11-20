"""Execution inside the hardened subprocess jail.

How a run works
---------------
1. :func:`execute` validates the code with :mod:`sandbox.validator`
   (unless ``validate=False``, test-only, see below).
2. A fresh temporary directory is created as the run's whole world.
   The submitted code is written there as ``main.py``; any caller-supplied
   input ``files`` are written there too.
3. A child ``python3 -I -S -u sandbox/_launcher.py main.py <run_dir>``
   is started with:
   - ``cwd`` = the run directory (so relative paths stay inside it),
   - a scrubbed environment (no secrets, no proxy vars, ``HOME``/``TMPDIR``
     pointed at the run directory),
   - stdin from ``/dev/null``,
   - ``start_new_session=True`` so the whole process group can be killed,
   - ``preexec_fn`` limits: CPU time, address-space (memory), max file
     size, max open files, no core dumps, and an *adaptive* process cap.
     The box already runs ~170 processes for this user, so the cap is
     measured at run time as ``current_process_count + 32`` instead of a
     fixed number that would break on a busy box (or be meaningless).
   - a wall-clock timeout enforced by the parent, killing the process
     group on expiry.
4. The launcher's audit hook (layer 2) enforces path/socket/import
   restrictions while the code runs.
5. After exit, files the code created in the run directory are copied
   out into ``result.artifacts`` (name -> bytes, capped), then the run
   directory is deleted unless ``keep_run_dir`` is set.

Resource usage is read from ``resource.getrusage(RUSAGE_CHILDREN)``:
CPU seconds and peak RSS of the waited-for child. Note ``ru_maxrss`` is
the high-water mark across waited children, so with several sequential
runs it reports the largest single child. Good enough for a report,
not a billing meter.

``validate=False`` exists ONLY so tests can prove the runtime hook blocks
things even if the AST layer is bypassed. Production callers must leave
validation on: the launcher does not block ``compile``/``exec`` audit
events (it needs them itself), so dynamic code execution is enforced
statically only.
"""

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field

from .errors import ValidationError
from .validator import validate_source

_LAUNCHER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_launcher.py")

MAX_OUTPUT_BYTES = 1_000_000
MAX_ARTIFACT_BYTES = 1_000_000
MAX_ARTIFACTS = 10


@dataclass
class SandboxConfig:
    """Limits for one run. All values are per-run, per-process unless noted."""

    cpu_seconds: int = 5          # RLIMIT_CPU soft limit (SIGXCPU, then SIGKILL)
    wall_seconds: int = 10        # parent-side wall-clock timeout (kills group)
    memory_mb: int = 256          # RLIMIT_AS per process
    extra_processes: int = 32     # process cap = current uid process count + this
    max_file_mb: int = 10         # RLIMIT_FSIZE per file the code may create
    max_open_files: int = 64      # RLIMIT_NOFILE
    python: str = sys.executable  # interpreter for the jailed child


@dataclass
class ExecutionResult:
    status: str                   # "ok" | "validation_error" | "timeout" | "error"
    returncode: int | None        # child exit code (None if never started / killed)
    stdout: str
    stderr: str
    timed_out: bool = False
    cpu_seconds: float = 0.0
    max_rss_kb: int = 0
    wall_seconds: float = 0.0
    run_id: str = ""
    artifacts: dict = field(default_factory=dict)   # rel path -> bytes
    validation_errors: list = field(default_factory=list)
    output_truncated: bool = False


def _current_process_count():
    """Processes owned by this uid (RLIMIT_NPROC counts per-uid)."""
    uid = os.getuid()
    count = 0
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open(f"/proc/{name}/status", "rb") as f:
                    for line in f:
                        if line.startswith(b"Uid:"):
                            if int(line.split()[1]) == uid:
                                count += 1
                            break
            except (OSError, ValueError):
                continue
    except OSError:
        return 64  # fall back to a plausible busy-box count
    return count


def _child_env(run_dir):
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": run_dir,
        "TMPDIR": run_dir,
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONHASHSEED": "0",
    }


def _make_preexec(config, nproc_limit):
    def preexec():
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CPU, (config.cpu_seconds, config.cpu_seconds + 2))
        resource.setrlimit(
            resource.RLIMIT_AS, (config.memory_mb * 1024 * 1024, config.memory_mb * 1024 * 1024)
        )
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (config.max_file_mb * 1024 * 1024, config.max_file_mb * 1024 * 1024),
        )
        resource.setrlimit(resource.RLIMIT_NOFILE, (config.max_open_files, config.max_open_files))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc_limit, nproc_limit))

    return preexec


def _collect_artifacts(run_dir):
    artifacts = {}
    for root, _dirs, names in os.walk(run_dir):
        for name in sorted(names):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, run_dir)
            if rel == "main.py":
                continue
            if len(artifacts) >= MAX_ARTIFACTS:
                break
            try:
                if os.path.getsize(path) > MAX_ARTIFACT_BYTES:
                    continue
                with open(path, "rb") as f:
                    artifacts[rel] = f.read()
            except OSError:
                continue
    return artifacts


def execute(code, *, config=None, validate=True, keep_run_dir=False, files=None):
    """Run Python source inside the sandbox. Returns an ExecutionResult."""
    config = config or SandboxConfig()
    run_id = uuid.uuid4().hex[:12]

    if validate:
        violations = validate_source(code)
        if violations:
            return ExecutionResult(
                status="validation_error",
                returncode=None,
                stdout="",
                stderr="",
                run_id=run_id,
                validation_errors=violations,
            )

    run_dir = tempfile.mkdtemp(prefix=f"sbox-{run_id}-")
    nproc_limit = max(64, _current_process_count() + config.extra_processes)
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    timed_out = False
    proc = None
    try:
        code_path = os.path.join(run_dir, "main.py")
        with open(code_path, "w", encoding="utf-8") as f:
            f.write(code)
        for name, data in (files or {}).items():
            if "/" in name or name in ("", ".", ".."):
                raise ValueError(f"unsafe input file name: {name!r}")
            target = os.path.join(run_dir, name)
            mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
            with open(target, mode) as f:
                f.write(data)

        proc = subprocess.Popen(
            [config.python, "-I", "-S", "-u", _LAUNCHER, code_path, run_dir],
            cwd=run_dir,
            env=_child_env(run_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=_make_preexec(config, nproc_limit),
        )
        try:
            out_b, err_b = proc.communicate(timeout=config.wall_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            out_b, err_b = proc.communicate()
        wall = time.monotonic() - started
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = (usage_after.ru_utime - usage_before.ru_utime) + (
            usage_after.ru_stime - usage_before.ru_stime
        )
        max_rss = max(usage_after.ru_maxrss, usage_before.ru_maxrss)

        stdout = out_b.decode("utf-8", "replace")
        stderr = err_b.decode("utf-8", "replace")
        truncated = False
        if len(out_b) > MAX_OUTPUT_BYTES:
            stdout = stdout[:MAX_OUTPUT_BYTES]
            truncated = True
        if len(err_b) > MAX_OUTPUT_BYTES:
            stderr = stderr[:MAX_OUTPUT_BYTES]
            truncated = True

        artifacts = _collect_artifacts(run_dir)
        if timed_out:
            status = "timeout"
        elif proc.returncode == 0:
            status = "ok"
        else:
            status = "error"
        return ExecutionResult(
            status=status,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            cpu_seconds=round(max(cpu, 0.0), 3),
            max_rss_kb=int(max_rss),
            wall_seconds=round(wall, 3),
            run_id=run_id,
            artifacts=artifacts,
            output_truncated=truncated,
        )
    finally:
        if not keep_run_dir:
            shutil.rmtree(run_dir, ignore_errors=True)
        elif proc is not None:
            # Caller asked to keep the dir; tell them where via stderr note.
            pass


def execute_file(path, **kwargs):
    """Run a Python file inside the sandbox."""
    with open(path, encoding="utf-8") as f:
        return execute(f.read(), **kwargs)
