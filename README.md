# Sandboxed Code Executor

One of Suraj Sharma's 12 agentic-AI projects: run agent-written code
inside a sandbox so agents can code without burning the server. Spec:
E2B/gVisor microVMs, zero network egress, resource limits, AST
validation, isolated file systems.

## What this is

A Python library (`sandbox`) that executes untrusted Python code inside a
**hardened subprocess jail** and returns a structured result (status, exit
code, stdout/stderr, CPU time, peak RSS, wall time, timed-out flag, output
artifacts). Intended adoption: the Spark's autonomous coding loop submits
agent-written code here instead of running it directly on the Spark.

## The honest adaptation: no E2B/gVisor on this box

E2B and gVisor do not exist on the Spark, and the sandboxing primitives
that would replace them are **blocked for the unprivileged user**:

- `bwrap` (bubblewrap) is installed but unusable: every invocation fails
  (`setting up uid map: Permission denied`, and `--unshare-net` fails with
  `loopback: Failed RTM_NEWADDR: Operation not permitted`).
- `unshare -n` / `unshare -Urm` fail with `Operation not permitted`
  (user namespaces cannot be created: writing `uid_map` is denied).
- `systemd-nspawn` needs root and a container image; neither is available.

So this project is the honest subset: a **two-layer subprocess jail**
built from what the box actually has. It is genuinely useful: it stops the realistic failure modes of
agent-written code, but it is **not** a microVM, and this README says
exactly where the boundary is.

### Layer 1: static AST validation (`sandbox/validator.py`)

Runs before anything executes. Rejects:

- **Imports outside an allowlist** (~35 pure-computation stdlib modules:
  `math`, `json`, `re`, `random`, `statistics`, `datetime`, `decimal`,
  `csv`, `collections`, `itertools`, `functools`, `hashlib`, …).
  `os`, `sys`, `subprocess`, `socket`, `ctypes`, `pathlib`, `shutil`,
  `multiprocessing`, `threading`, `importlib`, `urllib`, `http`,
  `asyncio`, `inspect`, `signal`, … are all rejected. Relative imports
  are rejected.
- **Dangerous builtins**: `eval`, `exec`, `compile`, `__import__`,
  `breakpoint`, `getattr`, `setattr`, `delattr`, `hasattr`, `globals`,
  `locals`, `vars`. (`getattr` is banned because it is the classic route
  to dunder access via strings.)
- **Dunder abuse**: any attribute or name starting with `__` (except the
  module-level `__name__`), e.g. `x.__class__`, `().__class__.__base__`.
- **Oversized submissions**: source > 64 KiB or AST > 20,000 nodes.

`open()` is *allowed* statically. The runtime hook restricts which
paths it may touch.

### Layer 2: runtime audit hook (`sandbox/_launcher.py`)

The child runs as `python3 -I -S -u _launcher.py main.py <run_dir>`.
Before the submitted code runs, the launcher installs a
`sys.addaudithook` that enforces, on live behaviour:

- `open`: reads only under the run directory, the stdlib, or `/dev/null`;
  writes/creates only under the run directory. Paths are resolved with
  `realpath` first, so a symlink inside the run dir pointing outside is
  still blocked.
- `import`: any top-level module on the deny list is refused even if the
  AST layer was bypassed (tested with `validate=False`).
- `socket.*`, `subprocess.Popen`, `os.*`, `pty.spawn`, `ctypes.*`:
  refused outright.

The hook cannot be removed from Python (no API exists), and the modules
that could remove it from C (`ctypes`) or bypass it (`os`,
`subprocess`) are themselves blocked.

### Process containment (`sandbox/executor.py`)

- Fresh temp dir per run (`cwd` = run dir); input files can be supplied;
  files the code creates are copied out as `result.artifacts`, then the
  run dir is deleted (unless `keep_run_dir=True`).
- Scrubbed environment: only `PATH`, `HOME`/`TMPDIR` (= run dir),
  locale, and Python isolation flags. No secrets, no proxy vars.
- stdin from `/dev/null`; `start_new_session=True` so the whole process
  group is killed on timeout.
- `preexec_fn` resource limits: `RLIMIT_CPU`, `RLIMIT_AS` (memory),
  `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_CORE=0`, and an adaptive
  `RLIMIT_NPROC` (current per-uid process count + 32; see limits below).
- Wall-clock timeout enforced by the parent; stdout/stderr captured and
  capped at 1 MiB each.
- CPU time and peak RSS reported from `getrusage(RUSAGE_CHILDREN)`.

## What the sandbox enforces

| Threat | Enforcement | Evidence |
|---|---|---|
| Banned import (`os`, `subprocess`, `socket`, …) | AST allowlist rejects before execution | demo §5, §3a |
| Read outside the run dir (`/etc/passwd`, `~/.bashrc`) | audit hook blocks the `open` | demo §2 |
| Write outside the run dir | audit hook blocks the `open` | tests |
| Symlink escape | `realpath` resolution in the hook | tests |
| Network socket | AST rejects `socket`; hook blocks it even if AST is bypassed | demo §3a/§3b |
| Unbounded memory | `RLIMIT_AS` → `MemoryError` | demo §4 |
| Infinite loop / CPU burn | wall-clock timeout (kills group) + `RLIMIT_CPU` | demo §6, tests |
| Fork bomb | `os`/`multiprocessing` unreachable (AST); adaptive `RLIMIT_NPROC`; wall-clock kill as backstop | tests + demo §6 note |
| Cross-run contamination | fresh temp dir per run | tests |

## What it does NOT enforce (known gaps)

- **No network namespace.** Zero egress is enforced by blocking the
  `socket` module and the `socket.*` audit events, not by removing the
  network interface. A vulnerability in the interpreter itself, or a
  stdlib module that opens sockets without going through the audited
  paths, would not be caught. On this box the namespace that would give
  true zero-egress cannot be created by an unprivileged user.
- **No mount namespace / chroot.** The child process can *see* the
  filesystem layout (e.g. `open` attempts reveal existence via error
  type), but the audit hook blocks reads/writes outside the run dir and
  stdlib. It cannot hide file *names* or metadata.
- **No CPU accounting across a fork bomb.** `RLIMIT_CPU` is per-process
  and `RLIMIT_NPROC` must sit above the box's already-running ~170
  processes for this user, so the cap is adaptive (current count + 32)
  rather than tight. Containment of a fork attempt relies on the AST ban
  on `os`/`multiprocessing` plus the wall-clock kill.
- **Dynamic code execution is enforced statically only.** The launcher
  needs `compile`/`exec` itself, so those audit events are not blocked
  at runtime. `eval`/`exec`/`compile`/`__import__` are rejected by the
  AST validator; running with `validate=False` loses that layer (the
  flag exists only for tests of the runtime hook).
- **Not a security boundary against a determined local attacker.** This
  is a safety harness for agent-written code that is buggy or careless,
  not a sandbox for actively hostile code. A microVM (E2B/gVisor) would
  be needed for that threat model.

## Usage

```python
from sandbox import execute
from sandbox.executor import SandboxConfig

result = execute("import json\nprint(json.dumps({'ok': True}))\n")
print(result.status, result.returncode, result.stdout)

# Tighter limits, input files, artifacts back
result = execute(
    "open('out.txt', 'w').write(open('in.txt').read().upper())\n",
    config=SandboxConfig(cpu_seconds=5, wall_seconds=10, memory_mb=256),
    files={"in.txt": "hello"},
)
print(result.artifacts)  # {'out.txt': b'HELLO'}
```

CLI:

```bash
python3 -m sandbox check code.py   # AST-validate only
python3 -m sandbox run code.py --cpu 5 --mem 256 --timeout 10
```

## Run the demo and tests

```bash
python3 demo/demo.py                    # live proof; transcript in demo/evidence.txt
python3 -m unittest discover -s tests -v
```

## Layout

```
sandbox/            library: validator.py (AST), _launcher.py (audit hook),
                    executor.py (jail + limits + results), cli.py
demo/               demo.py + evidence.txt (observed transcript)
tests/              test_validator.py, test_executor.py,
                    test_isolation.py, test_limits.py
pyproject.toml      setuptools, stdlib only, no third-party dependencies
```

## Version

0.1.0: stdlib only, Python ≥ 3.11, tested on the Spark (Python 3.12.3).
