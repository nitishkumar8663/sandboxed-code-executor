"""Demo: prove the sandbox with observed evidence.

Runs six scenarios through the library and prints/writes a transcript:
  1. benign code succeeds and returns a file artifact
  2. exfiltration attempt (read /etc/passwd) is blocked, nothing leaks
  3. network attempt (import socket) is rejected; runtime hook blocks it
     even if validation is bypassed
  4. unbounded memory allocation is killed by the memory cap
  5. banned import (subprocess) is rejected before execution
  6. infinite loop is killed by the wall-clock timeout

Run:  python3 demo/demo.py            (from the project root)
The transcript is written to demo/evidence.txt.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbox import execute  # noqa: E402
from sandbox.executor import SandboxConfig  # noqa: E402

EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence.txt")


def _show(title, result, expect):
    lines = [
        f"### {title}",
        f"status:       {result.status}",
        f"returncode:   {result.returncode}",
        f"timed_out:    {result.timed_out}",
        f"cpu_seconds:  {result.cpu_seconds}",
        f"max_rss_kb:   {result.max_rss_kb}",
        f"wall_seconds: {result.wall_seconds}",
    ]
    if result.validation_errors:
        lines.append("validation errors:")
        lines.extend(f"  - {v}" for v in result.validation_errors)
    if result.artifacts:
        lines.append(f"artifacts:    {sorted(result.artifacts)}")
        for name, data in result.artifacts.items():
            lines.append(f"  {name}: {data[:80]!r}")
    if result.stdout.strip():
        lines.append(f"stdout: {result.stdout.strip()[:200]!r}")
    if result.stderr.strip():
        tail = result.stderr.strip()[-300:]
        lines.append(f"stderr (tail): {tail!r}")
    lines.append(f"EXPECTED: {expect}")
    lines.append("")
    return "\n".join(lines)


def main():
    out = []
    out.append("Sandboxed Code Executor: demo evidence")
    out.append(f"generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    out.append("")

    out.append(_show(
        "1. Benign code succeeds",
        execute(
            "import math, json\n"
            "primes = [n for n in range(2, 50) if all(n % d for d in range(2, int(math.sqrt(n)) + 1))]\n"
            "open('primes.json', 'w').write(json.dumps(primes))\n"
            "print(f'found {len(primes)} primes')\n"
        ),
        "status ok, returncode 0, primes.json returned as an artifact",
    ))

    out.append(_show(
        "2. Exfiltration attempt: read /etc/passwd",
        execute("print(open('/etc/passwd').read())\n"),
        "status error, returncode 1, stderr names the blocked read, no file content in stdout",
    ))

    out.append(_show(
        "3a. Network attempt: import socket (validation layer)",
        execute("import socket\nsocket.create_connection(('8.8.8.8', 53), timeout=2)\n"),
        "status validation_error, code never executes",
    ))
    out.append(_show(
        "3b. Network attempt: socket with validation bypassed (runtime hook layer)",
        execute(
            "import socket\nsocket.create_connection(('8.8.8.8', 53), timeout=2)\nprint('connected')\n",
            validate=False,
        ),
        "status error, audit hook blocks the import, 'connected' never prints",
    ))

    out.append(_show(
        "4. Unbounded memory allocation (512 MB vs 128 MB cap)",
        execute(
            "x = bytearray(512 * 1024 * 1024)\nprint(len(x))\n",
            config=SandboxConfig(cpu_seconds=5, wall_seconds=10, memory_mb=128),
        ),
        "status error, MemoryError in stderr, process killed by RLIMIT_AS",
    ))

    out.append(_show(
        "5. Banned import: subprocess",
        execute("import subprocess\nprint(subprocess.run(['id'], capture_output=True, text=True).stdout)\n"),
        "status validation_error, code never executes",
    ))

    out.append(_show(
        "6. Fork-bomb route + infinite loop (wall-clock timeout)",
        execute(
            "while True:\n    pass\n",
            config=SandboxConfig(cpu_seconds=30, wall_seconds=3, memory_mb=256),
        ),
        "status timeout, timed_out True, process group killed after ~3s. "
        "Note: a real fork bomb cannot even be written: os/multiprocessing are "
        "rejected at validation (scenario 5 pattern), and the process cap bounds forks.",
    ))

    text = "\n".join(out)
    print(text)
    with open(EVIDENCE, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"evidence written to {EVIDENCE}")


if __name__ == "__main__":
    main()
