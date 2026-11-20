"""CLI: python -m sandbox run <file.py> | check <file.py>"""

import argparse
import sys

from .errors import ValidationError
from .executor import SandboxConfig, execute_file
from .validator import validate_source


def _build_parser():
    p = argparse.ArgumentParser(prog="sandbox", description="Sandboxed Python code executor")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a Python file inside the sandbox")
    run.add_argument("file")
    run.add_argument("--cpu", type=int, default=5, help="CPU seconds (default 5)")
    run.add_argument("--mem", type=int, default=256, help="memory cap in MB (default 256)")
    run.add_argument("--timeout", type=int, default=10, help="wall-clock seconds (default 10)")
    run.add_argument("--keep", action="store_true", help="keep the per-run directory")

    check = sub.add_parser("check", help="AST-validate a Python file without running it")
    check.add_argument("file")
    return p


def main(argv=None):
    args = _build_parser().parse_args(argv)
    try:
        with open(args.file, encoding="utf-8") as f:
            source = f.read()
    except OSError as exc:
        print(f"cannot read {args.file}: {exc}", file=sys.stderr)
        return 2

    if args.command == "check":
        violations = validate_source(source)
        if violations:
            print("REJECTED:")
            for v in violations:
                print(f"  - {v}")
            return 1
        print("OK: code passes AST validation")
        return 0

    config = SandboxConfig(
        cpu_seconds=args.cpu, memory_mb=args.mem, wall_seconds=args.timeout
    )
    result = execute_file(args.file, config=config, keep_run_dir=args.keep)
    print(f"status:      {result.status}")
    print(f"returncode:  {result.returncode}")
    print(f"timed_out:   {result.timed_out}")
    print(f"cpu_seconds: {result.cpu_seconds}")
    print(f"max_rss_kb:  {result.max_rss_kb}")
    print(f"wall_seconds:{result.wall_seconds}")
    if result.validation_errors:
        print("validation errors:")
        for v in result.validation_errors:
            print(f"  - {v}")
    if result.artifacts:
        print(f"artifacts:   {sorted(result.artifacts)}")
    if result.stdout:
        print("--- stdout ---")
        print(result.stdout, end="")
    if result.stderr:
        print("--- stderr ---")
        print(result.stderr, end="")
    return 0 if result.status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
