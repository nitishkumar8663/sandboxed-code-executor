"""Resource-limit tests: wall-clock timeout, CPU cap, memory cap."""

import signal
import unittest

from sandbox.executor import SandboxConfig, execute


class TestWallClockTimeout(unittest.TestCase):
    def test_sleep_loop_is_killed(self):
        result = execute(
            "while True:\n    pass\n",
            config=SandboxConfig(cpu_seconds=30, wall_seconds=2, memory_mb=256),
        )
        self.assertEqual(result.status, "timeout")
        self.assertTrue(result.timed_out)
        self.assertLess(result.wall_seconds, 6.0)

    def test_slow_but_finite_code_is_not_killed(self):
        result = execute(
            "import time\ntime.sleep(1)\nprint('finished')\n",
            config=SandboxConfig(cpu_seconds=5, wall_seconds=10, memory_mb=256),
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.stdout.strip(), "finished")


class TestCpuLimit(unittest.TestCase):
    def test_busy_loop_hits_cpu_limit(self):
        result = execute(
            "while True:\n    pass\n",
            config=SandboxConfig(cpu_seconds=1, wall_seconds=10, memory_mb=256),
        )
        # Killed by SIGXCPU (24) at the soft limit or SIGKILL (9) at the hard
        # limit. Either way it is an error, not a timeout, not a hang.
        self.assertEqual(result.status, "error")
        self.assertFalse(result.timed_out)
        self.assertIn(result.returncode, (-signal.SIGXCPU, -signal.SIGKILL))
        self.assertLess(result.wall_seconds, 8.0)


class TestMemoryLimit(unittest.TestCase):
    def test_huge_allocation_is_killed(self):
        result = execute(
            "x = bytearray(512 * 1024 * 1024)\nprint(len(x))\n",
            config=SandboxConfig(cpu_seconds=5, wall_seconds=10, memory_mb=128),
        )
        self.assertEqual(result.status, "error")
        self.assertFalse(result.timed_out)
        self.assertIn("MemoryError", result.stderr)

    def test_modest_allocation_succeeds(self):
        result = execute(
            "x = bytearray(10 * 1024 * 1024)\nprint(len(x))\n",
            config=SandboxConfig(cpu_seconds=5, wall_seconds=10, memory_mb=128),
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.stdout.strip(), str(10 * 1024 * 1024))


class TestOutputLimit(unittest.TestCase):
    def test_stdout_is_capped_not_unbounded(self):
        # 2 MB of output with the default 1 MB capture cap.
        result = execute("print('x' * (2 * 1024 * 1024))\n")
        self.assertEqual(result.status, "ok")
        self.assertTrue(result.output_truncated)


if __name__ == "__main__":
    unittest.main()
