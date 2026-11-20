"""Isolation tests: a run cannot see or touch anything outside its own dir."""

import os
import unittest

from sandbox.executor import SandboxConfig, execute

SECRET = "sbox-isolation-marker"


class TestFilesystemIsolation(unittest.TestCase):
    def test_cannot_read_etc_passwd(self):
        code = "print(open('/etc/passwd').read())\n"
        result = execute(code)
        self.assertEqual(result.status, "error")
        self.assertNotIn("root:", result.stdout)
        self.assertIn("blocked", result.stderr)

    def test_cannot_read_home_directory(self):
        home = os.path.expanduser("~")
        code = f"print(open({home!r} + '/.bashrc').read())\n"
        result = execute(code)
        self.assertEqual(result.status, "error")
        self.assertNotIn("bashrc", result.stdout.lower().replace("blocked", ""))

    def test_cannot_write_outside_run_dir(self):
        marker = "/tmp/sbox-must-not-exist-marker"
        if os.path.exists(marker):
            os.unlink(marker)
        code = f"open({marker!r}, 'w').write('evil')\n"
        result = execute(code)
        self.assertEqual(result.status, "error")
        self.assertFalse(os.path.exists(marker), "sandboxed code wrote outside its dir!")
        self.assertIn("blocked", result.stderr)

    def test_symlink_escape_blocked(self):
        # Plant a symlink inside a run dir pointing at /etc/passwd, then
        # invoke the launcher directly on it: the audit hook resolves the
        # real path, so the read must still be blocked.
        import subprocess
        import sys
        import tempfile

        launcher = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sandbox",
            "_launcher.py",
        )
        run_dir = tempfile.mkdtemp(prefix="sbox-link-")
        try:
            code_path = os.path.join(run_dir, "main.py")
            with open(code_path, "w") as f:
                f.write("print(open('link.txt').read())\n")
            os.symlink("/etc/passwd", os.path.join(run_dir, "link.txt"))
            proc = subprocess.run(
                [sys.executable, "-I", "-S", "-u", launcher, code_path, run_dir],
                cwd=run_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn("root:", proc.stdout)
            self.assertIn("blocked", proc.stderr)
        finally:
            import shutil

            shutil.rmtree(run_dir, ignore_errors=True)

    def test_runs_do_not_see_each_other(self):
        first = execute("open('secret.txt', 'w').write('" + SECRET + "')\nprint('wrote')\n")
        self.assertEqual(first.status, "ok")
        second = execute(
            "try:\n"
            "    print(open('secret.txt').read())\n"
            "except FileNotFoundError:\n"
            "    print('not found')\n"
        )
        self.assertEqual(second.status, "ok")
        self.assertEqual(second.stdout.strip(), "not found")

    def test_relative_parent_escape_blocked(self):
        code = "print(open('../main.py').read())\n"
        result = execute(code)
        self.assertEqual(result.status, "error")
        self.assertIn("blocked", result.stderr)


class TestNetworkBlock(unittest.TestCase):
    def test_socket_import_rejected_by_validator(self):
        result = execute("import socket\nsocket.create_connection(('8.8.8.8', 53))\n")
        self.assertEqual(result.status, "validation_error")
        self.assertTrue(any("socket" in v for v in result.validation_errors))

    def test_runtime_hook_blocks_socket_even_if_validator_bypassed(self):
        # validate=False simulates an AST bypass: layer 2 must still stop it.
        code = (
            "import socket\n"
            "socket.create_connection(('8.8.8.8', 53), timeout=2)\n"
            "print('connected')\n"
        )
        result = execute(code, validate=False)
        self.assertEqual(result.status, "error")
        self.assertNotIn("connected", result.stdout)
        self.assertIn("blocked", result.stderr)

    def test_runtime_hook_blocks_os_import_even_if_validator_bypassed(self):
        result = execute("import os\nprint(os.listdir('/'))\n", validate=False)
        self.assertEqual(result.status, "error")
        self.assertNotIn("blocked", result.stdout)
        self.assertIn("blocked", result.stderr)

    def test_runtime_hook_blocks_listdir_outside_allowed_dirs(self):
        # os.listdir is allowed for the import system (stdlib/run-dir
        # package scans) but not as a user-code directory probe.
        result = execute(
            "import os\nprint(os.listdir('/etc'))\n", validate=False
        )
        self.assertEqual(result.status, "error")
        self.assertNotIn("passwd", result.stdout)
        self.assertIn("blocked", result.stderr)


if __name__ == "__main__":
    unittest.main()
