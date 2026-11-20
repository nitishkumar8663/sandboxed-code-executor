"""Executor tests: result structure, benign runs, validation gate, artifacts."""

import unittest

from sandbox.executor import SandboxConfig, execute, execute_file
from sandbox.validator import validate_source


class TestResultStructure(unittest.TestCase):
    def test_benign_code_succeeds(self):
        result = execute("print(40 + 2)\n")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "42")
        self.assertEqual(result.stderr, "")
        self.assertFalse(result.timed_out)
        self.assertTrue(result.run_id)
        self.assertGreaterEqual(result.cpu_seconds, 0.0)
        self.assertGreater(result.max_rss_kb, 0)
        self.assertGreater(result.wall_seconds, 0.0)

    def test_result_fields_present(self):
        result = execute("x = 1\n")
        for field in (
            "status", "returncode", "stdout", "stderr", "timed_out",
            "cpu_seconds", "max_rss_kb", "wall_seconds", "run_id",
            "artifacts", "validation_errors",
        ):
            self.assertTrue(hasattr(result, field), f"missing field {field}")

    def test_stderr_and_nonzero_exit_reported(self):
        result = execute("import math\nraise ValueError('boom')\n")
        self.assertEqual(result.status, "error")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ValueError: boom", result.stderr)

    def test_validation_error_never_executes(self):
        # The print would prove execution if it ever ran.
        result = execute("import os\nprint('PWNED')\n")
        self.assertEqual(result.status, "validation_error")
        self.assertIsNone(result.returncode)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.validation_errors)
        self.assertIn("os", result.validation_errors[0])

    def test_allowed_imports_run(self):
        code = "import json, math\nprint(json.dumps({'sqrt': math.sqrt(16)}))\n"
        result = execute(code)
        self.assertEqual(result.status, "ok")
        self.assertIn("4.0", result.stdout)

    def test_stdlib_internal_imports_still_work(self):
        # re -> sre_compile -> sys and email -> ... are stdlib-internal
        # imports of denied modules; the hook must allow them.
        for code in (
            "import re\nprint(bool(re.match('a', 'a')))\n",
            "import email\nfrom email.message import EmailMessage\n"
            "m = EmailMessage()\nm['Subject'] = 'hi'\nprint(m['Subject'])\n",
            "import functools, collections\nprint(functools.reduce(lambda a, b: a + b, [1, 2, 3]))\n",
        ):
            with self.subTest(code=code.splitlines()[0]):
                result = execute(code)
                self.assertEqual(result.status, "ok", result.stderr)


class TestArtifacts(unittest.TestCase):
    def test_file_written_inside_workspace_is_returned(self):
        code = (
            "with open('results.txt', 'w') as f:\n"
            "    f.write('hello sandbox')\n"
            "print('done')\n"
        )
        result = execute(code)
        self.assertEqual(result.status, "ok")
        self.assertIn("results.txt", result.artifacts)
        self.assertEqual(result.artifacts["results.txt"], b"hello sandbox")

    def test_input_files_are_visible_to_code(self):
        code = "with open('input.txt') as f:\n    print(f.read().strip())\n"
        result = execute(code, files={"input.txt": "payload-123"})
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.stdout.strip(), "payload-123")

    def test_execute_file(self):
        import os
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("print('from file')\n")
            path = f.name
        try:
            result = execute_file(path)
            self.assertEqual(result.status, "ok")
            self.assertEqual(result.stdout.strip(), "from file")
        finally:
            os.unlink(path)


class TestEnvironment(unittest.TestCase):
    def test_child_env_is_scrubbed(self):
        from sandbox.executor import _child_env

        env = _child_env("/tmp/run-dir")
        self.assertEqual(env["HOME"], "/tmp/run-dir")
        for secretish in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY"):
            self.assertNotIn(secretish, env)
        self.assertEqual(env["TMPDIR"], "/tmp/run-dir")

    def test_process_count_is_positive(self):
        from sandbox.executor import _current_process_count

        self.assertGreater(_current_process_count(), 0)


if __name__ == "__main__":
    unittest.main()
