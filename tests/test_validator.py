"""AST validation tests: allowed code passes, each banned construct fails."""

import unittest

from sandbox.validator import ALLOWED_MODULES, validate_source


class TestAllowedCode(unittest.TestCase):
    def test_plain_computation_passes(self):
        self.assertEqual(validate_source("x = 1 + 2\nprint(x)\n"), [])

    def test_allowed_imports_pass(self):
        code = (
            "import math, json, re, random\n"
            "from collections import Counter\n"
            "from math import sqrt\n"
            "print(sqrt(16))\n"
        )
        self.assertEqual(validate_source(code), [])

    def test_open_is_allowed_statically(self):
        # open() is allowed by the AST layer; the runtime hook restricts paths.
        self.assertEqual(validate_source("with open('data.txt') as f:\n    print(f.read())\n"), [])

    def test_functions_loops_classes_pass(self):
        code = (
            "def fib(n):\n"
            "    a, b = 0, 1\n"
            "    for _ in range(n):\n"
            "        a, b = b, a + b\n"
            "    return a\n"
            "print(fib(10))\n"
        )
        self.assertEqual(validate_source(code), [])

    def test_every_allowlisted_module_imports(self):
        for mod in sorted(ALLOWED_MODULES):
            with self.subTest(module=mod):
                self.assertEqual(validate_source(f"import {mod}\n"), [])


class TestBannedImports(unittest.TestCase):
    def test_banned_modules(self):
        for mod in (
            "os", "sys", "subprocess", "socket", "ctypes", "pathlib",
            "shutil", "multiprocessing", "threading", "importlib",
            "urllib", "http", "asyncio", "inspect", "signal", "pty",
        ):
            with self.subTest(module=mod):
                violations = validate_source(f"import {mod}\n")
                self.assertTrue(violations, f"import {mod} should be rejected")

    def test_banned_from_import(self):
        violations = validate_source("from os import system\n")
        self.assertTrue(violations)

    def test_banned_submodule_import(self):
        violations = validate_source("import os.path\n")
        self.assertTrue(violations)

    def test_relative_import_rejected(self):
        violations = validate_source("from . import helper\n")
        self.assertTrue(violations)


class TestBannedConstructs(unittest.TestCase):
    def test_eval_exec_compile_rejected(self):
        for code in ("eval('1+1')\n", "exec('x = 1')\n", "compile('x=1', '<s>', 'exec')\n"):
            with self.subTest(code=code.strip()):
                self.assertTrue(validate_source(code))

    def test_dunder_import_rejected(self):
        self.assertTrue(validate_source("__import__('os')\n"))

    def test_dunder_attribute_rejected(self):
        for code in (
            "x = ().__class__\n",
            "x = [].__class__.__base__\n",
            "print(obj.__dict__)\n",
        ):
            with self.subTest(code=code.strip()):
                self.assertTrue(validate_source(code))

    def test_dunder_name_rejected(self):
        self.assertTrue(validate_source("print(__builtins__)\n"))

    def test_getattr_setattr_rejected(self):
        for code in ("getattr(x, 'a')\n", "setattr(x, 'a', 1)\n", "hasattr(x, 'a')\n"):
            with self.subTest(code=code.strip()):
                self.assertTrue(validate_source(code))

    def test_globals_locals_rejected(self):
        self.assertTrue(validate_source("print(globals())\n"))
        self.assertTrue(validate_source("print(locals())\n"))

    def test_syntax_error_reported(self):
        violations = validate_source("def broken(:\n")
        self.assertTrue(violations)
        self.assertIn("syntax error", violations[0])

    def test_oversized_source_rejected(self):
        violations = validate_source("x = 1\n" * 20000)
        self.assertTrue(violations)


if __name__ == "__main__":
    unittest.main()
