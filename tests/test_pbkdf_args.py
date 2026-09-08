"""Exercise argument decoding without LLDB, WeChat, or account data."""

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "cmd/wxkey/main.go"
PROBE = SOURCE.read_text().split("const pbkdfProbePython = `", 1)[1].split("`", 1)[0]
FUNCTIONS = ast.Module(
    body=[node for node in ast.parse(PROBE).body
          if isinstance(node, ast.FunctionDef) and node.name in {"reg_u", "pbkdf_args"}],
    type_ignores=[],
)


class Frame:
    def __init__(self, **registers):
        self.registers = registers

    def FindRegister(self, name):
        return SimpleNamespace(GetValueAsUnsigned=lambda: self.registers[name])

    def GetCFA(self):
        return 0x1008


class PBKDFArgumentTests(unittest.TestCase):
    def setUp(self):
        self.namespace = {}
        exec(compile(FUNCTIONS, "pbkdf_args", "exec"), self.namespace)

    def args(self, arch, frame):
        process = SimpleNamespace(GetTarget=lambda: SimpleNamespace(GetTriple=lambda: arch))
        return self.namespace["pbkdf_args"](process, frame)

    def test_intel_registers_and_stack(self):
        for rounds in (2, 256000):
            with self.subTest(rounds=rounds):
                reads = []

                def read_memory(process, address, size):
                    reads.append((address, size))
                    return rounds.to_bytes(4, "little")

                self.namespace["read_mem"] = read_memory
                frame = Frame(rsi=0x2000, rdx=32, rcx=0x3000, r8=16, r9=5)
                self.assertEqual(self.args("x86_64-apple-macosx", frame),
                                 (0x2000, 32, 0x3000, 16, 5, rounds))
                self.assertEqual(reads, [(0x1008, 4)])

    def test_arm_register_mapping_is_preserved(self):
        for arch in ("arm64", "arm64e", "aarch64"):
            for rounds in (2, 256000):
                with self.subTest(arch=arch, rounds=rounds):
                    frame = Frame(x1=0x2000, x2=32, x3=0x3000, x4=16, x5=5, x6=rounds)
                    self.assertEqual(self.args(arch + "-apple-macosx", frame),
                                     (0x2000, 32, 0x3000, 16, 5, rounds))

    def test_short_stack_read_fails(self):
        self.namespace["read_mem"] = lambda *args: b""
        with self.assertRaisesRegex(RuntimeError, "cannot read"):
            self.args("x86_64-apple-macosx", Frame())

    def test_unsupported_architecture_fails(self):
        with self.assertRaisesRegex(RuntimeError, "unsupported"):
            self.args("unknown-apple-macosx", Frame())


if __name__ == "__main__":
    unittest.main()
