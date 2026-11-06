"""Master-password derivation in the PBKDF probe, without LLDB or WeChat."""

import ast
import hashlib
import hmac
import os
from pathlib import Path
from types import SimpleNamespace
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "cmd/wxkey/main.go"
PROBE = SOURCE.read_text().split("const pbkdfProbePython = `", 1)[1].split("`", 1)[0]
TREE = ast.parse(PROBE)
NAMES = {"verify_enc_key", "derive_all_from_master", "handle_hit", "should_stop_early"}
MODULE = ast.Module(
    body=[node for node in TREE.body
          if (isinstance(node, ast.FunctionDef) and node.name in NAMES)
          or (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id.isupper())],
    type_ignores=[],
)

PAGE_SIZE, SALT_SIZE, KEY_SIZE, HMAC_SIZE, KDF_ITER = 4096, 16, 32, 64, 256000


def fake_page1(password):
    salt = os.urandom(SALT_SIZE)
    enc_key = hashlib.pbkdf2_hmac("sha512", password, salt, KDF_ITER, KEY_SIZE)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, bytes(b ^ 0x3A for b in salt), 2, KEY_SIZE)
    body = os.urandom(PAGE_SIZE - SALT_SIZE - HMAC_SIZE)
    digest = hmac.new(mac_key, body + (1).to_bytes(4, "little"), hashlib.sha512).digest()
    return salt + body + digest, enc_key


class MasterKeyTests(unittest.TestCase):
    def setUp(self):
        self.ns = {"hashlib": hashlib, "hmac": hmac}
        exec(compile(MODULE, "probe", "exec"), self.ns)

    def test_one_verified_call_derives_every_db(self):
        password = os.urandom(KEY_SIZE)
        salt_to_db, expected = {}, {}
        for rel in ("db_storage/message/message_0.db", "db_storage/message/media_1.db", "db_storage/migrate/unspportmsg.db"):
            page1, enc_key = fake_page1(password)
            salt_to_db[page1[:SALT_SIZE]] = [{"rel": rel, "page1": page1, "salt": page1[:SALT_SIZE]}]
            expected[rel] = enc_key.hex()
        opened = next(iter(salt_to_db))  # WeChat only opens this one DB.
        memory = {0x1000: password, 0x2000: opened}
        self.ns["pbkdf_args"] = lambda process, frame: (0x1000, KEY_SIZE, 0x2000, SALT_SIZE, 5, KDF_ITER)
        self.ns["read_mem"] = lambda process, addr, size: memory[addr][:size]
        found, seen = {}, set()
        counters = {"hits": 0, "kdf_256k_salt_hits": 0, "mac_kdf_salt_hits": 0, "found": 0, "master_key": 0}

        changed = self.ns["handle_hit"](None, None, salt_to_db, {}, found, seen, counters)

        self.assertTrue(changed)
        self.assertEqual({rel: hit["key_hex"] for rel, hit in found.items()}, expected)
        self.assertEqual(counters["master_key"], 1)
        self.assertTrue(self.ns["should_stop_early"](found, seen, salt_to_db, False, counters))

    def test_unverified_password_is_not_treated_as_master(self):
        page1, _ = fake_page1(os.urandom(KEY_SIZE))
        salt = page1[:SALT_SIZE]
        salt_to_db = {salt: [{"rel": "db_storage/session/session.db", "page1": page1, "salt": salt}]}
        memory = {0x1000: os.urandom(KEY_SIZE), 0x2000: salt}
        self.ns["pbkdf_args"] = lambda process, frame: (0x1000, KEY_SIZE, 0x2000, SALT_SIZE, 5, KDF_ITER)
        self.ns["read_mem"] = lambda process, addr, size: memory[addr][:size]
        found, seen = {}, set()
        counters = {"hits": 0, "kdf_256k_salt_hits": 0, "mac_kdf_salt_hits": 0, "found": 0, "master_key": 0}

        self.assertFalse(self.ns["handle_hit"](None, None, salt_to_db, {}, found, seen, counters))
        self.assertEqual(found, {})
        self.assertEqual(counters["master_key"], 0)
        self.assertFalse(self.ns["should_stop_early"](found, seen, salt_to_db, False, counters))


if __name__ == "__main__":
    unittest.main()
