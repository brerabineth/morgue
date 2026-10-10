import os
import shutil
import tempfile
import unittest

from morgue import forge


class ForgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="morgue-forge-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_deterministic_byte_identical(self):
        a = forge.forge(self.tmp, family="lumma", seed=42, creds=20, cookies=10)
        tree_a = {}
        for dirpath, _, files in os.walk(a):
            for f in files:
                p = os.path.join(dirpath, f)
                tree_a[os.path.relpath(p, a)] = open(p, "rb").read()
        b = forge.forge(self.tmp, family="lumma", seed=42, creds=20, cookies=10)
        tree_b = {}
        for dirpath, _, files in os.walk(b):
            for f in files:
                p = os.path.join(dirpath, f)
                tree_b[os.path.relpath(p, b)] = open(p, "rb").read()
        self.assertEqual(tree_a, tree_b)

    def test_different_seed_differs(self):
        forge.forge(self.tmp, family="lumma", seed=1)
        forge.forge(self.tmp, family="lumma", seed=2)
        import morgue.bundle as bundle_mod
        b1 = bundle_mod.parse_bundle(os.path.join(self.tmp, "lumma"), self.tmp)
        guid1 = b1.machine.guid
        shutil.rmtree(os.path.join(self.tmp, "lumma"))
        forge.forge(self.tmp, family="lumma", seed=3)
        b2 = bundle_mod.parse_bundle(os.path.join(self.tmp, "lumma"), self.tmp)
        self.assertNotEqual(guid1, b2.machine.guid)

    def test_layouts_exist(self):
        for family, expected in (
            ("lumma", ["System Information.txt", "Password.txt", "Cookies.txt", "Autofill.txt", "Cards.txt"]),
            ("redline", ["Password.txt", "Cookies.txt", "Processes.txt"]),
            ("stealc", ["vault/info.txt", "Password.txt"]),
        ):
            out = forge.forge(self.tmp, family=family, seed=5)
            for rel in expected:
                path = os.path.join(out, rel)
                if family == "stealc" and rel == "Password.txt":
                    path = os.path.join(out, "vault", "browser", "Chrome", "passwords.txt")
                self.assertTrue(os.path.exists(path), "%s: %s" % (family, rel))
            shutil.rmtree(out)

    def test_no_real_seed_phrases(self):
        out = forge.forge(self.tmp, family="lumma", seed=9)
        wallet_note = None
        for dirpath, _, files in os.walk(out):
            for f in files:
                if f == "notes.txt":
                    wallet_note = open(os.path.join(dirpath, f), encoding="utf-8").read()
        self.assertIsNotNone(wallet_note)
        self.assertIn("word01", wallet_note)  # generated placeholders only

    def test_invalid_family_rejected(self):
        with self.assertRaises(ValueError):
            forge.forge(self.tmp, family="doesnotexist")

    def test_invalid_counts_rejected(self):
        with self.assertRaises(ValueError):
            forge.forge(self.tmp, creds=0)
        with self.assertRaises(ValueError):
            forge.forge(self.tmp, cookies=99999)


if __name__ == "__main__":
    unittest.main()
