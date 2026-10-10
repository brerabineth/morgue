import os
import shutil
import tempfile
import unittest

from morgue import forge, detect
from morgue.bundle import parse_bundle


class DetectTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="morgue-detect-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _forge(self, family, seed=11):
        return forge.forge(self.tmp, family=family, seed=seed, creds=10, cookies=5)


class FamilyDetectionTests(DetectTestBase):
    def test_lumma_detected(self):
        root = self._forge("lumma", seed=1)
        files = detect.walk_layout(root)
        machine = next(f for f in files if f.name == "system information.txt")
        import os as _os
        text = open(_os.path.join(root, machine.rel), encoding="utf-8").read()
        v = detect.detect_family(files, text)
        self.assertEqual(v.family, "lumma")
        self.assertGreaterEqual(v.confidence, 0.5)

    def test_redline_detected(self):
        root = self._forge("redline", seed=2)
        files = detect.walk_layout(root)
        v = detect.detect_family(files, "Computer name: X\n")
        self.assertEqual(v.family, "redline")

    def test_stealc_detected(self):
        root = self._forge("stealc", seed=3)
        files = detect.walk_layout(root)
        v = detect.detect_family(files, "BuildID: ABC\n")
        self.assertEqual(v.family, "stealc")

    def test_generic_fallback_is_safe(self):
        v = detect.detect_family([], "")
        self.assertEqual(v.family, "generic")

    def test_parse_bundle_family_and_content(self):
        root = self._forge("lumma", seed=4)
        b = parse_bundle(root, self.tmp)
        self.assertEqual(b.family, "lumma")
        self.assertEqual(len(b.credentials), 10)
        self.assertEqual(len(b.cookies), 5)
        self.assertTrue(b.machine.identified)
        self.assertIn("telegram", b.artifact_kinds)
        self.assertTrue(any(w.name == "metamask" for w in b.wallets))

    def test_parse_bundle_stealc(self):
        root = self._forge("stealc", seed=5)
        b = parse_bundle(root, self.tmp)
        self.assertEqual(b.family, "stealc")
        self.assertEqual(b.machine.hostname, b.machine.hostname)  # present
        self.assertTrue(b.machine.hostname.startswith("WS-"))
        self.assertEqual(len(b.credentials), 10)


class BundleDiscoveryTests(DetectTestBase):
    def test_single_log(self):
        root = self._forge("lumma", seed=6)
        roots, mode = detect.find_bundles(root)
        self.assertEqual(mode, "single")
        self.assertEqual(roots, [root])

    def test_wrapper_folder_with_one_log(self):
        self._forge("lumma", seed=61)
        roots, mode = detect.find_bundles(self.tmp)
        self.assertEqual(mode, "multi")
        self.assertEqual(len(roots), 1)

    def test_multi_victim_folder(self):
        self._forge("lumma", seed=7)
        self._forge("redline", seed=8)
        self._forge("stealc", seed=9)
        roots, mode = detect.find_bundles(self.tmp)
        self.assertEqual(mode, "multi")
        self.assertEqual(len(roots), 3)

    def test_empty_dir(self):
        roots, mode = detect.find_bundles(self.tmp)
        self.assertEqual(mode, "empty")
        self.assertEqual(roots, [])

    def test_walk_bounded_and_relpaths(self):
        root = self._forge("lumma", seed=10)
        files = detect.walk_layout(root)
        for f in files:
            self.assertNotIn("\\", f.rel)  # forward slashes only
            self.assertTrue(f.rel, "rel path set")


class GenericLayoutTests(DetectTestBase):
    def test_generic_txt_credentials(self):
        src = os.path.join(self.tmp, "some_dump.txt")
        rows = ["https://mail.example.com\tu%d@example.com\tpw%d" % (i, i) for i in range(10)]
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + "\n")
        roots, mode = detect.find_bundles(self.tmp)
        self.assertEqual(mode, "fallback")
        b = parse_bundle(roots[0], self.tmp)
        self.assertEqual(len(b.credentials), 10)
        self.assertEqual(b.family, "generic")

    def test_noise_txt_not_credentials(self):
        # history-like rows (url + timestamp) must not become credentials
        src = os.path.join(self.tmp, "History.txt")
        rows = ["https://site%d.example.com/\\tSome Page Title %d\\t2025-01-0%d" % (i, i, i % 9 + 1) for i in range(10)]
        rows = [r.replace("\\t", "\t") for r in rows]
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + "\n")
        b = parse_bundle(self.tmp, self.tmp)
        self.assertEqual(len(b.credentials), 0)


if __name__ == "__main__":
    unittest.main()
