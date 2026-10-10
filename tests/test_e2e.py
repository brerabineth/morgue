"""In-process end-to-end: forge -> CLI scan -> artifacts -> exit codes."""

import io
import json
import os
import contextlib
import shutil
import tempfile
import unittest

from morgue.cli import main
from morgue import forge


class CliE2ETests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="morgue-e2e-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_forge_scan_pipeline(self):
        code, _ = self._run(["forge", "--out", os.path.join(self.tmp, "logs"),
                             "--family", "lumma", "--seed", "3", "--creds", "25"])
        self.assertEqual(code, 0)
        log_dir = os.path.join(self.tmp, "logs", "lumma")
        self.assertTrue(os.path.isdir(log_dir))

        outdir = os.path.join(self.tmp, "reports")
        code, out = self._run(["scan", log_dir, "--outdir", outdir,
                               "--no-color", "--corp", "acme-corp.example"])
        self.assertEqual(code, 0)
        self.assertIn("exposure score", out.lower())
        for name in ("report.json", "credentials.csv", "report.html"):
            self.assertTrue(os.path.exists(os.path.join(outdir, name)), name)

        data = json.load(open(os.path.join(outdir, "report.json"), encoding="utf-8"))
        self.assertEqual(data["counts"]["credentials"], 25)
        self.assertEqual(data["family"], "lumma")
        self.assertTrue(data["machines_detail"][0]["machine"]["hostname"].startswith("WS-"))

    def test_multi_folder_scan(self):
        logs = os.path.join(self.tmp, "logs")
        for family, seed in (("lumma", 1), ("redline", 2), ("stealc", 3)):
            code, _ = self._run(["forge", "--out", logs, "--family", family, "--seed", str(seed)])
            self.assertEqual(code, 0)
        code, out = self._run(["scan", logs, "--outdir", os.path.join(self.tmp, "r"),
                               "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("machines  : 3", out)

    def test_fail_on_threshold(self):
        log = forge.forge(self.tmp, family="lumma", seed=11, creds=30)
        code, _ = self._run(["scan", log, "--outdir", os.path.join(self.tmp, "r2"),
                             "--quiet", "--fail-on", "medium"])
        self.assertEqual(code, 10)

    def test_scan_empty_dir_fails_clean(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["scan", empty, "--outdir", os.path.join(self.tmp, "r3")])
        self.assertEqual(code, 3)

    def test_scan_missing_path_usage_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["scan", os.path.join(self.tmp, "nope")])
        self.assertEqual(code, 2)

    def test_ioc_command(self):
        log = forge.forge(self.tmp, family="redline", seed=12, creds=10)
        out = os.path.join(self.tmp, "iocs.jsonl")
        code, out_text = self._run(["ioc", log, "--out", out])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out))
        rec = json.loads(open(out, encoding="utf-8").readline())
        self.assertEqual(rec["type"], "infostealer_victim")
        self.assertNotIn("password", rec)

    def test_no_absolute_paths_in_any_output(self):
        log = forge.forge(self.tmp, family="lumma", seed=13, creds=12)
        outdir = os.path.join(self.tmp, "r4")
        code, _ = self._run(["scan", log, "--outdir", outdir, "--no-color"])
        self.assertEqual(code, 0)
        for name in os.listdir(outdir):
            blob = open(os.path.join(outdir, name), encoding="utf-8").read()
            self.assertNotIn("/home/", blob, name)
            self.assertNotIn("/tmp/", blob, name)

    def test_forge_invalid_family_exit2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main(["forge", "--family", "nope", "--out", os.path.join(self.tmp, "x")])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
