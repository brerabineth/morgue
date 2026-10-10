import json
import os
import shutil
import tempfile
import unittest

from morgue import forge, report, scanner
from morgue.passwords import mask_password


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="morgue-report-")
        self.out = os.path.join(self.tmp, "out")
        self.log = forge.forge(self.tmp, family="lumma", seed=77, creds=15, cookies=8)
        self.scan = scanner.scan_path(self.log, corp_domains=("acme-corp.example",))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_json_masked_by_default(self):
        path = os.path.join(self.out, "report.json")
        report.write_json(self.scan, path)
        data = json.load(open(path, encoding="utf-8"))
        self.assertEqual(data["tool"], "morgue")
        self.assertEqual(data["counts"]["credentials"], 15)
        first_pw = data["credentials"][0]["password"]
        self.assertNotIn("Password1!", first_pw)
        self.assertIn("(", first_pw)  # mask format
        self.assertFalse(any("/home" in str(v) for v in _flatten(data)), "no host paths")

    def test_json_reveal_shows_plaintext(self):
        path = os.path.join(self.out, "report.json")
        report.write_json(self.scan, path, reveal=True)
        data = json.load(open(path, encoding="utf-8"))
        plain = [c["password"] for c in data["credentials"]]
        self.assertTrue(any(len(p) >= 6 and "(" not in p for p in plain))

    def test_csv_rows(self):
        path = os.path.join(self.out, "credentials.csv")
        report.write_csv(self.scan, path)
        import csv as _csv
        with open(path, encoding="utf-8", newline="") as fh:
            rows = list(_csv.reader(fh))
        self.assertEqual(rows[0], ["url", "username", "password", "domain", "category"])
        self.assertEqual(len(rows), 16)
        body = open(path, encoding="utf-8").read()
        # masked: no long plaintext secrets
        self.assertNotIn("Password1!", body)

    def test_iocs_jsonl_no_secrets(self):
        path = os.path.join(self.out, "iocs.jsonl")
        report.write_iocs(self.scan, path)
        lines = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        self.assertEqual(len(lines), 1)
        rec = lines[0]
        self.assertEqual(rec["type"], "infostealer_victim")
        self.assertNotIn("password", rec)
        blob = open(path, encoding="utf-8").read()
        self.assertNotIn("Password1!", blob)

    def test_html_self_contained_and_masked(self):
        path = os.path.join(self.out, "report.html")
        report.write_html(self.scan, path)
        blob = open(path, encoding="utf-8").read()
        self.assertIn("MORGUE", blob)
        self.assertNotIn('src="http', blob)   # no external assets
        self.assertNotIn('href="http', blob)
        self.assertNotIn("Password1!", blob)  # masked
        self.assertNotIn("/home/", blob)      # no host paths
        self.assertIn("exposure", blob.lower())

    def test_cookie_values_masked(self):
        path = os.path.join(self.out, "report.json")
        report.write_json(self.scan, path)
        data = json.load(open(path, encoding="utf-8"))
        # cookie values are not present at all in the report (masked upstream)
        self.assertNotIn("cookie_values", data)

    def test_report_dict_shape(self):
        d = report.scan_report_dict(self.scan)
        for key in ("tool", "version", "family", "machines", "counts",
                    "exposure", "password_hygiene", "domain_census"):
            self.assertIn(key, d)
        self.assertEqual(d["exposure"]["band"], self.scan.score.band)


def _flatten(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _flatten(v)
    else:
        yield obj


if __name__ == "__main__":
    unittest.main()
