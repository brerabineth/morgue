import unittest

from morgue.models import Credential, ExposureScore, PasswordHygiene, ScanResult
from morgue.passwords import analyze, mask_password, shannon_entropy
from morgue.scoring import band_of, compute


def _cred(domain, pw, host=""):
    return Credential(url="https://%s/" % (host or domain), username="u",
                      password=pw, host=host or domain, domain=domain)


class HygieneTests(unittest.TestCase):
    def test_reuse_and_weak(self):
        creds = [
            _cred("a.example.com", "Password1!"),
            _cred("b.example.com", "Password1!"),
            _cred("c.example.com", "Password1!"),
            _cred("d.example.com", "12345678"),
            _cred("e.example.com", ""),
        ]
        hy = analyze(creds)
        self.assertEqual(hy.total, 5)
        self.assertEqual(hy.unique, 2)
        self.assertEqual(hy.empty, 1)
        self.assertEqual(hy.reuse_ratio, 0.6)  # 3 of 5 use Password1!
        self.assertEqual(hy.short_count, 0)  # "12345678" is len 8, not <8
        self.assertEqual(hy.digits_only, 1)
        self.assertTrue(hy.top_reused)
        masked, count = hy.top_reused[0]
        self.assertNotIn("Password1!", masked)
        self.assertEqual(count, 3)

    def test_mask_never_full(self):
        masked = mask_password("sup3r-s3cret-value")
        self.assertNotIn("s3cret", masked)
        self.assertTrue(masked.endswith(")"))

    def test_entropy(self):
        self.assertGreater(shannon_entropy("aB3$xY9#"), shannon_entropy("aaaa"))
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_empty_scan(self):
        hy = analyze([])
        self.assertEqual(hy.total, 0)
        self.assertEqual(hy.reuse_ratio, 0.0)


class BandTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(band_of(0), "clean")
        self.assertEqual(band_of(5), "low")
        self.assertEqual(band_of(25), "medium")
        self.assertEqual(band_of(45), "high")
        self.assertEqual(band_of(95), "critical")


class ScoringTests(unittest.TestCase):
    def _scan(self, creds, cookies=(), corp=()):
        scan = ScanResult(root="t")
        scan.credentials = list(creds)
        scan.cookies = list(cookies)
        from morgue.classify import collect_session_flags
        scan.session_flags = collect_session_flags(scan.cookies)
        return compute(scan, frozenset(corp))

    def test_clean_log(self):
        score = self._scan([_cred("blog.example.org", "pw123456")])
        self.assertEqual(score.value, 0)
        self.assertEqual(score.band, "clean")

    def test_corp_domain_scores(self):
        score = self._scan([_cred("portal.acme.com", "pw")], corp=("acme.com",))
        self.assertGreaterEqual(score.value, 25)
        self.assertTrue(any("corporate domain" in r.message for r in score.reasons))

    def test_sso_and_cloud(self):
        score = self._scan([
            _cred("login.microsoftonline.com", "pw", host="login.microsoftonline.com"),
            _cred("console.aws.amazon.com", "pw", host="console.aws.amazon.com"),
        ])
        self.assertGreaterEqual(score.value, 35)
        self.assertTrue(any("SSO" in r.message for r in score.reasons))

    def test_session_cookies_push(self):
        from morgue.models import CookieRecord
        cookies = [CookieRecord(domain="portal.acme.com", name="PHPSESSID", value="x" * 30)]
        score = self._scan([_cred("portal.acme.com", "pw")], cookies=cookies, corp=("acme.com",))
        self.assertTrue(any("replayable session" in r.message for r in score.reasons))

    def test_cap_at_100(self):
        creds = []
        creds += [_cred("portal.acme.com", "pw"), _cred("vpn.acme.com", "pw")]
        creds += [_cred("login.microsoftonline.com", "pw", host="login.microsoftonline.com")]
        creds += [_cred("console.aws.amazon.com", "pw", host="console.aws.amazon.com")]
        creds += [_cred("github.com", "pw"), _cred("binance.com", "pw"),
                  _cred("nordvpn.com", "pw"), _cred("paypal.com", "pw")]
        creds += [_cred("a.example.com", "ghp_" + "A" * 36),
                  _cred("b.example.com", "ghp_" + "B" * 36)]
        scan = ScanResult(root="t")
        scan.credentials = creds
        from morgue.models import SecretHit
        scan.secrets = [SecretHit(kind="github_token", masked_value="ghp_AAAA...b1", source_file="x"),
                        SecretHit(kind="aws_access_key", masked_value="AKIA...b2", source_file="x"),
                        SecretHit(kind="stripe_secret", masked_value="sk_li...b3", source_file="x")]
        score = compute(scan, frozenset({"acme.com"}))
        self.assertEqual(score.value, 100)
        self.assertEqual(score.band, "critical")


if __name__ == "__main__":
    unittest.main()
