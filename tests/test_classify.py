import unittest

from morgue.classify import (
    categorize_domain, collect_session_flags, is_corporate, scan_secret_values,
    session_flag,
)
from morgue.models import AutofillEntry, CookieRecord, Credential


class CategoryTests(unittest.TestCase):
    def test_crypto(self):
        self.assertEqual(categorize_domain("binance.com"), "crypto_exchange")
        self.assertEqual(categorize_domain("www.coinbase.com"), "crypto_exchange")

    def test_sso_subdomain_marker(self):
        self.assertEqual(categorize_domain("login.microsoftonline.com"), "corporate_sso")
        self.assertEqual(categorize_domain("acme.okta.com"), "corporate_sso")
        self.assertEqual(categorize_domain("sso.corp.example"), "corporate_sso")

    def test_cloud(self):
        self.assertEqual(categorize_domain("console.aws.amazon.com"), "cloud_console")
        self.assertEqual(categorize_domain("portal.azure.com"), "cloud_console")

    def test_dev_vpn_social(self):
        self.assertEqual(categorize_domain("github.com"), "dev_platform")
        self.assertEqual(categorize_domain("nordvpn.com"), "vpn_provider")
        self.assertEqual(categorize_domain("web.telegram.org"), "social")

    def test_unknown(self):
        self.assertEqual(categorize_domain("blog.example.org"), "other")
        self.assertEqual(categorize_domain(""), "other")


class CorpTests(unittest.TestCase):
    def test_suffix_match(self):
        corp = frozenset({"acme.com"})
        self.assertTrue(is_corporate("acme.com", corp))
        self.assertTrue(is_corporate("mail.acme.com", corp))
        self.assertFalse(is_corporate("notacme.com", corp))
        self.assertFalse(is_corporate("acme.com.evil.example", corp))


class SessionCookieTests(unittest.TestCase):
    def test_known_names(self):
        for name in ("auth_token", ".ASPXAUTH", "JSESSIONID", "__Secure-1PSID"):
            c = CookieRecord(domain="x.example.com", name=name, value="v" * 30)
            self.assertIsNotNone(session_flag(c), name)

    def test_session_like_on_unknown(self):
        c = CookieRecord(domain="app.example.org", name="weird_session_thing", value="v" * 40)
        self.assertIn("session-like", session_flag(c))

    def test_plain_cookie_not_flagged(self):
        c = CookieRecord(domain="example.com", name="theme", value="dark")
        self.assertIsNone(session_flag(c))

    def test_collect_dedupes(self):
        cookies = [
            CookieRecord(domain="a.example.com", name="PHPSESSID", value="1"),
            CookieRecord(domain="a.example.com", name="PHPSESSID", value="1"),
            CookieRecord(domain="a.example.com", name="theme", value="dark"),
        ]
        flags = collect_session_flags(cookies)
        self.assertEqual(len(flags), 1)


class SecretValueTests(unittest.TestCase):
    def test_ghp_in_autofill(self):
        autofill = [AutofillEntry(name="notes", value="key ghp_" + "A" * 36)]
        hits = scan_secret_values(autofill, [])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].kind, "github_token")
        self.assertNotIn("A" * 36, hits[0].masked_value)

    def test_aws_in_password(self):
        creds = [Credential(url="https://x.example.com", username="u",
                            password="AKIA" + "B" * 16)]
        hits = scan_secret_values([], creds)
        self.assertEqual(hits[0].kind, "aws_access_key")

    def test_no_false_positive_on_normal_pw(self):
        creds = [Credential(url="https://x.example.com", username="u",
                            password="P@ssw0rd-2025")]
        self.assertEqual(scan_secret_values([], creds), [])


if __name__ == "__main__":
    unittest.main()
