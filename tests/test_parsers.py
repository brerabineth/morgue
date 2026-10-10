import unittest

from morgue.parsers import (
    domain_of, host_of, looks_like_host, looks_like_url, mask_pan,
    parse_autofill_line, parse_card_line, parse_cookie_line,
    parse_credential_line, parse_machine_auto, parse_machine_json,
    parse_machine_text,
)


class UrlHostTests(unittest.TestCase):
    def test_url_detection(self):
        self.assertTrue(looks_like_url("https://x.example.com/a"))
        self.assertTrue(looks_like_url("ftp://files.example.org"))
        self.assertFalse(looks_like_url("www.example.com"))
        self.assertFalse(looks_like_url(""))
        self.assertFalse(looks_like_url("not a url"))

    def test_host_detection(self):
        self.assertTrue(looks_like_host("mail.example.com"))
        self.assertFalse(looks_like_host("https://mail.example.com"))
        self.assertFalse(looks_like_host("no-dot"))
        self.assertFalse(looks_like_host(""))

    def test_host_of_variants(self):
        self.assertEqual(host_of("https://portal.example.com/login"), "portal.example.com")
        self.assertEqual(host_of("http://EXAMPLE.com:8080/x?y=1#z"), "example.com:8080")
        self.assertEqual(host_of("https://user:pass@host.example.org/"), "host.example.org")
        self.assertEqual(host_of("garbage"), "")

    def test_domain_of(self):
        self.assertEqual(domain_of("a.b.example.com"), "example.com")
        self.assertEqual(domain_of("www.example.co.uk"), "example.co.uk")
        self.assertEqual(domain_of("EXAMPLE.ORG."), "example.org")
        self.assertEqual(domain_of("localhost"), "localhost")
        self.assertEqual(domain_of(""), "")


class CredentialLineTests(unittest.TestCase):
    def test_three_col(self):
        c = parse_credential_line("https://mail.example.com\tbob@example.com\ts3cret")
        self.assertEqual(c.url, "https://mail.example.com")
        self.assertEqual(c.username, "bob@example.com")
        self.assertEqual(c.password, "s3cret")
        self.assertEqual(c.domain, "example.com")

    def test_six_col_redline(self):
        line = "https://sso.example.org/\tsso.example.org\talice\tP@ss\tWS-AB12\talice"
        c = parse_credential_line(line)
        self.assertEqual(c.username, "alice")
        self.assertEqual(c.password, "P@ss")

    def test_host_col_not_confused_with_login(self):
        # col1 is a bare host -> 4+ col shape; login in col2
        line = "https://x.example.com\tx.example.com\tcarol\tpw123"
        c = parse_credential_line(line)
        self.assertEqual(c.username, "carol")

    def test_rejects_non_url_first_col(self):
        self.assertIsNone(parse_credential_line("noturl\tbob\tpw"))

    def test_rejects_short_rows(self):
        self.assertIsNone(parse_credential_line("https://a.example.com"))
        self.assertIsNone(parse_credential_line(""))


class CookieLineTests(unittest.TestCase):
    def test_netscape_seven_col(self):
        line = ".example.com\tTRUE\t/\tTRUE\t1893456000\tsessionid\tabc123def456"
        c = parse_cookie_line(line)
        self.assertEqual(c.domain, "example.com")
        self.assertEqual(c.name, "sessionid")
        self.assertEqual(c.value, "abc123def456")

    def test_netscape_six_col(self):
        line = ".example.com\tTRUE\t/\t1893456000\tPHPSESSID\txyz987"
        c = parse_cookie_line(line)
        self.assertEqual(c.name, "PHPSESSID")
        self.assertEqual(c.value, "xyz987")

    def test_three_col(self):
        c = parse_cookie_line("app.example.org\tconnect.sid\ts%3Adeadbeef")
        self.assertEqual(c.name, "connect.sid")

    def test_four_col_with_path(self):
        c = parse_cookie_line("app.example.org\t/\ttheme\tdark")
        self.assertEqual(c.name, "theme")

    def test_comment_and_empty_rejected(self):
        self.assertIsNone(parse_cookie_line("# HttpOnly_.example.com\tTRUE\t/\t1\t2\tn\tv"))
        self.assertIsNone(parse_cookie_line("d\tn"))

    def test_leading_dot_stripped_and_lowered(self):
        c = parse_cookie_line(".MAIL.Example.COM\ta\tb")
        self.assertEqual(c.domain, "mail.example.com")


class AutofillCardTests(unittest.TestCase):
    def test_autofill(self):
        a = parse_autofill_line("email\tperson@example.com")
        self.assertEqual(a.name, "email")
        self.assertEqual(a.value, "person@example.com")
        self.assertIsNone(parse_autofill_line("justone"))

    def test_card_masking(self):
        c = parse_card_line("4111111111111111\t12/27\t123\tHolder Name")
        self.assertEqual(c.masked_pan, "************1111")
        self.assertEqual(c.expiry, "12/27")
        self.assertNotIn("4111111111111111", c.masked_pan)

    def test_card_rejects_non_pan(self):
        self.assertIsNone(parse_card_line("not-a-card\t12/27"))


class MachineInfoTests(unittest.TestCase):
    def test_text_parse(self):
        text = ("Computer name: WS-XYZ\r\nUser name: bob\r\nDomain: CORP\r\n"
                "OS: Windows 11 Pro\r\nGlobal ID: {AABBCCDD-1122-3344-5566-778899001122}\r\n"
                "IP: 192.0.2.10\r\nInstall date: 2025-03-01 10:00:00\r\n"
                "Language: en-US\r\nCPU: Intel i7\r\n")
        m = parse_machine_text(text)
        self.assertEqual(m.hostname, "WS-XYZ")
        self.assertEqual(m.username, "bob")
        self.assertEqual(m.domain, "CORP")
        self.assertTrue(m.guid.startswith("AABBCCDD"))
        self.assertEqual(m.external_ip, "192.0.2.10")
        self.assertTrue(m.identified)

    def test_json_parse(self):
        m = parse_machine_json({
            "Hostname": "WS-J1", "Username": "kim", "IP": "192.0.2.99",
            "BuildID": "DEADBEEF00112233", "unknownkey": "x",
        })
        self.assertEqual(m.hostname, "WS-J1")
        self.assertEqual(m.username, "kim")
        self.assertEqual(m.build_id, "DEADBEEF00112233")
        self.assertEqual(m.unrecognized_keys, 1)

    def test_auto_dispatch(self):
        self.assertEqual(parse_machine_auto('{"Hostname":"WS-A"}').hostname, "WS-A")
        self.assertEqual(parse_machine_auto("Hostname: WS-B").hostname, "WS-B")

    def test_empty_is_unidentified(self):
        self.assertFalse(parse_machine_text("nothing here").identified)


class MaskTests(unittest.TestCase):
    def test_mask_pan_short(self):
        self.assertEqual(mask_pan("12345"), "*****")


if __name__ == "__main__":
    unittest.main()
