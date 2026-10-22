import json
import subprocess
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path

from phishscope.analyzer import analyze_bytes, analyze_file
from phishscope.domains import lookalike_of, registrable_domain

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def ids(report):
    return {i.id for i in report.indicators}


def make(**headers) -> EmailMessage:
    body = headers.pop("body", "Hello")
    html = headers.pop("html", None)
    m = EmailMessage()
    m["From"] = headers.pop("From", "Alice <alice@example.com>")
    m["To"] = "bob@example.com"
    m["Subject"] = headers.pop("Subject", "Hi")
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return m


class DomainTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(registrable_domain("shop.example.co.uk"), "example.co.uk")

    def test_lookalikes_detected(self):
        for host, brand in [
            ("paypa1.com", "PayPal"),
            ("rnicrosoft.com", "Microsoft"),
            ("xn--pypal-4ve.com", "PayPal"),          # Cyrillic 'а' in pаypal
            ("sberbank-online.ru", "Sberbank"),
            ("paypal.com.account-check.example", "PayPal"),
            ("gosusl0gi.ru", "Gosuslugi"),            # digit substitution + one-letter change
        ]:
            with self.subTest(host=host):
                self.assertEqual(lookalike_of(host), brand)

    def test_legitimate_domains_not_flagged(self):
        for host in ["paypal.com", "www.paypal.com", "login.microsoftonline.com", "s3.amazonaws.com",
                     "ozone.ru", "applebees.com", "github.com"]:
            with self.subTest(host=host):
                self.assertIsNone(lookalike_of(host))


class AnalyzerTests(unittest.TestCase):
    def test_clean_message(self):
        r = analyze_bytes(bytes(make(Authentication_Results="mx; spf=pass; dkim=pass; dmarc=pass")))
        self.assertEqual(r.verdict, "clean")
        self.assertEqual(r.score, 0)

    def test_auth_failures(self):
        r = analyze_bytes(bytes(make(Authentication_Results="mx; spf=fail; dkim=fail; dmarc=fail")))
        self.assertTrue({"AUTH-SPF", "AUTH-DKIM", "AUTH-DMARC"} <= ids(r))

    def test_reply_to_mismatch(self):
        r = analyze_bytes(bytes(make(Reply_To="x@other.example")))
        self.assertIn("HDR-REPLYTO", ids(r))

    def test_link_text_mismatch(self):
        html = '<a href="https://evil.example/login">https://www.mybank.example/</a>'
        r = analyze_bytes(bytes(make(html=html)))
        self.assertIn("URL-MISMATCH", ids(r))

    def test_same_domain_link_is_not_mismatch(self):
        html = '<a href="https://www.github.com/settings">github.com</a>'
        r = analyze_bytes(bytes(make(html=html)))
        self.assertNotIn("URL-MISMATCH", ids(r))

    def test_ip_and_userinfo_urls(self):
        r = analyze_bytes(bytes(make(body="go http://192.0.2.1/x and https://paypal.com@evil.example/")))
        self.assertTrue({"URL-IP", "URL-USERINFO"} <= ids(r))

    def test_double_extension_attachment(self):
        m = make()
        m.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
        r = analyze_bytes(bytes(m))
        self.assertIn("ATT-RISKY", ids(r))
        self.assertTrue(r.attachments[0].risky)
        self.assertEqual(len(r.attachments[0].sha256), 64)

    def test_russian_language_indicators(self):
        r = analyze_bytes(bytes(make(body="Срочно подтвердите личность и сообщите код из SMS")))
        self.assertTrue({"TXT-URGENCY", "TXT-CREDS"} <= ids(r))

    def test_score_is_capped(self):
        r = analyze_file(SAMPLES / "phish-paypal.eml")
        self.assertEqual(r.score, 100)


class SampleTests(unittest.TestCase):
    def test_verdicts(self):
        expected = {
            "phish-paypal.eml": "malicious",
            "phish-bank-ru.eml": "malicious",
            "bec-ceo-fraud.eml": "suspicious",
            "legit-github.eml": "clean",
        }
        for name, verdict in expected.items():
            with self.subTest(name=name):
                self.assertEqual(analyze_file(SAMPLES / name).verdict, verdict)

    def test_cli_json_and_exit_code(self):
        proc = subprocess.run([sys.executable, "-m", "phishscope", str(SAMPLES / "legit-github.eml"), "--format", "json"],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)[0]["verdict"], "clean")

        proc = subprocess.run([sys.executable, "-m", "phishscope", str(SAMPLES)], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
