import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze_email, analyze_url

class PhishingTests(unittest.TestCase):
    def test_ip_link(self):
        self.assertGreaterEqual(analyze_url('http://192.0.2.5/login')['score'], 30)
    def test_fake_brand(self):
        self.assertGreaterEqual(analyze_url('https://secure-microsoft-login.example')['score'], 25)
    def test_real_brand_domain_not_flagged(self):
        self.assertEqual(analyze_url('https://login.microsoft.com')['score'], 0)
    def test_credential_request(self):
        self.assertGreaterEqual(analyze_email('From: user@example.com\nSubject: urgent\n\nPlease verify your password immediately')['score'], 40)
    def test_clean_message(self):
        self.assertEqual(analyze_email('From: user@example.com\nSubject: Hello\n\nMeeting at noon.')['score'], 0)
    def test_forged_headers_are_described_as_reported(self):
        report = analyze_email('From: a@example.com\nAuthentication-Results: x; spf=fail\n\nHi')
        self.assertTrue(any('not independently verified' in x for x in report['findings']))

if __name__ == '__main__': unittest.main()
