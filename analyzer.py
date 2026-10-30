"""Offline, educational phishing assessment for synthetic emails and URLs."""
from __future__ import annotations
import argparse
import ipaddress
import json
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

URGENCY = ("act now", "immediately", "urgent", "within 24 hours", "account suspended")
CREDENTIALS = ("verify your password", "enter your password", "confirm your login", "security verification")
BRANDS = ("paypal.com", "microsoft.com", "google.com", "amazon.com")
SUSPICIOUS_WORDS = ("verify", "secure", "login", "update", "account")


def analyze_url(raw: str) -> dict:
    """Inspect URL text without opening it or making network requests."""
    findings = []
    raw = raw.strip()
    parsed = urlsplit(raw if '://' in raw else 'https://' + raw)
    host = (parsed.hostname or '').lower().rstrip('.')
    if not host:
        return {"score": 0, "level": "Unknown", "findings": ["No valid hostname found."], "host": ""}
    try:
        ipaddress.ip_address(host)
        findings.append((30, "Link uses an IP address instead of a domain name."))
    except ValueError:
        pass
    if parsed.scheme == 'http':
        findings.append((10, "Link uses HTTP instead of HTTPS."))
    if '@' in parsed.netloc:
        findings.append((25, "URL contains '@', which can disguise the actual destination."))
    if host.count('.') >= 3:
        findings.append((15, "Unusually many subdomain levels."))
    if any(word in host for word in SUSPICIOUS_WORDS) and '-' in host:
        findings.append((15, "Domain uses security-related wording with hyphens."))
    for brand in BRANDS:
        brand_name = brand.split('.')[0]
        if brand_name in host and host != brand and not host.endswith('.' + brand):
            findings.append((30, f"Domain contains '{brand_name}' but is not {brand}."))
            break
    if 'xn--' in host:
        findings.append((20, "Domain uses internationalized-name encoding; inspect carefully."))
    return result(findings, host=host)


def result(findings: list[tuple[int, str]], **extra) -> dict:
    score = min(100, sum(points for points, _ in findings))
    level = "High" if score >= 60 else "Moderate" if score >= 25 else "Low"
    return {"score": score, "level": level, "findings": [reason for _, reason in findings], **extra}


def analyze_email(source: str) -> dict:
    message = Parser(policy=policy.default).parsestr(source)
    sender = parseaddr(message.get('From', ''))[1].lower()
    reply_to = parseaddr(message.get('Reply-To', ''))[1].lower()
    sender_domain = sender.rsplit('@', 1)[-1] if '@' in sender else ''
    reply_domain = reply_to.rsplit('@', 1)[-1] if '@' in reply_to else ''
    body = message.get_body(preferencelist=('plain',)) if message.is_multipart() else message
    content = body.get_content() if body else ''
    if not isinstance(content, str):
        content = ''
    text = (message.get('Subject', '') + '\n' + content).lower()
    findings = []
    if sender_domain and reply_domain and sender_domain != reply_domain:
        findings.append((25, "Reply-To domain differs from sender domain."))
    auth = str(message.get('Authentication-Results', '')).lower()
    # Header flags are user-supplied text, not independently verified authentication.
    if re.search(r'\bspf\s*=\s*(fail|softfail)\b', auth):
        findings.append((25, "Provided headers report an SPF failure (not independently verified)."))
    if re.search(r'\bdkim\s*=\s*fail\b', auth):
        findings.append((25, "Provided headers report a DKIM failure (not independently verified)."))
    if any(term in text for term in URGENCY):
        findings.append((20, "Message uses urgency or account-lockout language."))
    if any(term in text for term in CREDENTIALS):
        findings.append((30, "Message requests account credentials or verification."))
    links = re.findall(r'https?://[^\s<>"\']+', content, re.I)
    for link in links[:20]:
        url_result = analyze_url(link.rstrip('.,);'))
        if url_result['score'] >= 25:
            findings.append((min(30, url_result['score']), f"Suspicious link ({url_result['host']}): " + '; '.join(url_result['findings'])))
    assessment = result(findings, sender_domain=sender_domain, links_checked=min(len(links), 20))
    assessment['disclaimer'] = "Heuristics can produce false positives and miss threats. Never use this score alone to trust an email."
    return assessment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--email', type=Path, help='Synthetic/sanitized .eml file')
    group.add_argument('--url', help='Synthetic URL to inspect without connecting')
    args = parser.parse_args()
    if args.email:
        if args.email.suffix.lower() != '.eml':
            parser.error('Only .eml samples are supported')
        try:
            assessment = analyze_email(args.email.read_text(encoding='utf-8'))
        except (OSError, UnicodeError) as exc:
            parser.error(str(exc))
    else:
        assessment = analyze_url(args.url)
    print(json.dumps(assessment, indent=2))


if __name__ == "__main__":
    main()
