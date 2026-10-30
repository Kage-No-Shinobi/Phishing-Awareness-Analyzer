# Phishing Awareness Analyzer

Offline educational email/URL analysis using only Python's standard library. **Analyze only synthetic or sanitized samples**. Nothing is fetched, clicked, uploaded or executed.

## Run

```bash
python3 analyzer.py --email samples/suspicious.eml
python3 analyzer.py --email samples/legitimate.eml
python3 analyzer.py --url https://secure-microsoft-login.example
python3 -m unittest discover -s tests -v
```

## Heuristics and score

Scores are additive, capped at 100. Low: 0–24; Moderate: 25–59; High: 60–100. Signals: reported SPF softfail/fail (+25), DKIM fail (+25), sender/Reply-To mismatch (+25), urgent language (+20), credential request (+30), suspicious links (up to +30 each). URL checks include IP hostname (+30), HTTP (+10), @ URL userinfo (+25), deep subdomains (+15), misleading brand name (+30), and IDN punycode (+20).

`Authentication-Results` headers are **untrusted provided input**, not actual DNS-based SPF/DKIM verification. Brand comparisons cover only a small illustrative allowlist. This is not a phishing classifier or a guarantee of safety: heuristics can raise false positives and miss real attacks. Never enter credentials based on a Low score alone. No external network operations occur.
