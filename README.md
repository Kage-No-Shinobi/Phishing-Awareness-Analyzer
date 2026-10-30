# Phishing Awareness Analyzer

Offline, educational phishing assessment for synthetic emails and URLs.

## Run locally
```bash
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000.

## Render deployment
- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`

The analyzer does not fetch, click, upload, or execute URLs. Email Authentication-Results headers are user-supplied and not independently verified. Heuristics can produce false positives and miss real threats; a Low score is not proof of safety. Use synthetic or sanitized samples only.
