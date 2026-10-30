from flask import Flask, render_template_string, request
from analyzer import analyze_email, analyze_url

app = Flask(__name__)
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing Awareness Analyzer</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#131b2e;--line:#293550;--text:#eaf0ff;--muted:#9eacc7;--accent:#78a9ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#17233d,#0b1020 55%);font:16px/1.55 system-ui,-apple-system,sans-serif;color:var(--text)}
main{max-width:900px;margin:48px auto;padding:0 20px}.brand{color:var(--accent);font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:.78rem}
h1{font-size:clamp(2rem,5vw,3.4rem);line-height:1.1;margin:12px 0}p{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px;margin-top:24px;box-shadow:0 20px 60px #0002}
.tabs{display:flex;gap:8px;margin-bottom:18px}.tabs button{background:#1d2942;color:var(--muted);border:1px solid var(--line);padding:10px 16px;border-radius:10px;cursor:pointer}.tabs button.active{background:var(--accent);color:#071226}
label{display:block;font-weight:650;margin:12px 0 8px}textarea,input{width:100%;background:#0b1222;border:1px solid #34415d;border-radius:10px;padding:13px;color:var(--text);font:inherit}textarea{min-height:190px;resize:vertical}
.submit{margin-top:16px;background:var(--accent);color:#071226;border:0;border-radius:10px;padding:12px 18px;font-weight:750;cursor:pointer}.hidden{display:none}
.result{margin-top:22px;border:1px solid var(--line);border-radius:14px;padding:20px}.score{font-size:2.3rem;font-weight:800}.level{display:inline-block;padding:4px 10px;border-radius:999px;background:#263652;margin-left:8px;font-size:.85rem}
li{margin:8px 0;color:#cbd6ea}.notice{font-size:.85rem;border-left:3px solid #e6b85c;padding-left:12px;margin-top:20px}
footer{margin:26px 0;color:var(--muted);font-size:.82rem}
</style>
</head><body><main>
<div class="brand">Security education · Offline analysis</div>
<h1>Phishing Awareness Analyzer</h1>
<p>Inspect suspicious email text or a URL using simple, explainable heuristics. Nothing is opened, clicked, uploaded to another service, or executed.</p>
<section class="panel">
<div class="tabs"><button id="urltab" class="active" type="button" onclick="setMode('url')">Analyze URL</button><button id="emailtab" type="button" onclick="setMode('email')">Analyze email</button></div>
<form method="post">
<input type="hidden" name="mode" id="mode" value="{{ mode }}">
<div id="urlform" class="{{ 'hidden' if mode == 'email' else '' }}"><label for="url">URL to inspect</label><input id="url" name="url" type="text" placeholder="https://example.com/login" value="{{ url }}" maxlength="2048"></div>
<div id="emailform" class="{{ '' if mode == 'email' else 'hidden' }}"><label for="email">Email headers and body (.eml text)</label><textarea id="email" name="email" placeholder="From: sender@example.com&#10;Subject: Example message&#10;&#10;Paste a synthetic or sanitized email here.">{{ email }}</textarea></div>
<button class="submit" type="submit">Analyze sample →</button>
</form>
{% if error %}<p role="alert">{{ error }}</p>{% endif %}
{% if result %}
<div class="result" aria-live="polite"><div class="brand">Assessment</div><div class="score">{{ result.score }}/100 <span class="level">{{ result.level }}</span></div>
{% if result.host %}<p>Hostname: <strong>{{ result.host }}</strong></p>{% endif %}
{% if result.sender_domain is defined %}<p>Sender domain: <strong>{{ result.sender_domain or 'Not detected' }}</strong> · Links checked: {{ result.links_checked }}</p>{% endif %}
<h3>Findings</h3>{% if result.findings %}<ul>{% for finding in result.findings %}<li>{{ finding }}</li>{% endfor %}</ul>{% else %}<p>No indicators were detected by these checks.</p>{% endif %}
{% if result.disclaimer %}<p class="notice">{{ result.disclaimer }}</p>{% endif %}</div>
{% endif %}
</section>
<p class="notice">Educational tool only. A low score does not prove a message or website is safe. Use synthetic or sanitized samples and never paste passwords, private information, or confidential emails.</p>
<footer>Phishing Awareness Analyzer · Built with Python and Flask</footer>
</main>
<script>
function setMode(mode){document.getElementById('mode').value=mode;document.getElementById('urlform').classList.toggle('hidden',mode!=='url');document.getElementById('emailform').classList.toggle('hidden',mode!=='email');document.getElementById('urltab').classList.toggle('active',mode==='url');document.getElementById('emailtab').classList.toggle('active',mode==='email');}
setMode(document.getElementById('mode').value);
</script></body></html>"""

@app.route("/", methods=["GET", "POST"])
def index():
    mode = "url"
    url = ""
    email = ""
    result = None
    error = None
    if request.method == "POST":
        mode = request.form.get("mode", "url")
        url = request.form.get("url", "").strip()
        email = request.form.get("email", "")
        try:
            if mode == "email":
                if not email.strip():
                    raise ValueError("Paste a sample email before analyzing.")
                if len(email) > 100_000:
                    raise ValueError("Email sample is too large (100 KB limit).")
                result = analyze_email(email)
            else:
                if not url:
                    raise ValueError("Enter a URL before analyzing.")
                if len(url) > 2048:
                    raise ValueError("URL is too long.")
                result = analyze_url(url)
        except (ValueError, TypeError) as exc:
            error = str(exc)
    return render_template_string(PAGE, mode=mode, url=url, email=email, result=result, error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
