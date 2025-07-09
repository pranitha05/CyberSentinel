from dotenv import load_dotenv
import os
load_dotenv()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("❌ GEMINI_API_KEY not found in .env.")

import google.generativeai as genai
genai.configure(api_key=GEMINI_API_KEY)

from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify, make_response
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet, InvalidToken
from urllib.parse import urlparse
import socket, hashlib, re
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth

cred = credentials.Certificate("/etc/secrets/firebase-admin-sdk.json")
firebase_admin.initialize_app(cred)

main = Blueprint('main', __name__)
encryption_bp = Blueprint('encryption', __name__)
chatbot_bp = Blueprint('chatbot', __name__)
gemini_model = genai.GenerativeModel("gemini-1.5-flash")

@main.route('/')
def index():
    return render_template('index.html')

    

@main.route('/session-login', methods=['POST'])
def session_login():
    id_token = request.json.get('idToken')
    try:
        decoded = firebase_auth.verify_id_token(id_token)
        session['user_logged_in'] = True
        session['user_email'] = decoded.get('email', '')
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 401

@main.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('main.index'))

from .password_checker import check_password_strength

@main.route('/password-checker', methods=['GET', 'POST'])
def password_checker():
    result = None
    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            result = check_password_strength(password)
            result['password'] = password
    return render_template('password_checker.html', result=result)

with open('data/feed.txt') as f:
    PHISHING_DOMAINS = [line.strip().lower() for line in f if line.strip()]

@main.route('/url-checker', methods=['GET', 'POST'])
def url_checker():
    url, result = None, None
    if request.method == 'POST':
        url = request.form.get('url', '').strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        domain = urlparse(url).netloc.lower().split(':')[0].replace('www.', '')
        if not domain:
            result = "❌ Invalid URL"
        elif any(phish in domain for phish in PHISHING_DOMAINS):
            result = "🚨 Malicious domain (blacklisted)"
        else:
            result = "✅ Appears safe (not in known threat list)"
    return render_template('url_checker.html', url=url, result=result)

def login_required(route):
    def wrapper(*args, **kwargs):
        if not session.get('user_logged_in'):
            return redirect(url_for('main.index'))
        return route(*args, **kwargs)
    wrapper.__name__ = route.__name__
    return wrapper

@main.route('/network-scanner', methods=['GET', 'POST'])
@login_required
def network_scanner():
    target, scan_results = None, []
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        try:
            ip = socket.gethostbyname(target)
            ports = {
                21: ("FTP", "⚠️ Risky"),
                22: ("SSH", "⚠️ Risky"),
                23: ("Telnet", "⚠️ Dangerous"),
                25: ("SMTP", "⚠️ Risky"),
                53: ("DNS", "✅ Safe"),
                80: ("HTTP", "✅ Safe"),
                110: ("POP3", "⚠️ Risky"),
                139: ("NetBIOS", "⚠️ Risky"),
                143: ("IMAP", "⚠️ Risky"),
                443: ("HTTPS", "✅ Safe"),
                445: ("SMB", "⚠️ Risky"),
                3306: ("MySQL", "⚠️ Risky"),
                3389: ("RDP", "⚠️ Risky"),
            }
            for port, (svc, note) in ports.items():
                with socket.socket() as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        symbol = "✅" if note.startswith("✅") else "⚠️"
                        scan_results.append(f"{symbol} Port {port} ({svc}) - {note}")
        except socket.gaierror:
            scan_results.append("❌ Unable to resolve host")
    return render_template('network_scanner.html', target=target, scan_results=scan_results)

@main.route('/download-scan', methods=['POST'])
@login_required
def download_scan():
    target = request.form.get('target')
    results = request.form.getlist('scan_results')
    text = f"Scan Results for: {target}\n\n" + "\n".join(results)
    resp = make_response(text)
    resp.headers['Content-Disposition'] = f'attachment; filename=scan_{target}.txt'
    resp.mimetype = 'text/plain'
    return resp

@encryption_bp.route('/encryption-tools')
@login_required
def encryption_tools():
    return render_template('encryption_tools.html')

@encryption_bp.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    text = request.form.get("inputText", "")
    cipher = request.form.get("cipher", "")
    key = request.form.get("key", "")
    result = ""
    try:
        if cipher == "caesar":
            result = ''.join(chr((ord(c)-65+3)%26+65) if c.isupper() else chr((ord(c)-97+3)%26+97) if c.islower() else c for c in text)
        elif cipher == "base64":
            result = b64encode(text.encode()).decode()
        elif cipher == "aes":
            if not key:
                result = "⚠️ Password required"
            else:
                fernet = Fernet(b64encode(hashlib.sha256(key.encode()).digest()[:32]))
                result = fernet.encrypt(text.encode()).decode()
    except Exception as e:
        result = f"❌ {str(e)}"
    return render_template('encryption_tools.html', result=result)

@encryption_bp.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    text = request.form.get("inputText","")
    cipher = request.form.get("cipher","")
    key = request.form.get("key","")
    result = ""
    try:
        if cipher == "caesar":
            result = ''.join(chr((ord(c)-65-3)%26+65) if c.isupper() else chr((ord(c)-97-3)%26+97) if c.islower() else c for c in text)
        elif cipher == "base64":
            result = b64decode(text.encode()).decode()
        elif cipher == "aes":
            if not key: result = "⚠️ Password required"
            else:
                f = Fernet(b64encode(hashlib.sha256(key.encode()).digest()[:32]))
                result = f.decrypt(text.encode()).decode()
    except Exception as e:
        result = f"❌ {str(e)}"
    return render_template('encryption_tools.html', result=result)

@main.route('/privacy-analyzer', methods=['GET','POST'])
@login_required
def privacy_analyzer():
    text, result = '', None
    if request.method == 'POST':
        text = request.form.get('inputText','')
        score, details, suggestions = 100, [], []
        patterns = {
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            'Phone': r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b',
            'Aadhaar': r'\b\d{4}\s\d{4}\s\d{4}\b',
            'Credit Card': r'\b(?:\d{4}[-\s]?){4}\b',
            'Address': r'\b(street|road|nagar|layout|avenue|colony)\b',
            'Name': r'\b[A-Z][a-z]{2,}\s[A-Z][a-z]{2,}\b'
        }
        import re
        for label, pat in patterns.items():
            matches = re.findall(pat, text)
            if matches:
                details.append(f"{label}s: {', '.join(set(matches))[:100]}")
                score -= 15
                suggestions.append(f"Avoid exposing {label.lower()}.")
        result = {
            'score': max(score,0),
            'details': "\n".join(details) if details else "✅ No sensitive info detected.",
            'suggestions': suggestions or ["✔️ Looks safe!"],
            'color': 'green' if score>70 else 'orange' if score>40 else 'red'
        }
    return render_template('privacy_analyzer.html', result=result, text=text)

@chatbot_bp.route('/chatbot', methods=['POST'])
def chatbot():
    msg = request.json.get('message', "")
    if not msg:
        return jsonify({"response": "Please enter a message."})
    try:
        res = gemini_model.generate_content(msg).text
        return jsonify({"response": res})
    except Exception as e:
        return jsonify({"response": f"❌ {str(e)}"})
