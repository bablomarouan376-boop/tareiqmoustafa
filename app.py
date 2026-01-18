# app.py (Updated with all suggested features: security improvements, rate limiting, VirusTotal integration, AI analysis using OpenAI, history storage in Firebase, advanced stats)

import os
import re
import requests
import time
import json
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import tldextract
from firebase_admin import credentials, initialize_app, db  # Add firebase_admin for server-side
import openai  # For AI integration

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Initialize Firebase (use your credentials)
cred = credentials.Certificate(json.loads(os.environ.get("FIREBASE_CREDENTIALS")))  # Store JSON in env var
initialize_app(cred, options={'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'})

# Environment variables for security
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai.api_key = OPENAI_API_KEY

# Static file routes
@app.route('/robots.txt')
@app.route('/api/robots')
def robots(): 
    return send_from_directory('static', 'robots.txt')

@app.route('/sitemap.xml')
@app.route('/api/sitemap')
def sitemap(): 
    return send_from_directory('static', 'sitemap.xml')

@app.route('/sw.js')
@app.route('/api/sw')
def sw(): 
    return send_from_directory('static', 'sw.js')

# Main index
@app.route('/')
@app.route('/api/index')
def index(): 
    return render_template('index.html')

# Analyze endpoint with enhancements
@app.route('/analyze', methods=['POST'])
@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    data = request.json
    if not data: return jsonify({"error": "No data"}), 400
    
    url = data.get('link', '').strip()
    user_id = data.get('user_id', 'anonymous')  # For history, from client
    if not url: return jsonify({"error": "Empty URL"}), 400
    if not url.startswith('http'): url = 'https://' + url
    
    score, v_key = 0, "CLEAN"
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    details = {}

    try:
        # Whitelist check
        WHITELIST = {'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'github.com'}
        BLACKLIST = ['casajoys.com']  # From your original
        if any(w in domain for w in WHITELIST):
            score, v_key = 0, "TRUSTED"
        elif any(b in domain for b in BLACKLIST):
            score, v_key = 100, "BLACKLISTED"
        else:
            # Fetch with security
            res = requests.get(url, timeout=5, verify=True, allow_redirects=True, headers={"User-Agent": "SecuCode-AI"})
            html = res.text
            details['redirects'] = len(res.history)
            
            # Regex checks
            if re.search(r'getUserMedia|camera|microphone', html, re.I):
                score += 50
                v_key = "SPYWARE"
            if len(re.findall(r'<script', html)) > 50:
                score += 30
                v_key = "EXCESSIVE_SCRIPTS"
            
            # VirusTotal integration
            if VIRUSTOTAL_API_KEY:
                vt_url_id = requests.post("https://www.virustotal.com/api/v3/urls", 
                                          headers={"x-apikey": VIRUSTOTAL_API_KEY}, 
                                          data={"url": url}).json().get('data', {}).get('id')
                time.sleep(15)  # Wait for analysis
                vt_res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{vt_url_id}", 
                                      headers={"x-apikey": VIRUSTOTAL_API_KEY})
                if vt_res.status_code == 200:
                    vt_data = vt_res.json()
                    malicious = vt_data['data']['attributes']['stats'].get('malicious', 0)
                    if malicious > 0:
                        score = max(score, 80)
                        v_key = "MALICIOUS_VT"
            
            # AI analysis (OpenAI for advanced phishing detection)
            if OPENAI_API_KEY:
                ai_prompt = f"Analyze this HTML snippet for phishing or malicious patterns: {html[:2000]}"  # Limit to avoid tokens
                ai_res = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": ai_prompt}])
                ai_analysis = ai_res['choices'][0]['message']['content']
                if "phishing" in ai_analysis.lower() or "malicious" in ai_analysis.lower():
                    score += 40
                    v_key = "AI_SUSPICIOUS"
                details['ai_analysis'] = ai_analysis

        # Update global stats
        ref = db.reference('stats')
        ref.child('clicks').transaction(lambda current: (current or 0) + 1)
        if score > 60:
            ref.child('threats').transaction(lambda current: (current or 0) + 1)
        
        # Store user history
        history_ref = db.reference(f'users/{user_id}/history')
        history_ref.push({
            'url': url,
            'score': score,
            'v_key': v_key,
            'timestamp': time.time()
        })

    except Exception as e:
        score, v_key = 45, "SHIELD"
        details['error'] = str(e)

    # Telegram notification
    try:
        msg = f"🔍 [SCAN] {domain}\n📊 Risk: {score}%\n🛡️ Key: {v_key}\nDetails: {json.dumps(details)}"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                      json={"chat_id": CHAT_ID, "text": msg}, timeout=1)
    except: pass

    return jsonify({
        "risk_score": "Critical" if score >= 75 else "Safe",
        "points": score,
        "violation_key": v_key,
        "details": details,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

# New endpoint for user history
@app.route('/history', methods=['GET'])
@app.route('/api/history', methods=['GET'])
def get_history():
    user_id = request.args.get('user_id', 'anonymous')
    history_ref = db.reference(f'users/{user_id}/history')
    history = history_ref.get() or {}
    return jsonify(list(history.values()))

# New endpoint for advanced stats (for charts)
@app.route('/stats', methods=['GET'])
@app.route('/api/stats', methods=['GET'])
def get_stats():
    ref = db.reference('stats')
    stats = ref.get() or {'clicks': 0, 'threats': 0}
    # Add more advanced stats if needed, e.g., daily trends from history
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=True)
