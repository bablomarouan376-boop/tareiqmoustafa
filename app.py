import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url

app = Flask(__name__, static_folder='static', template_folder='templates')

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

def decode_logic(text):
    """فك تشفير Base64 لكشف الروابط المستترة"""
    findings = ""
    potential = re.findall(r'["\']([A-Za-z0-9+/]{20,})={0,2}["\']', text)
    for b in potential:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            if any(k in decoded.lower() for k in ['http', 'script', 'camera', 'getusermedia']):
                findings += "\n" + decoded
        except: continue
    return findings

def scan_deep(html, url):
    """جلب وتحليل كل ملفات الجافا سكريبت"""
    js_all = ""
    scripts = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
    for s in scripts[:5]:
        try:
            r = requests.get(urljoin(url, s), headers=HEADERS, timeout=4)
            js_all += "\n" + r.text
        except: continue
    return js_all

@app.route('/')
def home(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    target = request.json.get('link', '').strip()
    if not target.startswith('http'): target = 'https://' + target
    
    start = time.time()
    path = [target]
    risk = 0
    rules = []

    try:
        res = requests.Session().get(target, headers=HEADERS, timeout=12, allow_redirects=True)
        for r in res.history: path.append(r.url)
        if res.url not in path: path.append(res.url)
        
        full_code = res.text + scan_deep(res.text, res.url) + decode_logic(res.text)
        
        # كشف الكاميرا والماركات
        if re.search(r'getUserMedia|mediaDevices\.getUserMedia|camera', full_code, re.I):
            risk += 85
            rules.append({"name": "تجسس", "risk_description": "محاولة وصول للكاميرا."})
            
        domain = urlparse(res.url).netloc.lower()
        if 'facebook' in domain and 'facebook.com' not in domain:
            risk += 75
            rules.append({"name": "انتحال", "risk_description": "الموقع ينتحل صفحة فيسبوك."})

    except: risk = 25
    
    return jsonify({
        "risk_score": "Critical" if risk >= 75 else "Safe",
        "suspicious_points": min(risk, 100),
        "violated_rules": rules,
        "redirect_path": path,
        "execution_time": round(time.time() - start, 2)
    })

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory('static', 'sitemap.xml')

if __name__ == '__main__':
    app.run(debug=True)
