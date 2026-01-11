import time
import re
import requests
from flask import Flask, render_template, send_from_directory, request, jsonify

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- دعم PWA والارشفة ---
@app.route('/manifest.json')
def manifest():
    # هذا المسار يرسل ملف المانيفست للمتصفح ليظهر كأيقونة تطبيق
    return send_from_directory(app.static_folder, 'manifest.json')

@app.route('/googlecc048452b42b8f02.html')
def google_verify():
    # مسار إثبات ملكية جوجل الخاص بك
    return "google-site-verification: googlecc048452b42b8f02.html"

# --- محرك فحص الروابط الذكي ---
def deep_analyze(url):
    start_time = time.time()
    data = {
        "points": 0,
        "risk_score": "Low",
        "redirects": [url],
        "violations": [],
        "analysis_time": 0
    }
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecuCodePro/3.5'}
        # تتبع التحويلات
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        data["redirects"] = [r.url for r in response.history] + [response.url]
        content = response.text
        
        # 1. فحص التشفير SSL
        if not response.url.startswith('https'):
            data["points"] += 45
            data["violations"].append({"name": "اتصال مكشوف", "desc": "الموقع لا يستخدم بروتوكول HTTPS الآمن."})

        # 2. فحص تشفير Base64
        if len(re.findall(r"([A-Za-z0-9+/]{60,}=*)", content)) > 0:
            data["points"] += 35
            data["violations"].append({"name": "تشفير مشبوه", "desc": "تم رصد محاولات إخفاء أكواد برمجية في الصفحة."})

        # 3. تحليل كلمات التصيد
        if any(word in content.lower() for word in ['login', 'verify', 'password', 'bank']):
            data["points"] += 20
            data["violations"].append({"name": "اشتباه تصيد", "desc": "الصفحة تحتوي على عناصر لسرقة البيانات."})

    except Exception:
        data["risk_score"] = "Medium"
        data["violations"].append({"name": "تنبيه", "desc": "الموقع محمي أو يمنع الفحص التلقائي."})

    p = data["points"]
    data["risk_score"] = "Critical" if p >= 80 else "High" if p >= 50 else "Medium" if p >= 25 else "Low"
    data["analysis_time"] = round(time.time() - start_time, 2)
    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    req = request.json or {}
    url = req.get('link', '').strip()
    if not url: return jsonify({"error": "No URL"}), 400
    if not url.startswith('http'): url = 'https://' + url
    return jsonify(deep_analyze(url))

if __name__ == '__main__':
    app.run(debug=True)
