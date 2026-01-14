import os, re, requests, time, random
from flask import Flask, request, jsonify, render_template, Response
from urllib.parse import urlparse
from datetime import datetime
from threading import Thread

app = Flask(__name__)

# --- بيانات طارق مصطفى الأمنية ---
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# --- مزامنة التهديدات العالمية ---
BLACKLIST_DB = set()
def sync_threats():
    global BLACKLIST_DB
    while True:
        try:
            new_db = set()
            feeds = ["https://openphish.com/feed.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
            for url in feeds:
                res = requests.get(url, timeout=10)
                if res.status_code == 200:
                    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', res.text)
                    new_db.update([d.lower() for d in domains])
            new_db.update(['grabify', 'iplogger', 'webcam360', 'bit.ly', 'r.mtdv.me'])
            BLACKLIST_DB = new_db
        except: pass
        time.sleep(3600)

Thread(target=sync_threats, daemon=True).start()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    
    score, violations = 0, []
    # منطق الفحص الشرس (تطوير طارق مصطفى)
    try:
        domain = urlparse(url).netloc.lower()
        if any(threat in domain for threat in BLACKLIST_DB):
            score, violations = 100, [{"name": "قائمة سوداء / Blacklist", "desc": "الرابط مسجل كتهديد أمني في قواعد البيانات العالمية."}]
        else:
            res = requests.get(url, timeout=7, headers={"User-Agent": "SecuCode-Scanner-2026"}, verify=False)
            content = res.text
            # فحص الـ JavaScript العميق (الكاميرا واللوكيشن)
            if re.search(r'getUserMedia|mediaDevices|camera|videoinput|facingMode', content, re.I):
                score = 98
                violations.append({"name": "تجسس كاميرا / Camera Spy", "desc": "الموقع يحاول الوصول للكاميرا أو الميكروفون برمجياً."})
            
            if re.search(r'password|login|كلمة المرور|signin|verify', content, re.I):
                score = max(score, 90)
                violations.append({"name": "تصيد احتيالي / Phishing", "desc": "تم اكتشاف واجهة تطلب بيانات حساسة بشكل مشبوه."})
            
            if re.search(r'getCurrentPosition|geolocation|watchPosition', content, re.I):
                score = max(score, 85)
                violations.append({"name": "تتبع جغرافي / GPS Track", "desc": "الموقع يطلب سحب إحداثيات موقعك الجغرافي الدقيق."})
    except:
        score, violations = 45, [{"name": "تحليل محدود / Encrypted", "desc": "الموقع يفرض جدار حماية يمنع الفحص العميق."}]
    
    # --- إرسال تقرير تليجرام الفوري لطارق ---
    risk_text = "CRITICAL 🚨" if score >= 80 else "SAFE ✅"
    try:
        msg = f"🛡️ رادار طارق مصطفى\n🔗 الرابط: {url}\n📊 النتيجة: {score}%\n⚠️ الحالة: {risk_text}"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg}, timeout=1)
    except: pass

    return jsonify({
        "risk_score": "Critical" if score >= 80 else "Safe", 
        "points": score, 
        "violations": violations
    })

# --- ملفات SEO الكاملة ---
@app.route('/robots.txt')
def robots():
    return Response("User-agent: *\nAllow: /\nSitemap: https://secu-code-pro.vercel.app/sitemap.xml", mimetype="text/plain")

@app.route('/sitemap.xml')
def sitemap():
    content = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://secu-code-pro.vercel.app/</loc><lastmod>2026-01-14</lastmod><priority>1.0</priority></url></urlset>'
    return Response(content, mimetype="application/xml")

@app.route('/manifest.json')
def manifest():
    return Response('{"name":"SecuCode Pro","short_name":"SecuCode","start_url":"/","display":"standalone","background_color":"#020617","theme_color":"#2563eb"}', mimetype="application/json")

if __name__ == '__main__':
    app.run(debug=True)
