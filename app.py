import os, re, requests, time
from flask import Flask, request, jsonify, render_template, Response
from urllib.parse import urlparse
from threading import Thread

app = Flask(__name__)

# بيانات المطور طارق مصطفى
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# --- [ نظام مزامنة التهديدات الشامل ] ---
# هذا الجزء هو المسؤول عن قوة الفحص، يعمل في الخلفية لتحديث القوائم السوداء
GLOBAL_BLACKLIST = set()
def update_threat_intelligence():
    global GLOBAL_BLACKLIST
    while True:
        try:
            new_data = set()
            # جلب البيانات من OpenPhish و StevenBlack
            sources = ["https://openphish.com/feed.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
            for src in sources:
                r = requests.get(src, timeout=15)
                if r.status_code == 200:
                    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', r.text)
                    new_data.update([d.lower() for d in domains])
            # إضافة الروابط المشبوهة يدوياً
            new_data.update(['grabify', 'iplogger', 'webcam360', 'bit.ly', 'r.mtdv.me'])
            GLOBAL_BLACKLIST = new_data
        except: pass
        time.sleep(3600) # تحديث كل ساعة

Thread(target=update_threat_intelligence, daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    
    score, violations = 0, []
    domain = urlparse(url).netloc.lower()

    try:
        # 1. فحص القائمة السوداء (Match)
        if any(bad in domain for bad in GLOBAL_BLACKLIST):
            score, violations = 100, [{"name": "Blacklist Alert", "desc": "هذا النطاق مسجل عالمياً كتهديد أمني خطير."}]
        else:
            # 2. الفحص البرمجي الصارم (Deep Inspection)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
            response = requests.get(url, timeout=10, headers=headers, verify=False)
            html = response.text

            # كشف محاولات فتح الكاميرا/الميكروفون (JS)
            if re.search(r'getUserMedia|mediaDevices|camera|videoinput|facingMode', html, re.I):
                score = 98
                violations.append({"name": "Spyware Detected", "desc": "الموقع يحتوي على كود برمجى يحاول تشغيل الكاميرا سراً."})
            
            # كشف صفحات التصيد (Phishing)
            if re.search(r'password|login|كلمة المرور|signin|verify|bank', html, re.I):
                score = max(score, 90)
                violations.append({"name": "Phishing Risk", "desc": "تم العثور على حقول إدخال بيانات حساسة تشبه صفحات انتحال الشخصية."})

    except:
        # في حالة فشل الفحص أو الحماية
        score, violations = 45, [{"name": "Encrypted / Hidden", "desc": "الموقع مشفر أو يستخدم جدران حماية لمنع تحليل الأكواد."}]

    # إرسال التقرير لتليجرام (فوري)
    try:
        msg = f"🛡️ رادار طارق مصطفى\n🔗 {url}\n📊 الخطورة: {score}%\n👤 المطور: طارق مصطفى"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg}, timeout=1)
    except: pass

    return jsonify({"risk_score": "Critical" if score >= 80 else ("Warning" if score > 0 else "Safe"), "points": score, "violations": violations})

# --- [ ملفات SEO والتعريف ] ---
@app.route('/robots.txt')
def robots(): return Response("User-agent: *\nAllow: /", mimetype="text/plain")

@app.route('/manifest.json')
def manifest():
    content = '{"name":"SecuCode Pro","short_name":"SecuCode","start_url":"/","display":"standalone","background_color":"#020617","theme_color":"#2563eb"}'
    return Response(content, mimetype="application/json")

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
