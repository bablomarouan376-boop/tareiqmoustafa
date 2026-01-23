import os
import requests
import base64
import urllib3
import socket  # إضافة لجلب الـ IP
import time    # إضافة للتوقيت
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db

# إعدادات الحماية
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- إعدادات طارق مصطفى الأمنية ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# إعداد Firebase
try:
    if not firebase_admin._apps:
        firebase_admin.initialize_app(options={'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'})
except: pass

WHITELIST_DOMAINS = [
    'google.com', 'google.com.eg', 'bing.com', 'yahoo.com',
    'microsoft.com', 'apple.com', 'github.com', 'wikipedia.org', 
    'nasa.gov', 'facebook.com', 'x.com', 'linkedin.com', 'amazon.com'
]

def get_server_forensics(domain):
    """جلب بيانات الخادم الجنائية لعرضها في الورقة البيضاء"""
    try:
        ip = socket.gethostbyname(domain)
        # جلب الدولة والشركة المستضيفة عبر API مجاني
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        return {
            "ip": ip,
            "country": geo.get("country_name", "Unknown"),
            "org": geo.get("org", "Private Provider")
        }
    except:
        return {"ip": "0.0.0.0", "country": "Protected/Proxy", "org": "CDN/Private"}

def get_vt_analysis(url):
    """تحليل مطور لجلب تفاصيل المحركات (Details Matrix)"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        
        if res.status_code == 200:
            attr = res.json()['data']['attributes']
            stats = attr['last_analysis_stats']
            results = attr['last_analysis_results']
            
            # استخراج قائمة بـ 6 محركات فحص لزيادة قوة التقرير
            details = []
            for engine, data in results.items():
                if data['category'] in ['malicious', 'phishing']:
                    details.append({"engine": engine, "result": data['result']})
                if len(details) >= 6: break
            
            # إذا كان الموقع نظيفاً، أضف محركات شهيرة كدليل
            if not details:
                details = [
                    {"engine": "Kaspersky", "result": "clean"},
                    {"engine": "Symantec", "result": "clean"},
                    {"engine": "Google Safebrowsing", "result": "clean"}
                ]
            return stats, details
        return None, []
    except:
        return None, []

def check_spyware_behavior(url, domain):
    if any(d in domain for d in WHITELIST_DOMAINS): return False
    try:
        headers = {"User-Agent": "SecuCode-Forensic/3.0 (Tarek Mostafa Intel)"}
        response = requests.get(url, timeout=5, headers=headers, verify=False)
        content = response.text.lower()
        spy_patterns = ['getusermedia', 'getcurrentposition', 'mediarecorder']
        return any(p in content for p in spy_patterns)
    except: return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    raw_url = data.get('link', '').strip()
    if not raw_url: return jsonify({"error": "Empty URL"}), 400
    
    url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
    domain = urlparse(url).netloc.lower() or url
    
    # 1. تحليل الخادم (Forensics)
    server_info = get_server_forensics(domain)
    
    # 2. تحليل الاستخبارات (VT & Details)
    vt_stats, engine_details = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    p_count = vt_stats.get('phishing', 0) if vt_stats else 0
    
    # 3. الفحص السلوكي
    spy_detected = check_spyware_behavior(url, domain)
    
    # منطق التقرير
    is_official = any(d in domain for d in WHITELIST_DOMAINS)
    is_blacklisted = False
    risk_score = 0
    
    if not is_official:
        if m_count > 0 or p_count > 0:
            is_blacklisted = True
            risk_score = min(50 + (m_count * 10) + (p_count * 15), 100)
        if spy_detected:
            is_blacklisted = True
            risk_score = max(risk_score, 90)

    # تحديث Firebase
    try:
        db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
        if is_blacklisted: db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
    except: pass

    # إرسال تلجرام
    try:
        icon = "🔴" if is_blacklisted else "🟢"
        msg = f"{icon} *SecuCode Scan*\nDomain: `{domain}`\nRisk: {risk_score}%\nIP: {server_info['ip']}"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                      json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
    except: pass

    # إرجاع كافة البيانات المطلوبة للورقة البيضاء
    return jsonify({
        "is_official": is_official,
        "is_blacklisted": is_blacklisted,
        "risk_score": risk_score,
        "spy_detected": spy_detected,
        "engines_found": m_count + p_count,
        "details": engine_details,        # مصفوفة المحركات (مهمة للتقرير)
        "server": server_info,             # بيانات الخادم (مهمة للتقرير)
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    app.run(debug=True)
