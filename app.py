import os
import requests
import base64
import urllib3
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db

# إعدادات الحماية وتجاهل التحذيرات
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

# 1. القائمة البيضاء الموسعة (المواقع الرسمية والعلمية والتقنية)
WHITELIST_DOMAINS = [
    'google.com', 'google.com.eg', 'bing.com', 'yahoo.com',
    'microsoft.com', 'apple.com', 'icloud.com', 'github.com',
    'wikipedia.org', 'wikimedia.org', 'archive.org', 'nasa.gov',
    'nih.gov', 'sciencedirect.com', 'researchgate.net', 'ieee.org',
    'mit.edu', 'stanford.edu', 'harvard.edu', 'ox.ac.uk',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
    'amazon.com', 'netflix.com', 'zoom.us', 'adobe.com', 'oracle.com'
]

def check_spyware_behavior(url, domain):
    # المواقع الرسمية مستثناة من فحص الكود السلوكي لمنع النتائج الخاطئة
    if any(d in domain for d in WHITELIST_DOMAINS):
        return False
        
    try:
        headers = {"User-Agent": "SecuCode-Forensic/3.0 (Tarek Mostafa Intel)"}
        response = requests.get(url, timeout=5, headers=headers, verify=False)
        content = response.text.lower()
        
        # أنماط تجسس متقدمة
        spy_patterns = [
            'navigator.mediadevices.getusermedia',
            'getcurrentposition',
            'webcam.attach',
            'mediarecorder',
            '.startrecording'
        ]
        return any(p in content for p in spy_patterns)
    except:
        return False

def get_vt_analysis(url):
    """يغطي VirusTotal بيانات PhishTank والقوائم السوداء منذ سنوات"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            # إضافة بيانات إضافية عن التصنيف (Phishing, Malware)
            return stats
        else:
            # طلب فحص جديد إذا كان الرابط مجهولاً للنظام
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            return None
    except:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    raw_url = data.get('link', '').strip()
    if not raw_url: return jsonify({"error": "Empty URL"}), 400
    
    url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
    parsed = urlparse(url)
    domain = parsed.netloc.lower() or url
    
    # استعلام الاستخبارات (يغطي القوائم السوداء التاريخية و PhishTank)
    vt_stats = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    p_count = vt_stats.get('phishing', 0) if vt_stats else 0 # فحص محدد لروابط الاحتيال
    
    # الفحص السلوكي للتجسس
    spy_detected = check_spyware_behavior(url, domain)
    
    # --- منطق القائمة السوداء والبيضاء ---
    is_blacklisted = False
    risk_score = 0
    
    # إذا كان في القائمة البيضاء (حماية المواقع الرسمية)
    if any(d in domain for d in WHITELIST_DOMAINS):
        is_blacklisted = False
        risk_score = 0
    else:
        # إذا تم رصده في القوائم السوداء (VirusTotal / PhishTank)
        if m_count > 0 or p_count > 0:
            is_blacklisted = True
            risk_score = min(50 + (m_count * 10) + (p_count * 15), 100)
            
        # إذا تم رصد سلوك تجسس
        if spy_detected:
            is_blacklisted = True
            risk_score = max(risk_score, 90)

    # تحديث Firebase
    try:
        db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
        if is_blacklisted: db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
    except: pass

    # إرسال تلجرام بصيغة مطورة
    try:
        icon = "🔴" if is_blacklisted else "🟢"
        msg = (f"{icon} *SecuCode Intel Update*\n"
               f"Domain: `{domain}`\n"
               f"Phish/Malware: {m_count + p_count}\n"
               f"Spyware Behavior: {spy_detected}\n"
               f"Final Risk: {risk_score}%")
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                      json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
    except: pass

    return jsonify({
        "is_official": (not is_blacklisted and any(d in domain for d in WHITELIST_DOMAINS)),
        "is_blacklisted": is_blacklisted,
        "risk_score": risk_score,
        "spy_detected": spy_detected,
        "engines_found": m_count + p_count,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    app.run(debug=True)
