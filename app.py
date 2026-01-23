import os
import requests
import base64
import urllib3
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse

# كتم تحذيرات SSL للمواقع التي لا تملك شهادات صالحة أثناء الفحص
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- إعدادات المطور: طارق مصطفى (SecuCode Pro 2026) ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

def check_spyware_behavior(url):
    """تحليل معمق لكود الصفحة لكشف طلبات الكاميرا والميكروفون والموقع"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecuCode-Audit/2.0",
            "Accept-Language": "en-US,en;q=0.9"
        }
        # جلب كود الصفحة (HTML/JS)
        response = requests.get(url, timeout=10, headers=headers, verify=False)
        content = response.text.lower()
        
        # أنماط برمجية تستخدم في صفحات التصيد وسرقة البيانات
        spy_patterns = [
            'getusermedia', 'navigator.mediadevices', 'video', 
            'canvas.todataurl', 'geolocation.getcurrentposition', 
            'track.stop', 'recorder.start', 'webcam.js'
        ]
        
        found_threats = [p for p in spy_patterns if p in content]
        return len(found_threats) > 0
    except Exception as e:
        print(f"[-] Behavior Analysis Error: {e}")
        return False

def get_vt_analysis(url):
    """جلب بيانات الاستخبارات الأمنية من VirusTotal API v3"""
    try:
        # تشفير الرابط حسب متطلبات API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=12)
        
        if res.status_code == 200:
            return res.json()['data']['attributes']['last_analysis_stats']
        else:
            print(f"[-] VT Response Error: {res.status_code}")
            return None
    except Exception as e:
        print(f"[-] VT API Connection Error: {e}")
        return None

def send_telegram_alert(domain, is_spyware, m_count, score):
    """إرسال تقرير الفحص فوراً إلى بوت التليجرام الخاص بطارق"""
    try:
        status_icon = "🔴" if (is_spyware or m_count > 0) else "🟢"
        threat_text = "CRITICAL THREAT" if (is_spyware or m_count > 0) else "SAFE DOMAIN"
        
        msg = (
            f"{status_icon} *SecuCode Pro: Forensic Report*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🌐 *Domain:* `{domain}`\n"
            f"🛡️ *Status:* {threat_text}\n"
            f"📸 *Spyware:* {'Detected' if is_spyware else 'None'}\n"
            f"🚨 *Engines:* {m_count} flagged\n"
            f"📊 *Risk Level:* {score}%\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"👤 *Analyst:* Tarek Mostafa Core"
        )
        
        tg_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": CHAT_ID,
            "text": msg,
            "parse_mode": "Markdown"
        }
        
        r = requests.post(tg_url, json=payload, timeout=10)
        if r.status_code == 200:
            print(f"[+] Telegram Alert Sent: {domain}")
        else:
            print(f"[-] Telegram Failed: {r.text}")
            
    except Exception as e:
        print(f"[-] Telegram Notification Error: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('link', '').strip()
    
    if not raw_url:
        return jsonify({"error": "Empty URL"}), 400
    
    # تصحيح صيغة الرابط
    url = raw_url if raw_url.startswith(('http://', 'https://')) else 'https://' + raw_url
    domain = urlparse(url).netloc.lower() or url
    
    # 1. تنفيذ الفحص السلوكي
    spy_detected = check_spyware_behavior(url)
    
    # 2. تنفيذ فحص الاستخبارات العالمية
    vt_stats = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    
    # 3. حساب معامل الخطورة (Logic)
    if spy_detected:
        risk_score = 99.9
        v_key = "SPYWARE_CONTENT_DETECTED"
    elif m_count > 0:
        risk_score = min(m_count * 20, 100)
        v_key = "MALICIOUS_ENGINE_FLAG"
    else:
        risk_score = 0
        v_key = "CLEAN_AUDIT"

    is_blacklisted = (spy_detected or m_count > 0)

    # 4. إرسال التنبيه فوراً
    send_telegram_alert(domain, spy_detected, m_count, risk_score)

    # 5. الاستجابة للفرونت إند
    return jsonify({
        "is_official": False,
        "is_blacklisted": is_blacklisted,
        "risk_score": risk_score,
        "violation_key": v_key,
        "spy_detected": spy_detected,
        "engines_found": m_count,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    # تشغيل السيرفر
    print("[*] SecuCode Pro Backend Starting...")
    app.run(host='0.0.0.0', port=5000, debug=True)
