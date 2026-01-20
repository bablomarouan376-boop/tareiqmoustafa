import os, requests, base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse

app = Flask(__name__, 
            static_folder='static', 
            static_url_path='/static',
            template_folder='templates')

# --- إعدادات المطور طارق مصطفى ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

def check_spyware_behavior(url):
    """فحص كود الصفحة لكشف طلبات الكاميرا والميكروفون"""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecuCode-Audit/1.0"}
        # تعطيل verify=False لتجنب مشاكل شهادات SSL
        response = requests.get(url, timeout=7, headers=headers, verify=False)
        html = response.text.lower()
        
        spy_patterns = ['getusermedia', 'navigator.mediadevices', 'video', 'canvas.todataurl', 'geolocation']
        found = [p for p in spy_patterns if p in html]
        return len(found) > 0
    except Exception as e:
        print(f"Spy Check Error: {e}")
        return False

def get_vt_analysis(url):
    """جلب تقارير المحركات العالمية من VirusTotal"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if res.status_code == 200:
            return res.json()['data']['attributes']['last_analysis_stats']
        return None
    except Exception as e:
        print(f"VT Error: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('link', '').strip()
    
    if not url:
        return jsonify({"error": "URL missing"}), 400
    
    # تصحيح الرابط إذا لم يحتوي على بروتوكول
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain = urlparse(url).netloc.lower().replace('www.', '')
    
    # 1. فحص السلوك (الكاميرا/التجسس)
    is_spyware = check_spyware_behavior(url)
    
    # 2. فحص الاستخبارات العالمية
    vt_stats = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    
    # تحديد النتيجة
    if is_spyware:
        score, status, v_key = 99, "Critical", "SPYWARE_ATTEMPT"
    elif m_count > 0:
        score, status, v_key = min(m_count * 20, 100), "Critical", "SUSPICIOUS"
    else:
        score, status, v_key = 0, "Safe", "CLEAN_AUDIT"

    # 3. إشعار تليجرام
    try:
        status_emoji = "🔴" if is_spyware or m_count > 0 else "🟢"
        msg = (f"{status_emoji} *SecuCode Scan Result*\n"
               f"🌐 Domain: {domain}\n"
               f"📸 Spyware Detected: {'YES' if is_spyware else 'No'}\n"
               f"🚨 Malicious Engines: {m_count}\n"
               f"📊 Risk Score: {score}%")
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                      json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
    except: pass

    return jsonify({
        "risk_score": status,
        "points": score,
        "violation_key": v_key,
        "engines_found": m_count,
        "spy_detected": is_spyware,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    app.run(debug=True)
