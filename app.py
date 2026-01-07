import os
import re
import requests
import socket
import ssl
import time
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url

app = Flask(__name__, static_folder='static', template_folder='templates')

# إعدادات متقدمة لمحاكاة متصفح بشري كامل
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Referer": "https://www.google.com/",
}

def check_ssl_status(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except:
        return False

def extract_external_scripts(html_content, base_url):
    """استخراج محتوى ملفات الـ JavaScript الخارجية لفحصها"""
    scripts = re.findall(r'<script src=["\'](.*?)["\']', html_content, re.I)
    external_code = ""
    for script_url in scripts[:3]: # فحص أول 3 ملفات لتجنب البطء
        try:
            full_url = urljoin(base_url, script_url)
            res = requests.get(full_url, headers=HEADERS, timeout=5)
            external_code += res.text
        except:
            continue
    return external_code

def perform_deep_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    points = 0
    
    try:
        session = requests.Session()
        response = session.get(target_url, headers=HEADERS, timeout=12, allow_redirects=True)
        final_url = response.url
        main_content = response.text 
        
        # مطاردة الملفات الخارجية لجلب الكود المخفي
        external_content = extract_external_scripts(main_content, final_url)
        full_code_to_scan = main_content + external_content
        
        # 1. تتبع المسار الكامل
        for resp in response.history:
            if resp.url not in redirect_path:
                redirect_path.append(resp.url)
        if final_url not in redirect_path:
            redirect_path.append(final_url)

        # 2. رادار الخصوصية المتقدم (الكاميرا، الميكروفون، الموقع)
        privacy_triggers = {
            'Camera/Video': r'getUserMedia|mediaDevices|video|camera|webcam|snapshot|capture|stream',
            'Microphone': r'AudioContext|createMediaStreamSource|microphone|record',
            'Geolocation': r'getCurrentPosition|watchPosition|geolocation',
            'Obfuscation': r'eval\(|unescape\(|atob\(|_0x[a-f0-9]+' # كشف التشفير
        }
        
        found_triggers = []
        for key, pattern in privacy_triggers.items():
            if re.search(pattern, full_code_to_scan, re.I):
                found_triggers.append(key)
        
        if found_triggers:
            severity = 80 if 'Camera' in found_triggers or 'Geolocation' in found_triggers else 50
            points += severity
            violated_rules.append({
                "name": "محاولة اختراق خصوصية متقدمة", 
                "risk_description": f"تم رصد محاولة وصول للآتي: ({', '.join(found_triggers)}). الموقع يطلب أذونات حساسة برمجياً.", 
                "points_added": severity
            })

        # 3. فحص "سحب البيانات" (Exfiltration)
        exfiltration_patterns = [r'base64', r'FormData', r'binary', r'Buffer', r'arraybuffer', r'websocket', r'socket\.io']
        if any(re.search(p, full_code_to_scan, re.I) for p in exfiltration_patterns) and found_triggers:
            points += 20
            violated_rules.append({
                "name": "محرك سحب البيانات (Exfiltration)", 
                "risk_description": "تم رصد تقنيات لتحويل الوسائط (صور/صوت) وإرسالها فوراً لخادم خارجي.", 
                "points_added": 20
            })

        # 4. تحليل النطاق (Domain Intelligence)
        domain = urlparse(final_url).netloc
        if not final_url.startswith('https'):
            points += 40
            violated_rules.append({"name": "اتصال مكشوف", "risk_description": "الموقع لا يستخدم تشفير، أي بيانات تمر عبره قابلة للاختراق.", "points_added": 40})
        
        # كشف الروابط التي تحاول تقليد شركات كبرى
        suspicious_keywords = r'google|facebook|login|secure|verify|update|account|billing|support'
        if re.search(suspicious_keywords, domain, re.I):
            points += 25
            violated_rules.append({"name": "اشتباه انتحال صفحة (Phishing)", "risk_description": "اسم النطاق يحتوي على كلمات تستخدم عادةً لخداع المستخدمين.", "points_added": 25})

    except Exception as e:
        points += 30
        violated_rules.append({"name": "فشل التحليل العميق", "risk_description": "الموقع محمي بجدران نارية تمنع الفحص، وهذا سلوك مريب جداً.", "points_added": 30})
        final_url = target_url

    # النتيجة النهائية (The Beast Mode Logic)
    points = min(points, 100)
    risk = "Critical" if points >= 75 else "High" if points >= 50 else "Medium" if points >= 25 else "Low"

    return {
        "risk_score": risk,
        "suspicious_points": points,
        "violated_rules": violated_rules,
        "link_final": final_url,
        "redirect_path": redirect_path,
        "execution_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('link', '').strip()
    if not url: return jsonify({"message": "أدخل الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "رابط خاطئ"}), 400
    return jsonify(perform_deep_analysis(url))

@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')

if __name__ == '__main__':
    app.run(debug=True)

