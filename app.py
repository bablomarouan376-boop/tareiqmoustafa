import os
import re
import requests
import socket
import ssl
import time
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse
from validators import url as validate_url

app = Flask(__name__, static_folder='static', template_folder='templates')

# محاكاة متصفح متقدم جداً لتجاوز حماية المواقع
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

def check_ssl_status(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except:
        return False

def perform_deep_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    points = 0
    
    try:
        # محاولة جلب محتوى الصفحة مع تتبع التحويلات
        session = requests.Session()
        response = session.get(target_url, headers=HEADERS, timeout=12, allow_redirects=True)
        final_url = response.url
        content = response.text 
        
        # 1. تتبع المسار
        for resp in response.history:
            if resp.url not in redirect_path:
                redirect_path.append(resp.url)
        if final_url not in redirect_path:
            redirect_path.append(final_url)

        # 2. فحص كلمات "سحب الكاميرا" المشفرة والعادية (Behavioral Detection)
        # أضفت هنا كلمات يبحث عنها الهاكرز لإخفاء كود الكاميرا
        camera_patterns = [
            r'getUserMedia', r'mediaDevices', r'video', r'camera', 
            r'navigator\.webkitGetUserMedia', r'navigator\.mozGetUserMedia',
            r'stream', r'track', r'snapshot', r'webcam', r'capture'
        ]
        
        found_camera_triggers = [p for p in camera_patterns if re.search(p, content, re.I)]
        
        if found_camera_triggers:
            points += 85  # نقطة خطر عالية جداً
            violated_rules.append({
                "name": "رادار كشف الكاميرا", 
                "risk_description": f"تحذير! تم رصد محاولة وصول للوسائط (كاميرا/مايك) داخل كود الصفحة. الموقع يحاول استخدام: {', '.join(found_camera_triggers[:2])}", 
                "points_added": 85
            })

        # 3. فحص "إرسال البيانات" (Exfiltration Detection)
        # المواقع التي تصور الضحية يجب أن ترسل الصورة للسيرفر، سنكشف كود الإرسال
        upload_patterns = [r'ajax', r'fetch', r'XMLHttpRequest', r'POST', r'upload', r'base64']
        if found_camera_triggers and any(re.search(p, content, re.I) for p in upload_patterns):
            points += 15 # زيادة الخطر إذا وجدنا كود إرسال مع كود كاميرا
            violated_rules.append({
                "name": "نشاط سحب بيانات بصري", 
                "risk_description": "تم رصد كود يقوم بالتقاط صور وإرسالها إلى خادم خارجي.", 
                "points_added": 15
            })

        # 4. فحص الروابط المشبوهة (Metadata)
        if not final_url.startswith('https'):
            points += 40
            violated_rules.append({"name": "رابط غير مشفر", "risk_description": "الموقع لا يستخدم تشفير HTTPS.", "points_added": 40})
        
        # كشف الروابط الطويلة جداً أو الغريبة
        if len(final_url) > 100 or final_url.count('.') > 3:
            points += 20
            violated_rules.append({"name": "هيكل رابط مريب", "risk_description": "الرابط طويل جداً أو يحتوي على نطاقات فرعية مريبة.", "points_added": 20})

    except Exception:
        points += 30
        violated_rules.append({"name": "حماية ضد الفحص", "risk_description": "الموقع يستخدم تقنيات لمنع الرادار من قراءة محتواه.", "points_added": 30})
        final_url = target_url

    risk = "Critical" if points >= 80 else "High" if points >= 45 else "Medium" if points >= 20 else "Low"

    return {
        "risk_score": risk,
        "suspicious_points": min(points, 100), # لا يتعدى 100
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

