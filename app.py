import os
import requests
import base64
import socket
import time
import json
import logging
import cloudinary
import cloudinary.uploader
from flask import Flask, request, jsonify, render_template, make_response
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db
from xhtml2pdf import pisa
from io import BytesIO

app = Flask(__name__)

# إعداد السجلات (Logging)
logging.basicConfig(level=logging.INFO)

# --- إعداد Cloudinary ببياناتك يا طارق ---
cloudinary.config( 
  cloud_name = "dsn0uoooi", 
  api_key = "977478274789475", 
  api_secret = "DfXoA-V1Nuwq1EQbk1X-8HLPOOY"
)

# --- بيانات الوصول والرموز الحساسة ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# إعدادات Firebase Admin SDK
FIREBASE_CONFIG = {
  "type": "service_account",
  "project_id": "secucode-pro",
  "private_key_id": "131da2ca8578982b77e48fa71f8c4b65880b0784",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZwhV2C+HnRrp8\nTemJc7bdbGw2JUb47hZ1ShXk2ReFbQ256bhud1AIO+rxHJ0fzq8Ba+ZTaAsodLxU\nn74+dxpyrMUolvBONnWgFeQtgqFsHouAAy0j/iJs6yNny6o4f/TVp4UKixqY+jT0\nTSBo8ixU7Dxh6VWdom62BsKUAGN8ALFM5N6+4z3fbCj9fB4mmvibIQLLAVwxZ703\ndSP1ZFOJgd98LEHYOBYBKAOQ/fEyq20e8PEokuVnoLqvLxJDGCwGvv5aEadq2t3O\nhJ9oJAefIDD2YsAPgeMu8MAtlHlTuoqu82FGehQ2v6mtC4121W2NFLORPC1fttWE\nFr5U5La3AgMBAAECggEAAUqVcGNeFirBiZCBK7wwJ6P3mLGZpkmD9N5R6FByJyy+\nr91nA2d4fZpiP3ZA9jTda0K8Hr9B2uEm8CjcqcJGXmtDC/UTsQIhAm5H9DE2gAyr\nej0lkOh6l9ScwTHA0Z8MnTy0xOBpeRdjZ32pjiSSixW0QB8kj4u0NJ+yvW+3NDru\ntErFEF03IaMgfnK279reWuNKC72lZfVlkFk9qoi6b34j1mdhAXlkIqPm1plkd8py\nZDPxGf7/xdB32peadLpuWHvd/JyE9hLGa+CT9g12kKOcxh/KmJVD5MBkIriQAFoh\nT7pvJm9SDju4uDtc6O26IME3/YIwjB+YfgrXMySMiQKBgQDOSdjq2/TJTYXoen2X\ncvlssZGGVenb30rcQHIPtC9xHhczPJ6cAPhRltmeV37HO8g82unNnbsAePCsVZx+\nX6p2y9VDzTDimAJEXd/JVjwBnFs8/8GwUwLoFvsbnAvA8pSFHYmKURDJolPjJ0Gw\qr40NrApbRG47JYQHyhHTfOPwwKBgQC+z5Xa2yT1rSzOsNoOwfJmTo0oThNaTExE\n6/8/1F7NpeZLKbew5sai20CmmvWKljVKgiyUdJLZShlbnqv3QUvEL+PH9pWNftpd\phAlbEG9UPjF6nR8IrOwtAXK3tMyrGlYl7EI0dgwY8pzoYgUraRik2AqfaG2BRe/\n8oUXZMKh/QKBgGmwaiOCB/su7cF7KGd0r5fhrgZedA+Dao5HsmibT4cr/ITytOyG\njrL2j45Rk5Gt7lxHaGxBOLL4 (truncated for safety) \n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@secucode-pro.iam.gserviceaccount.com"
}

# تشغيل Firebase
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(FIREBASE_CONFIG)
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'
        })
except Exception as e:
    logging.error(f"Firebase Init Error: {e}")

WHITELIST_DOMAINS = ['google.com', 'microsoft.com', 'apple.com', 'facebook.com', 'github.com', 'wikipedia.org']

# --- الوظائف المساعدة ---

def get_vt_stats(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
        return None
    except: return None

def get_forensics(domain):
    try:
        ip = socket.gethostbyname(domain)
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        return {
            "ip": ip,
            "country": geo.get("country_name", "Unknown"),
            "org": geo.get("org", "Private Infrastructure")
        }
    except:
        return {"ip": "0.0.0.0", "country": "Cloud Nodes", "org": "CDN/Hidden"}

# --- المسارات (Routes) ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        if not raw_url: return jsonify({"error": "No URL provided"}), 400
        
        url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
        domain = urlparse(url).netloc.lower() or url
        
        server_info = get_forensics(domain)
        vt_stats = get_vt_stats(url)
        
        is_official = any(d in domain for d in WHITELIST_DOMAINS)
        mal_count = vt_stats.get('malicious', 0) if vt_stats else 0
        risk_score = 0 if is_official else min(20 + (mal_count * 20), 100)
        is_blacklisted = risk_score >= 60

        # تحديث Firebase
        try:
            db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
            if is_blacklisted:
                db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
        except: pass

        # تنبيه تليجرام
        try:
            status_icon = "🛑" if is_blacklisted else "✅"
            msg = f"{status_icon} *SecuCode Scan*\n*Domain:* {domain}\n*Risk:* {risk_score}%\n*IP:* {server_info['ip']}"
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                          json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
        except: pass

        return jsonify({
            "is_official": is_official,
            "is_blacklisted": is_blacklisted,
            "risk_score": risk_score,
            "server": server_info,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600",
            "url": url
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()
        res = data.get('result', {})
        lang = data.get('lang', 'ar')

        rendered_html = render_template('report.html', data=res, lang=lang)

        # تحويل HTML إلى PDF في الذاكرة
        pdf_buffer = BytesIO()
        pisa.CreatePDF(rendered_html, dest=pdf_buffer)
        pdf_buffer.seek(0)

        # --- الحل النهائي: الرفع على Cloudinary بدلاً من الإرسال المباشر ---
        upload_result = cloudinary.uploader.upload(
            pdf_buffer, 
            resource_type="raw", 
            folder="secucode_reports",
            public_id=f"audit_{int(time.time())}.pdf"
        )
        
        # إرجاع رابط الـ PDF المباشر بدلاً من الملف نفسه
        return jsonify({"pdf_url": upload_result['secure_url']})

    except Exception as e:
        logging.error(f"Report Error: {str(e)}")
        return jsonify({"error": "Failed to generate cloud link"}), 500

if __name__ == '__main__':
    app.run(debug=True)
