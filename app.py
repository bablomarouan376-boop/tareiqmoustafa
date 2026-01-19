# app.py (النسخة المطورة والمصححة)
import os
import json
import requests
import time
from flask import Flask, render_template, request, jsonify
import firebase_admin
from firebase_admin import credentials, db
from urllib.parse import urlparse
import tldextract  # لاستخراج النطاق الرئيسي

app = Flask(__name__, template_folder='templates', static_folder='static')

# إعداد Firebase باستخدام المتغيرات البيئية أو البيانات المقدمة
firebase_creds = os.environ.get('FIREBASE_CREDENTIALS')
if not firebase_creds:
    # استخدام البيانات المقدمة إذا لم تكن متوفرة في البيئة
    firebase_creds = json.dumps({
        "type": "service_account",
        "project_id": "secucode-pro",
        "private_key_id": "131da2ca8578982b77e48fa71f8c4b65880b0784",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZwhV2C+HnRrp8\nTemJc7bdbGw2JUb47hZ1ShXk2ReFbQ256bhud1AIO+rxHJ0fzq8Ba+ZTaAsodLxU\nn74+dxpyrMUolvBONnWgFeQtgqFsHouAAy0j/iJs6yNny6o4f/TVp4UKixqY+jT0\nTSBo8ixU7Dxh6VWdom62BsKUAGN8ALFM5N6+4z3fbCj9fB4mmvibIQLLAVwxZ703\ndSP1ZFOJgd98LEHYOBYBKAOQ/fEyq20e8PEokuVnoLqvLxJDGCwGvv5aEadq2t3O\nhJ9oJAefIDD2YsAPgeMu8MAtlHlTuoqu82FGehQ2v6mtC4121W2NFLORPC1fttWE\nFr5U5La3AgMBAAECggEAAUqVcGNeFirBiZCBK7wwJ6P3mLGZpkmD9N5R6FByJyy+\nr91nA2d4fZpiP3ZA9jTda0K8Hr9B2uEm8CjcqcJGXmtDC/UTsQIhAm5H9DE2gAyr\nej0lkOh6l9ScwTHA0Z8MnTy0xOBpeRdjZ32pjiSSixW0QB8kj4u0NJ+yvW+3NDru\ntErFEF03IaMgfnK279reWuNKC72lZfVlkFk9qoi6b34j1mdhAXlkIqPm1plkd8py\nZDPxGf7/xdB32peadLpuWHvd/JyE9hLGa+CT9g12kKOcxh/KmJVD5MBkIriQAFoh\nT7pvJm9SDju4uDtc6O26IME3/YIwjB+YfgrXMySMiQKBgQDOSdjq2/TJTYXoen2X\ncvlssZGGVenb30rcQHIPtC9xHhczPJ6cAPhRltmeV37HO8g82unNnbsAePCsVZx+\nX6p2y9VDzTDimAJEXd/JVjwBnFs8/8GwUwLoFvsbnAvA8pSFHYmKURDJolPjJ0Gw\nqr40NrApbRG47JYQHyhHTfOPwwKBgQC+z5Xa2yT1rSzOsNoOwfJmTo0oThNaTExE\n6/8/1F7NpeZLKbew5sai20CmmvWKljVKgiyUdJLZShlbnqv3QUvEL+PH9pWNftpd\nphAlbEG9UPjF6nR8IrOwtAXK3tMyrGlYl7EI0dgwY8pzoYgUraRik2AqfaG2BRe/\n8oUXZMKh/QKBgGmwaiOCB/su7cF7KGd0r5fhrgZedA+Dao5HsmibT4cr/ITytOyG\njrL2j45Rk5Gt7lxHaGxBOLL4Q4532lLg3qw4qI4xTa96ZAb09Zfox5unqRMqkeit\nzxpr08GEhH0Zi8BbrsEf4XL86O/DiCNkh0inEEBZMjBFfmjKHc/Sf0wTAoGALYVy\nl9LeP2pAHVNdwlWM0dF9pZby0QEQ1QSEUaMFtwQUK+xY8XAtBV9PTi/70kNBlXP2\n1Lf27LXb1NrG5ecC/1v5eJQgW7BewibDBVqNWG//2Z+0iITy334jP6HnOtidDVCr\nIJKHhAvambl4sI44gHfuYlS0hqsyXk2qaMlWEbUCgYEAmSFfrOq4+I32/Aqr8f2v\nWnU65jupo1jeBmzSDP+IZYCH4Ydf9msfzQS9eX4UoGnQ8qD07ICiVnXuP7hqY8JR\n8sjwYcTcZ6JHiuLp4HP+PhwrhsM/govb8BCcBrDRpggTx7bXPhqFYKgPN5jb6n7Q\nQgLue5qdPf3qb3a3n6CioWQ=\n-----END PRIVATE KEY-----\n",
        "client_email": "firebase-adminsdk-fbsvc@secucode-pro.iam.gserviceaccount.com",
        "client_id": "100797441781867873022",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40secucode-pro.iam.gserviceaccount.com",
        "universe_domain": "googleapis.com"
    })

creds_dict = json.loads(firebase_creds)
cred = credentials.Certificate(creds_dict)
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://secucode-pro-default-rtdb.firebaseio.com/'
    })

# جلب مفاتيح الـ API من البيئة أو البيانات المقدمة
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY') or '07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564'
TG_TOKEN = os.environ.get('TELEGRAM_TOKEN') or '8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o'
CH_ID = os.environ.get('CHAT_ID') or '7421725464'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url_to_scan = data.get('url')
    user_id = data.get('user_id', 'anonymous')
    
    if not url_to_scan:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    # 1. استخراج النطاق الرئيسي للرابط باستخدام tldextract
    extracted = tldextract.extract(url_to_scan)
    domain = f"{extracted.domain}.{extracted.suffix}"

    # 2. فحص الرابط باستخدام VirusTotal API
    vt_result = {}
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        url_id = urlparse(url_to_scan).netloc  # استخدام netloc كـ ID
        headers = {"x-apikey": VT_API_KEY}
        
        # إرسال الرابط للفحص إذا لم يكن مفحوصاً سابقاً
        scan_response = requests.post(vt_url, headers=headers, data={"url": url_to_scan})
        if scan_response.status_code == 200:
            analysis_id = scan_response.json()['data']['id']
            # انتظار نتيجة التحليل (يمكن تحسينه بـ polling)
            time.sleep(10)  # انتظار 10 ثواني للنتيجة (يمكن تحسينه)
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                vt_result = analysis_response.json()['data']['attributes']['stats']
    except Exception as e:
        vt_result = {"error": str(e)}

    # 3. إرسال تنبيه للتليجرام مع نتائج الفحص
    if TG_TOKEN and CH_ID:
        try:
            msg = f"🚀 فحص جديد!\n🔗 الرابط: {url_to_scan}\n👤 المستخدم: {user_id}\n📊 نتائج VirusTotal: {json.dumps(vt_result, ensure_ascii=False)}"
            requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", json={"chat_id": CH_ID, "text": msg})
        except:
            pass

    # 4. تحديث Firebase (الإحصائيات والسجل مع نتائج الفحص)
    try:
        ref_stats = db.reference('stats')
        ref_history = db.reference(f'history/{user_id}')
        
        # زيادة عداد الفحص الكلي
        current_total = ref_stats.child('total_scans').get() or 0
        ref_stats.update({'total_scans': current_total + 1})
        
        # إضافة للفحص التاريخي للمستخدم مع نتائج VirusTotal
        ref_history.push({
            'url': url_to_scan,
            'timestamp': time.time(),
            'vt_result': vt_result
        })
    except:
        pass

    return jsonify({
        "status": "success",
        "url": url_to_scan,
        "timestamp": time.time(),
        "vt_result": vt_result
    })

@app.route('/history/<user_id>')
def get_history(user_id):
    try:
        data = db.reference(f'history/{user_id}').get() or {}
        return jsonify(list(data.values()))
    except:
        return jsonify([])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
