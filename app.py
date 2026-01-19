import os
import json
import requests
import time
from flask import Flask, render_template, request, jsonify
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)

# إعداد Firebase باستخدام البيئة (Environment Variables)
firebase_creds = os.environ.get('FIREBASE_CREDENTIALS')
if firebase_creds:
    try:
        creds_dict = json.loads(firebase_creds)
        cred = credentials.Certificate(creds_dict)
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred, {
                'databaseURL': 'https://secucode-pro-default-rtdb.firebaseio.com/'
            })
    except Exception as e:
        print(f"Firebase Error: {e}")

# جلب مفاتيح الـ API
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
TG_TOKEN = os.environ.get('TELEGRAM_TOKEN')
CH_ID = os.environ.get('CHAT_ID')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url_to_scan = data.get('url')
    user_id = data.get('user_id', 'anonymous')
    
    if not url_to_scan:
        return jsonify({"status": "error", "message": "No URL"}), 400

    # 1. إرسال تنبيه للتليجرام
    if TG_TOKEN and CH_ID:
        try:
            msg = f"🚀 فحص جديد!\n🔗 الرابط: {url_to_scan}\n👤 المستخدم: {user_id}"
            requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", json={"chat_id": CH_ID, "text": msg})
        except: pass

    # 2. تحديث Firebase (الإحصائيات والسجل)
    try:
        ref_stats = db.reference('stats')
        ref_history = db.reference(f'history/{user_id}')
        
        # زيادة عداد الفحص الكلي
        current_total = ref_stats.child('total_scans').get() or 0
        ref_stats.update({'total_scans': current_total + 1})
        
        # إضافة للفحص التاريخي للمستخدم
        ref_history.push({
            'url': url_to_scan,
            'timestamp': time.time()
        })
    except: pass

    return jsonify({
        "status": "success",
        "url": url_to_scan,
        "timestamp": time.time()
    })

@app.route('/history/<user_id>')
def get_history(user_id):
    try:
        data = db.reference(f'history/{user_id}').get() or {}
        return jsonify(list(data.values()))
    except:
        return jsonify([])

if __name__ == '__main__':
    app.run(debug=True)
