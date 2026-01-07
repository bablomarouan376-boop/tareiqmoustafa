import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url
from datetime import datetime

app = Flask(__name__)

# إعدادات متصفح احترافية (Stealth Mode)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
}

def get_domain_age(domain):
    """فحص عمر النطاق لكشف المواقع الحديثة"""
    try:
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if res.status_code == 200:
            events = res.json().get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date = datetime.strptime(event.get('eventDate')[:10], "%Y-%m-%d")
                    return (datetime.now() - reg_date).days
    except: pass
    return None

def perform_analysis(target_url):
    """محرك التحليل الرئيسي لـ SecuCode Pro"""
    violated_rules = []
    risk_points = 0
    
    try:
        response = requests.get(target_url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        content = response.text
        domain = urlparse(final_url).netloc

        # 1. فحص عمر النطاق
        age = get_domain_age(domain)
        if age is not None and age < 60:
            risk_points += 40
            violated_rules.append({"name": "نطاق حديث الإنشاء", "risk_description": f"عمر الموقع {age} يوم فقط، مما يزيد من احتمالية كونه موقع تصيد."})

        # 2. فحص الأمان (HTTPS)
        if not final_url.startswith('https'):
            risk_points += 50
            violated_rules.append({"name": "اتصال غير مشفر (HTTP)", "risk_description": "الموقع لا يستخدم تشفير SSL، مما يسهل سرقة بياناتك."})

        # 3. كشف محاولات سحب البيانات
        if re.search(r'password|credit_card|cvv|pin_code', content, re.I):
            risk_points += 30
            violated_rules.append({"name": "نماذج جمع بيانات حساسة", "risk_description": "يحتوي الموقع على حقول لجمع كلمات مرور أو بيانات بطاقات بنكية."})

        # 4. انتحال العلامات التجارية
        brands = ['facebook', 'google', 'paypal', 'microsoft', 'binance']
        for b in brands:
            if b in domain.lower() and domain.lower() != f"{b}.com":
                risk_points += 45
                violated_rules.append({"name": "اشتباه انتحال علامة تجارية", "risk_description": f"يستخدم الموقع اسم '{b}' بطريقة مضللة."})

    except:
        risk_points = 20
        violated_rules.append({"name": "فشل الوصول العميق", "risk_description": "الموقع يمنع أدوات الفحص التلقائي، قد يكون ذلك لإخفاء برمجيات خبيثة."})

    # تحديد مستوى الخطر
    score = min(risk_points, 100)
    label = "Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"

    return {
        "risk_score": label,
        "suspicious_points": score,
        "violated_rules": violated_rules
    }

@app.route('/')
def home(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "Error"}), 400
    return jsonify(perform_analysis(url))

if __name__ == '__main__':
    app.run(debug=True)

