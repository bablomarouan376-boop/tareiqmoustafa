import os, re, requests, time, base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from datetime import datetime

app = Flask(__name__, static_folder='static', template_folder='templates')

# إعدادات التصفح المتخفي (Stealth)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "ar,en;q=0.9",
    "Referer": "https://www.google.com/"
}

# قائمة المواقع الموثوقة (لتجنب الأخطاء المنطقية)
WHITELIST = [
    'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
    'github.com', 'twitter.com', 'x.com', 'linkedin.com', 
    'gmail.com', 'youtube.com', 'vercel.app', 'netlify.app'
]

def get_domain_age(domain):
    """جلب عمر النطاق بطريقة سريعة"""
    try:
        if any(d in domain for d in WHITELIST): return 9999
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=4)
        if res.status_code == 200:
            events = res.json().get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date = datetime.strptime(event.get('eventDate')[:10], "%Y-%m-%d")
                    return (datetime.now() - reg_date).days
    except: pass
    return None

def analyze_logic(target_url):
    start_time = time.time()
    violated_rules = []
    risk_points = 0
    domain = urlparse(target_url).netloc.lower()

    # 1. فحص القائمة البيضاء (سرعة فورية)
    if any(d in domain for d in WHITELIST):
        return {
            "risk_score": "Low", "points": 0, "violations": [],
            "final_url": target_url, "redirects": [target_url], "time": 0.01
        }

    try:
        # 2. تتبع التحويلات وجلب المحتوى
        session = requests.Session()
        response = session.get(target_url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        content = response.text
        
        # 3. تحليل عمر النطاق (الأمان الزمني)
        age = get_domain_age(domain)
        if age and age < 60:
            risk_points += 55
            violated_rules.append({"name": "نطاق حديث (خطر)", "desc": f"الموقع أنشئ منذ {age} يوم. معظم مواقع الاحتيال لا تعيش طويلاً."})

        # 4. كشف انتحال الهوية (Brand Impersonation)
        brands = ['paypal', 'binance', 'amazon', 'netflix', 'instagram', 'wallet']
        for b in brands:
            if b in domain and domain != f"{b}.com":
                risk_points += 50
                violated_rules.append({"name": "اشتباه انتحال ماركة", "desc": f"استخدام اسم '{b}' في رابط غير رسمي هو سلوك تصيد مؤكد."})

        # 5. التحليل السلوكي للأكواد (Behavioral Analysis)
        threats = {
            r'getUserMedia|camera|microphone': ("طلب صلاحيات حساسة", 40),
            r'password|credit_card|cvv|secret': ("طلب بيانات خصوصية", 35),
            r'[A-Za-z0-9+/]{400,}=*': ("تشفير Base64 كثيف", 30),
            r'atob\(|eval\(|unescape\(': ("محاولة إخفاء أكواد برمجية", 25)
        }

        for pattern, (name, weight) in threats.items():
            if re.search(pattern, content, re.I):
                risk_points += weight
                violated_rules.append({"name": name, "desc": "تم رصد سلوك برمجي يحاول الوصول لبياناتك أو إخفاء نشاطه."})

        # 6. أمان التشفير
        if not final_url.startswith('https'):
            risk_points += 45
            violated_rules.append({"name": "اتصال غير آمن", "desc": "الموقع يفتقر لتشفير SSL، مما يجعل بياناتك مكشوفة."})

    except Exception:
        risk_points = 40
        violated_rules.append({"name": "جدار حماية ضد الفحص", "desc": "الموقع يحظر أدوات التحليل، مما يرفع احتمالية وجود محتوى ضار مخفي."})
        final_url = target_url

    # النتيجة النهائية
    p = min(risk_points, 100)
    label = "Critical" if p >= 80 else "High" if p >= 55 else "Medium" if p >= 30 else "Low"

    return {
        "risk_score": label, "points": p, "violations": violated_rules,
        "final_url": final_url, 
        "redirects": [r.url for r in getattr(response, 'history', [])] + [final_url],
        "time": round(time.time() - start_time, 2)
    }

# --- المسارات (Routes) ---

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"error": "أدخل رابطاً"}), 400
    if not url.startswith('http'): url = 'https://' + url
    return jsonify(analyze_logic(url))

@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')

@app.route('/manifest.json')
def manifest(): return send_from_directory(app.static_folder, 'manifest.json')

@app.route('/googlecc048452b42b8f02.html')
def google_verify(): return "google-site-verification: googlecc048452b42b8f02.html"

if __name__ == '__main__':
    app.run(debug=True)
