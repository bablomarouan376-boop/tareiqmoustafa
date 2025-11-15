import os
from flask import Flask, request, jsonify, render_template
import requests
import re 
from urllib.parse import urlparse
from validators import url

# تهيئة تطبيق Flask
# الأهم: يجب أن يكون اسم الكائن "app" لكي يعمل Vercel بشكل صحيح.
app = Flask(__name__)

# --- تعريف 42 قاعدة أمنية احترافية ومُعدلة (نقاط المخاطر مضاعفة للقواعد الحرجة) ---
SECURITY_RULES = [
    # ----------------------------------------------------
    # مجموعة 1: قواعد فحص البنية العامة والتخفي (Obfuscation)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(service in link.lower() for service in ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "cutt.ly", "is.gd", "t.co", "rebrand.ly"]),
        "name": "اختصار الرابط (URL Shortener)",
        "risk": "قد يخفي الوجهة الحقيقية الضارة خلف رابط قصير وموثوق. **مؤشر شائع للخداع.**",
        "points": 8
    },
    {
        "check": lambda link, content: bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(link).netloc)),
        "name": "استخدام رقم IP مباشر في النطاق",
        "risk": "يشير إلى خادم مؤقت أو موقع غير مسجل رسمياً، يستخدم لتجنب فحص DNS. **خطر عالٍ.**",
        "points": 12
    },
    {
        "check": lambda link, content: '@' in link,
        "name": "وجود رمز @ في الرابط (User Info Obfuscation)",
        "risk": "يستخدم لخداع المتصفح والزائر حول الوجهة الحقيقية للرابط. **مؤشر قوي لـ Phishing.**",
        "points": 15
    },
    {
        "check": lambda link, content: len(link) > 100,
        "name": "الطول المبالغ فيه للرابط (>100 حرف)",
        "risk": "الروابط الطويلة جداً تستخدم أحياناً لإخفاء محتوى ضار أو لتجنب الفلاتر الأمنية.",
        "points": 4
    },
    {
        "check": lambda link, content: link.lower().startswith('http://'),
        "name": "بروتوكول HTTP غير الآمن",
        "risk": "الرابط غير مشفر (غير HTTPS)، مما يعرض بيانات المستخدمين للتجسس. **يجب تجنبه دائماً.**",
        "points": 10
    },
    {
        "check": lambda link, content: bool(re.search(r':\d{4,}', link)),
        "name": "استخدام منفذ غير قياسي",
        "risk": "قد يشير إلى تشغيل خدمات غير تقليدية أو غير معتادة على المنافذ المعروفة.",
        "points": 5
    },
    {
        "check": lambda link, content: link.count('=') > 7,
        "name": "كثرة المتغيرات في الرابط (>7)",
        "risk": "قد تكون محاولة لحقن أو تمرير معلمات ضخمة غير مرغوب فيها.",
        "points": 3
    },
    {
        "check": lambda link, content: link.count('.') > 4,
        "name": "كثرة النطاقات الفرعية العميقة (>4)",
        "risk": "تستخدم لتقليد المواقع الشرعية (مثل: secure.login.google.com.xyz.com). **خداع بصري واضح.**",
        "points": 8
    },
    {
        "check": lambda link, content: link.count('http') > 1,
        "name": "تكرار البروتوكول داخل الرابط",
        "risk": "محاولة خداع متقدمة لتمرير http/https داخل مسار الرابط.",
        "points": 10
    },
    {
        "check": lambda link, content: 'xn--' in link.lower(),
        "name": "وجود Punycode/IDN (خداع الأحرف الدولية)",
        "risk": "يشير إلى استخدام أسماء نطاقات دولية قد تُستخدم لانتحال شخصية موقع آخر بحروف مشابهة. **خطر حرج.**",
        "points": 15
    },
    {
        "check": lambda link, content: bool(re.search(r'%.{2}', link)),
        "name": "وجود ترميز URL (%XX)",
        "risk": "يشير إلى وجود أحرف مشفرة قد تخفي كلمات مفتاحية ضارة.",
        "points": 3
    },
    {
        "check": lambda link, content: 'data:' in link.lower() or 'javascript:' in link.lower(),
        "name": "استخدام أنظمة URI خطيرة (Data/JavaScript)",
        "risk": "يسمح بتشغيل كود JavaScript مباشرة أو تضمين محتوى كقاعدة 64. **خطر عالٍ جداً.**",
        "points": 20
    },
    {
        "check": lambda link, content: bool(re.search(r'\.\./|\.\.\\|\.\.%2f|\.\.%5c', link, re.IGNORECASE)),
        "name": "مؤشر لـ Directory Traversal",
        "risk": "محاولة للوصول إلى ملفات خارج المسار المخصص على الخادم.",
        "points": 10
    },
    {
        "check": lambda link, content: '//' in urlparse(link).path,
        "name": "مسارات مزدوجة متكررة (Redundant Slashes)",
        "risk": "قد يُستخدم للتخفي أو لإرباك المتصفحات والفلاتر الأمنية البسيطة.",
        "points": 3
    },
    {
        "check": lambda link, content: len(urlparse(link).netloc.split('.')[0]) > 25,
        "name": "طول مبالغ فيه للنطاق الفرعي (Subdomain)",
        "risk": "النطاقات الفرعية الطويلة جداً غالباً ما تكون مؤشراً على الإزعاج أو الخداع.",
        "points": 5
    },
    
    # ----------------------------------------------------
    # مجموعة 2: قواعد فحص النطاق و Typosquatting (الاحتيال الإملائي)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(ext in link.lower() for ext in ['.cf', '.tk', '.ga', '.ml', '.xyz', '.cc', '.info', '.biz', '.top']),
        "name": "انتهاء نطاق مشبوه (TLD)",
        "risk": "امتدادات النطاقات هذه غالباً ما تستخدم في حملات التصيد والاحتيال لأنها مجانية أو رخيصة.",
        "points": 8
    },
    {
        "check": lambda link, content: any(re.search(rf'{word}', link.lower()) for word in ['faceb?ook', 'g00gle', 'appple', 'micr0s0ft', 'am@zon', 'payp@l']),
        "name": "خطأ إملائي في النطاق (Typosquatting - متقدم)",
        "risk": "انتحال شخصية المواقع الكبرى باستخدام أخطاء إملائية ذكية لسرقة بيانات الاعتماد. **خطر حرج.**",
        "points": 25 # نقطة عالية جداً للخداع المالي والاجتماعي
    },
    {
        "check": lambda link, content: any(company in link.lower() for company in ['microsoft', 'apple', 'amazon', 'facebook', 'google']) and 'https' not in link.lower(),
        "name": "استخدام اسم شركة كبرى بدون تشفير HTTPS",
        "risk": "لا يمكن لشركة كبرى مثل Google أو PayPal أن تستخدم HTTP. هذا تزوير واضح.",
        "points": 20
    },
    {
        "check": lambda link, content: any(char.isdigit() for char in urlparse(link).netloc.split('.')[1]) and link.count('.') >= 1,
        "name": "نطاق رئيسي يحتوي على أرقام",
        "risk": "النطاقات الرئيسية التي تحتوي على أرقام (مثل: pay123.com) غالباً ما تكون مشبوهة.",
        "points": 6
    },
    {
        "check": lambda link, content: len(urlparse(link).netloc.split('.')[0]) > 20 and len(urlparse(link).netloc.split('.')[0].split('-')) > 3,
        "name": "نطاق فرعي ضخم ومفصول بالواصلات",
        "risk": "حشو كلمات مفتاحية لتجنب الفلاتر وزيادة الخداع.",
        "points": 5
    },
    {
        "check": lambda link, content: link.count('free') > 1 or link.count('verify') > 1,
        "name": "تكرار كلمات الخداع (Free/Verify)",
        "risk": "الاستخدام المفرط لكلمات الإغراء والحاجة للتحقق.",
        "points": 7
    },
    # ----------------------------------------------------
    # مجموعة 3: قواعد فحص المسار والملفات (Path & Files)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(word in link.lower() for word in ['gift', 'prize', 'free', 'win', 'claim', 'discount', 'bonus', 'crypto', 'wallet']),
        "name": "استخدام كلمات خداع اجتماعي شائعة في المسار",
        "risk": "يشير إلى محاولة خداع اجتماعي أو إغراء المستخدم لتقديم بيانات حساسة.",
        "points": 5
    },
    {
        "check": lambda link, content: any(word in link.lower() for word in ['admin', 'upload', 'config', 'backup', 'db', 'password', 'clientarea']),
        "name": "كلمات إدارة وحساسة في الرابط",
        "risk": "قد يشير إلى محاولة الوصول لصفحة إدارة أو كشف مسار حساس.",
        "points": 8
    },
    {
        "check": lambda link, content: link.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar', '.zip', '.rar', '.7z', '.iso', '.bin')),
        "name": "الانتهاء بملف تنفيذي أو مضغوط ضار",
        "risk": "يشير إلى أن الرابط سيقوم بتحميل أو تشغيل ملف تنفيذي ضار مباشرة. **خطر حرج للغاية.**",
        "points": 30
    },
    {
        "check": lambda link, content: bool(re.search(r'/\d{10,}/', link)),
        "name": "سلسلة أرقام طويلة جداً في المسار",
        "risk": "قد تشير إلى ملفات تم تحميلها عشوائياً أو مُعرف جلسة مشبوه.",
        "points": 3
    },
    {
        "check": lambda link, content: link.count('?') > 1,
        "name": "وجود أكثر من علامة استفهام في الرابط",
        "risk": "الاستخدام غير القياسي لعلامة الاستفهام.",
        "points": 4
    },
    {
        "check": lambda link, content: 'base64' in link.lower() or 'hex' in link.lower(),
        "name": "استخدام كلمات الترميز (Base64/Hex)",
        "risk": "يشير إلى محاولة تمرير بيانات مشفرة لتجاوز فلاتر التحليل البسيطة.",
        "points": 6
    },
    {
        "check": lambda link, content: bool(re.search(r'[\u0600-\u06FF]', link)) and 'xn--' not in link.lower(),
        "name": "أحرف عربية أو غير لاتينية غير مشفرة",
        "risk": "قد يشير إلى ترميز غير صحيح.",
        "points": 4
    },
    {
        "check": lambda link, content: link.lower().count('/') > 7,
        "name": "عمق المسار المبالغ فيه (>7 مستويات)",
        "risk": "قد يدل على موقع يتمتع ببنية ملفات معقدة ومخفية بشكل غير طبيعي.",
        "points": 3
    },
    {
        "check": lambda link, content: 'index.html' in link.lower() or 'default.aspx' in link.lower(),
        "name": "اسم ملف صفحة افتراضية في المسار",
        "risk": "في الغالب، لا تحتاج المواقع الكبيرة لذكر هذه الملفات بشكل صريح في الرابط، وقد يشير إلى خادم بسيط.",
        "points": 1
    },
    {
        "check": lambda link, content: 'login' in link.lower() and urlparse(link).netloc.count('.') > 2,
        "name": "كلمة 'Login' في نطاق فرعي عميق",
        "risk": "مثل: `login.secure.paypal.com.scam.com` - محاولة للتخفي.",
        "points": 12
    },
    {
        "check": lambda link, content: any(param in urlparse(link).query for param in ['redir', 'forward', 'url']),
        "name": "وجود متغيرات إعادة التوجيه (Redirect Parameters)",
        "risk": "قد تسمح هذه المتغيرات (مثل ?url=) بالاستغلال لتنفيذ عمليات إعادة توجيه مفتوحة.",
        "points": 7
    },
    # ----------------------------------------------------
    # مجموعة 4: قواعد فحص الأمان والسلوك والمحتوى
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(word in link.lower() for word in ['secure', 'safe', 'trust', 'login', 'verify', 'ssl']) and 'https' not in link.lower(),
        "name": "كلمات أمان زائفة بدون تشفير",
        "risk": "محاولة إيهام المستخدم بالأمان (مثلاً: رابط فيه 'secure' ولكنه HTTP). **خطر عالٍ جداً.**",
        "points": 20
    },
    {
        "check": lambda link, content: any(word in urlparse(link).query.lower() for word in ['session', 'cookie', 'token', 'auth', 'apikey']),
        "name": "تضمين بيانات الجلسة/المصادقة الحساسة في متغيرات الرابط",
        "risk": "قد يشير إلى محاولة حقن أو سرقة بيانات الجلسة عبر الرابط.",
        "points": 10
    },
    {
        "check": lambda link, content: len(link) > 40 and link != link.lower() and link != link.upper(),
        "name": "أحرف كبيرة وصغيرة عشوائية",
        "risk": "تستخدم لتجاوز فلاتر البريد المزعج.",
        "points": 2
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'<form[^>]*\b(password|user|credit|card|cvv|secure|login|pin|social security)\b', content, re.IGNORECASE | re.DOTALL)),
        "name": "نموذج يطلب معلومات حساسة (Phishing Form)",
        "risk": "وجود نموذج إدخال يطلب كلمات مرور أو بيانات بطاقة ائتمان. **هذا هو المؤشر الأقوى على موقع تصيد.**",
        "points": 40 # أعلى نقطة لمؤشر Phishing صريح
    },
    {
        "check": lambda link, content: content is not None and len(content) < 500 and status_code == 200,
        "name": "محتوى صفحة قصير جداً (Under Construction/Redirect)",
        "risk": "يشير إلى أن الصفحة فارغة أو أنها مجرد صفحة إعادة توجيه فورية مخفية.",
        "points": 10
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'iframe\s*src\s*=\s*("|)\s*(http|https)', content, re.IGNORECASE)),
        "name": "استخدام IFRAME لتحميل محتوى من نطاق خارجي",
        "risk": "قد يُستخدم لتحميل صفحة التصيد داخل إطار مخفي على صفحة تبدو بريئة.",
        "points": 8
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'document\.write|eval\(|unescape\(', content, re.IGNORECASE)),
        "name": "كود JavaScript مُشفر أو خطير",
        "risk": "وجود دوال تُستخدم غالباً لتنفيذ كود ضار أو إعادة توجيه مخفية.",
        "points": 15
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'window\.location\.replace|window\.location\.href|meta\s*http-equiv\s*=\s*"refresh"', content, re.IGNORECASE)),
        "name": "كود إعادة توجيه متقدم (Client-Side Redirect)",
        "risk": "يشير إلى محاولة نقل المستخدم فوراً إلى رابط آخر باستخدام جافاسكريبت أو Meta Tags.",
        "points": 10
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'<script\s*src\s*=\s*".*?"\s*async\s*defer', content, re.IGNORECASE)),
        "name": "تحميل ملفات جافاسكريبت خارجية بـ 'Async/Defer'",
        "risk": "قد يشير إلى برامج تتبع ضارة أو سكربتات تعدين خفية.",
        "points": 5
    },
    {
        "check": lambda link, content: content is not None and 'paypal' in link.lower() and 'title' in content.lower() and 'update' in content.lower(),
        "name": "عنوان الصفحة يطلب 'تحديث' أو 'التحقق' لعلامة تجارية مشهورة",
        "risk": "نمط نموذجي لصفحات التصيد التي تحاول إجبارك على تحديث معلوماتك البنكية.",
        "points": 15
    }
]


# --- دالة التحليل الأمني (منطق العمل المُحدث) ---
def perform_security_scan(link):
    suspicious_points = 0
    detected_warnings = 0
    page_content = None 
    status_code = 0
    final_link = link 
    page_content_warning = "لم يتم إجراء تحليل للمحتوى بعد..."
    
    # 1. فحص الاتصال بالرابط والحصول على المحتوى
    try:
        # requests.get يتبع عمليات إعادة التوجيه تلقائياً
        response = requests.get(link, timeout=10, allow_redirects=True) 
        status_code = response.status_code
        final_link = response.url
        page_content = response.text 
        
        # قاعدة إضافية: فحص حالة إعادة التوجيه المفرطة
        if len(response.history) > 3:
            suspicious_points += 10 
            detected_warnings += 1
            page_content_warning = f"تحذير: تمت {len(response.history)} عملية إعادة توجيه. (مشبوه)."

        if status_code != 200:
            # زيادة النقاط إذا كان الخطأ هو 403 (Forbidden) أو 404 (Not Found)
            # 403 غالباً ما يستخدم لإخفاء صفحة التصيد عن البوتات
            if status_code in [403, 404]:
                suspicious_points += 15 
            else:
                suspicious_points += 5
                
            detected_warnings += 1
            page_content_warning = f"تحذير: الرابط يسبب خطأ {status_code}. (هذا يُعتبر مشبوهاً)."
        else:
            page_content_warning = f"تم جلب محتوى الصفحة بنجاح. (الحالة: {status_code})"
            
    except requests.exceptions.RequestException as e:
        suspicious_points += 20 # زيادة النقاط لفشل الاتصال التام
        detected_warnings += 1
        page_content_warning = f"خطأ حاد في الاتصال بالرابط أو حدوث مهلة (Timeout). ({e})"
        status_code = 0
        final_link = link 
        
    # 2. تطبيق جميع القواعد الأمنية 
    violated_rules = []
    link_for_rules = final_link
    content_to_check = page_content if page_content else ""

    for rule in SECURITY_RULES:
        try:
            if rule["check"](link_for_rules, content_to_check):
                suspicious_points += rule["points"] 
                detected_warnings += 1
                violated_rules.append({
                    "name": rule["name"],
                    "risk_description": rule["risk"],
                    "points_added": rule["points"]
                })
        except Exception as e:
            # طباعة الخطأ في حال فشل تطبيق قاعدة معينة
            print(f"Error applying rule {rule['name']}: {e}") 
            pass

    # 3. تحديد مستوى الخطورة بناءً على النقاط (المستويات مُعدلة للنقاط الجديدة)
    risk_score = "Low"
    result_message = "🟢 آمن نسبيًا: لم يتم اكتشاف مخاطر واضحة بناءً على التحليل السريع."

    if suspicious_points > 100:
        risk_score = "Critical"
        result_message = "🔴 خطر حرج جداً! تجاوزت النقاط 100، مما يشير إلى وجود مؤشرات قوية جداً على التصيد أو البرامج الضارة. **يجب عدم فتح هذا الرابط تحت أي ظرف.**"
    elif suspicious_points > 60:
        risk_score = "High"
        result_message = "🔥 خطر عالٍ! تم اكتشاف مخالفات هيكلية وسلوكية متعددة في الرابط (مثل Typosquatting أو HTTP غير مشفر). يفضل تجنبه تماماً."
    elif suspicious_points > 30:
        risk_score = "Medium"
        result_message = "⚠️ خطر متوسط. يحتوي على بعض العناصر المشبوهة مثل الاختصار أو العمق الزائد. استخدم بحذر."
    
    # 4. إعادة النتيجة
    return {
        "status": "success" if suspicious_points < 30 else "warning" if suspicious_points < 60 else "error",
        "message": f"تحليل مكتمل. تم تطبيق {len(SECURITY_RULES)} قاعدة فحص على الرابط النهائي ({link_for_rules}).",
        "link_input": link, 
        "link_final": link_for_rules, 
        "result_message": result_message,
        "risk_score": risk_score,
        "suspicious_points": suspicious_points,
        "detected_warnings": detected_warnings,
        "page_content_status": page_content_warning,
        "violated_rules": violated_rules 
    }

# --- نقطة النهاية الرئيسية لعرض الواجهة الأمامية ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


# --- نقطة النهاية للتحليل (API) ---
@app.route('/analyze', methods=['POST'])
def analyze_link():
    
    try:
        data = request.get_json()
        link_to_analyze = data.get('link')
    except Exception:
        return jsonify({
            "status": "critical_error",
            "message": "خطأ في معالجة بيانات الطلب (JSON).",
            "error_code": 400
        }), 400

    if not link_to_analyze or link_to_analyze.strip() == "":
        return jsonify({
            "status": "validation_error",
            "message": "❌ فشل التحقق: الرجاء إدخال رابط. حقل الرابط لا يمكن أن يكون فارغاً.",
            "error_code": 400
        }), 400

    # تعديل صغير: إضافة البروتوكول في حالة عدم وجوده
    if not link_to_analyze.lower().startswith(('http://', 'https://')):
        link_to_analyze = 'https://' + link_to_analyze
    
    # التحقق من صلاحية الرابط باستخدام مكتبة validators
    if url(link_to_analyze) is not True:
         return jsonify({
            "status": "validation_error",
            "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.",
            "error_code": 400
        }), 400
    
    
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200
