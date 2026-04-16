# app.py  ── FINAL VERSION ──

import re
import joblib
import pandas as pd
from math import log2
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Load model once at startup ─────────────────────────────────
print("📦 Loading model...")
model = joblib.load('phishing_model.pkl')
print("✅ Model ready\n")

# ── Trusted domains whitelist ──────────────────────────────────

TRUSTED_DOMAINS = {
    # ── Search Engines ─────────────────────────────
    'google.com',           'www.google.com',
    'bing.com',             'www.bing.com',
    'yahoo.com',            'www.yahoo.com',
    'duckduckgo.com',       'www.duckduckgo.com',

    # ── Social Media ───────────────────────────────
    'facebook.com',         'www.facebook.com',
    'instagram.com',        'www.instagram.com',
    'twitter.com',          'www.twitter.com',
    'x.com',                'www.x.com',
    'linkedin.com',         'www.linkedin.com',
    'reddit.com',           'www.reddit.com',
    'pinterest.com',        'www.pinterest.com',
    'tiktok.com',           'www.tiktok.com',
    'snapchat.com',         'www.snapchat.com',
    'threads.net',          'www.threads.net',

    # ── Video & Streaming ──────────────────────────
    'youtube.com',          'www.youtube.com',
    'netflix.com',          'www.netflix.com',
    'twitch.tv',            'www.twitch.tv',
    'vimeo.com',            'www.vimeo.com',
    'dailymotion.com',      'www.dailymotion.com',
    'disneyplus.com',       'www.disneyplus.com',
    'primevideo.com',       'www.primevideo.com',

    # ── Tech & Dev ─────────────────────────────────
    'github.com',           'www.github.com',
    'stackoverflow.com',    'www.stackoverflow.com',
    'microsoft.com',        'www.microsoft.com',
    'apple.com',            'www.apple.com',
    'developer.apple.com',
    'docs.microsoft.com',
    'support.microsoft.com',
    'azure.microsoft.com',
    'cloud.google.com',
    'aws.amazon.com',
    'vercel.com',           'www.vercel.com',
    'netlify.com',          'www.netlify.com',
    'heroku.com',           'www.heroku.com',
    'gitlab.com',           'www.gitlab.com',
    'bitbucket.org',        'www.bitbucket.org',
    'npmjs.com',            'www.npmjs.com',
    'pypi.org',             'www.pypi.org',

    # ── E-Commerce ─────────────────────────────────
    'amazon.com',           'www.amazon.com',
    'ebay.com',             'www.ebay.com',
    'shopify.com',          'www.shopify.com',
    'etsy.com',             'www.etsy.com',
    'aliexpress.com',       'www.aliexpress.com',
    'daraz.pk',             'www.daraz.pk',

    # ── Finance & Banking ──────────────────────────
    'paypal.com',           'www.paypal.com',
    'stripe.com',           'www.stripe.com',
    'wise.com',             'www.wise.com',

    # ── News & Media ───────────────────────────────
    'bbc.com',              'www.bbc.com',
    'bbc.co.uk',            'www.bbc.co.uk',
    'cnn.com',              'www.cnn.com',
    'reuters.com',          'www.reuters.com',
    'nytimes.com',          'www.nytimes.com',
    'theguardian.com',      'www.theguardian.com',
    'dawn.com',             'www.dawn.com',
    'geo.tv',               'www.geo.tv',
    'ary.news',             'www.ary.news',
    'thenews.com.pk',       'www.thenews.com.pk',
    'express.com.pk',       'www.express.com.pk',

    # ── Pakistani Domains ──────────────────────────
    'hec.gov.pk',           'www.hec.gov.pk',
    'nadra.gov.pk',         'www.nadra.gov.pk',
    'fbr.gov.pk',           'www.fbr.gov.pk',
    'punjab.gov.pk',        'www.punjab.gov.pk',
    'pakistan.gov.pk',      'www.pakistan.gov.pk',
    'pid.gov.pk',           'www.pid.gov.pk',
    'su.edu.pk',            'www.su.edu.pk',
    'uet.edu.pk',           'www.uet.edu.pk',
    'pu.edu.pk',            'www.pu.edu.pk',
    'nust.edu.pk',          'www.nust.edu.pk',
    'comsats.edu.pk',       'www.comsats.edu.pk',
    'fast.edu.pk',          'www.fast.edu.pk',
    'lums.edu.pk',          'www.lums.edu.pk',
    'aku.edu',              'www.aku.edu',

    # ── Knowledge & Reference ──────────────────────
    'wikipedia.org',        'www.wikipedia.org',
    'wikimedia.org',        'www.wikimedia.org',
    'wolframalpha.com',     'www.wolframalpha.com',
    'britannica.com',       'www.britannica.com',

    # ── Productivity & Cloud ───────────────────────
    'drive.google.com',
    'docs.google.com',
    'sheets.google.com',
    'mail.google.com',
    'calendar.google.com',
    'meet.google.com',
    'dropbox.com',          'www.dropbox.com',
    'notion.so',            'www.notion.so',
    'slack.com',            'www.slack.com',
    'zoom.us',              'www.zoom.us',
    'office.com',           'www.office.com',
    'onedrive.live.com',
    'trello.com',           'www.trello.com',

    # ── Education ──────────────────────────────────
    'coursera.org',         'www.coursera.org',
    'udemy.com',            'www.udemy.com',
    'edx.org',              'www.edx.org',
    'khanacademy.org',      'www.khanacademy.org',
    'duolingo.com',         'www.duolingo.com',
    'canvas.net',           'www.canvas.net',

    # ── Messaging ──────────────────────────────────
    'web.whatsapp.com',
    'telegram.org',         'www.telegram.org',
    'discord.com',          'www.discord.com',
}

def is_trusted_domain(url):
    try:
        domain = urlparse(url).netloc.lower()

        # Exact whitelist match
        if domain in TRUSTED_DOMAINS:
            return True

        # Any .edu or .edu.XX institutional domain is safe
        if '.edu.' in domain or domain.endswith('.edu'):
            return True

        # Any verified government domain is safe
        if domain.endswith('.gov') or domain.endswith('.gov.pk'):
            return True

        return False
    except:
        return False

# ── Feature extraction ─────────────────────────────────────────
# Must stay identical to retrain_v2.py — same features, same order

def calc_entropy(s):
    if not s:
        return 0
    prob = [s.count(c) / len(s) for c in set(s)]
    return round(-sum(p * log2(p) for p in prob), 4)

SUSPICIOUS_TLDS = {
    '.tk', '.xyz', '.pw', '.cc', '.ru', '.top', '.club',
    '.online', '.site', '.icu', '.gq', '.ml', '.cf',
    '.ga', '.live', '.buzz', '.zip', '.review', '.country'
}

BRAND_MAP = {
    'paypal':    'paypal.com',
    'amazon':    'amazon.com',
    'apple':     'apple.com',
    'microsoft': 'microsoft.com',
    'google':    'google.com',
    'facebook':  'facebook.com',
    'instagram': 'instagram.com',
    'netflix':   'netflix.com',
    'ebay':      'ebay.com',
    'bank':      None,
}

PHISH_KEYWORDS = [
    'login', 'secure', 'verify', 'account', 'update',
    'confirm', 'password', 'signin', 'free', 'bonus',
    'offer', 'click', 'lucky', 'winner', 'reset'
]

def is_brand_spoofing(url_l, domain):
    for brand, legit_domain in BRAND_MAP.items():
        if brand in url_l:
            if legit_domain is None:
                return 1
            if not domain.endswith(legit_domain):
                return 1
    return 0

def extract_features(url):
    features = {}

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        url_l  = url.lower()
    except:
        parsed = urlparse('')
        domain = ''
        path   = ''
        url_l  = url.lower()

    # --- URL-level ---
    features['url_length']          = len(url)
    features['dot_count']           = url.count('.')
    features['hyphen_count']        = url.count('-')
    features['at_count']            = url.count('@')
    features['digit_count']         = sum(c.isdigit() for c in url)
    features['special_char_count']  = len(re.findall(r'[^a-zA-Z0-9]', url))
    features['slash_count']         = url.count('/')
    features['question_count']      = url.count('?')
    features['equal_count']         = url.count('=')
    features['underscore_count']    = url.count('_')
    features['percent_count']       = url.count('%')
    features['ampersand_count']     = url.count('&')
    features['digit_ratio']         = round(sum(c.isdigit() for c in url) / max(len(url), 1), 4)
    features['has_https']           = 1 if parsed.scheme == 'https' else 0
    features['has_port']            = 1 if parsed.port else 0

    # --- Domain-level ---
    clean_domain                    = domain[4:] if domain.startswith('www.') else domain
    features['domain_length']       = len(domain)
    features['subdomain_count']     = max(clean_domain.count('.') - 1, 0)
    features['has_ip']              = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', domain) else 0
    features['is_suspicious_tld']   = 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0
    features['domain_entropy']      = calc_entropy(domain)
    features['domain_digit_count']  = sum(c.isdigit() for c in domain)
    features['domain_hyphen_count'] = domain.count('-')

    # --- Path-level ---
    features['path_length']         = len(path)
    features['path_depth']          = path.count('/')
    features['query_length']        = len(parsed.query)
    features['tld_in_path']         = 1 if re.search(r'\.(com|net|org|xyz|tk)', path) else 0

    # --- Entropy ---
    features['url_entropy']         = calc_entropy(url)

    # --- Keyword features ---
    features['has_brand_keyword']   = is_brand_spoofing(url_l, domain)
    features['has_phish_keyword']   = 1 if any(kw in url_l for kw in PHISH_KEYWORDS) else 0

    # --- Encoding / obfuscation ---
    features['has_hex_chars']       = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
    features['has_double_slash']    = 1 if '//' in url[8:] else 0

    return features

# ── Helper: risk label from score ─────────────────────────────

def get_risk_label(risk_score):
    if risk_score >= 75:
        return "High Risk"
    elif risk_score >= 45:
        return "Medium Risk"
    else:
        return "Safe"

# ── Routes ─────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':  'ok',
        'message': 'Phishing detector API is running'
    })


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" in request body'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    try:
        # ── Whitelist check first ──────────────────────────────
        if is_trusted_domain(url):
            print(f"✅ [WHITELIST] {url}")
            return jsonify({
                'url':        url,
                'prediction': 'legitimate',
                'risk_score': 2.0,
                'risk_label': 'Safe',
                'confidence': 98.0,
                'features': {
                    'has_https':          url.lower().startswith('https'),
                    'has_ip':             False,
                    'has_suspicious_tld': False,
                    'has_phish_keyword':  False,
                    'has_brand_keyword':  False,
                    'subdomain_count':    0,
                    'url_length':         len(url),
                }
            })

        # ── Model prediction ───────────────────────────────────
        features    = extract_features(url)
        df          = pd.DataFrame([features])
        prediction  = int(model.predict(df)[0])
        probability = model.predict_proba(df)[0]
        risk_score  = round(float(probability[1]) * 100, 1)

        result = {
            'url':        url,
            'prediction': 'malicious' if prediction == 1 else 'legitimate',
            'risk_score': risk_score,
            'risk_label': get_risk_label(risk_score),
            'confidence': round(float(max(probability)) * 100, 1),
            'features': {
                'has_https':          bool(features['has_https']),
                'has_ip':             bool(features['has_ip']),
                'has_suspicious_tld': bool(features['is_suspicious_tld']),
                'has_phish_keyword':  bool(features['has_phish_keyword']),
                'has_brand_keyword':  bool(features['has_brand_keyword']),
                'subdomain_count':    features['subdomain_count'],
                'url_length':         features['url_length'],
            }
        }

        status_icon = "🚨" if prediction == 1 else "✅"
        print(f"{status_icon} [{risk_score}%] {url}")
        return jsonify(result)

    except Exception as e:
        print(f"❌ Error processing {url}: {e}")
        return jsonify({'error': 'Failed to analyze URL', 'details': str(e)}), 500


# ── Start server ───────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, port=5000)