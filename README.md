# PhishGuard – Fake Website, Brand Impersonation & Scam Detection (PS-19)

## تشغيل المشروع خطوة بخطوة (Run it)
1. ثبّت Python 3.10+ من python.org (تأكد تختار "Add to PATH").
2. افتح Terminal داخل مجلد المشروع:
   ```
   python -m venv venv
   venv\Scripts\activate        # على Windows   |   source venv/bin/activate  على Mac/Linux
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```
3. افتح المتصفح: http://127.0.0.1:8000  (والتوثيق التلقائي للـ API: /docs)
4. لوحة المراجعة: اكتب الـ admin token (الافتراضي `admin123`، غيّره بمتغير `ADMIN_TOKEN`).

## How it works
`analyzer.py` runs 3 layers, each finding = what + why + source:
1. **URL structure**: no-HTTPS, IP host, `@` trick, punycode/homograph, deep subdomains, abused TLDs, shorteners, urgency keywords.
2. **Brand impersonation**: typosquatting (Levenshtein + leetspeak `paypa1`, `rnicrosoft`), brand name on unrelated domain.
3. **Page content** (optional live fetch): password form, form posting to another domain, brand in title, hidden iframes, redirects, bad TLS cert.
Score 0-100 → Low risk / Suspicious (>=30) / High risk (>=55).

## Reporting & review workflow
User clicks **Report** → saved in SQLite as `pending` → admin reviews → `confirmed_phishing` or `false_positive`.

## Privacy safeguards
- Scanned URLs are **not stored**; only URLs the user explicitly reports are saved.
- No cookies, no accounts, no third-party calls with the user's URL.
- SSRF protection: private/loopback IPs are never fetched; 6 s timeout; 300 KB cap; page is parsed, never executed.

## Limitations (be honest with the jury)
- Rule-based, not ML: can miss novel attacks and may false-positive on odd legit sites.
- Brand list is small (20 brands), easy to extend in `BRANDS`.
- No domain-age/WHOIS or live threat feeds yet (future work: PhishTank/Google Safe Browsing API, ML classifier, screenshot/logo matching).
- A "Low risk" result is never a guarantee of safety.

## Safe demo URLs (no real malicious sites)
google.com · paypa1-secure-login.xyz/verify · amazon-india.support/account/update · rnicrosoft.com · google.com@evil.tk · netflix.com.verify-id.top
(these are only *analyzed as text*; the sample fake domains are not opened unless they exist, and nothing is executed)
