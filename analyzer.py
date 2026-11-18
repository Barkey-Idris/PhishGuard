"""PhishGuard analyzer: rule-based phishing / brand-impersonation detection.
Every finding says WHAT was found, WHY it matters, and the SOURCE of the rule."""
import ipaddress, re, socket, ssl, urllib.request
from html.parser import HTMLParser
from urllib.parse import urlparse

# --- Local knowledge base (brand -> legitimate registered domains) -------------
BRANDS = {
    "paypal": ["paypal.com"], "google": ["google.com", "google.co.in"],
    "amazon": ["amazon.com", "amazon.in"], "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"], "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"], "netflix": ["netflix.com"], "whatsapp": ["whatsapp.com"],
    "flipkart": ["flipkart.com"], "paytm": ["paytm.com"], "phonepe": ["phonepe.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"], "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "irctc": ["irctc.co.in"],
    "linkedin": ["linkedin.com"], "dropbox": ["dropbox.com"], "binance": ["binance.com"],
}
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "zip",
                   "work", "support", "loan", "icu", "buzz", "cfd", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking",
            "wallet", "password", "suspend", "unlock", "billing", "refund", "kyc", "reward", "free"]
MULTI_TLD = {"co.in", "co.uk", "com.au", "gov.in", "ac.in", "org.in", "net.in", "com.br", "co.jp"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "$": "s"})

SRC_URL = "URL-structure indicators (APWG / PhishTank research)"
SRC_BRAND = "Local brand list (built-in, editable in analyzer.py)"
SRC_TLD = "Abused-TLD list (Spamhaus / Interisle reports)"
SRC_TLS = "Live TLS certificate check (Python ssl)"
SRC_PAGE = "Page-content analysis (fetched HTML)"


def normalize(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    return raw


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def f(id_, title, points, detail, source):
    return {"id": id_, "title": title, "points": points, "detail": detail, "source": source}


# --- URL-only checks (no network needed) ---------------------------------------
def check_url(url: str):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    out = []
    if not host:
        return [f("bad_url", "Not a valid URL", 40, "No hostname could be found.", SRC_URL)], host, ""

    reg = registered_domain(host)
    label = reg.split(".")[0]
    tld = host.split(".")[-1]

    if p.scheme != "https":
        out.append(f("no_https", "Connection is not encrypted (HTTP)", 15,
                     "Legitimate login pages use HTTPS. Plain HTTP lets anyone read what you type.", SRC_URL))
    try:
        ipaddress.ip_address(host)
        out.append(f("ip_host", "Address is a raw IP number", 25,
                     "Real brands use domain names, not IP addresses.", SRC_URL))
    except ValueError:
        pass
    if "@" in (p.netloc or ""):
        out.append(f("at_symbol", "URL contains '@'", 25,
                     "Text before '@' is ignored by browsers and is used to fake a trusted name.", SRC_URL))
    if host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host):
        out.append(f("homograph", "Look-alike (IDN/Punycode) characters", 30,
                     "Characters from other alphabets can imitate Latin letters (e.g. Cyrillic 'а').", SRC_URL))
    if len(host.split(".")) > 4:
        out.append(f("deep_sub", "Too many subdomains", 12,
                     "Attackers stack subdomains to hide the real domain at the end.", SRC_URL))
    if host.count("-") >= 3:
        out.append(f("hyphens", "Many hyphens in domain", 10, "Common in throw-away phishing domains.", SRC_URL))
    if len(url) > 100:
        out.append(f("long_url", "Very long URL", 8, "Long URLs hide the real destination.", SRC_URL))
    if p.port and p.port not in (80, 443):
        out.append(f("odd_port", f"Unusual port :{p.port}", 10, "Legitimate sites rarely use custom ports.", SRC_URL))
    if tld in SUSPICIOUS_TLDS:
        out.append(f("bad_tld", f"Frequently abused extension .{tld}", 15,
                     "This extension is cheap/free and heavily used for scam sites.", SRC_TLD))
    if reg in SHORTENERS:
        out.append(f("shortener", "Link shortener hides the destination", 15,
                     "You cannot see where the link really goes.", SRC_URL))
    found_kw = [k for k in KEYWORDS if k in (host + p.path).lower()]
    if found_kw:
        out.append(f("keywords", "Urgent / credential keywords: " + ", ".join(found_kw[:5]),
                     min(5 * len(found_kw), 15), "Words like these are used to pressure victims.", SRC_URL))

    # Brand impersonation
    legit = {d for ds in BRANDS.values() for d in ds}
    if reg not in legit:
        norm_label = label.translate(LEET).replace("rn", "m").replace("vv", "w")
        flagged = False
        hay = p.netloc.lower().translate(LEET).replace("-", "").replace(".", "")
        for brand, domains in BRANDS.items():
            main = domains[0].split(".")[0]
            d = levenshtein(norm_label, main)
            if 0 < d <= 2 and len(main) >= 5 or (norm_label == main and label != main):
                out.append(f("typosquat", f"Looks like '{main}' but is '{reg}'", 40,
                             f"Domain is almost identical to {domains[0]} (typo/character swap).", SRC_BRAND))
                flagged = True
                break
            if brand in hay:
                out.append(f("brand_in_host", f"Uses brand name '{brand}' on an unrelated domain", 35,
                             f"Real {brand.title()} sites live on {', '.join(domains)}, not {reg}.", SRC_BRAND))
                flagged = True
                break
        if not flagged and p.path:
            for brand, domains in BRANDS.items():
                if brand in p.path.lower():
                    out.append(f("brand_in_path", f"Brand '{brand}' appears only in the URL path", 20,
                                 f"The site is {reg}, not {domains[0]}.", SRC_BRAND))
                    break
    return out, host, reg


# --- Safe fetching (SSRF protected) --------------------------------------------
def is_public_host(host: str) -> bool:
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title, self._in_title = "", False
        self.forms, self.password_fields, self.hidden_iframes = [], 0, 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title": self._in_title = True
        if tag == "form": self.forms.append(a.get("action", ""))
        if tag == "input" and a.get("type", "").lower() == "password": self.password_fields += 1
        if tag == "iframe" and (a.get("width") in ("0", "1") or "display:none" in a.get("style", "").replace(" ", "")):
            self.hidden_iframes += 1

    def handle_endtag(self, tag):
        if tag == "title": self._in_title = False

    def handle_data(self, data):
        if self._in_title: self.title += data


def check_content(url: str, host: str, reg: str):
    out, meta = [], {"fetched": False}
    if not is_public_host(host):
        meta["note"] = "Skipped live fetch: host is private/unresolvable (safety rule)."
        return out, meta
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhishGuardBot/1.0 (+safe-analysis)"})
        with urllib.request.urlopen(req, timeout=6) as r:
            html = r.read(300_000).decode("utf-8", "ignore")
            meta.update(fetched=True, final_url=r.geturl())
    except ssl.SSLError:
        out.append(f("bad_cert", "Invalid TLS certificate", 25, "The site's certificate failed validation.", SRC_TLS))
        return out, meta
    except Exception as e:
        meta["note"] = f"Could not fetch page ({type(e).__name__})."
        return out, meta

    final_host = urlparse(meta["final_url"]).hostname or host
    if registered_domain(final_host) != reg:
        out.append(f("redirect", f"Redirects to a different domain ({final_host})", 15,
                     "The page you open is not the one in the link.", SRC_PAGE))
    pp = PageParser(); pp.feed(html)
    meta["title"] = pp.title.strip()[:120]
    if pp.password_fields:
        out.append(f("pw_form", "Page asks for a password", 10, "Credential-harvesting pages always contain one.", SRC_PAGE))
        for act in pp.forms:
            ah = urlparse(act).hostname
            if ah and registered_domain(ah) != reg:
                out.append(f("form_external", f"Form sends data to another domain ({ah})", 30,
                             "Your login would be submitted to a third party.", SRC_PAGE))
                break
    legit = {d for ds in BRANDS.values() for d in ds}
    if reg not in legit:
        for brand in BRANDS:
            if brand in pp.title.lower():
                out.append(f("title_brand", f"Page title mentions '{brand}' but domain differs", 25,
                             "A brand-named page on an unrelated domain is a classic impersonation sign.", SRC_PAGE))
                break
    if pp.hidden_iframes:
        out.append(f("hidden_iframe", "Hidden iframe present", 15, "Used to silently load other content.", SRC_PAGE))
    return out, meta


def analyze(raw_url: str, deep: bool = True) -> dict:
    url = normalize(raw_url)
    findings, host, reg = check_url(url)
    meta = {"fetched": False}
    legit = {d for ds in BRANDS.values() for d in ds}
    if deep and host and not any(x["id"] == "bad_url" for x in findings):
        extra, meta = check_content(url, host, reg)
        findings += extra
    if reg in legit:
        findings = [x for x in findings if x["id"] != "keywords"]
    score = min(sum(x["points"] for x in findings), 100)
    if reg in legit and not findings:
        score = 0
    verdict = "High risk" if score >= 55 else "Suspicious" if score >= 30 else "Low risk"
    advice = {"High risk": "Do NOT enter any information. Report this site.",
              "Suspicious": "Be careful. Open the official site by typing its address yourself.",
              "Low risk": "No strong indicators found, but this is not a guarantee of safety."}[verdict]
    return {"url": url, "domain": reg, "score": score, "verdict": verdict, "advice": advice,
            "findings": sorted(findings, key=lambda x: -x["points"]), "page": meta}
