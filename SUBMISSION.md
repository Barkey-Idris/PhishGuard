# نصوص جاهزة لنسخها في فورم الهاكثون

**Project title:** PhishGuard – Explainable Fake Website & Brand Impersonation Detector

**One-line summary:** Paste any link and get an instant risk score with plain-language reasons, sources, and a report-and-review workflow.

**Solution overview:**
Problem: Attackers clone banks, government and e-commerce sites on look-alike domains (e.g. paypa1-secure-login.xyz). Ordinary users cannot tell, and most tools only say "unsafe" without explaining why.
Approach: PhishGuard analyzes a submitted URL in three layers: (1) URL structure (no HTTPS, IP hosts, '@' tricks, punycode homographs, abused TLDs, shorteners, urgency keywords); (2) brand impersonation (typosquatting using edit distance and leetspeak normalization against a brand→official-domain list); (3) optional safe page analysis (password forms, forms posting to other domains, brand in title, hidden iframes, redirects, invalid TLS). Every finding shows what was detected, why it is dangerous, its score contribution and its source. The total becomes a 0-100 score and a verdict: Low risk / Suspicious / High risk, with advice.
What we built: a FastAPI backend, a web interface, and a reporting workflow where users flag sites and an admin confirms phishing or marks false positives. Privacy: scanned URLs are not stored; only explicit reports are. SSRF protection blocks fetching internal addresses, with timeouts and size caps. Limitations are documented: rule-based, small brand list, no ML/WHOIS yet. Roadmap: threat-feed integration, ML classifier, logo/screenshot matching, browser extension.

**Technology:** Python, FastAPI, SQLite, HTML/JavaScript (add Docker if you containerize)

**Deliverables checklist:**
- [ ] Working URL → deploy on Render.com / Railway (free) or show localhost in video
- [ ] Source repository → push folder to GitHub (public)
- [ ] Deck (5-8 slides): Problem, Solution, Architecture, Demo screenshots, Limitations, Roadmap
- [ ] Demo video (2-3 min): scan google.com (safe) → scan 3 fake examples → report one → admin confirms
- [ ] Code archive → ps19-phishguard.zip
- [ ] Put all in a Drive folder: "Anyone with the link can view"
