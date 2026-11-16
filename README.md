# PhishGuard AI

A Streamlit dashboard for defensive phishing and suspicious-URL screening.

## Features
- URL normalization and validation
- Heuristic checks for suspicious URL structure, keywords, punycode, IP hosts and lookalike-style hostnames
- DNS resolution and HTTPS/TLS certificate verification
- RDAP domain registration lookup (when registry data is available)
- Optional Google Safe Browsing lookup
- Risk score with evidence table, session-only scan history and JSON report export
- Responsive dark cybersecurity-themed interface

## Run locally
```bash
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
1. Push this repository to GitHub.
2. Open https://share.streamlit.io/
3. Create an app, select this repository, branch `main`, and file `app.py`.
4. Deploy.

Optional Google Safe Browsing API key can be entered in the app sidebar. The current integration uses the Safe Browsing v4 endpoint; verify Google's current product and API terms before relying on it. Google's Safe Browsing API is intended for non-commercial use; commercial use should use the appropriate Web Risk product.

## Important limitations
- A low risk score is **not** proof that a website is safe.
- Heuristic checks can produce false positives and false negatives.
- RDAP data may be missing or incomplete.
- This version does not crawl page content, inspect authenticated pages, submit forms, bypass logins, exploit websites, or guarantee security.
- The scanner performs DNS, RDAP and TLS lookups for the entered hostname. Deploy with appropriate rate limits and abuse protections.

## Responsible use
Use for defensive awareness and analyze websites only where you have a legitimate reason. Never submit credentials or sensitive information to suspicious websites.
