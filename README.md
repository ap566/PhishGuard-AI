# PhishGuard AI

A Streamlit dashboard for defensive phishing and suspicious-URL screening.

## Features
- URL normalization and validation
- Heuristic checks for suspicious URL structure, keywords, punycode, IP hosts and lookalike-style hostnames
- DNS resolution and HTTPS/TLS certificate verification
- RDAP domain registration lookup (when registry data is available)
- Google Safe Browsing v5 URL threat lookup (API key required)
- Optional Google Fact Check Tools claim search using the public page title and description (same Google API key; Fact Check Tools API must also be enabled)
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

Enter a Google API key in the sidebar to enable Google Safe Browsing v5 and Google Fact Check Tools claim search. In Google Cloud, enable **Safe Browsing API** and **Fact Check Tools API**, and ensure both are allowed by the key's API restrictions. Safe Browsing v5 checks the submitted URL against Google's known threat data. Fact Check Tools searches the page title and meta description against indexed ClaimReview records; it does not rate an entire publisher or prove an article true or false. See the [Safe Browsing v5 documentation](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search) and [Fact Check Tools API documentation](https://developers.google.com/fact-check/tools/api/reference/rest/v1alpha1/claims/search). Google's Safe Browsing API is for non-commercial use; commercial services should evaluate Google Web Risk.

## Important limitations
- A low technical risk score is **not** proof that a website is safe, legitimate, authentic, or truthful.
- No tool can reliably classify every website as real or fake. Newly created threats and unindexed misinformation may not appear in available sources.
- A missing Safe Browsing match means only that Google returned no known match for that submitted URL at scan time.
- Fact-check results apply to specific claims and their cited reviews, not to an entire domain or publisher.
- Heuristic checks can produce false positives and false negatives.
- RDAP data may be missing or incomplete.
- This version does not crawl page content, inspect authenticated pages, submit forms, bypass logins, exploit websites, or guarantee security.
- The scanner performs DNS, RDAP and TLS lookups for the entered hostname. Deploy with appropriate rate limits and abuse protections.

## Responsible use
Use for defensive awareness and analyze websites only where you have a legitimate reason. Never submit credentials or sensitive information to suspicious websites.
