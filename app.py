import json
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
:root{--bg:#080d18;--panel:#101a2c;--muted:#91a2bd;--cyan:#5eead4;--line:rgba(148,163,184,.17)}
.stApp{background:radial-gradient(ellipse at 12% 0%,rgba(37,99,235,.18),transparent 36%),radial-gradient(ellipse at 88% 12%,rgba(20,184,166,.11),transparent 30%),var(--bg);font-family:'DM Sans',sans-serif;color:#f5f8ff}
.block-container{max-width:1240px;padding-top:2rem;padding-bottom:3rem}
h1,h2,h3{font-family:'Space Grotesk',sans-serif;letter-spacing:-.035em}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0d1729,#0a1220);border-right:1px solid var(--line)}
.hero{padding:2rem 2.1rem;border:1px solid rgba(125,211,252,.22);border-radius:24px;background:linear-gradient(115deg,rgba(20,37,67,.96),rgba(12,28,47,.92));margin-bottom:1.35rem;box-shadow:0 18px 60px #0004}
.eyebrow,.kicker{font-size:.74rem;font-weight:700;letter-spacing:.16em;color:var(--cyan);text-transform:uppercase}
.hero h1{font-size:clamp(2rem,4vw,3.1rem);margin:.55rem 0;color:#f7fbff}
.hero p,.sub{color:#b4c5df;max-width:740px}
.chip{display:inline-block;margin-top:.7rem;padding:.4rem .75rem;border:1px solid #5eead444;border-radius:99px;color:#aaf8e9;background:#14b8a608;font-size:.8rem}
div[data-testid="stTextInput"] input{background:#0d1728!important;border:1px solid #344762!important;border-radius:13px!important;color:#f5f8ff!important;min-height:3.1rem}
.stButton>button[kind="primary"]{border:0;border-radius:13px;min-height:3.05rem;font-weight:700;color:#06131b;background:linear-gradient(100deg,#5eead4,#7dd3fc)}
div[data-testid="stMetric"]{background:linear-gradient(145deg,#14233b,#101a2b);padding:1rem;border:1px solid var(--line);border-radius:17px}
div[data-testid="stMetricValue"]{font-family:'Space Grotesk',sans-serif}
div[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:14px;overflow:hidden}
div[data-testid="stDownloadButton"] button{border-radius:12px;border:1px solid #38516f;background:#14243b;color:#dcecff}
hr{border-color:var(--line)}
.footer{text-align:center;color:#71839e;font-size:.78rem;padding:1rem 0}
@media(max-width:700px){.block-container{padding-left:1rem;padding-right:1rem}.hero{padding:1.4rem}}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
 <div class="eyebrow">PERSONAL CYBER DEFENSE · URL INTELLIGENCE</div>
 <h1>PhishGuard <span style="color:#5eead4">AI</span></h1>
 <p>Spot suspicious links before they become a security problem. Review URL patterns, domain signals, certificates and available threat intelligence in one place.</p>
 <div class="chip">✦ Smart URL screening · Evidence-led risk insights</div>
</div>
""", unsafe_allow_html=True)
st.warning("A risk assessment is not a guarantee. Never enter passwords or payment details just because a scanner reports a low risk.")

def normalize_url(raw):
    value = raw.strip()
    if not value:
        raise ValueError("Enter a website URL.")
    if any(ch.isspace() for ch in value):
        raise ValueError("The URL must not contain spaces.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("The hostname could not be normalized.")
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    clean = urlunparse((parsed.scheme, netloc, parsed.path or "/", parsed.params, parsed.query, ""))
    return clean, parsed._replace(netloc=netloc), host, is_ip

def lexical_checks(url, parsed, host, is_ip):
    score, findings = 0, []
    def add(points, severity, title, evidence):
        nonlocal score
        score += points
        findings.append({"Severity": severity, "Finding": title, "Evidence": evidence})
    if len(url) > 100: add(8, "Medium", "Unusually long URL", f"URL length: {len(url)} characters.")
    if len(url) > 180: add(8, "High", "Very long URL", "Long URLs can conceal the destination.")
    if "@" in url: add(18, "High", "Contains @ symbol", "The @ character can make the apparent destination misleading.")
    if is_ip: add(18, "High", "Uses an IP address", "The hostname is an IP address, not a regular domain.")
    if host.count(".") >= 4: add(10, "Medium", "Many subdomains", f"Hostname contains {host.count('.')} dots.")
    if "-" in host: add(5, "Low", "Hyphen in domain", "Hyphens are not malicious by themselves.")
    if host.startswith("xn--") or ".xn--" in host: add(15, "High", "Punycode hostname", "The internationalized hostname deserves visual inspection.")
    if parsed.scheme != "https": add(10, "Medium", "No HTTPS", "The URL uses unencrypted HTTP.")
    words = ["login","signin","verify","account","update","secure","password","wallet","payment","confirm","recover","bank"]
    found = sorted({w for w in words if w in (host + parsed.path + parsed.query).lower()})
    if found: add(min(15,4+2*len(found)), "Medium", "Sensitive-action keywords", "Found: " + ", ".join(found))
    risky = (".zip",".mov",".top",".click",".work",".country",".gq",".tk",".ml",".cf")
    if host.endswith(risky): add(10, "Medium", "TLD merits extra scrutiny", "This TLD can be abused; it is not proof of phishing.")
    if re.search(r"(paypal|google|microsoft|apple|amazon|facebook|instagram|netflix)[a-z0-9-]{0,15}\.", host):
        add(12, "Medium", "Possible brand-like hostname", "A familiar brand string appears in the hostname.")
    return min(score,70), findings

def dns_check(host):
    try:
        return sorted({x[4][0] for x in socket.getaddrinfo(host,None)}), None
    except Exception as exc:
        return [], str(exc)

def tls_check(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,443),timeout=4) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as secure:
                cert=secure.getpeercert()
                return {"valid":True,"expires":cert.get("notAfter","Unknown")},None
    except Exception as exc:
        return {"valid":False},str(exc)

def rdap_check(host):
    try:
        response=requests.get(f"https://rdap.org/domain/{host}",timeout=5,headers={"User-Agent":"PhishGuard-AI/1.0"})
        if response.status_code != 200: return {"available":False,"status":response.status_code}
        data=response.json()
        created=next((e.get("eventDate") for e in data.get("events",[]) if e.get("eventAction") in ("registration","registered")),None)
        age=None
        if created: age=(datetime.now(timezone.utc)-datetime.fromisoformat(created.replace("Z","+00:00"))).days
        return {"available":True,"created":created,"age_days":age}
    except Exception as exc: return {"available":False,"error":str(exc)}

def safe_browsing_check(url,key):
    """Google Safe Browsing v5 URL lookup. Empty threats means no known match, not safe."""
    if not key: return {"configured":False,"status":"Not configured"}
    endpoint="https://safebrowsing.googleapis.com/v5/urls:search"
    try:
        r=requests.get(endpoint,params=[("key",key),("urls",url),("alt","json")],
                       headers={"Accept":"application/json"},timeout=15)
        body=r.text.strip()
        if r.status_code != 200:
            detail=""
            try: detail=r.json().get("error",{}).get("message","")
            except Exception: detail=body[:240]
            return {"configured":True,"error":f"Google Safe Browsing HTTP {r.status_code}. {detail}".strip(),"matches":[]}
        try:
            data=r.json()
        except ValueError:
            # Preserve the response diagnostics instead of silently treating a parse failure as a clean result.
            return {"configured":True,"error":f"Google Safe Browsing returned an unreadable response (HTTP {r.status_code}, content-type: {r.headers.get('Content-Type','unknown')}). Response preview: {body[:240]!r}","matches":[]}
        if not isinstance(data,dict):
            return {"configured":True,"error":"Google Safe Browsing returned an unexpected response structure.","matches":[]}
        matches=data.get("threats",[])
        return {"configured":True,"matches":matches,"status":"Threat match" if matches else "No known threat match","cache_duration":data.get("cacheDuration")}
    except requests.RequestException as exc:
        return {"configured":True,"error":f"Google Safe Browsing request failed: {exc}","matches":[]}
    except Exception as exc:
        return {"configured":True,"error":f"Google Safe Browsing check failed: {exc}","matches":[]}

def factcheck_search(query,key):
    """Search Google's ClaimReview index for text extracted from the public page."""
    if not key or not query:
        return {"configured":bool(key),"status":"Not run","claims":[]}
    try:
        r=requests.get("https://factchecktools.googleapis.com/v1alpha1/claims:search",
                       params={"key":key,"query":query[:400],"pageSize":5,"languageCode":"en"},
                       timeout=10)
        if r.status_code != 200:
            detail=""
            try: detail=r.json().get("error",{}).get("message","")
            except Exception: pass
            hint=" Enable Fact Check Tools API in the same Google Cloud project and verify this key is allowed to call it." if r.status_code==403 else ""
            return {"configured":True,"error":f"Fact Check API HTTP {r.status_code}. {detail}{hint}".strip(),"claims":[]}
        claims=[]
        for item in r.json().get("claims",[]):
            reviews=item.get("claimReview",[])
            claims.append({"claim":item.get("text",""),"claim_date":item.get("claimDate",""),
                           "claimant":item.get("claimant",""),
                           "reviews":[{"publisher":x.get("publisher",{}).get("name","Unknown"),
                                       "url":x.get("url",""),"title":x.get("title",""),
                                       "rating":x.get("textualRating","")} for x in reviews[:3]]})
        return {"configured":True,"status":"Results found" if claims else "No matching fact-check indexed","claims":claims}
    except Exception as exc:
        return {"configured":True,"error":str(exc),"claims":[]}


def public_host_check(host):
    try:
        ips = sorted({x[4][0] for x in socket.getaddrinfo(host, None)})
        return bool(ips) and all(ipaddress.ip_address(x).is_global for x in ips), ips
    except Exception as exc:
        return False, [str(exc)]

def inspect_public_site(url):
    current = url
    redirects = []
    response = None
    for _ in range(6):
        p = urlparse(current)
        if p.scheme not in ("http", "https") or not p.hostname:
            return {"available": False, "error": "Unsupported redirect URL."}
        public, ips = public_host_check(p.hostname)
        if not public:
            return {"available": False, "error": "Blocked because host did not resolve exclusively to public IPs.", "ips": ips}
        try:
            response = requests.get(current, headers={"User-Agent":"PhishGuardAI/1.0 passive scanner", "Accept":"text/html"},
                                    timeout=(4, 7), allow_redirects=False, verify=True, stream=True)
        except requests.RequestException as exc:
            return {"available": False, "error": str(exc)[:200], "redirects": redirects}
        if response.status_code in (301,302,303,307,308):
            from urllib.parse import urljoin
            target = urljoin(current, response.headers.get("Location", ""))
            status = response.status_code
            response.close()
            if not target or target == current:
                return {"available": False, "error": "Invalid redirect.", "redirects": redirects}
            redirects.append({"status": status, "to": target})
            current = target
            continue
        break
    else:
        return {"available": False, "error": "Too many redirects.", "redirects": redirects}
    try:
        headers = dict(response.headers)
        status = response.status_code
        final_url = response.url
        body = b""
        if "html" in headers.get("Content-Type", "").lower():
            for chunk in response.iter_content(16384):
                body += chunk
                if len(body) >= 150000:
                    body = body[:150000]
                    break
    finally:
        response.close()
    html = body.decode("utf-8", errors="ignore")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", title_match.group(1))).strip()[:140] if title_match else "Not found"
    desc_match = re.search(r"""<meta[^>]+name=['"]description['"][^>]+content=['"]([^'"]*)""", html, re.I)
    if not desc_match:
        desc_match = re.search(r"""<meta[^>]+content=['"]([^'"]*)['"][^>]+name=['"]description['"]""", html, re.I)
    description = re.sub(r"\s+", " ", desc_match.group(1)).strip()[:500] if desc_match else ""
    visible_text = re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>", " ", html, flags=re.I|re.S)
    visible_text = re.sub(r"<[^>]+>", " ", visible_text)
    visible_text = re.sub(r"\s+", " ", visible_text).strip()[:3000]
    forms = re.findall(r"<form\b([^>]*)>(.*?)</form\s*>", html, re.I | re.S)
    password_forms = 0
    cross_domain_password_forms = 0
    from urllib.parse import urljoin
    for attrs, inner in forms:
        if re.search(r"""type\s*=\s*['"]?password""", inner, re.I):
            password_forms += 1
            action = re.search(r"""\baction\s*=\s*['"]([^'"]+)""", attrs, re.I)
            if action:
                action_host = urlparse(urljoin(final_url, action.group(1))).hostname
                if action_host and action_host.lower() != (urlparse(final_url).hostname or "").lower():
                    cross_domain_password_forms += 1
    lower_headers = {k.lower() for k in headers}
    security = {"Content-Security-Policy":"content-security-policy", "Strict-Transport-Security":"strict-transport-security",
                "X-Content-Type-Options":"x-content-type-options", "X-Frame-Options":"x-frame-options"}
    missing = [name for name, key in security.items() if key not in lower_headers]
    return {"available":True, "status":status, "final_url":final_url, "redirects":redirects, "title":title,
            "description":description, "page_text":visible_text,
            "content_type":headers.get("Content-Type",""), "forms":len(forms), "password_forms":password_forms,
            "cross_domain_password_forms":cross_domain_password_forms, "missing_headers":missing,
            "html_bytes_inspected":len(body)}

def run_scan(raw,key):
    url,parsed,host,is_ip=normalize_url(raw)
    score,findings=lexical_checks(url,parsed,host,is_ip)
    ips,dns_error=dns_check(host)
    if dns_error:
        findings.append({"Severity":"Medium","Finding":"DNS lookup failed","Evidence":dns_error[:180]}); score+=8
    if parsed.scheme=="https":
        tls,tls_error=tls_check(host)
    else:
        tls,tls_error={"valid":False},None
    if parsed.scheme=="https" and not tls.get("valid"):
        evidence=("TLS check failed: " + tls_error[:150]) if tls_error else "Could not validate a certificate on port 443."
        findings.append({"Severity":"High","Finding":"TLS certificate check failed","Evidence":evidence}); score+=15
    rdap=rdap_check(host) if not is_ip else {"available":False}
    age=rdap.get("age_days")
    if age is not None and age<30:
        findings.append({"Severity":"High","Finding":"Recently registered domain","Evidence":f"RDAP registration age: {age} days."}); score+=20
    elif age is not None and age<180:
        findings.append({"Severity":"Medium","Finding":"Relatively new domain","Evidence":f"RDAP registration age: {age} days."}); score+=8
    site=inspect_public_site(url)
    if site.get("available"):
        if site.get("cross_domain_password_forms"):
            findings.append({"Severity":"High","Finding":"Password form posts to another hostname","Evidence":"A password form action points to a different host."}); score+=20
        if site.get("status",200)>=400:
            findings.append({"Severity":"Low","Finding":"Website returned an HTTP error","Evidence":f"HTTP status {site['status']}."}); score+=3
    else:
        findings.append({"Severity":"Info","Finding":"Live page inspection unavailable","Evidence":site.get("error","Could not fetch page.")})
    intel=safe_browsing_check(url,key)
    confirmed=bool(intel.get("matches"))
    if intel.get("error"):
        findings.append({"Severity":"Info","Finding":"Threat-intelligence lookup could not be interpreted","Evidence":"Google Safe Browsing did not provide a usable result; the risk score excludes this unavailable check."})
    if confirmed:
        kinds=sorted({kind for match in intel.get("matches",[]) for kind in match.get("threatTypes",[])})
        findings.append({"Severity":"Critical","Finding":"Google Safe Browsing threat match","Evidence":"Threat type(s): " + (", ".join(kinds) if kinds else "Known unsafe URL")})
    page_query=" ".join([site.get("title",""),site.get("description","")]).strip() if site.get("available") else ""
    factchecks=factcheck_search(page_query,key) if page_query else {"configured":bool(key),"status":"Page text unavailable","claims":[]}
    if factchecks.get("claims"):
        findings.append({"Severity":"Info","Finding":"Fact-check references found","Evidence":f"{len(factchecks['claims'])} related claim(s) found in Google's fact-check index. Review each publisher's rating and context."})
    score=100 if confirmed else min(99,max(0,score))
    level="Known malicious/phishing indicator" if confirmed else "High technical risk" if score>=55 else "Suspicious technical signals" if score>=25 else "No strong technical warning signals"
    return {"url":url,"host":host,"score":score,"level":level,"findings":findings,"dns":ips,"tls":tls,"rdap":rdap,"intel":intel,"factchecks":factchecks,"site":site,"scanned_at":datetime.now(timezone.utc).isoformat()}

with st.sidebar:
    st.header("⚙️ Scanner settings")
    api_key=st.text_input("Google Safe Browsing API key (optional)",type="password",help="Leave blank to use local checks.")
    st.caption("Keep this key private. Enable Google Safe Browsing API and Fact Check Tools API in Cloud Console to use both services.")
    st.divider()
    st.markdown("**Detection layers**")
    st.write("• URL structure\n• DNS resolution\n• TLS certificate\n• RDAP registration\n• Optional threat intelligence")

st.markdown('<div class="kicker">START HERE</div><h2>Analyze a website</h2><p class="sub">Paste a complete URL or domain. Review the signals that may indicate phishing or impersonation.</p>',unsafe_allow_html=True)
u,b=st.columns([5,1.45],vertical_alignment="bottom")
with u: url_input=st.text_input("Website URL",placeholder="https://example.com",label_visibility="collapsed")
with b: scan=st.button("⌕  Scan URL",type="primary",use_container_width=True)
if "history" not in st.session_state: st.session_state.history=[]
if scan:
    try:
        with st.spinner("Analyzing URL, domain signals and available threat intelligence..."):
            result=run_scan(url_input,api_key.strip())
        st.session_state.latest=result
        st.session_state.history.insert(0,result)
    except ValueError as exc: st.error(str(exc))
    except Exception as exc: st.error(f"Scan could not be completed: {exc}")

if "latest" in st.session_state:
    r=st.session_state.latest
    st.divider()
    st.markdown('<div class="kicker">ANALYSIS COMPLETE</div><h2>Security assessment</h2><p class="sub">Review the score together with the supporting evidence.</p>',unsafe_allow_html=True)
    c1,c2,c3=st.columns(3)
    c1.metric("Risk score",f"{r['score']}/100")
    c2.metric("Assessment",r["level"])
    c3.metric("DNS addresses",len(r["dns"]))
    if r["score"]>=55: st.error(f"⚠️ {r['level']}: avoid interacting until independently verified.")
    elif r["score"]>=25: st.warning(f"⚠️ {r['level']}: review the evidence before proceeding.")
    elif r.get("intel", {}).get("error"): st.warning("Threat intelligence could not be verified. The displayed score excludes this check; do not treat it as a clean result.")
    else: st.success("No strong warning signals were identified. This does not prove the site is safe.")
    left,right=st.columns(2)
    with left:
        st.markdown("**🌐 URL & domain intelligence**")
        st.write("Scanned URL:",r["url"]); st.write("Hostname:",r["host"])
        st.write("DNS:",", ".join(r["dns"]) if r["dns"] else "No records returned")
        st.markdown("**🔒 TLS certificate**")
        st.write("Valid HTTPS certificate:","Yes" if r["tls"].get("valid") else "Not verified")
        if r["tls"].get("expires"): st.write("Certificate expiry:",r["tls"]["expires"])
    with right:
        st.markdown("**🗂️ Domain registration (RDAP)**")
        st.write("Registration date:",r["rdap"].get("created","Unavailable"))
        age=r["rdap"].get("age_days")
        st.write("Estimated age:",f"{age} days" if age is not None else "Unavailable")
        st.markdown("**🛰️ Threat intelligence**")
        if r["intel"].get("matches"): st.error("Known threat match found.")
        elif r["intel"].get("error"): st.warning(r["intel"]["error"])
        elif r["intel"].get("configured"): st.write("No known threat match returned by Google Safe Browsing v5.")
        else: st.write("Not configured. Add an API key in the sidebar.")
        st.markdown("**📰 Fact-check claim search**")
        fc=r.get("factchecks",{})
        if fc.get("claims"): st.write(f"{len(fc['claims'])} related fact-check record(s) found.")
        elif fc.get("error"): st.warning(fc["error"])
        else: st.write(fc.get("status","Not run"))

    st.markdown("### Live website inspection")
    site=r.get("site", {})
    if site.get("available"):
        a,b,c=st.columns(3)
        a.metric("HTTP status", site.get("status", "—"))
        b.metric("Forms found", site.get("forms", 0))
        c.metric("Password forms", site.get("password_forms", 0))
        st.write("Page title:", site.get("title", "Not found"))
        st.write("Final URL:", site.get("final_url", r["url"]))
        st.write("Missing security headers:", ", ".join(site.get("missing_headers", [])) or "None of the checked headers are missing")
        if site.get("cross_domain_password_forms"):
            st.warning("A password form submits to another hostname. Verify this manually.")
        if site.get("redirects"):
            st.write("Redirect chain:", site["redirects"])
    else:
        st.info("Live page inspection unavailable: " + site.get("error", "Unknown error"))
    st.caption("Passive inspection only: no form submissions, logins, exploitation, or crawling.")

    st.markdown("### Publisher and article fact-check references")
    fc=r.get("factchecks",{})
    if fc.get("claims"):
        for item in fc["claims"]:
            st.markdown(f"**Claim:** {item.get('claim') or 'Claim text unavailable'}")
            if item.get("claimant"): st.caption("Claimant: " + item["claimant"])
            for review in item.get("reviews",[]):
                st.write(f"**Rating:** {review.get('rating') or 'Not supplied'} · **Publisher:** {review.get('publisher') or 'Unknown'}")
                if review.get("title") and review.get("url"): st.markdown(f"[{review['title']}]({review['url']})")
    elif fc.get("error"):
        st.info("Fact-check lookup did not complete: " + fc["error"])
    else:
        st.caption("No matching ClaimReview record was returned for the page title/description. This does not mean the article is true.")
    st.caption("Fact-check results concern matching claims, not a blanket rating of the whole domain.")

    st.markdown("### Findings & evidence")
    if r["findings"]: st.dataframe(pd.DataFrame(r["findings"]),use_container_width=True,hide_index=True)
    else: st.info("No heuristic warning signals were detected.")
    report={"application":"PhishGuard AI","disclaimer":"Risk indicators are not proof. A low score does not guarantee safety.",**r}
    st.download_button("⬇️ Download JSON report",data=json.dumps(report,indent=2),file_name="phishguard_scan_report.json",mime="application/json")

st.divider()
st.markdown('<div class="kicker">YOUR ACTIVITY</div><h2>Recent scan history</h2><p class="sub">History is kept in this active browser session only.</p>',unsafe_allow_html=True)
if st.session_state.history:
    rows=[{"Scanned URL":x["url"],"Risk":x["score"],"Assessment":x["level"],"Scanned at":x["scanned_at"]} for x in st.session_state.history[:20]]
    st.dataframe(pd.DataFrame(rows),use_container_width=True,hide_index=True)
    if st.button("Clear scan history"): st.session_state.history=[]; st.rerun()
else: st.caption("Your scans in this browser session will appear here.")
st.divider()
st.markdown('<div class="footer">PHISHGUARD AI · DEFENSIVE URL ANALYSIS · A LOW RISK SCORE IS NOT A SAFETY GUARANTEE</div>',unsafe_allow_html=True)
