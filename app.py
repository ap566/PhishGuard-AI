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
    if not key: return {"configured":False}
    endpoint="https://safebrowsing.googleapis.com/v4/threatMatches:find"
    body={"client":{"clientId":"phishguard-ai","clientVersion":"1.0"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}}
    try:
        r=requests.post(endpoint,params={"key":key},json=body,timeout=8)
        if r.status_code != 200: return {"configured":True,"error":f"API returned HTTP {r.status_code}"}
        return {"configured":True,"matches":r.json().get("matches",[])}
    except Exception as exc: return {"configured":True,"error":str(exc)}

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
    intel=safe_browsing_check(url,key)
    confirmed=bool(intel.get("matches"))
    if confirmed: findings.append({"Severity":"Critical","Finding":"Threat-intelligence match","Evidence":"Google Safe Browsing returned a threat match."})
    score=100 if confirmed else min(99,max(0,score))
    level="Potentially malicious" if confirmed else "High risk" if score>=55 else "Suspicious" if score>=25 else "Lower risk"
    return {"url":url,"host":host,"score":score,"level":level,"findings":findings,"dns":ips,"tls":tls,"rdap":rdap,"intel":intel,"scanned_at":datetime.now(timezone.utc).isoformat()}

with st.sidebar:
    st.header("⚙️ Scanner settings")
    api_key=st.text_input("Google Safe Browsing API key (optional)",type="password",help="Leave blank to use local checks.")
    st.caption("The key is used for the current scan and is not added to scan history.")
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
        elif r["intel"].get("configured"): st.write("No match returned." if not r["intel"].get("error") else r["intel"]["error"])
        else: st.write("Not configured. Add an API key in the sidebar to enable this check.")
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
