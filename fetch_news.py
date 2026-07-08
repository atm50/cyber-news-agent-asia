"""
Global Cyber Threat Board — fetch script
Fetches:
  1. Cyber news (Overview, By Country, Breach & Dark Web tabs)
  2. IOC Intelligence (structured feeds + research blog extraction)

All sources are free — no API keys required.
"""
import json, os, re, csv, io, datetime, time, html, urllib.request, urllib.parse
import xml.etree.ElementTree as ET

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "docs", "news.json")
IOC_FILE    = os.path.join(os.path.dirname(__file__), "docs", "ioc_intel.json")
RANSOM_FILE = os.path.join(os.path.dirname(__file__), "docs", "ransomware.json")

# ISO country code → full name (for ransomware.live country codes)
RANSOM_COUNTRY_NAMES = {
    "US":"United States","GB":"United Kingdom","UK":"United Kingdom","CA":"Canada",
    "AU":"Australia","IN":"India","SG":"Singapore","MY":"Malaysia","PH":"Philippines",
    "ID":"Indonesia","JP":"Japan","KR":"South Korea","PK":"Pakistan","BD":"Bangladesh",
    "KH":"Cambodia","BR":"Brazil","DE":"Germany","FR":"France","UA":"Ukraine",
    "IL":"Israel","SA":"Saudi Arabia","ZA":"South Africa","RU":"Russia","CN":"China",
    "IT":"Italy","ES":"Spain","NL":"Netherlands","SE":"Sweden","CH":"Switzerland",
    "TW":"Taiwan","TH":"Thailand","VN":"Vietnam","MX":"Mexico","AE":"United Arab Emirates",
    "TR":"Turkey","PL":"Poland","BE":"Belgium","AT":"Austria","NO":"Norway",
    "DK":"Denmark","FI":"Finland","NZ":"New Zealand","IE":"Ireland","PT":"Portugal",
}

# Our 23 monitored countries (for the "my regions" filter)
MONITORED_COUNTRIES = {
    "India","Australia","Singapore","Malaysia","Philippines","Indonesia","Japan",
    "South Korea","Pakistan","Bangladesh","Cambodia","United States","Brazil",
    "Canada","United Kingdom","Germany","France","Ukraine","Israel","Saudi Arabia",
    "South Africa","Russia","China",
}

# ═══════════════════════════════════════════════════════════════════════════════
# NEWS CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

GENERAL_QUERIES = [
    "cyber attack world", "global cybersecurity breach",
    "ransomware attack", "data breach hacker", "cyber espionage APT",
]

COUNTRY_QUERIES = {
    # Asia Pacific
    "India":         "cyber attack India OR data breach India",
    "Australia":     "cyber attack Australia OR data breach Australia",
    "Singapore":     "cyber attack Singapore OR data breach Singapore",
    "Malaysia":      "cyber attack Malaysia OR data breach Malaysia",
    "Philippines":   "cyber attack Philippines OR data breach Philippines",
    "Indonesia":     "cyber attack Indonesia OR data breach Indonesia",
    "Japan":         "cyber attack Japan OR data breach Japan",
    "South Korea":   "cyber attack South Korea OR data breach South Korea",
    "Pakistan":      "cyber attack Pakistan OR data breach Pakistan",
    "Bangladesh":    "cyber attack Bangladesh OR data breach Bangladesh",
    "Cambodia":      "cyber attack Cambodia OR data breach Cambodia",
    # Americas
    "United States": "cyber attack United States OR data breach USA",
    "Brazil":        "cyber attack Brazil OR data breach Brazil",
    "Canada":        "cyber attack Canada OR data breach Canada",
    # Europe
    "United Kingdom":"cyber attack United Kingdom OR data breach UK",
    "Germany":       "cyber attack Germany OR data breach Germany",
    "France":        "cyber attack France OR data breach France",
    "Ukraine":       "cyber attack Ukraine OR data breach Ukraine",
    # Middle East & Africa
    "Israel":        "cyber attack Israel OR data breach Israel",
    "Saudi Arabia":  "cyber attack Saudi Arabia OR data breach Saudi Arabia",
    "South Africa":  "cyber attack South Africa OR data breach South Africa",
    # Other
    "Russia":        "cyber attack Russia OR data breach Russia",
    "China":         "cyber attack China OR data breach China",
}

THREAT_INTEL_FEEDS = [
    {"name": "BleepingComputer",  "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News",   "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "The Record",        "url": "https://therecord.media/feed"},
    {"name": "Security Week",     "url": "https://www.securityweek.com/feed/"},
]

DARKWEB_QUERIES = [
    "dark web data leak breach", "leaked credentials hacker forum",
    "ransomware darknet attack", "stolen data dark web cybercriminal",
]

MAX_GENERAL = 10
MAX_COUNTRY = 8
MAX_FEED    = 8
MAX_DARKWEB = 8

# ═══════════════════════════════════════════════════════════════════════════════
# IOC CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

# Research blogs — we extract IOCs from article text
RESEARCH_BLOGS = [
    {"name": "Unit 42",       "rss": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "Cisco Talos",   "rss": "https://blog.talosintelligence.com/rss"},
    {"name": "Kaspersky Securelist", "rss": "https://securelist.com/feed"},
    {"name": "Microsoft MSTIC","rss": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"name": "SANS ISC",      "rss": "https://isc.sans.edu/rssfeed.xml"},
    {"name": "Trend Micro",   "rss": "https://feeds.feedburner.com/TrendMicroSimplySecurity"},
    {"name": "Google TAG",    "rss": "https://blog.google/threat-analysis-group/rss/"},
    {"name": "FortiGuard",    "rss": "https://www.fortiguard.com/rss/outbreak.xml"},
]
MAX_ARTICLES_PER_BLOG = 3   # fetch full text of 3 most recent articles per blog

# Structured IOC feeds
FEODO_URL   = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EMERGING_URL  = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
BINARYDEF_URL = "https://www.binarydefense.com/banlist.txt"
TWEETFEED_URL = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv"

# C2 Tracker feeds from GitHub (Cobalt Strike, Sliver, Metasploit etc.)
C2_TRACKER_FEEDS = [
    {"name": "Cobalt Strike C2",  "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike%20C2%20IPs.txt"},
    {"name": "Sliver C2",         "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver%20C2%20IPs.txt"},
    {"name": "Metasploit C2",     "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit%20Framework%20C2%20IPs.txt"},
    {"name": "Brute Ratel C4",    "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C4%20IPs.txt"},
]

# Unit 42 publishes raw IOC txt files on GitHub
UNIT42_GITHUB_API = "https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents/"

# Private/reserved IP ranges to exclude from extraction
PRIVATE_IP_PREFIXES = (
    "0.", "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "224.",
    "240.", "255.",
)

# ═══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def http_get(url, timeout=20, post_data=None, headers=None):
    h = {"User-Agent": "GlobalThreatBoard/1.0"}
    if headers:
        h.update(headers)
    data = json.dumps(post_data).encode() if post_data else None
    if data:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_rss(raw, source_name=None, max_items=10):
    root = ET.fromstring(raw)
    items = []
    for item in root.findall("./channel/item")[:max_items]:
        sel = item.find("source")
        # Try to get article URL from link
        link = item.findtext("link", "").strip()
        # Also try description for content
        desc = item.findtext("description", "") or ""
        items.append({
            "title":     item.findtext("title", "").strip(),
            "link":      link,
            "published": item.findtext("pubDate", "").strip(),
            "source":    source_name or (sel.text.strip() if sel is not None and sel.text else ""),
            "description": html.unescape(re.sub(r"<[^>]+>", " ", desc)),
        })
    return items


def dedupe(items):
    seen, result = set(), []
    for it in items:
        key = it.get("title", "").lower().strip()
        if key and key not in seen:
            seen.add(key); result.append(it)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# NEWS FETCHING (unchanged from previous version)
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_TYPES = {
    "ransomware": ["ransomware", "ransom demand", "ransom payment", "encrypted files"],
    "phishing":   ["phish", "spear-phish", "credential harvest", "social engineer", "business email compromise"],
    "breach":     ["data breach", "data leak", "leaked database", "exposed data", "stolen data", "records exposed"],
    "ddos":       ["ddos", "denial of service", "botnet", "traffic flood"],
    "malware":    ["malware", "trojan", "backdoor", "spyware", "worm", "keylogger", "rootkit"],
    "apt":        ["apt", "state-sponsored", "nation-state", "advanced persistent", "cyber espionage"],
}
SOURCE_COUNTRIES = {
    "China":         ["china", "chinese", "prc ", "apt41", "apt10", "apt40", "volt typhoon", "salt typhoon"],
    "Russia":        ["russia", "russian", "kremlin", "sandworm", "cozy bear", "fancy bear", "apt28", "apt29", "midnight blizzard"],
    "North Korea":   ["north korea", "dprk", "lazarus", "kimsuky", "andariel"],
    "Iran":          ["iran", "iranian", "charming kitten", "apt33", "apt34"],
    "United States": ["nsa", "cia ", "us intelligence", "five eyes"],
}
TARGET_COUNTRIES_LOOKUP = sorted(list(COUNTRY_QUERIES.keys()) + [
    "Taiwan", "Vietnam", "Thailand", "Netherlands", "Poland", "Italy",
    "Spain", "Sweden", "Turkey", "UAE", "Nigeria", "Kenya", "Mexico",
    "New Zealand", "Hong Kong",
], key=len, reverse=True)

def detect_attack_type(text):
    t = text.lower()
    for atype, kws in ATTACK_TYPES.items():
        if any(k in t for k in kws): return atype
    return "other"

def detect_source_country(text):
    t = text.lower()
    for country, kws in SOURCE_COUNTRIES.items():
        if any(k in t for k in kws): return country
    return None

def detect_target_country(text, default=None):
    t = text.lower()
    for country in TARGET_COUNTRIES_LOOKUP:
        if country.lower() in t: return country
    return default

def tag_articles(articles, default_target=None):
    tagged = []
    for art in articles:
        text = art.get("title", "") + " " + art.get("source", "")
        tagged.append({**art,
            "attack_type":    detect_attack_type(text),
            "source_country": detect_source_country(text),
            "target_country": detect_target_country(text, default=default_target),
        })
    return tagged

def build_threat_events(general, countries, breach_intel):
    events = []
    def try_add(art, tgt_override=None):
        src = art.get("source_country")
        tgt = tgt_override or art.get("target_country")
        if src and tgt and src != tgt:
            events.append({"source_country": src, "target_country": tgt,
                "attack_type": art.get("attack_type", "other"),
                "title": art.get("title", ""), "link": art.get("link", ""),
                "published": art.get("published", "")})
    for art in general: try_add(art)
    for c, arts in countries.items():
        for art in arts: try_add(art, tgt_override=c)
    for art in breach_intel.get("blog_news",[]) + breach_intel.get("darkweb_news",[]):
        try_add(art)
    seen, unique = set(), []
    for e in events:
        k = e["title"].lower().strip()
        if k and k not in seen: seen.add(k); unique.append(e)
    return unique

def fetch_gnews(query, max_items):
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
        {"q": query, "hl": "en", "gl": "US", "ceid": "US:en"})
    return parse_rss(http_get(url), max_items=max_items)

def fetch_hibp():
    all_b = json.loads(http_get("https://haveibeenpwned.com/api/v3/breaches"))
    def fmt(b):
        return {"name": b.get("Name",""), "title": b.get("Title",""),
                "domain": b.get("Domain",""), "breach_date": b.get("BreachDate",""),
                "added_date": b.get("AddedDate",""), "pwn_count": b.get("PwnCount",0),
                "data_classes": b.get("DataClasses",[]), "description": b.get("Description","")}
    return [fmt(b) for b in sorted(all_b, key=lambda x: x.get("AddedDate",""), reverse=True)[:30]]


# ═══════════════════════════════════════════════════════════════════════════════
# IOC EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def is_private_ip(ip):
    return any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)

def refang(text):
    """Convert defanged IOCs back to normal form."""
    text = re.sub(r'\[\.\]', '.', text)
    text = re.sub(r'\(\.\)', '.', text)
    text = re.sub(r'hxxps?', lambda m: m.group().replace('xx','tt'), text)
    text = re.sub(r'\[:\]', ':', text)
    return text

def extract_iocs_from_text(text, source_name, article_title, article_url, article_date):
    """Extract IOCs from unstructured text using regex patterns."""
    if not text:
        return []
    text = refang(text)
    found = []
    seen_values = set()

    def add(value, ioc_type, context=""):
        v = value.strip().lower() if ioc_type in ("domain","url") else value.strip()
        if v and v not in seen_values and len(v) > 3:
            seen_values.add(v)
            found.append({
                "value":         v,
                "type":          ioc_type,
                "source_name":   source_name,
                "article_title": article_title,
                "article_url":   article_url,
                "article_date":  article_date,
                "context":       context[:120],
            })

    # SHA-256 (64 hex chars) — must appear near hash-related words
    for m in re.finditer(r'\b([a-fA-F0-9]{64})\b', text):
        ctx = text[max(0,m.start()-60):m.end()+60]
        if re.search(r'sha.?256|hash|ioc|indicator|malware|sample', ctx, re.I):
            add(m.group(1).lower(), "sha256", ctx)

    # SHA-1 (40 hex chars)
    for m in re.finditer(r'\b([a-fA-F0-9]{40})\b', text):
        ctx = text[max(0,m.start()-60):m.end()+60]
        if re.search(r'sha.?1|hash|ioc|indicator|malware|sample', ctx, re.I):
            add(m.group(1).lower(), "sha1", ctx)

    # MD5 (32 hex chars)
    for m in re.finditer(r'\b([a-fA-F0-9]{32})\b', text):
        ctx = text[max(0,m.start()-60):m.end()+60]
        if re.search(r'md5|hash|ioc|indicator|malware|sample', ctx, re.I):
            add(m.group(1).lower(), "md5", ctx)

    # CVE IDs
    for m in re.finditer(r'CVE-\d{4}-\d{4,7}', text, re.I):
        add(m.group(0).upper(), "cve", text[max(0,m.start()-40):m.end()+40])

    # IPv4 addresses (skip private/reserved)
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
        ip = m.group(1)
        if not is_private_ip(ip):
            # Validate each octet
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                ctx = text[max(0,m.start()-60):m.end()+60]
                if re.search(r'c2|command|control|server|host|ip|address|ioc|malicious|actor', ctx, re.I):
                    add(ip, "ip", ctx)

    # Defanged domains (most reliable — analysts defang intentionally)
    for m in re.finditer(r'\b([\w\-]+(?:\[\.\]|\(\.\))[\w\-\.]+\.[a-zA-Z]{2,})\b', text):
        domain = m.group(1).replace("[.]",".").replace("(.)",".")
        if "." in domain and len(domain) > 4:
            add(domain, "domain", text[max(0,m.start()-60):m.end()+60])

    # Defanged URLs
    for m in re.finditer(r'hxxps?://[\w\.\-/\?=&%_\[\]]+', text, re.I):
        url = refang(m.group(0))
        add(url, "url", text[max(0,m.start()-60):m.end()+60])

    return found


# ═══════════════════════════════════════════════════════════════════════════════
# STRUCTURED IOC FEEDS
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_feodo(errors):
    """Abuse.ch Feodo Tracker — C2 server IPs."""
    try:
        data = json.loads(http_get(FEODO_URL, timeout=15))
        result = []
        for entry in data[:150]:
            result.append({
                "value":      entry.get("ip_address",""),
                "type":       "ip",
                "threat":     entry.get("malware",""),
                "source":     "Feodo Tracker",
                "source_url": "https://feodotracker.abuse.ch",
                "tags":       ["c2", entry.get("malware","").lower()],
                "first_seen": entry.get("first_seen",""),
                "last_seen":  entry.get("last_seen",""),
                "country":    entry.get("country",""),
            })
        return result
    except Exception as e:
        errors.append(f"[feodo]: {e}"); return []

def fetch_threatfox(errors):
    """Abuse.ch ThreatFox — recent IOCs (last 3 days)."""
    try:
        raw = http_get(THREATFOX_URL, timeout=15,
                       post_data={"query": "get_iocs", "days": 3})
        data = json.loads(raw)
        if data.get("query_status") != "ok": return []
        result = []
        for entry in (data.get("data") or [])[:200]:
            result.append({
                "value":      entry.get("ioc",""),
                "type":       entry.get("ioc_type","").replace("_", " "),
                "threat":     entry.get("malware",""),
                "source":     "ThreatFox",
                "source_url": f"https://threatfox.abuse.ch/ioc/{entry.get('id','')}",
                "tags":       entry.get("tags") or [],
                "first_seen": entry.get("first_seen",""),
                "confidence": entry.get("confidence_level", 0),
                "reporter":   entry.get("reporter",""),
            })
        return result
    except Exception as e:
        errors.append(f"[threatfox]: {e}"); return []

def fetch_urlhaus(errors):
    """Abuse.ch URLhaus — recent malicious URLs."""
    try:
        raw = http_get(URLHAUS_URL, timeout=15)
        result = []
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#"): continue
            if len(row) < 6: continue
            result.append({
                "value":      row[2] if len(row) > 2 else "",
                "type":       "url",
                "threat":     row[4] if len(row) > 4 else "",
                "source":     "URLhaus",
                "source_url": f"https://urlhaus.abuse.ch/url/{row[0]}/",
                "tags":       [t.strip() for t in (row[5].split(",") if len(row) > 5 else [])],
                "first_seen": row[1] if len(row) > 1 else "",
                "status":     row[3] if len(row) > 3 else "",
            })
            if len(result) >= 150: break
        return result
    except Exception as e:
        errors.append(f"[urlhaus]: {e}"); return []

def fetch_emerging_threats(errors):
    """Emerging Threats — compromised IPs."""
    try:
        raw = http_get(EMERGING_URL, timeout=15)
        result = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            result.append({
                "value":      line,
                "type":       "ip",
                "threat":     "Compromised/Malicious",
                "source":     "Emerging Threats",
                "source_url": "https://rules.emergingthreats.net",
                "tags":       ["compromised"],
                "first_seen": "",
            })
            if len(result) >= 100: break
        return result
    except Exception as e:
        errors.append(f"[emerging]: {e}"); return []

def fetch_binary_defense(errors):
    """Binary Defense Artillery — banned IPs."""
    try:
        raw = http_get(BINARYDEF_URL, timeout=15)
        result = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            result.append({
                "value":      line,
                "type":       "ip",
                "threat":     "Artillery Banlist",
                "source":     "Binary Defense",
                "source_url": "https://www.binarydefense.com",
                "tags":       ["blocked"],
                "first_seen": "",
            })
            if len(result) >= 100: break
        return result
    except Exception as e:
        errors.append(f"[binarydef]: {e}"); return []

def fetch_c2_tracker(errors):
    """C2 Tracker — active C2 IPs by framework."""
    result = []
    for feed in C2_TRACKER_FEEDS:
        try:
            raw = http_get(feed["url"], timeout=15)
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                ip = line.split(",")[0].strip()
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
                    result.append({
                        "value":      ip,
                        "type":       "ip",
                        "threat":     feed["name"],
                        "source":     "C2 Tracker",
                        "source_url": "https://github.com/montysecurity/C2-Tracker",
                        "tags":       ["c2", feed["name"].lower().replace(" ", "-")],
                        "first_seen": "",
                    })
                if len(result) >= 200: break
        except Exception as e:
            errors.append(f"[c2tracker/{feed['name']}]: {e}")
        time.sleep(0.3)
    return result

def fetch_tweetfeed(errors):
    """TweetFeed.live — IOCs shared on X/Twitter today."""
    try:
        raw = http_get(TWEETFEED_URL, timeout=15)
        result = []
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            ioc_type = row.get("type","").lower().strip()
            value    = row.get("value","").strip()
            if not value or not ioc_type: continue
            # Map TweetFeed types to our types
            type_map = {"url":"url","domain":"domain","ip":"ip",
                        "sha256":"sha256","md5":"md5"}
            mapped = type_map.get(ioc_type, ioc_type)
            result.append({
                "value":      value,
                "type":       mapped,
                "threat":     row.get("tags",""),
                "source":     "TweetFeed.live",
                "source_url": row.get("tweet",""),
                "tags":       [t.strip() for t in row.get("tags","").split(",") if t.strip()],
                "first_seen": row.get("date",""),
                "reporter":   row.get("user",""),
            })
            if len(result) >= 150: break
        return result
    except Exception as e:
        errors.append(f"[tweetfeed]: {e}"); return []

def fetch_cisa_kev(errors):
    """CISA Known Exploited Vulnerabilities catalogue."""
    try:
        data = json.loads(http_get(CISA_KEV_URL, timeout=15))
        vulns = data.get("vulnerabilities", [])
        # Sort by dateAdded descending, return last 50
        vulns.sort(key=lambda x: x.get("dateAdded",""), reverse=True)
        result = []
        for v in vulns[:50]:
            result.append({
                "cve_id":            v.get("cveID",""),
                "vendor":            v.get("vendorProject",""),
                "product":           v.get("product",""),
                "name":              v.get("vulnerabilityName",""),
                "description":       v.get("shortDescription",""),
                "date_added":        v.get("dateAdded",""),
                "due_date":          v.get("dueDate",""),
                "required_action":   v.get("requiredAction",""),
                "known_ransomware":  v.get("knownRansomwareCampaignUse","Unknown"),
            })
        return result
    except Exception as e:
        errors.append(f"[cisa_kev]: {e}"); return []


# ═══════════════════════════════════════════════════════════════════════════════
# BLOG IOC EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def extract_from_blog(blog, errors):
    """Fetch blog RSS, download recent articles, extract IOCs from text."""
    results = []
    try:
        rss_raw = http_get(blog["rss"], timeout=15)
        articles = parse_rss(rss_raw, source_name=blog["name"],
                             max_items=MAX_ARTICLES_PER_BLOG)
    except Exception as e:
        errors.append(f"[blog_rss/{blog['name']}]: {e}"); return []

    for art in articles:
        # First try extracting from RSS description (fast, no extra HTTP)
        iocs = extract_iocs_from_text(
            art.get("description",""), blog["name"],
            art["title"], art["link"], art["published"])

        # If few IOCs found in summary, fetch the full article
        if len(iocs) < 3 and art.get("link"):
            try:
                full_html = http_get(art["link"], timeout=20)
                # Strip tags
                text = re.sub(r'<[^>]+>', ' ', full_html)
                text = html.unescape(text)
                iocs = extract_iocs_from_text(
                    text, blog["name"], art["title"],
                    art["link"], art["published"])
            except Exception as e:
                errors.append(f"[blog_article/{blog['name']}]: {e}")

        results.extend(iocs)
        time.sleep(1)  # polite delay between article fetches

    return results

def fetch_unit42_github(errors):
    """Unit 42 publishes raw IOC .txt files on GitHub — fetch and parse them."""
    results = []
    try:
        contents = json.loads(http_get(UNIT42_GITHUB_API, timeout=15,
                                       headers={"Accept": "application/vnd.github.v3+json"}))
        # Get the 5 most recently added .txt files
        txt_files = [f for f in contents if f.get("name","").endswith(".txt")]
        txt_files = sorted(txt_files, key=lambda x: x.get("name",""), reverse=True)[:5]
        for f in txt_files:
            try:
                raw = http_get(f["download_url"], timeout=15)
                iocs = extract_iocs_from_text(
                    raw, "Unit 42 (GitHub)",
                    f["name"], f["html_url"],
                    datetime.datetime.now(datetime.timezone.utc).isoformat())
                results.extend(iocs)
                time.sleep(0.5)
            except Exception as e:
                errors.append(f"[unit42_github/{f['name']}]: {e}")
    except Exception as e:
        errors.append(f"[unit42_github]: {e}")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# IOC DEDUPLICATION & STATS
# ═══════════════════════════════════════════════════════════════════════════════

def dedupe_iocs(iocs):
    seen, result = set(), []
    for ioc in iocs:
        key = f"{ioc['type']}:{ioc['value'].lower()}"
        if key not in seen:
            seen.add(key); result.append(ioc)
    return result

def ioc_stats(structured, extracted):
    all_iocs = structured + extracted
    by_type = {}
    by_source = {}
    for ioc in all_iocs:
        t = ioc.get("type","unknown")
        s = ioc.get("source") or ioc.get("source_name","unknown")
        by_type[t]   = by_type.get(t, 0) + 1
        by_source[s] = by_source.get(s, 0) + 1
    return {
        "total_structured": len(structured),
        "total_extracted":  len(extracted),
        "total":            len(all_iocs),
        "by_type":          dict(sorted(by_type.items(), key=lambda x: -x[1])),
        "by_source":        dict(sorted(by_source.items(), key=lambda x: -x[1])),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# RANSOMWARE TRACKER (ransomware.live v2 API — free, no auth)
# ═══════════════════════════════════════════════════════════════════════════════

RANSOM_API = "https://api.ransomware.live/v2"

def normalize_country(code_or_name):
    """Turn a country code or raw name into a consistent full country name."""
    if not code_or_name:
        return ""
    val = code_or_name.strip()
    if len(val) <= 3 and val.upper() in RANSOM_COUNTRY_NAMES:
        return RANSOM_COUNTRY_NAMES[val.upper()]
    return val

def fetch_ransomware_victims(errors):
    """Recent ransomware victims from ransomware.live."""
    try:
        raw = http_get(f"{RANSOM_API}/recentvictims", timeout=25)
        data = json.loads(raw)
        victims = []
        for v in data:
            country = normalize_country(v.get("country",""))
            victims.append({
                "victim":     v.get("victim") or v.get("post_title") or "",
                "group":      v.get("group_name") or v.get("group") or "",
                "country":    country,
                "sector":     v.get("activity") or v.get("sector") or "",
                "discovered": v.get("discovered") or v.get("published") or "",
                "attack_date":v.get("attackdate") or v.get("date") or "",
                "website":    v.get("website") or "",
                "description":(v.get("description") or "")[:300],
                "claim_url":  v.get("claim_url") or v.get("url") or "",
                "monitored":  country in MONITORED_COUNTRIES,
            })
        return victims
    except Exception as e:
        errors.append(f"[ransom_victims]: {e}")
        return []

def fetch_ransomware_groups(errors):
    """All tracked ransomware groups."""
    try:
        raw = http_get(f"{RANSOM_API}/groups", timeout=25)
        data = json.loads(raw)
        groups = []
        for g in data:
            groups.append({
                "name":        g.get("name",""),
                "description": (g.get("description") or "")[:400],
                "locations":   len(g.get("locations") or []),
                "meta":        g.get("meta",""),
            })
        return groups
    except Exception as e:
        errors.append(f"[ransom_groups]: {e}")
        return []

def build_ransomware_stats(victims):
    """Aggregate victim data into stats for charts."""
    by_country, by_group, by_sector = {}, {}, {}
    monitored_count = 0
    for v in victims:
        c = v.get("country") or "Unknown"
        g = v.get("group") or "Unknown"
        s = v.get("sector") or "Unknown"
        by_country[c] = by_country.get(c, 0) + 1
        by_group[g]   = by_group.get(g, 0) + 1
        if s and s != "Unknown":
            by_sector[s] = by_sector.get(s, 0) + 1
        if v.get("monitored"):
            monitored_count += 1
    srt = lambda d: dict(sorted(d.items(), key=lambda x: -x[1]))
    return {
        "total_victims":     len(victims),
        "monitored_victims": monitored_count,
        "unique_groups":     len(by_group),
        "unique_countries":  len(by_country),
        "by_country":        srt(by_country),
        "by_group":          srt(by_group),
        "by_sector":         srt(by_sector),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    errors = []
    print("── Fetching news ──")

    # Tab 1 — General
    general_items = []
    for q in GENERAL_QUERIES:
        try: general_items.extend(fetch_gnews(q, MAX_GENERAL)); time.sleep(0.5)
        except Exception as e: errors.append(f"[general] {q}: {e}")
    general_items = tag_articles(dedupe(general_items))

    # Tab 2 — By Country
    countries_output = {}
    for country, query in COUNTRY_QUERIES.items():
        try:
            items = dedupe(fetch_gnews(query, MAX_COUNTRY))
            countries_output[country] = tag_articles(items, default_target=country)
            time.sleep(0.5)
        except Exception as e:
            countries_output[country] = []
            errors.append(f"[country] {country}: {e}")

    # Tab 3 — Breach intel
    blog_items = []
    for feed in THREAT_INTEL_FEEDS:
        try:
            raw = http_get(feed["url"])
            blog_items.extend(parse_rss(raw, source_name=feed["name"], max_items=MAX_FEED))
            time.sleep(0.5)
        except Exception as e: errors.append(f"[blog] {feed['name']}: {e}")
    blog_items = tag_articles(dedupe(blog_items))

    darkweb_items = []
    for q in DARKWEB_QUERIES:
        try: darkweb_items.extend(fetch_gnews(q, MAX_DARKWEB)); time.sleep(0.5)
        except Exception as e: errors.append(f"[darkweb] {q}: {e}")
    darkweb_items = tag_articles(dedupe(darkweb_items))

    hibp_recent = []
    try: hibp_recent = fetch_hibp()
    except Exception as e: errors.append(f"[hibp]: {e}")

    breach_intel = {"blog_news": blog_items, "darkweb_news": darkweb_items, "hibp_recent": hibp_recent}
    threat_events = build_threat_events(general_items, countries_output, breach_intel)

    # Save news.json
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "items":            general_items,
            "countries":        countries_output,
            "breach_intel":     breach_intel,
            "threat_events":    threat_events,
            "errors":           errors,
        }, f, indent=2, ensure_ascii=False)
    print(f"  News saved: {len(general_items)} general | {sum(len(v) for v in countries_output.values())} country | {len(threat_events)} threat events")

    # ── IOC Intelligence ──────────────────────────────────────────
    print("── Fetching IOC Intelligence ──")
    ioc_errors = []

    print("  Structured feeds...")
    structured = []
    structured += fetch_feodo(ioc_errors)
    structured += fetch_threatfox(ioc_errors)
    structured += fetch_urlhaus(ioc_errors)
    structured += fetch_emerging_threats(ioc_errors)
    structured += fetch_binary_defense(ioc_errors)
    structured += fetch_c2_tracker(ioc_errors)
    structured += fetch_tweetfeed(ioc_errors)
    structured = dedupe_iocs(structured)

    print(f"  {len(structured)} structured IOCs fetched")

    print("  CISA KEV...")
    cisa_kev = fetch_cisa_kev(ioc_errors)
    print(f"  {len(cisa_kev)} CISA KEV entries")

    print("  Research blog extraction...")
    extracted = []
    for blog in RESEARCH_BLOGS:
        print(f"    {blog['name']}...")
        iocs = extract_from_blog(blog, ioc_errors)
        extracted += iocs
        print(f"      → {len(iocs)} IOCs extracted")
        time.sleep(1)

    print("  Unit 42 GitHub IOC files...")
    extracted += fetch_unit42_github(ioc_errors)
    extracted = dedupe_iocs(extracted)
    print(f"  {len(extracted)} extracted IOCs total")

    stats = ioc_stats(structured, extracted)

    os.makedirs(os.path.dirname(IOC_FILE), exist_ok=True)
    with open(IOC_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "structured_iocs":  structured,
            "extracted_iocs":   extracted,
            "cisa_kev":         cisa_kev,
            "stats":            stats,
            "errors":           ioc_errors,
        }, f, indent=2, ensure_ascii=False)

    print(f"  IOC Intel saved: {stats['total']} total IOCs | {len(cisa_kev)} KEV entries")
    if ioc_errors:
        print("  IOC errors:", ioc_errors[:5])

    # ── Ransomware Tracker ────────────────────────────────────────
    print("── Fetching Ransomware Tracker ──")
    ransom_errors = []
    victims = fetch_ransomware_victims(ransom_errors)
    print(f"  {len(victims)} recent victims")
    groups = fetch_ransomware_groups(ransom_errors)
    print(f"  {len(groups)} ransomware groups")
    ransom_stats = build_ransomware_stats(victims)

    with open(RANSOM_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "victims":          victims,
            "groups":           groups,
            "stats":            ransom_stats,
            "errors":           ransom_errors,
        }, f, indent=2, ensure_ascii=False)
    print(f"  Ransomware saved: {ransom_stats['total_victims']} victims | {ransom_stats['unique_groups']} groups | {ransom_stats['monitored_victims']} in monitored regions")
    if ransom_errors:
        print("  Ransomware errors:", ransom_errors[:5])

    if errors:
        print("News errors:", errors[:5])


if __name__ == "__main__":
    main()
