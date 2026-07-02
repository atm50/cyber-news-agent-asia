"""
Fetches cyber threat intelligence for the APAC Threat Board dashboard.
Tabs: Overview | By Country | Breach & Dark Web | Analytics | Threat Map

All sources are free — no API keys required.
Adds keyword-based tagging (attack type + source/target country) to power the Threat Map arcs.
"""
import json, os, datetime, time
import urllib.request, urllib.parse
import xml.etree.ElementTree as ET

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "docs", "news.json")

# ── Tab 1 ─────────────────────────────────────────────────────────────────────
GENERAL_QUERIES = [
    "cyber attack Asia Pacific",
    "cybersecurity breach APAC",
    "ransomware Asia",
    "data breach Singapore OR Japan OR India OR Australia OR Philippines",
]
MAX_GENERAL = 10

# ── Tab 2 ─────────────────────────────────────────────────────────────────────
COUNTRY_QUERIES = {
    "India":       "cyber attack India OR cybersecurity breach India",
    "Australia":   "cyber attack Australia OR cybersecurity breach Australia",
    "Singapore":   "cyber attack Singapore OR cybersecurity breach Singapore",
    "Malaysia":    "cyber attack Malaysia OR cybersecurity breach Malaysia",
    "Philippines": "cyber attack Philippines OR cybersecurity breach Philippines",
    "Indonesia":   "cyber attack Indonesia OR cybersecurity breach Indonesia",
}
MAX_COUNTRY = 8

# ── Tab 3 ─────────────────────────────────────────────────────────────────────
THREAT_INTEL_FEEDS = [
    {"name": "BleepingComputer",  "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News",   "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "The Record",        "url": "https://therecord.media/feed"},
    {"name": "Security Week",     "url": "https://www.securityweek.com/feed/"},
]
MAX_FEED_ITEMS = 8

DARKWEB_QUERIES = [
    "dark web data leak breach",
    "leaked credentials hacker forum",
    "ransomware darknet attack",
    "stolen data dark web cybercriminal",
    "data breach underground forum leaked",
]
MAX_DARKWEB = 8

# ── Threat Tagging ────────────────────────────────────────────────────────────

ATTACK_TYPES = {
    "ransomware": ["ransomware", "ransom demand", "ransom payment", "encrypted files", "decryptor"],
    "phishing":   ["phish", "spear-phish", "credential harvest", "social engineer", "business email"],
    "breach":     ["data breach", "data leak", "leaked database", "exposed data", "stolen data",
                   "information leak", "records exposed", "database dump"],
    "ddos":       ["ddos", "denial of service", "botnet", "traffic flood"],
    "malware":    ["malware", "trojan", "backdoor", "spyware", "worm", "keylogger", "rootkit", "rat "],
    "apt":        ["apt", "state-sponsored", "nation-state", "advanced persistent", "cyber espionage",
                   "government hackers", "military hackers"],
}

SOURCE_COUNTRIES = {
    "China":       ["china", "chinese", "prc ", "beijing", "apt41", "apt10", "apt40",
                    "volt typhoon", "salt typhoon", "hafnium"],
    "Russia":      ["russia", "russian", "kremlin", "sandworm", "cozy bear", "fancy bear",
                    "apt28", "apt29", "midnight blizzard", "nobelium"],
    "North Korea": ["north korea", "dprk", "lazarus", "kimsuky", "andariel", "bluenoroff"],
    "Iran":        ["iran", "iranian", "charming kitten", "apt33", "apt34", "phosphorus"],
    "United States": ["nsa", "cia ", "us intelligence", "american intelligence"],
}

TARGET_COUNTRIES_LOOKUP = [
    "India", "Australia", "Singapore", "Malaysia", "Philippines", "Indonesia",
    "Japan", "South Korea", "Taiwan", "Vietnam", "Thailand", "Bangladesh",
    "Pakistan", "Sri Lanka", "Myanmar", "Cambodia", "Nepal", "Hong Kong",
    "United States", "United Kingdom", "Germany", "France", "Ukraine",
    "Israel", "Saudi Arabia", "United Arab Emirates", "Turkey",
    "Brazil", "Canada", "Netherlands", "Poland", "Italy", "Spain",
    "South Africa", "Nigeria", "Kenya",
]


def detect_attack_type(text):
    t = text.lower()
    for atype, keywords in ATTACK_TYPES.items():
        if any(k in t for k in keywords):
            return atype
    return "other"


def detect_source_country(text):
    t = text.lower()
    for country, keywords in SOURCE_COUNTRIES.items():
        if any(k in t for k in keywords):
            return country
    return None


def detect_target_country(text, default=None):
    t = text.lower()
    for country in TARGET_COUNTRIES_LOOKUP:
        if country.lower() in t:
            return country
    return default


def tag_articles(articles, default_target=None):
    tagged = []
    for art in articles:
        text = art.get("title", "") + " " + art.get("source", "")
        tagged.append({
            **art,
            "attack_type":    detect_attack_type(text),
            "source_country": detect_source_country(text),
            "target_country": detect_target_country(text, default=default_target),
        })
    return tagged


def build_threat_events(general_items, countries_output, breach_intel):
    events = []

    def add_event(art, target_override=None):
        source  = art.get("source_country")
        target  = target_override or art.get("target_country")
        atype   = art.get("attack_type", "other")
        if source and target and source != target:
            events.append({
                "source_country": source,
                "target_country": target,
                "attack_type":    atype,
                "title":          art.get("title", ""),
                "link":           art.get("link", ""),
                "published":      art.get("published", ""),
            })

    for art in general_items:
        add_event(art)

    for country, articles in countries_output.items():
        for art in articles:
            add_event(art, target_override=country)

    for art in breach_intel.get("blog_news", []) + breach_intel.get("darkweb_news", []):
        add_event(art)

    # Deduplicate by title
    seen, unique = set(), []
    for e in events:
        key = e["title"].lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(e)

    return unique


# ── HTTP + Feed helpers ───────────────────────────────────────────────────────

def http_get(url, timeout=20):
    headers = {"User-Agent": "APAC-ThreatBoard/1.0"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_google_news_rss(query, max_items):
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
        {"q": query, "hl": "en", "gl": "US", "ceid": "US:en"})
    root = ET.fromstring(http_get(url))
    items = []
    for item in root.findall("./channel/item")[:max_items]:
        source_el = item.find("source")
        items.append({
            "title":     item.findtext("title", "").strip(),
            "link":      item.findtext("link",  "").strip(),
            "published": item.findtext("pubDate", "").strip(),
            "source":    source_el.text.strip() if source_el is not None and source_el.text else "",
        })
    return items


def fetch_rss_feed(name, url, max_items):
    root = ET.fromstring(http_get(url))
    items = []
    for item in root.findall("./channel/item")[:max_items]:
        items.append({
            "title":     item.findtext("title", "").strip(),
            "link":      item.findtext("link",  "").strip(),
            "published": item.findtext("pubDate", "").strip(),
            "source":    name,
        })
    return items


def fetch_hibp_breaches():
    all_b = json.loads(http_get("https://haveibeenpwned.com/api/v3/breaches"))
    def fmt(b):
        return {
            "name":        b.get("Name", ""),
            "title":       b.get("Title", ""),
            "domain":      b.get("Domain", ""),
            "breach_date": b.get("BreachDate", ""),
            "added_date":  b.get("AddedDate", ""),
            "pwn_count":   b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "description": b.get("Description", ""),
        }
    recent = sorted(all_b, key=lambda x: x.get("AddedDate", ""), reverse=True)[:30]
    return [fmt(b) for b in recent]


def dedupe(items):
    seen, result = set(), []
    for it in items:
        key = it.get("title", "").lower().strip()
        if key and key not in seen:
            seen.add(key); result.append(it)
    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    errors = []

    # Tab 1 — Overview
    general_items = []
    for q in GENERAL_QUERIES:
        try:
            general_items.extend(fetch_google_news_rss(q, MAX_GENERAL)); time.sleep(0.5)
        except Exception as e:
            errors.append(f"[overview] {q}: {e}")
    general_items = tag_articles(dedupe(general_items))

    # Tab 2 — By Country
    countries_output = {}
    for country, query in COUNTRY_QUERIES.items():
        try:
            items = dedupe(fetch_google_news_rss(query, MAX_COUNTRY))
            countries_output[country] = tag_articles(items, default_target=country)
            time.sleep(0.5)
        except Exception as e:
            countries_output[country] = []
            errors.append(f"[country] {country}: {e}")

    # Tab 3 — Breach Intel
    blog_items = []
    for feed in THREAT_INTEL_FEEDS:
        try:
            blog_items.extend(fetch_rss_feed(feed["name"], feed["url"], MAX_FEED_ITEMS))
            time.sleep(0.5)
        except Exception as e:
            errors.append(f"[blog] {feed['name']}: {e}")
    blog_items = tag_articles(dedupe(blog_items))

    darkweb_items = []
    for q in DARKWEB_QUERIES:
        try:
            darkweb_items.extend(fetch_google_news_rss(q, MAX_DARKWEB)); time.sleep(0.5)
        except Exception as e:
            errors.append(f"[darkweb] {q}: {e}")
    darkweb_items = tag_articles(dedupe(darkweb_items))

    hibp_recent = []
    try:
        hibp_recent = fetch_hibp_breaches()
    except Exception as e:
        errors.append(f"[hibp]: {e}")

    breach_intel = {
        "blog_news":    blog_items,
        "darkweb_news": darkweb_items,
        "hibp_recent":  hibp_recent,
    }

    # Tab 5 — Threat Map events
    threat_events = build_threat_events(general_items, countries_output, breach_intel)

    output = {
        "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "items":            general_items,
        "countries":        countries_output,
        "breach_intel":     breach_intel,
        "threat_events":    threat_events,
        "errors":           errors,
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Overview: {len(general_items)} | Countries: {sum(len(v) for v in countries_output.values())} | "
          f"Blogs: {len(blog_items)} | DW: {len(darkweb_items)} | "
          f"HIBP: {len(hibp_recent)} | Threat events: {len(threat_events)}")
    if errors:
        print("Errors:", errors)


if __name__ == "__main__":
    main()
