"""
APAC Threat Board — worldwide edition
Fetches cyber threat news globally across 20 countries + general feeds.
Tags each article with attack_type, source_country, target_country to power the Threat Map arcs.
All sources are free — no API keys required.
"""
import json, os, datetime, time
import urllib.request, urllib.parse
import xml.etree.ElementTree as ET

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "docs", "news.json")

# ── Tab 1: General global cyber news ─────────────────────────────────────────
GENERAL_QUERIES = [
    "cyber attack world",
    "global cybersecurity breach",
    "ransomware attack",
    "data breach hacker",
    "cyber espionage APT",
]
MAX_GENERAL = 10

# ── Tab 2: Per-country (20 countries worldwide) ───────────────────────────────
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
    # Americas
    "United States": "cyber attack United States OR data breach USA",
    "Brazil":        "cyber attack Brazil OR data breach Brazil",
    "Canada":        "cyber attack Canada OR data breach Canada",
    # Europe
    "United Kingdom":"cyber attack United Kingdom OR data breach UK",
    "Germany":       "cyber attack Germany OR data breach Germany",
    "France":        "cyber attack France OR data breach France",
    "Ukraine":       "cyber attack Ukraine OR data breach Ukraine",
    # South Asia
    "Pakistan":      "cyber attack Pakistan OR data breach Pakistan",
    "Bangladesh":    "cyber attack Bangladesh OR data breach Bangladesh",
    "Cambodia":      "cyber attack Cambodia OR data breach Cambodia",
    # Middle East & Africa
    "Israel":        "cyber attack Israel OR data breach Israel",
    "Saudi Arabia":  "cyber attack Saudi Arabia OR data breach Saudi Arabia",
    "South Africa":  "cyber attack South Africa OR data breach South Africa",
    # Other
    "Russia":        "cyber attack Russia OR data breach Russia",
    "China":         "cyber attack China OR data breach China",
}
MAX_COUNTRY = 8

# ── Tab 3: Threat intel blogs ─────────────────────────────────────────────────
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
]
MAX_DARKWEB = 8

# ── Threat Tagging ────────────────────────────────────────────────────────────

ATTACK_TYPES = {
    "ransomware": ["ransomware", "ransom demand", "ransom payment", "encrypted files"],
    "phishing":   ["phish", "spear-phish", "credential harvest", "social engineer", "business email compromise"],
    "breach":     ["data breach", "data leak", "leaked database", "exposed data",
                   "stolen data", "records exposed", "database dump"],
    "ddos":       ["ddos", "denial of service", "botnet", "traffic flood"],
    "malware":    ["malware", "trojan", "backdoor", "spyware", "worm", "keylogger", "rootkit"],
    "apt":        ["apt", "state-sponsored", "nation-state", "advanced persistent",
                   "cyber espionage", "government hackers"],
}

SOURCE_COUNTRIES = {
    "China":         ["china", "chinese", "prc ", "beijing", "apt41", "apt10", "apt40",
                      "volt typhoon", "salt typhoon", "hafnium", "mustang panda"],
    "Russia":        ["russia", "russian", "kremlin", "sandworm", "cozy bear", "fancy bear",
                      "apt28", "apt29", "midnight blizzard", "nobelium", "killnet"],
    "North Korea":   ["north korea", "dprk", "lazarus", "kimsuky", "andariel", "bluenoroff"],
    "Iran":          ["iran", "iranian", "charming kitten", "apt33", "apt34", "phosphorus", "muddy water"],
    "United States": ["nsa", "cia ", "us intelligence", "five eyes"],
}

# All countries we want to detect as targets
TARGET_COUNTRIES_LOOKUP = sorted(list(COUNTRY_QUERIES.keys()) + [
    "Taiwan", "Vietnam", "Thailand", "Pakistan", "Bangladesh",
    "Netherlands", "Poland", "Italy", "Spain", "Sweden",
    "Turkey", "UAE", "Nigeria", "Kenya", "Mexico",
    "Argentina", "Colombia", "New Zealand", "Hong Kong",
], key=len, reverse=True)  # longest first to avoid partial matches


def detect_attack_type(text):
    t = text.lower()
    for atype, kws in ATTACK_TYPES.items():
        if any(k in t for k in kws):
            return atype
    return "other"


def detect_source_country(text):
    t = text.lower()
    for country, kws in SOURCE_COUNTRIES.items():
        if any(k in t for k in kws):
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

    def try_add(art, target_override=None):
        src = art.get("source_country")
        tgt = target_override or art.get("target_country")
        if src and tgt and src != tgt:
            events.append({
                "source_country": src,
                "target_country": tgt,
                "attack_type":    art.get("attack_type", "other"),
                "title":          art.get("title", ""),
                "link":           art.get("link", ""),
                "published":      art.get("published", ""),
            })

    for art in general_items:
        try_add(art)

    for country, articles in countries_output.items():
        for art in articles:
            try_add(art, target_override=country)

    for art in (breach_intel.get("blog_news", []) +
                breach_intel.get("darkweb_news", [])):
        try_add(art)

    # Deduplicate
    seen, unique = set(), []
    for e in events:
        key = e["title"].lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(e)

    return unique


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_get(url, timeout=20):
    req = urllib.request.Request(
        url, headers={"User-Agent": "APAC-ThreatBoard/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def parse_rss_items(raw, source_name=None, max_items=10):
    root = ET.fromstring(raw)
    items = []
    for item in root.findall("./channel/item")[:max_items]:
        sel = item.find("source")
        items.append({
            "title":     item.findtext("title", "").strip(),
            "link":      item.findtext("link",  "").strip(),
            "published": item.findtext("pubDate", "").strip(),
            "source":    source_name or (sel.text.strip() if sel is not None and sel.text else ""),
        })
    return items


def fetch_gnews(query, max_items):
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
        {"q": query, "hl": "en", "gl": "US", "ceid": "US:en"})
    return parse_rss_items(http_get(url), max_items=max_items)


def fetch_hibp():
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
    return [fmt(b) for b in sorted(all_b, key=lambda x: x.get("AddedDate",""), reverse=True)[:30]]


def dedupe(items):
    seen, result = set(), []
    for it in items:
        key = it.get("title","").lower().strip()
        if key and key not in seen:
            seen.add(key); result.append(it)
    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    errors = []

    # Tab 1 — General
    general_items = []
    for q in GENERAL_QUERIES:
        try:
            general_items.extend(fetch_gnews(q, MAX_GENERAL)); time.sleep(0.5)
        except Exception as e:
            errors.append(f"[general] {q}: {e}")
    general_items = tag_articles(dedupe(general_items))

    # Tab 2 — By Country (20 countries)
    countries_output = {}
    for country, query in COUNTRY_QUERIES.items():
        try:
            items = dedupe(fetch_gnews(query, MAX_COUNTRY))
            countries_output[country] = tag_articles(items, default_target=country)
            time.sleep(0.5)
        except Exception as e:
            countries_output[country] = []
            errors.append(f"[country] {country}: {e}")

    # Tab 3 — Blogs
    blog_items = []
    for feed in THREAT_INTEL_FEEDS:
        try:
            raw = http_get(feed["url"])
            blog_items.extend(parse_rss_items(raw, source_name=feed["name"], max_items=MAX_FEED_ITEMS))
            time.sleep(0.5)
        except Exception as e:
            errors.append(f"[blog] {feed['name']}: {e}")
    blog_items = tag_articles(dedupe(blog_items))

    darkweb_items = []
    for q in DARKWEB_QUERIES:
        try:
            darkweb_items.extend(fetch_gnews(q, MAX_DARKWEB)); time.sleep(0.5)
        except Exception as e:
            errors.append(f"[darkweb] {q}: {e}")
    darkweb_items = tag_articles(dedupe(darkweb_items))

    hibp_recent = []
    try:
        hibp_recent = fetch_hibp()
    except Exception as e:
        errors.append(f"[hibp]: {e}")

    breach_intel = {
        "blog_news":    blog_items,
        "darkweb_news": darkweb_items,
        "hibp_recent":  hibp_recent,
    }

    # Threat Map events
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

    print(f"General: {len(general_items)} | Countries: {sum(len(v) for v in countries_output.values())} | "
          f"Blogs: {len(blog_items)} | DW: {len(darkweb_items)} | "
          f"HIBP: {len(hibp_recent)} | Threat events: {len(threat_events)}")
    if errors:
        print("Errors:", errors)


if __name__ == "__main__":
    main()
