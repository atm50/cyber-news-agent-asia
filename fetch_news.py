"""
Fetches data for three dashboard tabs:
  1. Overview     — General APAC cyber attack news (Google News RSS)
  2. By Country   — Per-country news for 6 APAC nations (Google News RSS)
  3. Breach Intel — Breach catalogue (HIBP) + threat intel blogs + dark web news

All sources are free and require no API keys.
Saves everything to docs/news.json.
"""
import json, os, datetime, time
import urllib.request, urllib.parse
import xml.etree.ElementTree as ET

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "docs", "news.json")

GENERAL_QUERIES = [
    "cyber attack Asia Pacific",
    "cybersecurity breach APAC",
    "ransomware Asia",
    "data breach Singapore OR Japan OR India OR Australia OR Philippines",
]
MAX_GENERAL = 10

COUNTRY_QUERIES = {
    "India":       "cyber attack India OR cybersecurity breach India",
    "Australia":   "cyber attack Australia OR cybersecurity breach Australia",
    "Singapore":   "cyber attack Singapore OR cybersecurity breach Singapore",
    "Malaysia":    "cyber attack Malaysia OR cybersecurity breach Malaysia",
    "Philippines": "cyber attack Philippines OR cybersecurity breach Philippines",
    "Indonesia":   "cyber attack Indonesia OR cybersecurity breach Indonesia",
}
MAX_COUNTRY = 8

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


def http_get(url, timeout=20):
    headers = {"User-Agent": "APAC-ThreatBoard/1.0"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_google_news_rss(query, max_items):
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
        {"q": query, "hl": "en", "gl": "US", "ceid": "US:en"})
    data = http_get(url)
    root = ET.fromstring(data)
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


def fetch_rss_feed(feed_name, feed_url, max_items):
    data = http_get(feed_url)
    root = ET.fromstring(data)
    items = []
    for item in root.findall("./channel/item")[:max_items]:
        items.append({
            "title":     item.findtext("title", "").strip(),
            "link":      item.findtext("link",  "").strip(),
            "published": item.findtext("pubDate", "").strip(),
            "source":    feed_name,
        })
    return items


def fetch_hibp_breaches():
    data  = http_get("https://haveibeenpwned.com/api/v3/breaches")
    all_b = json.loads(data)

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
            seen.add(key)
            result.append(it)
    return result


def main():
    errors = []

    general_items = []
    for q in GENERAL_QUERIES:
        try:
            general_items.extend(fetch_google_news_rss(q, MAX_GENERAL))
            time.sleep(0.5)
        except Exception as e:
            errors.append(f"[overview] {q}: {e}")
    general_items = dedupe(general_items)

    countries_output = {}
    for country, query in COUNTRY_QUERIES.items():
        try:
            countries_output[country] = dedupe(fetch_google_news_rss(query, MAX_COUNTRY))
            time.sleep(0.5)
        except Exception as e:
            countries_output[country] = []
            errors.append(f"[country] {country}: {e}")

    blog_items = []
    for feed in THREAT_INTEL_FEEDS:
        try:
            blog_items.extend(fetch_rss_feed(feed["name"], feed["url"], MAX_FEED_ITEMS))
            time.sleep(0.5)
        except Exception as e:
            errors.append(f"[blog] {feed['name']}: {e}")
    blog_items = dedupe(blog_items)

    darkweb_items = []
    for q in DARKWEB_QUERIES:
        try:
            darkweb_items.extend(fetch_google_news_rss(q, MAX_DARKWEB))
            time.sleep(0.5)
        except Exception as e:
            errors.append(f"[darkweb] {q}: {e}")
    darkweb_items = dedupe(darkweb_items)

    hibp_recent = []
    try:
        hibp_recent = fetch_hibp_breaches()
    except Exception as e:
        errors.append(f"[hibp]: {e}")

    output = {
        "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "items": general_items,
        "countries": countries_output,
        "breach_intel": {
            "blog_news":    blog_items,
            "darkweb_news": darkweb_items,
            "hibp_recent":  hibp_recent,
        },
        "errors": errors,
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Overview: {len(general_items)} | Country: {sum(len(v) for v in countries_output.values())} | Blogs: {len(blog_items)} | Dark web: {len(darkweb_items)} | HIBP: {len(hibp_recent)}")
    if errors:
        print("Errors:", errors)


if __name__ == "__main__":
    main()
