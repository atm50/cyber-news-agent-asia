"""
Fetches:
1. A general "Asia Pacific cyber attack" news feed (for the Overview tab)
2. Separate news feeds for 6 specific countries (for the By Country tab)

Uses free Google News RSS feeds - no API key required.
Saves everything to docs/news.json for the dashboard to display.
"""
import json
import os
import datetime
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET

# --- Overview tab queries ---
GENERAL_QUERIES = [
    "cyber attack Asia Pacific",
    "cybersecurity breach APAC",
    "ransomware Asia",
    "data breach Singapore OR Japan OR India OR Australia OR Philippines",
]
MAX_ITEMS_PER_GENERAL_QUERY = 10

# --- By Country tab queries ---
COUNTRY_QUERIES = {
    "India": "cyber attack India OR cybersecurity breach India",
    "Australia": "cyber attack Australia OR cybersecurity breach Australia",
    "Singapore": "cyber attack Singapore OR cybersecurity breach Singapore",
    "Malaysia": "cyber attack Malaysia OR cybersecurity breach Malaysia",
    "Philippines": "cyber attack Philippines OR cybersecurity breach Philippines",
    "Indonesia": "cyber attack Indonesia OR cybersecurity breach Indonesia",
}
MAX_ITEMS_PER_COUNTRY = 8

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "docs", "news.json")


def fetch_google_news_rss(query, max_items):
    """Fetch and parse a Google News RSS feed for a given search query."""
    base_url = "https://news.google.com/rss/search"
    params = {"q": query, "hl": "en", "gl": "US", "ceid": "US:en"}
    url = base_url + "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()

    root = ET.fromstring(data)
    items = []
    for item in root.findall("./channel/item")[:max_items]:
        title = item.findtext("title", default="").strip()
        link = item.findtext("link", default="").strip()
        pub_date = item.findtext("pubDate", default="").strip()
        source_el = item.find("source")
        source = source_el.text.strip() if source_el is not None and source_el.text else ""
        items.append({
            "title": title,
            "link": link,
            "published": pub_date,
            "source": source,
        })
    return items


def dedupe(items):
    seen = set()
    result = []
    for it in items:
        key = it["title"].lower().strip()
        if key and key not in seen:
            seen.add(key)
            result.append(it)
    return result


def main():
    errors = []

    # --- Overview feed ---
    general_items = []
    for q in GENERAL_QUERIES:
        try:
            general_items.extend(fetch_google_news_rss(q, MAX_ITEMS_PER_GENERAL_QUERY))
        except Exception as e:
            errors.append(f"[overview] {q}: {e}")
    general_items = dedupe(general_items)

    # --- By Country feeds ---
    countries_output = {}
    for country, query in COUNTRY_QUERIES.items():
        try:
            items = fetch_google_news_rss(query, MAX_ITEMS_PER_COUNTRY)
            countries_output[country] = dedupe(items)
        except Exception as e:
            countries_output[country] = []
            errors.append(f"[country] {country}: {e}")

    output = {
        "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "items": general_items,
        "countries": countries_output,
        "errors": errors,
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    total_country_items = sum(len(v) for v in countries_output.values())
    print(f"Saved {len(general_items)} overview items + {total_country_items} country items to {OUTPUT_FILE}")
    if errors:
        print("Errors:", errors)


if __name__ == "__main__":
    main()
