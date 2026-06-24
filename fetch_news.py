"""
Fetches recent news about cyber attacks in Asia Pacific using free Google News RSS feeds.
No API key required. Saves results to docs/news.json for the dashboard to display.
"""
import json
import os
import datetime
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET

# Search terms - feel free to edit these to widen/narrow results
SEARCH_QUERIES = [
    "cyber attack Asia Pacific",
    "cybersecurity breach APAC",
    "ransomware Asia",
    "data breach Singapore OR Japan OR India OR Australia OR Philippines",
]

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "docs", "news.json")
MAX_ITEMS_PER_QUERY = 10


def fetch_google_news_rss(query):
    """Fetch and parse a Google News RSS feed for a given search query."""
    base_url = "https://news.google.com/rss/search"
    params = {"q": query, "hl": "en", "gl": "US", "ceid": "US:en"}
    url = base_url + "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()

    root = ET.fromstring(data)
    items = []
    for item in root.findall("./channel/item")[:MAX_ITEMS_PER_QUERY]:
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
            "query": query,
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
    all_items = []
    errors = []
    for q in SEARCH_QUERIES:
        try:
            all_items.extend(fetch_google_news_rss(q))
        except Exception as e:
            errors.append(f"{q}: {e}")

    all_items = dedupe(all_items)

    output = {
        "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "count": len(all_items),
        "items": all_items,
        "errors": errors,
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Saved {len(all_items)} items to {OUTPUT_FILE}")
    if errors:
        print("Errors:", errors)


if __name__ == "__main__":
    main()
