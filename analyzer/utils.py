# analyzer/utils.py
"""
Advanced SEO analyzer + stable crawler for Django
Features:
 - Single-page + deep crawl (bounded)
 - Meta, meta-robots, page quality, headings, links
 - Images (alt, sample size), structured data (JSON-LD/microdata)
 - Lightweight performance heuristics (resource counts, sample HEAD sizes)
 - Basic security checks (HSTS, CSP, mixed content)
 - Robots.txt parsing and sitemap detection/parsing
 - Enhanced scoring with todos
 - Keyword check logic
"""

import requests
import time
import re
import json
import os
from collections import deque
from urllib.parse import urlparse, urljoin, urlunparse, parse_qsl, urlencode
from bs4 import BeautifulSoup

IS_LIVE = bool(os.environ.get("RENDER"))


# -----------------------------
# CONFIG
# -----------------------------
# -----------------------------
# CONFIG
# -----------------------------

IS_LIVE = bool(os.environ.get("RENDER"))

# Entire website crawl limits
DEEP_MAX_PAGES = 5 if IS_LIVE else 120
DEEP_MAX_LINKS_PER_PAGE = 5 if IS_LIVE else 12
DEEP_MAX_DEPTH = 2 if IS_LIVE else 4

# Single page (always safe)
DEFAULT_MAX_PAGES = 1
DEFAULT_MAX_LINKS_PER_PAGE = 8
DEFAULT_MAX_DEPTH = 1

REQUEST_TIMEOUT = 6 if IS_LIVE else 8
DELAY_BETWEEN_REQUESTS = 0.2

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "_hsenc", "_hsmi"
}


# -----------------------------
# URL normalization + small cache
# -----------------------------
_normalize_cache = {}

def _clean_query(query):
    if not query:
        return ""
    params = parse_qsl(query, keep_blank_values=True)
    filtered = [(k, v) for (k, v) in params if k not in TRACKING_PARAMS]
    return urlencode(filtered, doseq=True)

def normalize_url(url):
    if not url:
        return url
    if url in _normalize_cache:
        return _normalize_cache[url]
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "http"
        netloc = parsed.netloc.lower()
        query = _clean_query(parsed.query)
        path = parsed.path.rstrip("/") or "/"
        normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path, query=query, fragment="")
        final = urlunparse(normalized)
        _normalize_cache[url] = final
        return final
    except Exception:
        return url

# -----------------------------
# CRAWLER (single + deep)
# -----------------------------
def crawl_site(start_url, full=False):
    """
    Crawl starting from start_url.
    If full=True, will follow internal links (bounded by DEEP_* settings).
    Returns list of page analysis dicts.
    """
    start_url = normalize_url(start_url)
    parsed_base = urlparse(start_url)
    base_domain = parsed_base.netloc

    visited = set()
    queue = deque([(start_url, 0)])
    results = []

    session = requests.Session()
    session.headers.update({"User-Agent": "django-seo-tool/advanced/1.0"})

    # choose limits
    if full:
        MAX_PAGES = DEEP_MAX_PAGES
        MAX_LINKS_PER_PAGE = DEEP_MAX_LINKS_PER_PAGE
        MAX_DEPTH = DEEP_MAX_DEPTH
    else:
        MAX_PAGES = DEFAULT_MAX_PAGES
        MAX_LINKS_PER_PAGE = DEFAULT_MAX_LINKS_PER_PAGE
        MAX_DEPTH = DEFAULT_MAX_DEPTH

    while queue:
        if MAX_PAGES is not None and len(results) >= MAX_PAGES:
            break

        url, depth = queue.popleft()
        url = normalize_url(url)

        if url in visited:
            continue
        visited.add(url)

        # Analyze page (safe)
        result = analyze_page(url, session=session)
        results.append(result)

        # Single page mode -> stop after first
        if not full:
            break

        # If page had error or depth limit reached -> skip link discovery
        if result.get("error") or depth >= MAX_DEPTH:
            time.sleep(DELAY_BETWEEN_REQUESTS)
            continue

        # Discover internal links (bounded)
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
        except Exception:
            time.sleep(DELAY_BETWEEN_REQUESTS)
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            time.sleep(DELAY_BETWEEN_REQUESTS)
            continue

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            time.sleep(DELAY_BETWEEN_REQUESTS)
            continue

        added = 0
        for a in soup.find_all("a", href=True):
            if added >= MAX_LINKS_PER_PAGE:
                break
            href = a.get("href")
            full_link = urljoin(url, href)
            full_link = normalize_url(full_link)
            parsed_link = urlparse(full_link)
            if parsed_link.scheme not in ("http", "https"):
                continue
            if parsed_link.netloc != base_domain:
                continue
            if full_link in visited:
                continue
            queue.append((full_link, depth + 1))
            added += 1

        time.sleep(DELAY_BETWEEN_REQUESTS)

    return results

# -----------------------------
# MASTER PAGE ANALYZER
# -----------------------------
def analyze_page(url, session=None):
    """
    Return analysis dict for a single page.
    Keys: url, meta, meta_robots, page_quality, links, mobile, headings,
          crawlability, external, images, schema, performance, security, sitemap, score, todos
    """
    session = session or requests.Session()
    session.headers.update({"User-Agent": "django-seo-tool/advanced/1.0"})
    try:
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.Timeout:
            return {"url": url, "error": "Timeout"}
        except requests.exceptions.RequestException as e:
            return {"url": url, "error": str(e)}

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return {"url": url, "error": "Not HTML content", "status_code": resp.status_code}

        soup = BeautifulSoup(resp.text, "html.parser")
        parsed = urlparse(url)

        # Core analyzers
        meta = analyze_meta_data(url, soup)
        meta_robots = analyze_meta_robots(soup)
        page_quality = analyze_page_quality(soup)
        links = analyze_links(url, soup, parsed, session=session)
        mobile = analyze_mobile_technical(soup, resp)
        headings = analyze_headings(soup)
        crawlability = analyze_crawlability(url, session=session)
        external = analyze_external_factors(soup)

        # Advanced
        images = analyze_images(soup, session, url)
        schema = analyze_structured_data(soup)
        performance = analyze_performance(soup, session, url)
        security = analyze_security(soup, resp, url)
        sitemap = analyze_sitemap(url, session=session)

        score, todos = calculate_score_enhanced(meta, page_quality, links, images, security)

        return {
            "url": url,
            "meta": meta,
            "meta_robots": meta_robots,
            "page_quality": page_quality,
            "links": links,
            "mobile": mobile,
            "headings": headings,
            "crawlability": crawlability,
            "external": external,
            "images": images,
            "schema": schema,
            "performance": performance,
            "security": security,
            "sitemap": sitemap,
            "score": score,
            "todos": todos
        }

    except Exception as e:
        return {"url": url, "error": str(e)}

# -----------------------------
# SCORING (enhanced)
# -----------------------------
def calculate_score_enhanced(meta, page_quality, links, images, security):
    score = 100
    todos = []

    # Title & meta
    tlen = meta.get("Title_Length", 0)
    if tlen == 0:
        score -= 10; todos.append("Add a title tag.")
    elif tlen > 60:
        score -= 3; todos.append("Shorten title (<60 chars).")

    dlen = meta.get("Description_Length", 0)
    if dlen == 0:
        score -= 8; todos.append("Add meta description.")
    elif dlen > 160:
        score -= 2; todos.append("Shorten meta description (<160 chars).")

    # Content
    wc = page_quality.get("Word_Count", 0)
    if wc < 400:
        score -= 6; todos.append("Add more content (word count low).")

    # Images
    missing = images.get("missing_alt", 0)
    if missing > 0:
        deduct = min(8, missing)
        score -= deduct
        todos.append(f"{missing} images missing alt text.")

    # Links / broken
    broken = links.get("Broken", 0)
    if broken > 0:
        deduct = min(10, broken * 2)
        score -= deduct
        todos.append(f"{broken} broken links found.")

    # Security heuristics
    if not security.get("has_hsts", False):
        score -= 2; todos.append("Add HSTS header.")
    if security.get("mixed_content", False):
        score -= 5; todos.append("Remove mixed (HTTP) resources on HTTPS page.")

    # clamp
    score = max(0, min(100, score))
    return score, todos

# -----------------------------
# META / META ROBOTS
# -----------------------------
def analyze_meta_data(url, soup):
    result = {}
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    result["Title"] = title or "Missing"
    result["Title_Length"] = len(title)

    desc_tag = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "description"})
    desc = desc_tag["content"].strip() if desc_tag and desc_tag.get("content") else ""
    result["Meta_Description"] = desc or "Missing"
    result["Description_Length"] = len(desc)

    canonical = soup.find("link", rel="canonical")
    result["Canonical"] = canonical["href"] if canonical and canonical.get("href") else "Missing"

    html_tag = soup.find("html")
    result["Language"] = html_tag.get("lang") if html_tag and html_tag.get("lang") else "Missing"

    charset = soup.find("meta", charset=True)
    result["Charset"] = charset["charset"] if charset else "Missing"

    icon = soup.find("link", rel=lambda x: x and "icon" in x)
    result["Favicon"] = icon["href"] if icon and icon.get("href") else "Missing"

    try:
        doctype = soup.contents[0]
        result["Doctype"] = str(doctype) if str(doctype).lower().startswith("<!doctype") else "Missing"
    except Exception:
        result["Doctype"] = "Missing"

    result["URL_Status"] = "Clean" if len(url) < 100 else "Long URL"
    return result

def analyze_meta_robots(soup):
    result = {}
    try:
        robots_tag = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "robots"})
        content = robots_tag["content"].strip() if robots_tag and robots_tag.get("content") else ""
        result["raw"] = content or "Missing"

        flags = {
            "index": None, "follow": None,
            "noarchive": False, "nosnippet": False, "noimageindex": False,
            "max-snippet": None, "max-image-preview": None, "other": []
        }
        if content:
            parts = [p.strip().lower() for p in content.split(",") if p.strip()]
            for p in parts:
                if p == "noindex": flags["index"] = False
                elif p == "index": flags["index"] = True
                elif p == "nofollow": flags["follow"] = False
                elif p == "follow": flags["follow"] = True
                elif p == "noarchive": flags["noarchive"] = True
                elif p == "nosnippet": flags["nosnippet"] = True
                elif p == "noimageindex": flags["noimageindex"] = True
                elif p.startswith("max-snippet:"):
                    try:
                        flags["max-snippet"] = int(p.split(":")[1])
                    except:
                        flags["other"].append(p)
                elif p.startswith("max-image-preview:"):
                    flags["max-image-preview"] = p.split(":", 1)[1]
                else:
                    flags["other"].append(p)
        if flags["index"] is None:
            flags["index"] = "unspecified"
        if flags["follow"] is None:
            flags["follow"] = "unspecified"
        result.update(flags)
    except Exception as e:
        result = {"raw": "Error", "error": str(e)}
    return result

# -----------------------------
# PAGE QUALITY
# -----------------------------
def analyze_page_quality(soup):
    text = soup.get_text(" ")
    words = re.findall(r"\w+", text)
    result = {
        "Word_Count": len(words),
        "Content_Status": "Good" if len(words) >= 600 else "Low Content",
        "Paragraphs": len(soup.find_all("p")),
        "Lists": len(soup.find_all(["ul", "ol"])),
        "Bold_Text_Count": len(soup.find_all(["b", "strong"])),
        "Placeholder_Text": "Found" if "lorem ipsum" in text.lower() else "Clean",
    }
    sentences = re.split(r'[.!?]+', text)
    sw = [len(re.findall(r"\w+", s)) for s in sentences if s.strip()]
    result["Avg_Sentence_Length"] = round(sum(sw) / len(sw), 1) if sw else 0
    return result

# -----------------------------
# LINKS (RENDER-SAFE)
# -----------------------------
def analyze_links(url, soup, parsed, session=None):
    """
    Render-safe link analyzer:
    - Counts internal/external links
    - Broken link checking is DISABLED on Render to prevent worker timeout
    """
    session = session or requests
    base = parsed.netloc
    result = {"Internal": 0, "External": 0, "Broken": 0}

    links = soup.find_all("a", href=True)[:120]

    for a in links:
        href = a.get("href")
        if not href:
            continue

        full_link = normalize_url(urljoin(url, href))
        parsed_link = urlparse(full_link)

        if parsed_link.scheme not in ("http", "https"):
            continue

        if parsed_link.netloc == base:
            result["Internal"] += 1
        else:
            result["External"] += 1

        # ❗ Broken link checks DISABLED on Render (critical)
        if os.environ.get("RENDER"):
            continue

        # Local / dev only
        try:
            r = session.head(full_link, timeout=3, allow_redirects=True)
            if r.status_code >= 400:
                result["Broken"] += 1
        except Exception:
            result["Broken"] += 1

    return result

# -----------------------------
# IMAGES (image SEO)
# -----------------------------
def analyze_images(soup, session, base_url):
    session = session or requests
    imgs = soup.find_all("img")
    total = len(imgs)
    with_alt = 0
    missing_alt = 0
    large_images_sample = 0
    total_bytes_sample = 0
    checked = 0
    for img in imgs:
        alt = img.get("alt", "").strip()
        if alt:
            with_alt += 1
        else:
            missing_alt += 1
    # HEAD sample to estimate sizes for first few resources
    for img in imgs[:10]:
        src = img.get("src")
        if not src:
            continue
        full = urljoin(base_url, src)
        try:
            r = session.head(full, timeout=4, allow_redirects=True)
            size = int(r.headers.get("Content-Length") or 0)
            if size and size > 200_000:
                large_images_sample += 1
            total_bytes_sample += size
            checked += 1
        except Exception:
            continue
    avg_bytes = round(total_bytes_sample / checked) if checked else 0
    return {
        "total_images": total,
        "with_alt": with_alt,
        "missing_alt": missing_alt,
        "large_images_sample": large_images_sample,
        "avg_image_bytes_sample": avg_bytes
    }

# -----------------------------
# STRUCTURED DATA (JSON-LD / microdata)
# -----------------------------
def analyze_structured_data(soup):
    found = {"json_ld": False, "json_ld_types": [], "microdata": False, "microdata_types": []}
    # JSON-LD
    for s in soup.find_all("script", type="application/ld+json"):
        text = s.string or s.get_text()
        if not text:
            continue
        try:
            payload = json.loads(text)
            found["json_ld"] = True
            types = []
            if isinstance(payload, dict):
                t = payload.get("@type") or payload.get("type")
                if t:
                    types.append(t)
            elif isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict) and item.get("@type"):
                        types.append(item.get("@type"))
            found["json_ld_types"].extend(types)
        except Exception:
            continue
    # microdata (itemscope)
    items = soup.find_all(attrs={"itemscope": True})
    if items:
        found["microdata"] = True
        for it in items[:10]:
            itype = it.get("itemtype") or ""
            found["microdata_types"].append(itype)
    # dedup
    found["json_ld_types"] = list(dict.fromkeys(found["json_ld_types"]))
    found["microdata_types"] = list(dict.fromkeys(found["microdata_types"]))
    return found

# -----------------------------
# PERFORMANCE (lightweight heuristics)
# -----------------------------
def analyze_performance(soup, session, base_url):
    session = session or requests
    res = {"page_bytes_sample": 0, "resources": 0, "scripts": 0, "css": 0, "images": 0, "sample_requests": 0}
    scripts = soup.find_all("script", src=True)
    links_css = soup.find_all("link", rel=lambda v: v and "stylesheet" in v)
    imgs = soup.find_all("img", src=True)

    res["scripts"] = len(scripts)
    res["css"] = len(links_css)
    res["images"] = len(imgs)
    res["resources"] = res["scripts"] + res["css"] + res["images"]

    checked = 0
    max_check = 6
    for tag in (scripts + links_css + imgs):
        if checked >= max_check:
            break
        src = tag.get("src") or tag.get("href")
        if not src:
            continue
        full = urljoin(base_url, src)
        try:
            r = session.head(full, timeout=4, allow_redirects=True)
            size = int(r.headers.get("Content-Length") or 0)
            res["page_bytes_sample"] += size
            res["sample_requests"] += 1
            checked += 1
        except Exception:
            continue

    return res

# -----------------------------
# SECURITY checks
# -----------------------------
def analyze_security(soup, resp, base_url):
    headers = {k.lower(): v for (k, v) in (resp.headers.items() if resp and resp.headers else [])}
    parsed = urlparse(base_url)
    uses_https = parsed.scheme == "https"
    has_hsts = "strict-transport-security" in headers
    has_csp = "content-security-policy" in headers
    x_frame = headers.get("x-frame-options") or headers.get("x-frame-options".lower())
    security_headers = {
        "HSTS": resp.headers.get("Strict-Transport-Security") if resp and resp.headers else None,
        "CSP": resp.headers.get("Content-Security-Policy") if resp and resp.headers else None,
        "X-Frame-Options": resp.headers.get("X-Frame-Options") if resp and resp.headers else None
    }
    # Mixed content detection: any http:// resource on https page
    mixed = False
    if uses_https:
        # check script/img/link src/href attributes
        tags = soup.find_all(["script", "img", "link"])
        for t in tags:
            src = t.get("src") or t.get("href") or ""
            if src.startswith("http://"):
                mixed = True
                break
    return {"uses_https": uses_https, "has_hsts": has_hsts, "has_csp": has_csp, "mixed_content": mixed, "security_headers": security_headers}

# -----------------------------
# HEADINGS
# -----------------------------
def analyze_headings(soup):
    h1s = [h.get_text(strip=True) for h in soup.find_all("h1")]
    headings = {f"H{i}": len(soup.find_all(f"h{i}")) for i in range(1, 7)}
    return {"H1_Count": len(h1s), "H1_Text": h1s, "Headings": headings}

# -----------------------------
# MOBILE / TECHNICAL
# -----------------------------
def analyze_mobile_technical(soup, resp):
    viewport = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "viewport"})
    apple = soup.find("link", rel=lambda v: v and "apple-touch-icon" in v)
    https_flag = "Secure" if resp and getattr(resp, "url", "").startswith("https") else "Not Secure"
    compression = resp.headers.get("Content-Encoding") if resp and resp.headers else None
    return {
        "Viewport": "Present" if viewport else "Missing",
        "Apple_Touch_Icon": "Present" if apple else "Missing",
        "HTTPS": https_flag,
        "Compression": compression or "Not Compressed"
    }

# -----------------------------
# CRAWLABILITY / ROBOTS
# -----------------------------
def analyze_crawlability(url, session=None):
    session = session or requests
    result = {}
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = f"{base}/robots.txt"
        r = session.get(robots_url, timeout=6)
        allow_rules = []
        disallow_rules = []
        crawl_delay = None
        sitemaps = []
        if r.status_code == 200:
            result["Robots.txt"] = "Found"
            lines = r.text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                lower = line.lower()
                if lower.startswith("allow:"):
                    allow_rules.append(line.split(":", 1)[1].strip())
                elif lower.startswith("disallow:"):
                    disallow_rules.append(line.split(":", 1)[1].strip())
                elif lower.startswith("crawl-delay:"):
                    crawl_delay = line.split(":", 1)[1].strip()
                elif lower.startswith("sitemap:"):
                    sitemaps.append(line.split(":", 1)[1].strip())
            path = parsed.path or "/"
            blocked = False
            for rule in disallow_rules:
                if rule and path.startswith(rule):
                    blocked = True
                    break
            result["Blocked_Page"] = "Yes" if blocked else "No"
            result["Allow_Rules"] = allow_rules or "None"
            result["Disallow_Rules"] = disallow_rules or "None"
            result["Crawl_Delay"] = crawl_delay or "None"
            result["Sitemaps_Found"] = sitemaps or "None"
        else:
            result["Robots.txt"] = "Missing"
            result["Blocked_Page"] = "Unknown"
    except Exception:
        result["Robots.txt"] = "Error"
        result["Blocked_Page"] = "Unknown"
    return result

# -----------------------------
# SITEMAP detection & parse
# -----------------------------
def analyze_sitemap(url, session=None):
    session = session or requests
    result = {"found": False, "sitemap_url": None, "type": None, "sitemaps": [], "urls": [], "error": None}
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        possible_locations = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemap1.xml"]
        sitemap_url = None
        for loc in possible_locations:
            test = base + loc
            try:
                r = session.get(test, timeout=6)
            except Exception:
                continue
            ctype = r.headers.get("Content-Type") or ""
            if r.status_code == 200 and ("xml" in ctype or test.endswith(".xml")):
                sitemap_url = test
                break
        # fallback: robots.txt sitemap entry
        if not sitemap_url:
            try:
                r = session.get(base + "/robots.txt", timeout=6)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        if line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            break
            except Exception:
                pass
        if not sitemap_url:
            result["error"] = "Sitemap not found"
            return result
        result["found"] = True
        result["sitemap_url"] = sitemap_url
        xml = session.get(sitemap_url, timeout=8).text
        soup = BeautifulSoup(xml, "xml")
        index_tags = soup.find_all("sitemap")
        if index_tags:
            result["type"] = "index"
            for sm in index_tags:
                loc = sm.find("loc")
                lastmod = sm.find("lastmod")
                result["sitemaps"].append({"loc": loc.text if loc else "", "lastmod": lastmod.text if lastmod else ""})
            return result
        # single sitemap
        result["type"] = "single"
        url_tags = soup.find_all("url")
        for u in url_tags[:500]:
            loc = u.find("loc"); lastmod = u.find("lastmod")
            result["urls"].append({"loc": loc.text if loc else "", "lastmod": lastmod.text if lastmod else ""})
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

# -----------------------------
# EXTERNAL OG / Twitter
# -----------------------------
def analyze_external_factors(soup):
    og = soup.find("meta", property="og:title")
    tw = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "twitter:title"})
    return {
        "OpenGraph_Title": (og.get("content") if og and og.get("content") else "Missing"),
        "Twitter_Title": (tw.get("content") if tw and tw.get("content") else "Missing"),
        "Backlinks": "External API required"
    }

# -----------------------------
# KEYWORD CHECK
# -----------------------------
def keyword_check_logic(url, keyword):
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if "text/html" not in (resp.headers.get("Content-Type") or ""):
            return {"error": "URL does not contain HTML content."}
        soup = BeautifulSoup(resp.text, "html.parser")
        text = soup.get_text(" ").lower()
        total_words = len(text.split())
        key = keyword.lower().strip()
        occurrences = text.count(key)
        density = round((occurrences / total_words) * 100, 2) if total_words else 0
        found_in = []
        title = soup.title.string.lower() if soup.title and soup.title.string else ""
        if key in title: found_in.append("Title")
        desc_tag = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "description"})
        meta_desc = desc_tag["content"].lower() if desc_tag and desc_tag.get("content") else ""
        if key in meta_desc: found_in.append("Meta Description")
        h1s = [h.get_text(strip=True).lower() for h in soup.find_all("h1")]
        if any(key in h for h in h1s): found_in.append("H1 Tag")
        first_para = soup.find("p").get_text(strip=True).lower() if soup.find("p") else ""
        if key in first_para: found_in.append("First Paragraph")
        alts = [img.get("alt", "").lower() for img in soup.find_all("img") if img.get("alt")]
        if any(key in alt for alt in alts): found_in.append("Image Alt Text")
        if not found_in:
            found_in = ["Not found in key areas"]
        return {"url": url, "keyword": key, "occurrences": occurrences, "density": density, "found_in": found_in}
    except Exception as e:
        return {"error": str(e)}
