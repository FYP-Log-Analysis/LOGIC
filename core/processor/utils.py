import re
from urllib.parse import urlparse, parse_qs, unquote_plus

# Known bots / crawler patterns
BOT_PATTERNS = re.compile(
    r"(Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|"
    r"Sogou|Exabot|facebot|ia_archiver|Semrush|AhrefsBot|MJ12bot|"
    r"DotBot|BLEXBot|SiteExplorer|Scrapy|python-requests|curl|wget|"
    r"libwww-perl)",
    re.IGNORECASE,
)

STATUS_CLASSES = {
    "1xx": range(100, 200),
    "2xx": range(200, 300),
    "3xx": range(300, 400),
    "4xx": range(400, 500),
    "5xx": range(500, 600),
}


def classify_status(status: int) -> str:
    for label, rng in STATUS_CLASSES.items():
        if status in rng:
            return label
    return "unknown"


def extract_path_parts(full_path: str) -> dict:
    try:
        parsed = urlparse(unquote_plus(full_path))
        return {
            "path_clean":   parsed.path,
            "query_string": parsed.query or None,
            "query_params": parse_qs(parsed.query) if parsed.query else {},
            "extension":    parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else None,
        }
    except Exception:
        return {"path_clean": full_path, "query_string": None, "query_params": {}, "extension": None}


def is_bot(user_agent: str | None) -> bool:
    if not user_agent:
        return False
    return bool(BOT_PATTERNS.search(user_agent))


def categorise_request(method: str, path: str, status: int) -> str:
    if status in range(400, 500):
        return "client_error"
    if status in range(500, 600):
        return "server_error"
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "write_operation"
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if ext in {"js", "css", "png", "jpg", "jpeg", "gif", "ico", "woff", "woff2", "svg", "ttf"}:
        return "static_asset"
    return "page_request"
