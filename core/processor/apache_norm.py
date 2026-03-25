from core.processor.utils import classify_status, extract_path_parts, is_bot, categorise_request


def normalise_access_entry(entry: dict, server_type: str = "apache") -> dict:
    path_info = extract_path_parts(entry.get("path", "/"))
    return {
        # identity
        "source":         entry.get("source"),
        "log_type":       "access",
        "server_type":    server_type,
        # temporal
        "timestamp":      entry.get("timestamp"),
        # network
        "client_ip":      entry.get("ip"),
        "auth_user":      entry.get("user"),
        # request
        "http_method":    entry.get("method"),
        "request_path":   entry.get("path"),
        "path_clean":     path_info["path_clean"],
        "query_string":   path_info["query_string"],
        "query_params":   path_info["query_params"],
        "file_extension": path_info["extension"],
        "protocol":       entry.get("protocol"),
        # response
        "status_code":    entry.get("status"),
        "status_class":   classify_status(entry.get("status", 0)),
        "response_size":  entry.get("size", 0),
        # metadata
        "referer":        entry.get("referer"),
        "user_agent":     entry.get("user_agent"),
        "is_bot":         is_bot(entry.get("user_agent")),
        "category":       categorise_request(
                              entry.get("method", ""),
                              entry.get("path", ""),
                              entry.get("status", 0),
                          ),
        "raw":            entry.get("raw"),
    }


# Keep old names as aliases so any existing external callers still work
def normalise_apache_entry(entry: dict) -> dict:
    return normalise_access_entry(entry, server_type="apache")


def normalise_nginx_access(entry: dict) -> dict:
    return normalise_access_entry(entry, server_type="nginx")


def normalise_nginx_error(entry: dict) -> dict:
    return {
        "source":      entry.get("source"),
        "log_type":    "error",
        "server_type": "nginx",
        "timestamp":   entry.get("timestamp"),
        "client_ip":   entry.get("ip"),
        "level":       entry.get("level", "error").lower(),
        "message":     entry.get("message"),
        "raw":         entry.get("raw"),
    }
