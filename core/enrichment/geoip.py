from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import maxminddb
except ModuleNotFoundError:  # pragma: no cover - dependency may be installed later
    maxminddb = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GEOLITE_DB_PATH = PROJECT_ROOT / "GeoLite2-Country_20260303" / "GeoLite2-Country.mmdb"

UNKNOWN_GEO = {
    "country_code": None,
    "country_name": "Unknown",
    "is_private_or_unknown": True,
    "lookup_source": "unknown",
}


@lru_cache(maxsize=1)
def _get_reader() -> Any | None:
    if maxminddb is None:
        logger.warning("GeoIP dependency 'maxminddb' is not installed; country lookups disabled.")
        return None
    if not GEOLITE_DB_PATH.exists():
        logger.warning("GeoLite country database not found at %s", GEOLITE_DB_PATH)
        return None
    return maxminddb.open_database(str(GEOLITE_DB_PATH))


@lru_cache(maxsize=65536)
def lookup_ip_country(client_ip: str | None) -> dict[str, Any]:
    if not client_ip:
        return dict(UNKNOWN_GEO)

    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return {
            **UNKNOWN_GEO,
            "lookup_source": "invalid_ip",
        }

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_reserved
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        return {
            **UNKNOWN_GEO,
            "lookup_source": "private_or_reserved",
        }

    reader = _get_reader()
    if reader is None:
        return {
            **UNKNOWN_GEO,
            "lookup_source": "lookup_unavailable",
        }

    try:
        record = reader.get(client_ip) or {}
    except Exception as exc:  # pragma: no cover - reader failures are environment-dependent
        logger.warning("GeoLite lookup failed for %s: %s", client_ip, exc)
        return {
            **UNKNOWN_GEO,
            "lookup_source": "lookup_error",
        }

    country = record.get("country") or {}
    registered = record.get("registered_country") or {}
    code = country.get("iso_code") or registered.get("iso_code")
    names = country.get("names") or registered.get("names") or {}
    name = names.get("en")

    if not code and not name:
        return {
            **UNKNOWN_GEO,
            "lookup_source": "maxmind_no_match",
        }

    return {
        "country_code": code,
        "country_name": name or code or "Unknown",
        "is_private_or_unknown": False,
        "lookup_source": "maxmind_geolite2_country",
    }
