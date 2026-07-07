#!/usr/bin/env python3
"""
Optional GeoIP/ASN enrichment for SSH Honeypot.

Requires MaxMind GeoLite2 databases (free registration required):
  - GeoLite2-City.mmdb   (country, city)
  - GeoLite2-ASN.mmdb    (ASN, organization)

Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""

from __future__ import annotations

import functools
import ipaddress
import os
from typing import Any, Optional


class GeoResolver:
    """Resolves IP → country/city/ASN using optional GeoIP databases."""

    def __init__(
        self,
        city_db_path: str | None = None,
        asn_db_path: str | None = None,
        cache_size: int = 10000,
    ) -> None:
        self._city_db_path = city_db_path
        self._asn_db_path = asn_db_path
        self._city_reader: Any = None
        self._asn_reader: Any = None
        self._enabled = False

        self._load_databases()

        if self._enabled:
            self.lookup = functools.lru_cache(maxsize=cache_size)(self._lookup)  # type: ignore[method-assign]
        else:
            self.lookup = self._noop  # type: ignore[method-assign]

    def _load_databases(self) -> None:
        try:
            import geoip2.database
        except ImportError:
            return

        if self._city_db_path and os.path.isfile(self._city_db_path):
            try:
                self._city_reader = geoip2.database.Reader(self._city_db_path)
            except Exception:
                self._city_reader = None

        if self._asn_db_path and os.path.isfile(self._asn_db_path):
            try:
                self._asn_reader = geoip2.database.Reader(self._asn_db_path)
            except Exception:
                self._asn_reader = None

        self._enabled = self._city_reader is not None or self._asn_reader is not None

    def _noop(self, ip: str) -> dict[str, Any]:
        return {}

    def _lookup(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = {}

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return result

        if self._city_reader:
            try:
                city = self._city_reader.city(ip)
                if city.country and city.country.iso_code:
                    result["country"] = city.country.iso_code
                if city.city and city.city.name:
                    result["city"] = city.city.name
            except Exception:
                pass

        if self._asn_reader:
            try:
                asn = self._asn_reader.asn(ip)
                if asn.autonomous_system_number:
                    result["asn"] = f"AS{asn.autonomous_system_number}"
                if asn.autonomous_system_organization:
                    result["org"] = asn.autonomous_system_organization
            except Exception:
                pass

        return result

    def close(self) -> None:
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
