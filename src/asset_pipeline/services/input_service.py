from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import socket
import urllib.parse
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional

from asset_pipeline.shared import (
    DEFAULT_PORTS,
    DOMAIN_RE,
    IP_RANGE_RE,
    InputValidationError,
    NormalizedAsset,
    RESULTS_DIR,
    RunConfig,
    print_block,
)


class InputService:
    """Validates CLI input, normalizes assets, resolves host IPs, and builds run config."""

    def resolve_domain_input(self, raw_domain: Optional[str]) -> str:
        if raw_domain is None:
            print("Add target domain:")
            raw_domain = input("> ").strip()
        domain = self.normalize_domain_input(raw_domain)
        if not domain:
            raise InputValidationError("Target domain is required")
        if not DOMAIN_RE.match(domain):
            raise InputValidationError(f"Invalid domain value: {raw_domain}")
        return domain

    def normalize_domain_input(self, raw_value: str) -> str:
        raw_value = raw_value.strip().strip('"').strip("'")
        if not raw_value:
            return ""
        if "://" in raw_value:
            parsed = urllib.parse.urlparse(raw_value)
            host = parsed.hostname or ""
        else:
            host = raw_value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.strip().rstrip(".").lower()
        if host.startswith("*."):
            host = host[2:]
        return host

    def resolve_assets_path(self, raw_path: Optional[str]) -> Path:
        """Legacy helper kept for service-level compatibility with old JSON input."""
        if raw_path is None:
            print("Add repository:")
            raw_path = input("> ").strip()
        raw_path = raw_path.strip().strip('"').strip("'")
        if not raw_path:
            raise InputValidationError("Assets JSON path is required")
        path = Path(os.path.expanduser(raw_path)).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Assets file does not exist: {path}")
        return path

    def configure_ports(self) -> RunConfig:
        default_csv = ",".join(str(port) for port in DEFAULT_PORTS)
        print_block("PORTS", [f"default : {default_csv}", "input   : Enter = keep default | csv = custom ports"])
        raw = input("> ").strip()
        ports = self.parse_ports_input(raw or default_csv)
        print_block("PORTS ACTIVE", [f"ports : {','.join(str(port) for port in ports)}"])
        return RunConfig(ports=ports)

    def parse_ports_input(self, raw: str) -> List[int]:
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        if not parts:
            raise InputValidationError("Ports list must not be empty")
        ports: List[int] = []
        seen: set[int] = set()
        for part in parts:
            if not part.isdigit():
                raise InputValidationError(f"Invalid port value: {part}")
            port = int(part)
            if port < 1 or port > 65535:
                raise InputValidationError(f"Port out of range: {port}")
            if port not in seen:
                seen.add(port)
                ports.append(port)
        ports.sort()
        return ports

    def build_output_path_for_domain(self, domain: str) -> Path:
        timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_stem = self.safe_output_stem(domain) or "domain"
        return RESULTS_DIR / f"{safe_stem}_{timestamp}.json"

    def build_theharvester_raw_base_path(self, domain: str) -> Path:
        """Canonical raw theHarvester output path without timestamp.

        theHarvester may rewrite the -f value depending on its internal formatter.
        The pipeline still writes its own canonical copy to this path so the user
        always knows where the complete raw OSINT artifact is stored.
        """
        safe_stem = self.safe_output_stem(domain) or "domain"
        return RESULTS_DIR / f"{safe_stem}-theharvester"

    def safe_output_stem(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")

    def build_output_path(self, assets_path: Path) -> Path:
        """Legacy helper kept for old JSON-input compatibility."""
        timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", assets_path.stem).strip("._") or "assets"
        return RESULTS_DIR / f"{safe_stem}_{timestamp}.json"

    def load_assets(self, path: Path) -> List[Dict[str, Any]]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
            raise InputValidationError("Input JSON must contain top-level key 'assets' as a list")
        return data["assets"]

    def normalize_asset_record(self, item: Dict[str, Any], index: int = 1) -> NormalizedAsset:
        if not isinstance(item, dict):
            raise InputValidationError(f"Asset #{index} must be an object")
        value = str(item.get("value", "")).strip()
        if not value:
            raise InputValidationError(f"Asset #{index} is missing 'value'")
        notes = str(item.get("notes", "")).strip()
        target_type = self.normalize_target_type(str(item.get("type", "")).strip(), value)
        scan_host = self.derive_scan_host(value, target_type)
        return NormalizedAsset(target=value, target_type=target_type, scan_host=scan_host, notes=notes)

    def normalize_assets(self, raw_assets: List[Dict[str, Any]]) -> List[NormalizedAsset]:
        normalized: List[NormalizedAsset] = []
        for index, item in enumerate(raw_assets, start=1):
            normalized.append(self.normalize_asset_record(item, index=index))
        return normalized

    def count_assets_by_type(self, assets: List[NormalizedAsset]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for asset in assets:
            counts[asset.target_type] = counts.get(asset.target_type, 0) + 1
        return counts

    def analyze_dependency_state(self, assets: List[NormalizedAsset]) -> Dict[str, int]:
        ip_groups: Dict[str, bool] = {}
        unresolved_assets = 0
        for asset in assets:
            group_key = asset.target if asset.target_type == "ip" else asset.target_ip
            if asset.target_type != "ip" and not group_key:
                unresolved_assets += 1
                continue
            if isinstance(group_key, str) and group_key.strip():
                ip_groups[group_key.strip()] = True
        return {
            "ip_groups": len(ip_groups),
            "unresolved_assets": unresolved_assets,
        }

    def attach_target_ips(self, assets: List[NormalizedAsset]) -> List[NormalizedAsset]:
        cache: Dict[str, Optional[str]] = {}
        result: List[NormalizedAsset] = []
        for asset in assets:
            if asset.target_type == "ip":
                result.append(replace(asset, target_ip=asset.target))
                continue
            if asset.scan_host not in cache:
                cache[asset.scan_host] = self.resolve_host_ip(asset.scan_host)
            result.append(replace(asset, target_ip=cache.get(asset.scan_host)))
        return result

    def resolve_host_ip(self, host: str) -> Optional[str]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return None
        except Exception:
            return None
        for info in infos:
            address = info[4][0]
            if isinstance(address, str) and address:
                return address
        return None

    def normalize_target_type(self, raw_type: str, value: str) -> str:
        raw_type = raw_type.lower()
        if raw_type in {"domain", "subdomain", "ip", "url"}:
            return raw_type
        if self.is_url(value):
            return "url"
        if self.is_ip_or_cidr(value):
            return "ip"
        if DOMAIN_RE.match(value):
            return "domain"
        return "domain"

    def derive_scan_host(self, value: str, target_type: str) -> str:
        if target_type == "url":
            parsed = urllib.parse.urlparse(value if "://" in value else f"https://{value}")
            host = parsed.hostname
            if not host:
                raise InputValidationError(f"Unable to derive host from URL: {value}")
            return host.strip().lower()
        return value.strip().lower()

    def is_url(self, value: str) -> bool:
        return value.startswith("http://") or value.startswith("https://")

    def is_ip_or_cidr(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
        if IP_RANGE_RE.match(value):
            try:
                ipaddress.ip_network(value, strict=False)
                return True
            except ValueError:
                return False
        return False
