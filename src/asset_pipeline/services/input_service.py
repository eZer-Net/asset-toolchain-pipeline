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

    def configure_pipeline(self) -> RunConfig:
        self.print_passive_osint()
        dns_profile, dns_wordlist = self.configure_dns_bruteforce()
        status_codes = self.configure_status_codes()
        port_config = self.configure_ports()
        return RunConfig(
            ports=port_config.ports,
            full_scan=port_config.full_scan,
            dns_bruteforce_profile=dns_profile,
            dns_wordlist_path=dns_wordlist,
            status_codes=status_codes,
        )

    def print_passive_osint(self) -> None:
        print_block(
            "PASSIVE OSINT",
            [
                "stage  : passive asset discovery from public sources",
                "tools  : theHarvester + Certificate Transparency (crt.sh)",
                "status : always enabled",
            ],
        )

    def configure_dns_bruteforce(self) -> tuple[str, Optional[str]]:
        print_block(
            "ACTIVE DISCOVERY",
            [
                "stage : active DNS discovery by wordlist bruteforce",
                "tool  : Gobuster DNS",
                "lists : downloaded from SecLists/Discovery/DNS",
                "1 : disabled (default)",
                "2 : small  (5,000 entries)",
                "    source: SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
                "3 : medium (20,000 entries)",
                "    source: SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
                "4 : large  (110,000 entries)",
                "    source: SecLists/Discovery/DNS/subdomains-top1million-110000.txt",
                "5 : custom wordlist (one DNS label per line)",
                "input : Enter = disabled | 1/2/3/4/5",
            ],
        )
        raw = input("> ").strip().lower()
        if raw in {"", "1", "disabled", "off", "no", "n"}:
            return "disabled", None
        if raw in {"2", "small"}:
            return "small", None
        if raw in {"3", "medium"}:
            return "medium", None
        if raw in {"4", "large"}:
            return "large", None
        if raw in {"5", "custom"}:
            print("Enter local wordlist path:")
            path = Path(os.path.expanduser(input("> ").strip().strip('"').strip("'"))).resolve()
            self.validate_custom_wordlist(path)
            return "custom", str(path)
        raise InputValidationError(f"Unknown DNS bruteforce mode: {raw}")

    def validate_custom_wordlist(self, path: Path) -> None:
        if not path.is_file():
            raise InputValidationError(f"Wordlist does not exist: {path}")
        if not os.access(path, os.R_OK):
            raise InputValidationError(f"Wordlist is not readable: {path}")
        valid = 0
        invalid: List[str] = []
        seen: set[str] = set()
        for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            value = raw_line.strip().lower().rstrip(".")
            if not value or value.startswith("#"):
                continue
            if any(char.isspace() for char in value) or "://" in value or "/" in value:
                invalid.append(f"line {line_number}: {raw_line[:80]}")
                continue
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
                invalid.append(f"line {line_number}: {raw_line[:80]}")
                continue
            if value not in seen:
                seen.add(value)
                valid += 1
        if invalid:
            preview = "; ".join(invalid[:5])
            raise InputValidationError(f"Wordlist contains invalid entries ({len(invalid)}): {preview}")
        if valid == 0:
            raise InputValidationError("Wordlist does not contain valid entries")
        print_block("WORDLIST VALIDATION", [f"path    : {path}", f"entries : {valid}", "format  : one DNS label per line", "status  : accepted"])

    def configure_status_codes(self) -> Optional[List[int]]:
        print_block(
            "HTTP STATUS FILTER",
            [
                "1 : all valid HTTP responses (default)",
                "2 : exact status codes, for example 200,201,301,403",
                "3 : status classes, for example: 2xx 3xx 4xx",
                "input : Enter = all | 1/2/3",
            ],
        )
        raw = input("> ").strip().lower()
        if raw in {"", "1", "all"}:
            return None
        if raw in {"2", "custom", "exact"}:
            print("Add HTTP status codes as comma-separated values:")
            values = input("> ").strip()
            codes: List[int] = []
            seen: set[int] = set()
            for part in values.split(","):
                part = part.strip()
                if not part.isdigit():
                    raise InputValidationError(f"Invalid HTTP status code: {part}")
                code = int(part)
                if code < 100 or code > 599:
                    raise InputValidationError(f"HTTP status code out of range: {code}")
                if code not in seen:
                    seen.add(code); codes.append(code)
            if not codes:
                raise InputValidationError("HTTP status-code list must not be empty")
            codes.sort()
            print_block("HTTP STATUS FILTER ACTIVE", ["mode  : exact codes", f"codes : {','.join(str(code) for code in codes)}"])
            return codes
        if raw in {"3", "range", "ranges", "classes"}:
            print("Add HTTP status classes separated by spaces (example: 2xx 3xx):")
            values = input("> ").strip().lower().split()
            if not values:
                raise InputValidationError("HTTP status-class list must not be empty")
            allowed = {"1xx", "2xx", "3xx", "4xx", "5xx"}
            invalid = [value for value in values if value not in allowed]
            if invalid:
                raise InputValidationError(f"Invalid HTTP status class: {', '.join(invalid)}")
            classes = sorted(set(values), key=lambda item: int(item[0]))
            codes = [code for item in classes for code in range(int(item[0]) * 100, int(item[0]) * 100 + 100)]
            print_block("HTTP STATUS FILTER ACTIVE", ["mode    : status classes", f"classes : {' '.join(classes)}"])
            return codes
        raise InputValidationError(f"Unknown HTTP status filter mode: {raw}")

    def configure_ports(self) -> RunConfig:
        default_csv = ",".join(str(port) for port in DEFAULT_PORTS)
        print_block(
            "PORTS",
            [
                f"default : {default_csv}",
                "1       : default port profile",
                "2       : custom comma-separated ports",
                "3       : full TCP scan (1-65535)",
                "input   : Enter = default | 1/2/3 = choose mode | csv = custom ports",
            ],
        )
        raw = input("> ").strip().lower()

        if raw in {"3", "full", "all", "full-scan", "full_scan"}:
            print_block("PORTS ACTIVE", ["mode  : full TCP scan", "ports : 1-65535 (nmap -p-)"])
            return RunConfig(ports=[], full_scan=True)

        if raw == "2":
            print("Add custom TCP ports as comma-separated values:")
            raw = input("> ").strip()

        if raw in {"", "1", "default"}:
            raw = default_csv

        ports = self.parse_ports_input(raw)
        print_block("PORTS ACTIVE", ["mode  : selected TCP ports", f"ports : {','.join(str(port) for port in ports)}"])
        return RunConfig(ports=ports, full_scan=False)

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
        if raw_type in {"domain", "subdomain", "ip"}:
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
