#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from asset_pipeline.services.input_service import InputService  # noqa: E402
from asset_pipeline.shared import DEFAULT_PORTS  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Input service for asset pipeline")
    parser.add_argument("--domain", required=True, help="Target domain for theHarvester")
    parser.add_argument("--ports", default=",".join(str(port) for port in DEFAULT_PORTS), help="Comma-separated ports list")
    args = parser.parse_args()

    service = InputService()
    domain = service.resolve_domain_input(args.domain)
    ports = service.parse_ports_input(args.ports)
    payload = {
        "domain": domain,
        "ports": ports,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
