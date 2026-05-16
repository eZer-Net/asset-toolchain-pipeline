#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from asset_pipeline.services.orchestrator_service import console_main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(console_main(sys.argv[1:]))
