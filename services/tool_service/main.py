#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from asset_pipeline.services.tool_service import ToolService  # noqa: E402


def main() -> int:
    service = ToolService()
    tool_paths = service.ensure_required_tools_installed()
    print(json.dumps(tool_paths, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
