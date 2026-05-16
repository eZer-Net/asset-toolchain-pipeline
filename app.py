#!/usr/bin/env python3
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import console_main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(console_main(sys.argv[1:]))
