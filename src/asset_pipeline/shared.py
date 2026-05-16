from __future__ import annotations

import datetime as dt
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "Results"
BIN_DIR = PROJECT_ROOT / "bin"
THEHARVESTER_DIR = BIN_DIR / "theHarvester"
THEHARVESTER_REPO_URL = "https://github.com/laramies/theHarvester.git"
USER_AGENT = "asset-pipeline-ip-centric/2.0"
STOP_REQUESTED = False
LAST_PROGRESS_LINE = ""
CHECK_MARK = "✓"
CROSS_MARK = "✗"
BULLET_MARK = "•"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
IP_RANGE_RE = re.compile(r"^[0-9A-Fa-f:.]+/[0-9]{1,3}$")
DEFAULT_PORTS = [22, 25, 53, 80, 81, 110, 143, 443, 444, 465, 587, 631, 993, 995, 3306, 3389, 5432, 6379, 7001, 7443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443]
VISIBLE_PORT_STATES = {"open", "filtered", "open|filtered", "unfiltered"}
HTTPX_TRIGGER_STATES = {"open", "open|filtered", "unfiltered"}
HTTPX_TRIGGER_PORTS = {80, 81, 88, 443, 444, 591, 593, 7001, 7443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9043, 9080, 9090, 9443}
HTTPX_SERVICE_HINTS = ("http", "https", "nginx", "apache", "iis", "caddy", "traefik", "envoy", "haproxy")

TOOL_SPECS = {
    "httpx": {
        "repo": "projectdiscovery/httpx",
        "go_install": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "binary": "httpx",
    },
    "cdncheck": {
        "repo": "projectdiscovery/cdncheck",
        "go_install": "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
        "binary": "cdncheck",
    },
}

APT_FALLBACK_PACKAGES = [
    "ca-certificates",
    "curl",
    "tar",
    "unzip",
    "git",
    "golang-go",
    "libpcap-dev",
    "nmap",
]


@dataclass(frozen=True)
class NormalizedAsset:
    target: str
    target_type: str
    scan_host: str
    notes: str = ""
    target_ip: Optional[str] = None


@dataclass(frozen=True)
class RunConfig:
    ports: List[int]

    @property
    def ports_csv(self) -> str:
        return ",".join(str(port) for port in self.ports)

    @property
    def ports_display(self) -> str:
        text = self.ports_csv
        if len(text) <= 96:
            return text
        return text[:93] + "..."


class PipelineError(RuntimeError):
    pass


class GracefulStop(Exception):
    pass


class InputValidationError(PipelineError):
    pass


class InstallError(PipelineError):
    pass


class Spinner:
    def __init__(self, label: str):
        self.label = label
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._frames = ["-", "\\", "|", "/"]

    def __enter__(self) -> "Spinner":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()
        sys.stdout.write("\r" + " " * 140 + "\r")
        sys.stdout.flush()

    def _run(self) -> None:
        start = time.time()
        index = 0
        while not self._stop.is_set():
            elapsed = int(time.time() - start)
            frame = self._frames[index % len(self._frames)]
            sys.stdout.write(f"\r{self.label} {frame} {elapsed:>4}s")
            sys.stdout.flush()
            time.sleep(0.15)
            index += 1


class LiveBlock:
    def __init__(self, title: str, lines: List[str]):
        self.title = title
        self.lines = lines
        self._last_line = ""
        self._opened = False

    def open(self) -> None:
        if self._opened:
            return
        print(f"┌─[ {self.title} ]")
        for line in self.lines:
            if line:
                print(f"│ {line}")
            else:
                print("│")
        self._opened = True

    def update(self, line: str) -> None:
        if not self._opened:
            self.open()
        rendered = fit_console_line(f"│ {line}")
        if rendered != self._last_line:
            sys.stdout.write("\r" + rendered)
            sys.stdout.flush()
            self._last_line = rendered

    def close(self, final_lines: Optional[List[str]] = None, keep_last_progress: bool = True) -> None:
        if not self._opened:
            self.open()
        final_lines = final_lines or []
        if keep_last_progress and self._last_line:
            sys.stdout.write("\r" + self._last_line + "\n")
        elif self._last_line:
            sys.stdout.write("\r" + " " * len(self._last_line) + "\r")
        for line in final_lines:
            if line:
                print(f"│ {line}")
            else:
                print("│")
        print("└─")
        print("")
        sys.stdout.flush()
        self._last_line = ""
        self._opened = False

def print_block(title: str, lines: List[str]) -> None:
    print(f"┌─[ {title} ]")
    for line in lines:
        if line:
            print(f"│ {line}")
        else:
            print("│")
    print("└─")
    print("")



def print_stage_header(index: int, total: int, title: str, lines: List[str]) -> None:
    print_block(f"PIPELINE {index}/{total} · {title}", lines)



def install_signal_handlers() -> None:
    def _handler(signum: int, frame: Any) -> None:
        del signum, frame
        global STOP_REQUESTED
        STOP_REQUESTED = True
        raise GracefulStop()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)



def ensure_directories() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)



def get_httpx_workers() -> int:
    return get_worker_value("ASSET_PIPELINE_HTTPX_WORKERS", default=max(4, min(16, (os.cpu_count() or 4) * 2)))



def get_cdncheck_workers() -> int:
    return get_worker_value("ASSET_PIPELINE_CDNCHECK_WORKERS", default=max(4, min(12, os.cpu_count() or 4)))



def get_ports_workers() -> int:
    return get_worker_value("ASSET_PIPELINE_PORTS_WORKERS", default=max(2, min(4, os.cpu_count() or 4)))



def get_worker_value(env_name: str, default: int) -> int:
    raw = os.environ.get(env_name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise InputValidationError(f"{env_name} must be integer, got: {raw}") from exc
    if value <= 0:
        raise InputValidationError(f"{env_name} must be > 0")
    return value



def run_command(
    args: List[str],
    label: str,
    timeout: Optional[int] = None,
    check: bool = False,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
    show_spinner: bool = False,
) -> subprocess.CompletedProcess[str]:
    if STOP_REQUESTED:
        raise GracefulStop()
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None,
    )
    try:
        if show_spinner:
            with Spinner(f"Run    : {label}"):
                stdout, stderr = process.communicate(timeout=timeout)
        else:
            stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise PipelineError(f"Command timed out: {' '.join(args)}")
    except KeyboardInterrupt:
        process.kill()
        stdout, stderr = process.communicate()
        raise GracefulStop()

    completed = subprocess.CompletedProcess(args=args, returncode=process.returncode, stdout=stdout, stderr=stderr)
    if check and completed.returncode != 0:
        raise PipelineError(format_failed_command(completed))
    return completed



def format_failed_command(completed: subprocess.CompletedProcess[str]) -> str:
    stderr_excerpt = (completed.stderr or "").strip().splitlines()[-5:]
    stdout_excerpt = (completed.stdout or "").strip().splitlines()[-5:]
    excerpt = "\n".join([line for line in stderr_excerpt or stdout_excerpt if line])
    return f"Command failed with exit code {completed.returncode}: {' '.join(completed.args)}\n{excerpt}"



def render_stage_progress(stage_label: str, done: int, total: int) -> None:
    global LAST_PROGRESS_LINE
    total = max(total, 1)
    width = 24
    filled = min(width, int((done / total) * width)) if total else width
    bar = "#" * filled + "-" * (width - filled)
    raw_line = f"[{bar}] {stage_label:<11} | {done}/{total} all"
    line = fit_console_line(raw_line)
    if line != LAST_PROGRESS_LINE:
        sys.stdout.write("\r" + line)
        sys.stdout.flush()
        LAST_PROGRESS_LINE = line



def fit_console_line(value: str) -> str:
    columns = shutil.get_terminal_size((100, 20)).columns
    max_len = max(40, columns - 1)
    if len(value) > max_len:
        value = value[: max_len - 3] + "..."
    return value.ljust(max_len)



def clear_progress_cache() -> None:
    global LAST_PROGRESS_LINE
    LAST_PROGRESS_LINE = ""



def is_debian_like() -> bool:
    os_release = Path("/etc/os-release")
    if not os_release.is_file():
        return False
    text = os_release.read_text(encoding="utf-8", errors="ignore").lower()
    return "debian" in text or "ubuntu" in text



def download_latest_release_binary(repo: str, binary_name: str) -> bool:
    system_name = platform.system().lower()
    machine = platform.machine().lower()
    if system_name != "linux":
        return False
    arch_tokens = {
        "x86_64": ["amd64", "x86_64"],
        "amd64": ["amd64", "x86_64"],
        "aarch64": ["arm64", "aarch64"],
        "arm64": ["arm64", "aarch64"],
    }.get(machine)
    if not arch_tokens:
        return False

    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            import json
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return False

    assets = payload.get("assets", []) if isinstance(payload, dict) else []
    matched_url = None
    matched_name = None
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name", "")).lower()
        if "linux" not in name:
            continue
        if not any(token in name for token in arch_tokens):
            continue
        if not (name.endswith(".zip") or name.endswith(".tar.gz") or name.endswith(".tgz")):
            continue
        matched_url = asset.get("browser_download_url")
        matched_name = asset.get("name")
        if matched_url:
            break

    if not matched_url or not matched_name:
        return False

    temp_dir = PROJECT_ROOT / ".tmp-downloads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    archive_path = temp_dir / str(matched_name)
    try:
        urllib.request.urlretrieve(str(matched_url), archive_path)
        extract_binary_from_archive(archive_path, binary_name)
        target_path = BIN_DIR / binary_name
        target_path.chmod(0o755)
        return True
    except Exception:
        return False
    finally:
        try:
            archive_path.unlink(missing_ok=True)
        except Exception:
            pass



def extract_binary_from_archive(archive_path: Path, binary_name: str) -> None:
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            member_name = find_archive_member(zf.namelist(), binary_name)
            if not member_name:
                raise InstallError(f"Unable to find {binary_name} in archive {archive_path.name}")
            extracted_path = BIN_DIR / binary_name
            with zf.open(member_name) as source, extracted_path.open("wb") as target:
                shutil.copyfileobj(source, target)
        return

    if archive_path.name.endswith(".tar.gz") or archive_path.name.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as tf:
            member_name = find_archive_member((member.name for member in tf.getmembers()), binary_name)
            if not member_name:
                raise InstallError(f"Unable to find {binary_name} in archive {archive_path.name}")
            member = tf.getmember(member_name)
            extracted = tf.extractfile(member)
            if extracted is None:
                raise InstallError(f"Unable to extract {binary_name} from archive {archive_path.name}")
            extracted_path = BIN_DIR / binary_name
            with extracted, extracted_path.open("wb") as target:
                shutil.copyfileobj(extracted, target)
        return

    raise InstallError(f"Unsupported archive format: {archive_path.name}")



def find_archive_member(names: Iterable[str], binary_name: str) -> Optional[str]:
    binary_name = binary_name.lower()
    for name in names:
        if Path(name).name.lower() == binary_name:
            return name
    return None
