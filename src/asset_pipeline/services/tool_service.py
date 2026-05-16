from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from asset_pipeline.shared import (
    APT_FALLBACK_PACKAGES,
    BIN_DIR,
    BULLET_MARK,
    CHECK_MARK,
    CROSS_MARK,
    InstallError,
    THEHARVESTER_DIR,
    THEHARVESTER_REPO_URL,
    TOOL_SPECS,
    download_latest_release_binary,
    is_debian_like,
    print_block,
    run_command,
)


THEHARVESTER_API_ENV_MAP: Dict[str, Dict[str, List[str]]] = {
    "bevigil": {"key": ["THEHARVESTER_BEVIGIL_KEY"]},
    "binaryedge": {"key": ["THEHARVESTER_BINARYEDGE_KEY"]},
    "bitbucket": {"key": ["THEHARVESTER_BITBUCKET_KEY"]},
    "brave": {"key": ["THEHARVESTER_BRAVE_KEY"]},
    "builtwith": {"key": ["THEHARVESTER_BUILTWITH_KEY"]},
    "censys": {
        "id": ["THEHARVESTER_CENSYS_ID"],
        "secret": ["THEHARVESTER_CENSYS_SECRET"],
        "key": ["THEHARVESTER_CENSYS_KEY"],
    },
    "criminalip": {"key": ["THEHARVESTER_CRIMINALIP_KEY", "THEHARVESTER_CRIMINAL_IP_KEY"]},
    "dehashed": {"key": ["THEHARVESTER_DEHASHED_KEY"]},
    "dnsdumpster": {"key": ["THEHARVESTER_DNSDUMPSTER_KEY"]},
    "dymo": {"key": ["THEHARVESTER_DYMO_KEY"]},
    "fofa": {"key": ["THEHARVESTER_FOFA_KEY"], "email": ["THEHARVESTER_FOFA_EMAIL"]},
    "fullhunt": {"key": ["THEHARVESTER_FULLHUNT_KEY"]},
    "github": {"key": ["THEHARVESTER_GITHUB_KEY", "THEHARVESTER_GITHUB_TOKEN"]},
    "github-code": {"key": ["THEHARVESTER_GITHUB_CODE_KEY", "THEHARVESTER_GITHUB_TOKEN"]},
    "haveibeenpwned": {"key": ["THEHARVESTER_HIBP_KEY", "THEHARVESTER_HAVEIBEENPWNED_KEY"]},
    "hunter": {"key": ["THEHARVESTER_HUNTER_KEY"]},
    "hunterhow": {"key": ["THEHARVESTER_HUNTERHOW_KEY"]},
    "intelx": {"key": ["THEHARVESTER_INTELX_KEY"]},
    "leakix": {"key": ["THEHARVESTER_LEAKIX_KEY"]},
    "leaklookup": {"key": ["THEHARVESTER_LEAKLOOKUP_KEY"]},
    "netlas": {"key": ["THEHARVESTER_NETLAS_KEY"]},
    "onyphe": {"key": ["THEHARVESTER_ONYPHE_KEY"]},
    "pentesttools": {"key": ["THEHARVESTER_PENTESTTOOLS_KEY", "THEHARVESTER_PENTEST_TOOLS_KEY"]},
    "projecdiscovery": {"key": ["THEHARVESTER_PROJECTDISCOVERY_KEY", "THEHARVESTER_PROJECT_DISCOVERY_KEY"]},
    "projectdiscovery": {"key": ["THEHARVESTER_PROJECTDISCOVERY_KEY", "THEHARVESTER_PROJECT_DISCOVERY_KEY"]},
    "rocketreach": {"key": ["THEHARVESTER_ROCKETREACH_KEY"]},
    "securityTrails": {"key": ["THEHARVESTER_SECURITYTRAILS_KEY", "THEHARVESTER_SECURITY_TRAILS_KEY"]},
    "shodan": {"key": ["THEHARVESTER_SHODAN_KEY"]},
    "tomba": {"key": ["THEHARVESTER_TOMBA_KEY"]},
    "venacus": {"key": ["THEHARVESTER_VENACUS_KEY"]},
    "virustotal": {"key": ["THEHARVESTER_VIRUSTOTAL_KEY", "THEHARVESTER_VT_KEY"]},
    "whoisxml": {"key": ["THEHARVESTER_WHOISXML_KEY"]},
    "windvane": {"key": ["THEHARVESTER_WINDVANE_KEY"]},
    "zoomeye": {"key": ["THEHARVESTER_ZOOMEYE_KEY"]},
}


class ToolService:
    """Checks required binaries/repos, installs missing tools, and returns executable paths."""

    def print_tools_catalog(self) -> None:
        print_block(
            "REQUIRED TOOLS",
            [
                f"{BULLET_MARK} theHarvester",
                f"{BULLET_MARK} httpx",
                f"{BULLET_MARK} cdncheck",
                f"{BULLET_MARK} nmap",
            ],
        )

    def ensure_required_tools_installed(self) -> Dict[str, str]:
        required_tools = ["theharvester", "httpx", "cdncheck", "nmap"]
        resolved: Dict[str, str] = {}
        missing: List[str] = []
        check_lines: List[str] = []

        for tool_name in required_tools:
            existing = self.resolve_tool(tool_name)
            if existing:
                if tool_name == "theharvester" and Path(existing).is_dir():
                    self.bootstrap_theharvester_python_env(Path(existing))
                resolved[tool_name] = existing
                check_lines.append(f"{CHECK_MARK} {tool_name:<12} {existing}")
            else:
                missing.append(tool_name)
                check_lines.append(f"{CROSS_MARK} {tool_name:<12} not found")
        print_block("TOOLS CHECK", check_lines)

        if missing:
            print_block("TOOLS INSTALL", [f"{BULLET_MARK} install missing tools", *[f"{BULLET_MARK} {tool_name}" for tool_name in missing]])
            for tool_name in missing:
                self.install_tool(tool_name)
                existing = self.resolve_tool(tool_name)
                if not existing:
                    raise InstallError(f"Failed to install required tool: {tool_name}")
                resolved[tool_name] = existing
            print_block("TOOLS INSTALLED", [f"{CHECK_MARK} {tool_name:<12} {resolved[tool_name]}" for tool_name in missing])

        print_block("TOOLS READY", [f"{CHECK_MARK} {tool_name:<12} {resolved[tool_name]}" for tool_name in required_tools])
        return resolved

    def resolve_tool(self, tool_name: str) -> Optional[str]:
        if tool_name == "theharvester":
            if self.is_theharvester_source_dir(THEHARVESTER_DIR):
                return str(THEHARVESTER_DIR)
            for binary_name in ("theHarvester", "theharvester"):
                system_path = shutil.which(binary_name)
                if system_path:
                    return system_path
            return None

        if tool_name == "nmap":
            local_path = BIN_DIR / "nmap"
            if local_path.is_file() and os.access(local_path, os.X_OK):
                return str(local_path)
            system_path = shutil.which("nmap")
            return system_path if system_path else None

        spec = TOOL_SPECS[tool_name]
        local_path = BIN_DIR / spec["binary"]
        if local_path.is_file() and os.access(local_path, os.X_OK):
            return str(local_path)
        system_path = shutil.which(spec["binary"])
        return system_path if system_path else None


    def is_theharvester_source_dir(self, path: Path) -> bool:
        if not path.is_dir():
            return False
        # Legacy source layout had root-level theHarvester.py. Current releases use
        # a pyproject/uv entrypoint and run as `uv run theHarvester`.
        return (path / "theHarvester.py").is_file() or (path / "pyproject.toml").is_file()

    def install_tool(self, tool_name: str) -> None:
        if tool_name == "theharvester":
            self.install_theharvester_from_source()
            return

        if tool_name == "nmap":
            self.install_nmap_via_apt()
            return

        spec = TOOL_SPECS[tool_name]
        if download_latest_release_binary(spec["repo"], spec["binary"]):
            return

        self.ensure_go_fallback_prerequisites()
        go_bin = shutil.which("go")
        if not go_bin:
            raise InstallError(f"Unable to install {tool_name}: no downloadable binary and Go not found")

        env = os.environ.copy()
        env["GOBIN"] = str(BIN_DIR)
        run_command(
            [go_bin, "install", "-v", spec["go_install"]],
            label=f"install {tool_name} via go",
            env=env,
            check=True,
            timeout=1800,
            show_spinner=True,
        )

    def install_theharvester_from_source(self) -> None:
        self.ensure_theharvester_prerequisites()
        git_bin = shutil.which("git")
        if not git_bin:
            raise InstallError("Unable to install theHarvester: git is not available")

        if not THEHARVESTER_DIR.exists():
            run_command(
                [git_bin, "clone", THEHARVESTER_REPO_URL, str(THEHARVESTER_DIR)],
                label="git clone theHarvester",
                check=True,
                timeout=1800,
                show_spinner=True,
            )

        if not self.is_theharvester_source_dir(THEHARVESTER_DIR):
            raise InstallError(
                "theHarvester source tree is incomplete after clone: "
                f"{THEHARVESTER_DIR}. Expected pyproject.toml or legacy theHarvester.py"
            )

        self.bootstrap_theharvester_python_env(THEHARVESTER_DIR)

    def ensure_theharvester_prerequisites(self) -> None:
        if shutil.which("git") and shutil.which("python3"):
            return
        if not is_debian_like():
            return
        sudo_prefix = ["sudo"] if os.geteuid() != 0 and shutil.which("sudo") else []
        run_command(sudo_prefix + ["apt-get", "update"], label="apt update", check=True, timeout=1800, show_spinner=True)
        run_command(
            sudo_prefix + ["apt-get", "install", "-y", "git", "python3", "python3-venv", "python3-pip"],
            label="apt install theHarvester prerequisites",
            check=True,
            timeout=1800,
            show_spinner=True,
        )

    def bootstrap_theharvester_python_env(self, repo_dir: Path) -> None:
        venv_python = repo_dir / ".venv" / "bin" / "python"
        if venv_python.is_file():
            return

        uv_bin = shutil.which("uv")
        if uv_bin:
            run_command(
                [uv_bin, "sync"],
                label="uv sync theHarvester",
                cwd=repo_dir,
                check=True,
                timeout=1800,
                show_spinner=True,
            )
            return

        python_bin = shutil.which("python3")
        if not python_bin:
            raise InstallError("Unable to bootstrap theHarvester: python3 is not available")

        run_command([python_bin, "-m", "venv", ".venv"], label="create theHarvester venv", cwd=repo_dir, check=True, timeout=600, show_spinner=True)
        pip_bin = repo_dir / ".venv" / "bin" / "pip"
        requirements_path = repo_dir / "requirements" / "base.txt"
        if requirements_path.is_file():
            run_command([str(pip_bin), "install", "-r", str(requirements_path)], label="pip install theHarvester requirements", cwd=repo_dir, check=True, timeout=1800, show_spinner=True)
            return

        run_command([str(pip_bin), "install", "."], label="pip install theHarvester package", cwd=repo_dir, check=True, timeout=1800, show_spinner=True)

    def configure_theharvester_api_keys_from_env(self, tool_path: str) -> List[str]:
        api_keys = self.collect_theharvester_api_keys_from_env()
        if not api_keys:
            print_block("THEHARVESTER API", ["env-keys : not found", "status   : continue with public/free sources"])
            return []

        yaml_text = self.render_api_keys_yaml(api_keys)
        paths = self.api_key_target_paths(tool_path)
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(yaml_text, encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass

        configured_sources = sorted(api_keys.keys(), key=str.lower)
        print_block(
            "THEHARVESTER API",
            [
                f"env-keys : {len(configured_sources)} source(s)",
                f"sources  : {', '.join(configured_sources)}",
                *[f"file     : {path}" for path in paths],
            ],
        )
        return configured_sources

    def collect_theharvester_api_keys_from_env(self) -> Dict[str, Dict[str, str]]:
        configured: Dict[str, Dict[str, str]] = {}

        raw_json = os.environ.get("THEHARVESTER_API_KEYS_JSON", "").strip()
        if raw_json:
            try:
                parsed = json.loads(raw_json)
            except json.JSONDecodeError as exc:
                raise InstallError(f"THEHARVESTER_API_KEYS_JSON is not valid JSON: {exc}") from exc
            if isinstance(parsed, dict):
                for source, fields in parsed.items():
                    if isinstance(source, str) and isinstance(fields, dict):
                        clean_fields = {str(k): str(v) for k, v in fields.items() if str(v).strip()}
                        if clean_fields:
                            configured[source] = clean_fields

        for source, fields in THEHARVESTER_API_ENV_MAP.items():
            source_fields = configured.setdefault(source, {})
            for field_name, env_names in fields.items():
                if field_name in source_fields and source_fields[field_name]:
                    continue
                value = self.first_env_value(env_names)
                if value:
                    source_fields[field_name] = value
            if not source_fields:
                configured.pop(source, None)

        return configured

    def first_env_value(self, names: List[str]) -> Optional[str]:
        for name in names:
            value = os.environ.get(name, "").strip()
            if value:
                return value
        return None

    def render_api_keys_yaml(self, api_keys: Dict[str, Dict[str, str]]) -> str:
        lines = ["apikeys:"]
        for source in sorted(api_keys.keys(), key=str.lower):
            lines.append(f"  {source}:")
            fields = api_keys[source]
            for field_name in sorted(fields.keys()):
                escaped = fields[field_name].replace('"', '\\"')
                lines.append(f"    {field_name}: \"{escaped}\"")
        lines.append("")
        return "\n".join(lines)

    def api_key_target_paths(self, tool_path: str) -> List[Path]:
        path = Path(tool_path)
        if path.is_dir():
            candidates = [path / "api-keys.yaml"]
            data_path = path / "theHarvester" / "data" / "api-keys.yaml"
            if data_path.parent.is_dir():
                candidates.append(data_path)
            return candidates
        home_config = Path.home() / ".theHarvester" / "api-keys.yaml"
        return [home_config]

    def install_nmap_via_apt(self) -> None:
        if shutil.which("nmap"):
            return
        if not is_debian_like():
            raise InstallError("nmap is required. Auto-install is supported only on Debian/Ubuntu")
        sudo_prefix = ["sudo"] if os.geteuid() != 0 and shutil.which("sudo") else []
        run_command(sudo_prefix + ["apt-get", "update"], label="apt update", check=True, timeout=1800, show_spinner=True)
        run_command(sudo_prefix + ["apt-get", "install", "-y", "nmap"], label="apt install nmap", check=True, timeout=1800, show_spinner=True)

    def ensure_go_fallback_prerequisites(self) -> None:
        if shutil.which("go"):
            return
        if not is_debian_like():
            return
        sudo_prefix = ["sudo"] if os.geteuid() != 0 and shutil.which("sudo") else []
        run_command(sudo_prefix + ["apt-get", "update"], label="apt update", check=True, timeout=1800, show_spinner=True)
        run_command(sudo_prefix + ["apt-get", "install", "-y", *APT_FALLBACK_PACKAGES], label="apt install base packages", check=True, timeout=1800, show_spinner=True)
