from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import ipaddress
import json
import os
import secrets
import socket
import re
import shlex
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import replace
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import asset_pipeline.shared as shared
from asset_pipeline.services.input_service import InputService
from asset_pipeline.services.tool_service import ToolService
from asset_pipeline.shared import (
    CHECK_MARK,
    VISIBLE_PORT_STATES,
    GracefulStop,
    LiveBlock,
    RunConfig,
    ensure_directories,
    get_cdncheck_workers,
    get_httpx_workers,
    get_ports_workers,
    install_signal_handlers,
    print_block,
    run_command,
)


class PipelineOrchestratorService:
    """Runs the scan pipeline with stage-by-stage orchestration and report persistence."""

    def __init__(self, input_service: Optional[InputService] = None, tool_service: Optional[ToolService] = None):
        self.input_service = input_service or InputService()
        self.tool_service = tool_service or ToolService()

    def console_main(self, argv: Optional[List[str]] = None) -> int:
        install_signal_handlers()
        ensure_directories()
        raw_domain = argv[0] if argv else None

        target_domain = self.input_service.resolve_domain_input(raw_domain)
        print_block("TARGET", [f"domain : {target_domain}"])

        run_config = self.input_service.configure_pipeline()
        self.print_pipeline_architecture(run_config)
        self.tool_service.print_tools_catalog(run_config)
        tool_paths = self.tool_service.ensure_required_tools_installed(run_config)
        dns_wordlist = self.tool_service.ensure_dns_wordlist(run_config)
        if dns_wordlist is not None:
            run_config = replace(run_config, dns_wordlist_path=str(dns_wordlist))
        theharvester_api_sources = self.tool_service.configure_theharvester_api_keys_from_env(tool_paths["theharvester"])
        self.print_configuration_summary(target_domain, run_config)

        output_path = self.input_service.build_output_path_for_domain(target_domain)
        raw_harvester_base_path = self.input_service.build_theharvester_raw_base_path(target_domain)

        print_block(
            "PIPELINE",
            [
                f"result-path        : {output_path}",
                f"raw-harvester-json : {self.json_path_from_base(raw_harvester_base_path)}",
                f"input-domain       : {target_domain}",
                f"ports              : {run_config.ports_display}",
                "",
                "stages",
                "1. passive and active asset discovery",
                "2. merge, DNS resolution and HTTP filtering",
                "3. initial IP -> domain -> subdomain graph",
                "4. CDN detection and unique-IP port scanning",
                "5. Recon JSON export",
            ],
        )

        report: Optional[Dict[str, Any]] = None
        try:
            report = self.run_pipeline(
                target_domain,
                tool_paths,
                run_config,
                output_path,
                raw_harvester_base_path,
                theharvester_api_sources,
            )
        except GracefulStop:
            if report is not None:
                self.finalize_report_summary(report)
                self.persist_report(report, output_path)
                print_block("STOP", [f"recon-import : {output_path}", f"pipeline-log : {output_path.with_name(output_path.stem + '_pipeline' + output_path.suffix)}", "status       : interrupted"])
            else:
                print_block("STOP", ["status       : interrupted before report initialization"])
            return 130

        self.finalize_report_summary(report)
        self.persist_report(report, output_path)
        print_block("DONE", [f"recon-import : {output_path}", f"pipeline-log : {output_path.with_name(output_path.stem + '_pipeline' + output_path.suffix)}", "status       : completed"])
        return 0

    def run_pipeline(
        self,
        target_domain: str,
        tool_paths: Dict[str, str],
        run_config: RunConfig,
        output_path: Any,
        raw_harvester_base_path: Path,
        theharvester_api_sources: List[str],
    ) -> Dict[str, Any]:
        raw_harvester_json, raw_harvester_json_path, harvester_assets, harvester_returncode = self.run_theharvester_stage(
            target_domain=target_domain,
            theharvester_path=tool_paths["theharvester"],
            raw_output_base_path=raw_harvester_base_path,
        )

        discovery_sources: Dict[str, List[Dict[str, Any]]] = {"theHarvester": harvester_assets}
        discovery_sources["certificate-transparency"] = self.run_certificate_transparency_stage(target_domain)
        if run_config.dns_bruteforce_enabled:
            discovery_sources["dns-bruteforce"] = self.run_dns_bruteforce_stage(
                target_domain, tool_paths["gobuster"], Path(str(run_config.dns_wordlist_path))
            )
        raw_assets = self.merge_discovered_assets(discovery_sources, target_domain)

        report, _, _, _ = self.run_standardization_stage(raw_assets, run_config, output_path, target_domain)
        report.setdefault("summary", {})["discovery-sources"] = {name: len(items) for name, items in discovery_sources.items()}
        report["summary"]["discovered-assets-after-deduplication"] = len(raw_assets)
        self.apply_theharvester_summary(
            report=report, target_domain=target_domain, raw_json_path=raw_harvester_json_path,
            raw_harvester_json=raw_harvester_json, converted_assets=harvester_assets,
            api_sources=theharvester_api_sources, returncode=harvester_returncode,
        )
        self.persist_report(report, output_path)

        resolved_http_targets = self.collect_resolved_http_targets(report)
        httpx_block = LiveBlock("PIPELINE 2/5 · host validation", [
            f"targets     : {len(resolved_http_targets)}",
            f"status-filter: {run_config.status_filter_display}",
            f"workers     : {get_httpx_workers()}",
            "command     : httpx -json -probe -status-code -ip -location -fr -include-chain -silent",
        ])
        httpx_block.open()
        httpx_stats = self.execute_parallel_stage(
            items=resolved_http_targets, worker_count=get_httpx_workers(),
            task_func=lambda target: self.run_httpx_single(target, tool_paths["httpx"]),
            on_result=lambda target, payload: self.apply_httpx_single_result(report, target, payload),
            output_path=output_path, report=report, submit_delay=self.get_httpx_submit_delay(), live_block=httpx_block,
        )
        removed_hosts = self.apply_http_status_filter(report, run_config.status_codes, include_urls=False)
        httpx_block.close([f"processed   : {httpx_stats['done']}/{httpx_stats['total']}", f"errors      : {httpx_stats['failed']}", f"filtered-out: {removed_hosts}"])

        ip_groups = self.build_ip_group_map(report["ips"])
        ip_targets = list(ip_groups.keys())
        print_block("PIPELINE 3/5 · ASSET RELATION GRAPH", [
            f"ip-groups   : {len(ip_targets)}",
            f"domains     : {sum(len(g.get('domains', [])) for g in report.get('ips', []))}",
            f"subdomains  : {sum(len(g.get('subdomains', [])) for g in report.get('ips', []))}",
            "relation     : IP -> Domain -> Subdomain",
        ])

        cdn_map: Dict[str, List[Dict[str, Any]]] = {}
        cdn_block = LiveBlock("PIPELINE 4/5 · IP enrichment / cdncheck", [f"ips        : {len(ip_targets)}", f"workers    : {get_cdncheck_workers()}"])
        cdn_block.open()
        cdn_stats = self.execute_parallel_stage(
            items=ip_targets, worker_count=get_cdncheck_workers(),
            task_func=lambda ip_value: self.run_cdncheck_single(ip_value, tool_paths["cdncheck"]),
            on_result=lambda ip_value, records: self.apply_cdncheck_single_result(report, cdn_map, ip_value, records),
            output_path=output_path, report=report, live_block=cdn_block,
        )
        cdn_block.close([f"processed  : {cdn_stats['done']}/{cdn_stats['total']}", f"errors     : {cdn_stats['failed']}"])

        run_port_ips = [ip for ip in ip_targets if not self.should_skip_ports_for_cdn(cdn_map.get(ip, []))]
        self.initialize_port_scan_notes(report, cdn_map, run_port_ips)
        nmap_workers = min(get_ports_workers(), 2) if run_config.full_scan else get_ports_workers()
        if run_config.full_scan:
            command_display = self.format_command([
                tool_paths["nmap"], "-Pn", "-n", "-p-", "-T4", "--min-rate", "1000",
                "--max-retries", "2", "--host-timeout", "15m", "-oX", "-", "<ip>",
            ]) + " -> -sV only on discovered open ports"
        else:
            command_display = self.format_command([
                tool_paths["nmap"], "-Pn", "-n", "-sV", "-T4", "--max-retries", "2",
                "--host-timeout", "10m", "-p", run_config.ports_csv, "-oX", "-", "<ip>",
            ])
        nmap_block = LiveBlock("PIPELINE 4/5 · IP enrichment / nmap", [
            f"scan-ips   : {len(run_port_ips)}", f"skipped-cdn: {len(ip_targets)-len(run_port_ips)}",
            f"ports      : {run_config.ports_display}",
            f"workers    : {nmap_workers}",
            f"command    : {command_display}",
        ])
        nmap_block.open()
        nmap_stats = self.execute_parallel_stage(
            items=run_port_ips, worker_count=nmap_workers,
            task_func=lambda ip_value: self.run_nmap_single(ip_value, tool_paths["nmap"], run_config),
            on_result=lambda ip_value, records: self.apply_ports_single_result(report, ip_value, records),
            output_path=output_path, report=report, live_block=nmap_block,
        )
        nmap_block.close([f"processed  : {nmap_stats['done']}/{nmap_stats['total']}", f"errors     : {nmap_stats['failed']}"])

        self.update_runtime_summary(report, cdn_map, run_port_ips, resolved_http_targets)
        print_block("PIPELINE 5/5 · REPORT GENERATION", ["assets       : normalized", "relations    : generated", "port-bindings: generated", "format       : assets + relations + portBindings"])
        return report

    def print_pipeline_architecture(self, run_config: RunConfig) -> None:
        print_block("ASSET TOOLCHAIN", [
            "Target Domain",
            "  -> OSINT Asset Discovery",
            "     -> Passive: theHarvester + Certificate Transparency",
            "     -> Active : optional DNS bruteforce with Gobuster",
            "  -> Merge, deduplicate, DNS resolve and HTTP filtering",
            "  -> IP -> Domain -> Subdomain relation graph",
            "  -> CDN/WAF detection and unique-IP port scan",
            "  -> Final Recon JSON for Pentester Dashboard",
        ])

    def print_configuration_summary(self, target_domain: str, run_config: RunConfig) -> None:
        print_block("ASSET TOOLCHAIN CONFIGURATION", [
            f"target              : {target_domain}",
            "passive OSINT       : theHarvester + Certificate Transparency",
            f"DNS bruteforce      : {run_config.dns_bruteforce_profile}",
            f"wordlist            : {run_config.dns_wordlist_path or 'n/a'}",
            f"HTTP status filter  : {run_config.status_filter_display}",
            f"port scan           : {run_config.ports_display}",
        ])

    def run_certificate_transparency_stage(self, target_domain: str) -> List[Dict[str, Any]]:
        timeout = self.get_certificate_transparency_timeout()
        url = "https://crt.sh/?q=" + urllib.parse.quote(f"%.{target_domain}") + "&output=json"
        block = LiveBlock(
            "PIPELINE 1/5 · PASSIVE OSINT / Certificate Transparency",
            [
                f"domain  : {target_domain}",
                "source  : crt.sh HTTP API",
                f"timeout : {timeout}s",
            ],
        )
        block.open()
        started = time.monotonic()
        request = urllib.request.Request(url, headers={"User-Agent": shared.USER_AGENT})
        try:
            with cf.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._fetch_certificate_transparency, request, timeout)
                while not future.done():
                    elapsed = int(time.monotonic() - started)
                    block.update(f"[{'#' * min(20, elapsed % 21):<20}] crt.sh query | running | elapsed {elapsed}s")
                    if elapsed >= timeout:
                        future.cancel()
                        raise TimeoutError(f"crt.sh did not answer within {timeout}s")
                    time.sleep(0.25)
                payload = future.result()
        except Exception as exc:
            block.close(["status  : skipped", f"reason  : {exc}", "continue: theHarvester and remaining stages"], keep_last_progress=False)
            return []

        assets: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for item in payload if isinstance(payload, list) else []:
            if not isinstance(item, dict):
                continue
            for raw_name in str(item.get("name_value", "")).splitlines():
                host = self.input_service.normalize_domain_input(raw_name)
                if not host or (host != target_domain and not host.endswith("." + target_domain)) or host in seen:
                    continue
                seen.add(host)
                assets.append({"value": host, "type": "domain" if host == target_domain else "subdomain", "notes": "Certificate Transparency"})
        block.close([f"status  : completed", f"assets  : {len(assets)}", f"elapsed : {int(time.monotonic() - started)}s"])
        return assets

    def _fetch_certificate_transparency(self, request: urllib.request.Request, timeout: int) -> Any:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    def get_certificate_transparency_timeout(self) -> int:
        raw = os.environ.get("ASSET_PIPELINE_CRTSH_TIMEOUT", "180").strip()
        try:
            value = int(raw)
        except ValueError:
            return 180
        return max(10, value)

    def run_dns_bruteforce_stage(self, target_domain: str, gobuster_path: str, wordlist: Path) -> List[Dict[str, Any]]:
        entries = self.count_wordlist_entries(wordlist)
        delay_ms = 250
        wildcard_ips = self.detect_wildcard_dns(target_domain)
        if wildcard_ips:
            print_block(
                "PIPELINE 1/5 · ACTIVE DNS DISCOVERY / Gobuster",
                [
                    f"domain    : {target_domain}",
                    f"wordlist  : {wordlist}",
                    f"entries   : {entries}",
                    "status    : skipped",
                    "reason    : wildcard DNS detected",
                    f"wildcard  : {', '.join(wildcard_ips)}",
                    "continue  : passive OSINT and remaining stages",
                ],
            )
            return []

        command = [
            gobuster_path, "dns",
            "-d", target_domain,
            "-w", str(wordlist),
            "-t", "1",
            "--delay", f"{delay_ms}ms",
            "--timeout", "3s",
            "--no-error",
            "--no-color",
        ]
        estimated_seconds = int(entries * delay_ms / 1000) if entries else 0
        timeout = max(7200, int(entries * 0.6) + 600)
        block = LiveBlock(
            "PIPELINE 1/5 · ACTIVE DNS DISCOVERY / Gobuster",
            [
                f"domain    : {target_domain}",
                f"wordlist  : {wordlist}",
                f"entries   : {entries}",
                f"workers   : 1",
                f"delay     : {delay_ms}ms between DNS requests",
                f"minimum   : ~{self.format_duration(estimated_seconds)}",
                f"command   : {self.format_command(command)}",
            ],
        )
        block.open()
        started = time.monotonic()
        try:
            completed = self.run_command_with_live_progress(
                command=command,
                cwd=None,
                timeout=timeout,
                live_block=block,
                label="Gobuster DNS",
            )
        except Exception:
            block.close(["status    : failed"], keep_last_progress=False)
            raise

        assets: List[Dict[str, Any]] = []
        combined_output = "\n".join(part for part in (completed.stdout or "", completed.stderr or "") if part)
        if "returned the same IP for every domain" in combined_output or "--wildcard" in combined_output and completed.returncode != 0:
            match = re.search(r"IP address\(es\) returned:\s*([^\n]+)", combined_output)
            wildcard = match.group(1).strip() if match else "detected by Gobuster"
            block.close([
                "status    : skipped",
                "reason    : wildcard DNS detected",
                f"wildcard  : {wildcard}",
                "continue  : passive OSINT and remaining stages",
            ], keep_last_progress=False)
            return []
        for line in combined_output.splitlines():
            match = re.search(r"(?:Found:\s*)?([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)", line)
            if not match:
                continue
            host = match.group(1).lower().rstrip(".")
            if host.endswith("." + target_domain):
                assets.append({"value": host, "type": "subdomain", "notes": "DNS bruteforce"})
        assets = self.unique_asset_records(assets)
        elapsed = int(time.monotonic() - started)
        final_lines = [
            f"status    : {'completed' if completed.returncode == 0 else 'completed with warnings'}",
            f"processed : {entries}",
            f"found     : {len(assets)}",
            f"elapsed   : {self.format_duration(elapsed)}",
        ]
        if completed.returncode != 0:
            final_lines.append(f"exit-code : {completed.returncode}")
        block.close(final_lines)
        return assets

    def detect_wildcard_dns(self, target_domain: str, probes: int = 3) -> List[str]:
        """Return wildcard DNS addresses when random labels resolve consistently."""
        resolved_sets: List[set[str]] = []
        for _ in range(max(2, probes)):
            label = f"asset-toolchain-{secrets.token_hex(8)}.{target_domain}"
            try:
                addresses = {
                    item[4][0]
                    for item in socket.getaddrinfo(label, None, type=socket.SOCK_STREAM)
                    if item and len(item) > 4 and item[4]
                }
            except socket.gaierror:
                return []
            except OSError:
                return []
            if not addresses:
                return []
            resolved_sets.append(addresses)

        common = set.intersection(*resolved_sets) if resolved_sets else set()
        return sorted(common)

    def count_wordlist_entries(self, wordlist: Path) -> int:
        try:
            with wordlist.open("r", encoding="utf-8", errors="ignore") as handle:
                return sum(1 for line in handle if line.strip() and not line.lstrip().startswith("#"))
        except OSError:
            return 0

    def format_duration(self, seconds: int) -> str:
        seconds = max(0, int(seconds))
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    def merge_discovered_assets(self, sources: Dict[str, List[Dict[str, Any]]], target_domain: str) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = [{"value": target_domain, "type": "domain", "notes": "Target domain"}]
        for source_name, items in sources.items():
            for item in items:
                if not isinstance(item, dict):
                    continue
                clone = dict(item)
                notes = str(clone.get("notes", "")).strip()
                clone["notes"] = "; ".join(part for part in (notes, source_name) if part)
                merged.append(clone)
        return self.unique_asset_records(merged)

    def unique_asset_records(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        index: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for item in assets:
            value = str(item.get("value", "")).strip()
            asset_type = str(item.get("type", "")).strip()
            if not value or asset_type not in {"ip", "domain", "subdomain"}:
                continue
            key = (asset_type, value.lower())
            if key in index:
                old_notes = str(index[key].get("notes", "")).strip()
                new_notes = str(item.get("notes", "")).strip()
                note_parts = []
                for part in (old_notes + "; " + new_notes).split(";"):
                    part = part.strip()
                    if part and part not in note_parts:
                        note_parts.append(part)
                if note_parts:
                    index[key]["notes"] = "; ".join(note_parts)
                continue
            clone = dict(item)
            index[key] = clone
            result.append(clone)
        return result

    def apply_http_status_filter(self, report: Dict[str, Any], allowed: Optional[List[int]], include_urls: bool = False, urls_only: bool = False) -> int:
        if allowed is None:
            return 0
        allowed_set = set(allowed)
        removed = 0
        retained_groups: List[Dict[str, Any]] = []
        for group in report.get("ips", []):
            if not isinstance(group, dict):
                continue
            if not urls_only:
                for key in ("domains", "subdomains"):
                    before = len(group.get(key, []))
                    group[key] = [entry for entry in group.get(key, []) if self.httpx_status_code(entry) in allowed_set]
                    removed += before - len(group[key])
            if group.get("input-ip-assets") or group.get("domains") or group.get("subdomains"):
                retained_groups.append(group)
        report["ips"] = retained_groups
        return removed

    def run_theharvester_stage(
        self,
        target_domain: str,
        theharvester_path: str,
        raw_output_base_path: Path,
    ) -> Tuple[Dict[str, Any], Path, List[Dict[str, Any]], int]:
        raw_json_path = self.json_path_from_base(raw_output_base_path)
        timeout = self.get_theharvester_timeout()

        # theHarvester always writes its own <name>.json and <name>.xml files
        # next to the -f prefix. Keep that tool output outside Results/ so the
        # public Results/ directory contains only the two stable project artifacts:
        #   1. <target>-theharvester.json
        #   2. <target>_<timestamp>.json
        with tempfile.TemporaryDirectory(prefix="asset-toolchain-theharvester-") as temp_dir:
            tool_output_base_path = Path(temp_dir) / raw_output_base_path.name
            command, cwd = self.build_theharvester_command(theharvester_path, target_domain, tool_output_base_path)
            started_at = time.time()

            stage_block = LiveBlock(
                "PIPELINE 1/5 · PASSIVE OSINT / theHarvester",
                [
                    f"domain      : {target_domain}",
                    f"raw-json    : {raw_json_path}",
                    f"command    : {self.format_command(command)}",
                ],
            )
            stage_block.open()

            completed = self.run_command_with_live_progress(
                command=command,
                cwd=cwd,
                timeout=timeout,
                live_block=stage_block,
                label="theHarvester OSINT",
            )

            discovered_json_path = self.find_theharvester_output_json(
                canonical_raw_json_path=self.json_path_from_base(tool_output_base_path),
                raw_output_base_path=tool_output_base_path,
                target_domain=target_domain,
                started_at=started_at,
            )
            raw_harvester_json = self.load_or_create_theharvester_raw_json(
                canonical_raw_json_path=raw_json_path,
                discovered_json_path=discovered_json_path,
                completed=completed,
                target_domain=target_domain,
                command=command,
                cwd=cwd,
            )

        converted_assets = self.convert_theharvester_json_to_assets(target_domain, raw_harvester_json)
        raw_counts = self.summarize_theharvester_console_snapshot_file(raw_json_path)

        stage_block.close(
            [
                f"raw-json    : {raw_json_path}",
                f"ASNS found  : {raw_counts.get('ASNS found', 0)}",
                f"Urls found  : {raw_counts.get('Interesting Urls found', 0)}",
                f"LinkedIn    : {raw_counts.get('LinkedIn users found', 0)}",
                f"IPs found   : {raw_counts.get('IPs found', 0)}",
                f"Emails found: {raw_counts.get('Emails found', 0)}",
                f"Hosts found : {raw_counts.get('Hosts found', 0)}",
            ]
        )
        return raw_harvester_json, raw_json_path, converted_assets, completed.returncode

    def run_command_with_live_progress(
        self,
        command: List[str],
        cwd: Optional[Path],
        timeout: int,
        live_block: LiveBlock,
        label: str,
    ) -> subprocess.CompletedProcess[str]:
        if shared.STOP_REQUESTED:
            raise GracefulStop()

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(cwd) if cwd else None,
        )
        started = time.monotonic()
        stdout = ""
        stderr = ""
        try:
            while True:
                elapsed = time.monotonic() - started
                if timeout and elapsed > timeout:
                    process.kill()
                    stdout, stderr = process.communicate()
                    raise shared.PipelineError(f"Command timed out: {self.format_command(command)}")
                try:
                    stdout, stderr = process.communicate(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    live_block.update(self.format_indeterminate_progress(label, elapsed))
                    if shared.STOP_REQUESTED:
                        process.kill()
                        stdout, stderr = process.communicate()
                        raise GracefulStop()
        except KeyboardInterrupt:
            process.kill()
            stdout, stderr = process.communicate()
            raise GracefulStop()

        live_block.update(self.format_indeterminate_progress(label, time.monotonic() - started, done=True))
        return subprocess.CompletedProcess(args=command, returncode=process.returncode, stdout=stdout, stderr=stderr)

    def format_indeterminate_progress(self, label: str, elapsed: float, done: bool = False) -> str:
        width = 24
        if done:
            bar = "#" * width
            status = "done"
        else:
            cycle = width * 2
            pos = int(elapsed * 4) % cycle
            filled = pos if pos <= width else cycle - pos
            bar = "#" * filled + "-" * (width - filled)
            status = "running"
        return f"[{bar}] {label} | {status} | elapsed {int(elapsed)}s"

    def format_command(self, command: Iterable[Any]) -> str:
        return " ".join(shlex.quote(str(part)) for part in command)

    def find_theharvester_output_json(
        self,
        canonical_raw_json_path: Path,
        raw_output_base_path: Path,
        target_domain: str,
        started_at: float,
    ) -> Optional[Path]:
        candidates: List[Path] = []
        target_variants = {
            target_domain,
            target_domain.split(".", 1)[0],
            raw_output_base_path.stem,
            canonical_raw_json_path.stem,
        }
        for stem in target_variants:
            if stem:
                candidates.append(raw_output_base_path.parent / f"{stem}.json")

        candidates.extend(sorted(raw_output_base_path.parent.glob("*.json"), key=lambda path: path.stat().st_mtime if path.exists() else 0, reverse=True))

        seen: set[Path] = set()
        fresh_candidates: List[Path] = []
        for path in candidates:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen or not path.is_file():
                continue
            seen.add(resolved)
            try:
                if path.stat().st_mtime + 1 < started_at:
                    continue
            except OSError:
                continue
            fresh_candidates.append(path)

        if canonical_raw_json_path in fresh_candidates:
            return canonical_raw_json_path
        return fresh_candidates[0] if fresh_candidates else None

    def json_path_from_base(self, base_path: Path) -> Path:
        text = str(base_path)
        if text.lower().endswith(".json"):
            return base_path
        return Path(text + ".json")

    def build_theharvester_command(self, theharvester_path: str, target_domain: str, raw_output_base_path: Path) -> Tuple[List[str], Optional[Path]]:
        path = Path(theharvester_path)
        base_args = ["-d", target_domain, "-b", "all", "-f", str(raw_output_base_path)]

        if path.is_dir():
            legacy_script = path / "theHarvester.py"
            venv_python = path / ".venv" / "bin" / "python"
            venv_binary_candidates = [path / ".venv" / "bin" / "theHarvester", path / ".venv" / "bin" / "theharvester"]
            for binary_path in venv_binary_candidates:
                if binary_path.is_file() and os.access(binary_path, os.X_OK):
                    return [str(binary_path), *base_args], path

            if legacy_script.is_file() and venv_python.is_file():
                return [str(venv_python), str(legacy_script), *base_args], path

            uv_path = self.find_executable("uv")
            if uv_path:
                # Current theHarvester uses a pyproject entrypoint, not root-level theHarvester.py.
                return [uv_path, "run", "theHarvester", *base_args], path

            if legacy_script.is_file():
                python_path = self.find_executable("python3") or self.find_executable("python")
                if python_path:
                    return [python_path, str(legacy_script), *base_args], path

            if venv_python.is_file():
                return [str(venv_python), "-m", "theHarvester", *base_args], path

        return [theharvester_path, *base_args], None

    def find_executable(self, name: str) -> Optional[str]:
        import shutil

        result = shutil.which(name)
        return result if result else None

    def get_theharvester_timeout(self) -> int:
        raw = os.environ.get("ASSET_PIPELINE_THEHARVESTER_TIMEOUT", "3600").strip()
        try:
            value = int(raw)
        except ValueError:
            value = 3600
        return max(value, 60)

    def load_or_create_theharvester_raw_json(
        self,
        canonical_raw_json_path: Path,
        discovered_json_path: Optional[Path],
        completed: Any,
        target_domain: str,
        command: List[str],
        cwd: Optional[Path],
    ) -> Dict[str, Any]:
        del target_domain, command, cwd
        tool_payload: Any = None
        if discovered_json_path and discovered_json_path.is_file():
            try:
                tool_payload = json.loads(discovered_json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                tool_payload = {
                    "status": "theharvester-json-produced-but-not-valid-json",
                    "path": str(discovered_json_path),
                    "content": discovered_json_path.read_text(encoding="utf-8", errors="replace"),
                }

        if tool_payload is None:
            tool_payload = {
                "status": "theharvester-json-not-produced",
                "stdout": getattr(completed, "stdout", ""),
                "stderr": getattr(completed, "stderr", ""),
            }

        if not isinstance(tool_payload, dict):
            tool_payload = {"records": tool_payload}

        console_snapshot = self.build_theharvester_console_snapshot(
            tool_payload=tool_payload,
            stdout=getattr(completed, "stdout", ""),
            stderr=getattr(completed, "stderr", ""),
        )
        canonical_raw_json_path.parent.mkdir(parents=True, exist_ok=True)
        canonical_raw_json_path.write_text(json.dumps(console_snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        return tool_payload

    def build_theharvester_console_snapshot(self, tool_payload: Dict[str, Any], stdout: str = "", stderr: str = "") -> Dict[str, Dict[str, Any]]:
        text_sections = self.parse_theharvester_console_sections("\n".join(part for part in [stdout, stderr] if part))

        def values(*items: Iterable[Any]) -> List[str]:
            combined: List[str] = []
            for item in items:
                combined.extend([str(value) for value in item])
            return self.unique_preserve_order(combined)

        asns = values(
            self.collect_values_for_keys(tool_payload, {"asn", "asns", "autonomous_system", "autonomous_systems"}),
            text_sections.get("asns_found", []),
        )
        interesting_urls = values(
            self.collect_values_for_keys(
                tool_payload,
                {"interesting_url", "interesting_urls", "interestingurls", "interesting_link", "interesting_links", "interestinglinks"},
            ),
            text_sections.get("interesting_urls_found", []),
        )
        linkedin_users = values(
            self.collect_values_for_keys(tool_payload, {"linkedin", "linkedin_users", "linkedin_people", "linkedin_profiles"}),
            text_sections.get("linkedin_users_found", []),
        )
        ips = values(
            self.collect_values_for_keys(tool_payload, {"ip", "ips", "address", "addresses", "ip_address", "ip_addresses"}),
            text_sections.get("ips_found", []),
        )
        emails = values(
            self.collect_values_for_keys(tool_payload, {"email", "emails", "e_mail", "e_mails"}),
            text_sections.get("emails_found", []),
        )
        hosts = values(
            self.collect_values_for_keys(
                tool_payload,
                {"host", "hosts", "hostname", "hostnames", "subdomain", "subdomains", "vhost", "vhosts", "virtualhost", "virtualhosts"},
            ),
            text_sections.get("hosts_found", []),
        )

        return {
            "ASNS found": self.build_theharvester_section(asns),
            "Interesting Urls found": self.build_theharvester_section(interesting_urls),
            "LinkedIn users found": self.build_theharvester_section(linkedin_users),
            "IPs found": self.build_theharvester_section(ips),
            "Emails found": self.build_theharvester_section(emails),
            "Hosts found": self.build_theharvester_section(hosts),
        }

    def build_theharvester_section(self, items: Iterable[Any]) -> Dict[str, Any]:
        values = self.unique_preserve_order(items)
        return {"count": len(values), "items": values}

    def summarize_theharvester_console_snapshot_file(self, raw_json_path: Path) -> Dict[str, int]:
        expected_keys = [
            "ASNS found",
            "Interesting Urls found",
            "LinkedIn users found",
            "IPs found",
            "Emails found",
            "Hosts found",
        ]
        try:
            payload = json.loads(raw_json_path.read_text(encoding="utf-8"))
        except Exception:
            return {key: 0 for key in expected_keys}

        counts: Dict[str, int] = {}
        for key in expected_keys:
            section = payload.get(key) if isinstance(payload, dict) else None
            if isinstance(section, dict):
                count_value = section.get("count")
                if isinstance(count_value, int):
                    counts[key] = count_value
                    continue
                items = section.get("items")
                counts[key] = len(items) if isinstance(items, list) else 0
            else:
                counts[key] = 0
        return counts

    def parse_theharvester_console_sections(self, text: str) -> Dict[str, List[str]]:
        sections: Dict[str, List[str]] = {}
        current_key: Optional[str] = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            header_match = re.match(r"^\[\*\]\s+(.+?)(?::\s*\d+)?\s*$", line)
            if header_match:
                title = header_match.group(1).strip().rstrip(".")
                lower_title = title.lower()
                if lower_title.startswith("no ") and lower_title.endswith(" found"):
                    possible_title = title[3:].strip()
                    current_key = self.normalize_json_key(possible_title + " found")
                    sections.setdefault(current_key, [])
                else:
                    current_key = self.normalize_json_key(title)
                    sections.setdefault(current_key, [])
                continue

            if current_key is None:
                continue
            if set(line) <= {"-"}:
                continue
            if line.startswith("[") and "]" in line:
                continue
            sections.setdefault(current_key, []).append(line)

        return {key: self.unique_preserve_order(values) for key, values in sections.items()}

    def build_normalized_theharvester_snapshot(self, raw_payload: Dict[str, Any]) -> Dict[str, List[str]]:
        normalized: Dict[str, List[str]] = {
            "emails": [],
            "hosts": [],
            "subdomains": [],
            "ips": [],
            "urls": [],
            "interesting-urls": [],
            "people": [],
            "linkedin": [],
            "twitter": [],
            "asns": [],
            "vhosts": [],
            "dns-records": [],
            "ports": [],
            "banners": [],
            "takeovers": [],
            "sources": [],
        }

        normalized["emails"] = self.unique_preserve_order(
            [*self.collect_values_for_keys(raw_payload, {"email", "emails", "e_mail", "e_mails"}), *self.extract_emails_from_anywhere(raw_payload)]
        )
        normalized["hosts"] = self.unique_preserve_order(self.collect_theharvester_hosts(raw_payload))
        normalized["subdomains"] = self.unique_preserve_order(
            self.collect_values_for_keys(raw_payload, {"subdomain", "subdomains", "host", "hosts", "hostname", "hostnames"})
        )
        normalized["ips"] = self.unique_preserve_order(self.collect_theharvester_ips(raw_payload))
        normalized["urls"] = self.unique_preserve_order(self.collect_theharvester_urls(raw_payload))
        normalized["interesting-urls"] = self.unique_preserve_order(
            self.collect_values_for_keys(raw_payload, {"interesting_url", "interesting_urls", "interestingurls", "interesting_links", "interestinglinks"})
        )
        normalized["people"] = self.unique_preserve_order(
            self.collect_values_for_keys(raw_payload, {"person", "people", "name", "names", "employee", "employees"})
        )
        normalized["linkedin"] = self.unique_preserve_order(
            self.collect_values_for_keys(raw_payload, {"linkedin", "linkedin_people", "linkedin_profiles", "linkedin_links"})
        )
        normalized["twitter"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"twitter", "twitter_people", "twitter_profiles"}))
        normalized["asns"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"asn", "asns", "autonomous_system", "autonomous_systems"}))
        normalized["vhosts"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"vhost", "vhosts", "virtualhost", "virtualhosts"}))
        normalized["dns-records"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"dns", "dns_record", "dns_records", "records"}))
        normalized["ports"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"port", "ports", "open_port", "open_ports"}))
        normalized["banners"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"banner", "banners"}))
        normalized["takeovers"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"takeover", "takeovers"}))
        normalized["sources"] = self.unique_preserve_order(self.collect_values_for_keys(raw_payload, {"source", "sources", "module", "modules"}))
        return normalized

    def get_raw_theharvester_payload(self, raw_json: Any) -> Any:
        if isinstance(raw_json, dict) and "raw" in raw_json:
            return raw_json.get("raw")
        return raw_json

    def get_normalized_theharvester_snapshot(self, raw_json: Any) -> Dict[str, List[str]]:
        if isinstance(raw_json, dict) and isinstance(raw_json.get("normalized"), dict):
            result: Dict[str, List[str]] = {}
            for key, value in raw_json["normalized"].items():
                result[str(key)] = [str(item) for item in value] if isinstance(value, list) else []
            return result
        if isinstance(raw_json, dict):
            return self.build_normalized_theharvester_snapshot(raw_json)
        return self.build_normalized_theharvester_snapshot({"records": raw_json})

    def summarize_theharvester_payload(self, raw_json: Any) -> Dict[str, int]:
        normalized = self.get_normalized_theharvester_snapshot(raw_json)
        return {key: len(value) for key, value in normalized.items() if isinstance(value, list)}

    def convert_theharvester_json_to_assets(self, target_domain: str, raw_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        assets: List[Dict[str, Any]] = []
        seen: set[Tuple[str, str]] = set()
        normalized = self.get_normalized_theharvester_snapshot(raw_json)
        raw_payload = self.get_raw_theharvester_payload(raw_json)

        def add_asset(value: str, target_type: str, notes: str) -> None:
            value = value.strip()
            if not value:
                return
            key = (target_type, value.lower())
            if key in seen:
                return
            seen.add(key)
            assets.append({"value": value, "type": target_type, "notes": notes})

        add_asset(target_domain, "domain", "theHarvester input-domain")

        for ip_value in normalized.get("ips", []):
            normalized_ip = self.normalize_ip_candidate(ip_value)
            if normalized_ip:
                add_asset(normalized_ip, "ip", "theHarvester ips")

        host_candidates: List[str] = []
        host_candidates.extend(normalized.get("hosts", []))
        host_candidates.extend(normalized.get("subdomains", []))
        host_candidates.extend(normalized.get("vhosts", []))
        for host_value in host_candidates:
            host, attached_ip = self.normalize_harvester_host_candidate(host_value)
            if attached_ip:
                add_asset(attached_ip, "ip", "theHarvester host-ip")
            if not host:
                continue
            target_type = "domain" if host == target_domain else "subdomain"
            add_asset(host, target_type, "theHarvester hosts")

        return assets

    def collect_theharvester_hosts(self, raw_json: Any) -> List[str]:
        payload = self.get_raw_theharvester_payload(raw_json)
        return self.unique_preserve_order(
            self.collect_values_for_keys(
                payload,
                {
                    "host",
                    "hosts",
                    "hostname",
                    "hostnames",
                    "subdomain",
                    "subdomains",
                    "vhost",
                    "vhosts",
                    "virtualhost",
                    "virtualhosts",
                },
            )
        )

    def collect_theharvester_ips(self, raw_json: Any) -> List[str]:
        payload = self.get_raw_theharvester_payload(raw_json)
        candidates = [
            *self.collect_values_for_keys(payload, {"ip", "ips", "address", "addresses", "ip_address", "ip_addresses"}),
            *self.extract_ips_from_anywhere(payload),
        ]
        result: List[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            ip_value = self.normalize_ip_candidate(candidate)
            if ip_value and ip_value not in seen:
                seen.add(ip_value)
                result.append(ip_value)
        return result

    def collect_theharvester_urls(self, raw_json: Any) -> List[str]:
        payload = self.get_raw_theharvester_payload(raw_json)
        candidates = [
            *self.collect_values_for_keys(
                payload,
                {
                    "url",
                    "urls",
                    "link",
                    "links",
                    "uri",
                    "uris",
                    "interesting_url",
                    "interesting_urls",
                    "interestingurls",
                    "interesting_link",
                    "interesting_links",
                    "interestinglinks",
                    "linkedin",
                    "linkedin_links",
                    "profile",
                    "profiles",
                },
            ),
            *self.extract_urls_from_anywhere(payload),
        ]
        return self.unique_preserve_order(candidates)

    def collect_values_for_keys(self, value: Any, wanted_keys: set[str]) -> List[str]:
        result: List[str] = []
        normalized_wanted_keys = {self.normalize_json_key(key) for key in wanted_keys}

        def walk(node: Any, parent_is_match: bool = False) -> None:
            if isinstance(node, dict):
                for key, item in node.items():
                    normalized_key = self.normalize_json_key(key)
                    matched = normalized_key in normalized_wanted_keys
                    if matched:
                        result.extend(self.flatten_scalar_strings(item))
                    walk(item, parent_is_match=matched)
                return
            if isinstance(node, list):
                for item in node:
                    walk(item, parent_is_match=parent_is_match)
                return
            if parent_is_match and isinstance(node, (str, int, float)):
                result.append(str(node))

        walk(value)
        return result

    def normalize_json_key(self, key: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")

    def flatten_scalar_strings(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, (str, int, float)):
            return [str(value)]
        if isinstance(value, list):
            result: List[str] = []
            for item in value:
                result.extend(self.flatten_scalar_strings(item))
            return result
        if isinstance(value, dict):
            result: List[str] = []
            preferred_keys = [
                "host",
                "hosts",
                "hostname",
                "hostnames",
                "name",
                "domain",
                "subdomain",
                "subdomains",
                "vhost",
                "vhosts",
                "ip",
                "ips",
                "address",
                "addresses",
                "url",
                "urls",
                "link",
                "links",
                "profile",
                "profiles",
                "value",
            ]
            normalized_map = {self.normalize_json_key(key): key for key in value.keys()}
            for key in preferred_keys:
                normalized_key = self.normalize_json_key(key)
                if normalized_key in normalized_map:
                    result.extend(self.flatten_scalar_strings(value[normalized_map[normalized_key]]))
            return result
        return []

    def collect_all_scalar_strings(self, value: Any) -> List[str]:
        result: List[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for item in node.values():
                    walk(item)
                return
            if isinstance(node, list):
                for item in node:
                    walk(item)
                return
            if isinstance(node, (str, int, float)):
                result.append(str(node))

        walk(value)
        return result

    def extract_urls_from_anywhere(self, value: Any) -> List[str]:
        result: List[str] = []
        url_re = re.compile(r"https?://[^\s\"'<>),]+", flags=re.IGNORECASE)
        for text in self.collect_all_scalar_strings(value):
            result.extend(match.group(0).rstrip(".]}") for match in url_re.finditer(text))
        return self.unique_preserve_order(result)

    def extract_emails_from_anywhere(self, value: Any) -> List[str]:
        result: List[str] = []
        email_re = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
        for text in self.collect_all_scalar_strings(value):
            result.extend(match.group(0) for match in email_re.finditer(text))
        return self.unique_preserve_order(result)

    def extract_ips_from_anywhere(self, value: Any) -> List[str]:
        result: List[str] = []
        ipv4_re = re.compile(r"(?<![A-Za-z0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9.])")
        for text in self.collect_all_scalar_strings(value):
            result.extend(match.group(0) for match in ipv4_re.finditer(text))
        return self.unique_preserve_order(result)

    def unique_preserve_order(self, values: Iterable[Any]) -> List[str]:
        result: List[str] = []
        seen: set[str] = set()
        for value in values:
            text = str(value).strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(text)
        return result

    def normalize_harvester_host_candidate(self, raw_value: str) -> Tuple[Optional[str], Optional[str]]:
        value = str(raw_value).strip().strip('"').strip("'")
        if not value or "@" in value:
            return None, None

        attached_ip: Optional[str] = None
        if "://" in value:
            parsed = urllib.parse.urlparse(value)
            host = parsed.hostname or ""
        else:
            host = value.split("/", 1)[0].strip()

        if host.startswith("[" ) and "]" in host:
            ip_candidate = host.strip("[]")
            return None, self.normalize_ip_candidate(ip_candidate)

        if ":" in host and host.count(":") == 1:
            left, right = host.rsplit(":", 1)
            ip_candidate = self.normalize_ip_candidate(right)
            if ip_candidate:
                host = left
                attached_ip = ip_candidate
            elif right.isdigit():
                host = left

        host = host.strip().rstrip(".").lower()
        if host.startswith("*."):
            host = host[2:]
        if not host or not self.looks_like_domain(host):
            return None, attached_ip
        return host, attached_ip

    def normalize_harvester_url_candidate(self, raw_value: str) -> Optional[str]:
        value = str(raw_value).strip().strip('"').strip("'").rstrip(".,;)]")
        if not value:
            return None
        if value.startswith("//"):
            value = "https:" + value
        if not value.startswith(("http://", "https://")):
            host_candidate = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip().rstrip(".").lower()
            if "/" not in value or not self.looks_like_domain(host_candidate):
                return None
            value = "https://" + value
        parsed = urllib.parse.urlparse(value)
        if not parsed.hostname:
            return None
        return value

    def normalize_ip_candidate(self, raw_value: str) -> Optional[str]:
        value = str(raw_value).strip().strip('"').strip("'")
        if not value:
            return None
        if "://" in value:
            parsed = urllib.parse.urlparse(value)
            value = parsed.hostname or value
        if value.startswith("[") and "]" in value:
            value = value.strip("[]")
        if ":" in value and value.count(":") == 1:
            left, right = value.rsplit(":", 1)
            if right.isdigit():
                value = left
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def looks_like_domain(self, value: str) -> bool:
        return bool(re.match(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", value, flags=re.IGNORECASE))

    def apply_theharvester_summary(
        self,
        report: Dict[str, Any],
        target_domain: str,
        raw_json_path: Path,
        raw_harvester_json: Dict[str, Any],
        converted_assets: List[Dict[str, Any]],
        api_sources: List[str],
        returncode: int,
    ) -> None:
        summary = report.setdefault("summary", {})
        summary["theharvester-enabled"] = True
        summary["theharvester-domain"] = target_domain
        summary["theharvester-source"] = "all"
        summary["theharvester-return-code"] = returncode
        summary["theharvester-raw-json"] = str(raw_json_path)
        summary["theharvester-converted-assets-total"] = len(converted_assets)
        summary["theharvester-api-key-sources-total"] = len(api_sources)
        summary["theharvester-api-key-sources"] = api_sources
        raw_payload = self.get_raw_theharvester_payload(raw_harvester_json)
        summary["theharvester-raw-keys"] = sorted([str(key) for key in raw_payload.keys()]) if isinstance(raw_payload, dict) else []
        summary["theharvester-normalized-counts"] = self.summarize_theharvester_payload(raw_harvester_json)

    def run_standardization_stage(
        self,
        raw_assets: List[Dict[str, Any]],
        run_config: RunConfig,
        output_path: Any,
        target_domain: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], List[Any], Dict[str, int], Dict[str, int]]:
        total = len(raw_assets)
        stage_block = LiveBlock(
            "PIPELINE 2/5 · MERGE, DNS RESOLUTION AND NORMALIZATION",
            [
                f"assets      : {total}",
                "dependency  : ip -> domain -> subdomain",
                "command    : internal Python normalization + socket.getaddrinfo(host)",
            ],
        )
        stage_block.open()

        normalized_assets: List[Any] = []
        resolve_cache: Dict[str, Optional[str]] = {}
        assets_by_type: Dict[str, int] = {"ip": 0, "domain": 0, "subdomain": 0}
        linked_to_ip = 0
        unresolved_assets = 0

        for index, item in enumerate(raw_assets, start=1):
            if shared.STOP_REQUESTED:
                raise GracefulStop()
            asset = self.input_service.normalize_asset_record(item, index=index)
            assets_by_type[asset.target_type] = assets_by_type.get(asset.target_type, 0) + 1

            if asset.target_type == "ip":
                asset = replace(asset, target_ip=asset.target)
                linked_to_ip += 1
            else:
                if asset.scan_host not in resolve_cache:
                    resolve_cache[asset.scan_host] = self.input_service.resolve_host_ip(asset.scan_host)
                target_ip = resolve_cache.get(asset.scan_host)
                if target_ip:
                    linked_to_ip += 1
                else:
                    unresolved_assets += 1
                asset = replace(asset, target_ip=target_ip)

            normalized_assets.append(asset)
            stage_block.update(self.format_standardization_progress(index, total, linked_to_ip, unresolved_assets))

        dependency_stats = self.input_service.analyze_dependency_state(normalized_assets)
        report = self.init_report(normalized_assets, run_config, target_domain)
        self.persist_report(report, output_path)

        stage_block.close(
            [
                f"processed   : {total}/{total}",
                f"total-ip    : {assets_by_type.get('ip', 0)}",
                f"total-domain: {assets_by_type.get('domain', 0)}",
                f"total-subdomain : {assets_by_type.get('subdomain', 0)}",
                f"total-url   : {assets_by_type.get('url', 0)}",
                f"unique-ip-groups : {dependency_stats['ip_groups']}",
                f"unresolved-assets: {dependency_stats['unresolved_assets']}",
            ]
        )
        return report, normalized_assets, assets_by_type, dependency_stats

    def execute_parallel_stage(
        self,
        items: List[str],
        worker_count: int,
        task_func: Callable[[str], Any],
        on_result: Callable[[str, Any], None],
        output_path: Any,
        report: Dict[str, Any],
        submit_delay: float = 0.0,
        live_block: Optional[LiveBlock] = None,
    ) -> Dict[str, int]:
        total = len(items)
        stats = {"total": total, "done": 0, "failed": 0}
        if live_block is not None:
            live_block.update(self.format_parallel_stage_progress(stats['done'], total, stats['failed'], 0))
        if not items:
            return stats

        queue = list(items)
        active: Dict[cf.Future, str] = {}
        next_submit_at = 0.0

        with cf.ThreadPoolExecutor(max_workers=worker_count) as executor:
            while queue and len(active) < worker_count:
                next_submit_at = self.submit_stage_item(executor, queue, active, task_func, submit_delay, next_submit_at)
                if live_block is not None:
                    live_block.update(self.format_parallel_stage_progress(stats['done'], total, stats['failed'], len(active)))

            while active:
                if shared.STOP_REQUESTED:
                    raise GracefulStop()
                done_futures, _ = cf.wait(active.keys(), timeout=0.2, return_when=cf.FIRST_COMPLETED)
                if not done_futures:
                    if live_block is not None:
                        live_block.update(self.format_parallel_stage_progress(stats['done'], total, stats['failed'], len(active)))
                    continue

                for future in done_futures:
                    item = active.pop(future)
                    if shared.STOP_REQUESTED:
                        raise GracefulStop()
                    try:
                        result = future.result()
                    except GracefulStop:
                        raise
                    except Exception:
                        result = []
                        stats['failed'] += 1
                    on_result(item, result)
                    stats['done'] += 1
                    self.persist_report(report, output_path)
                    while queue and len(active) < worker_count:
                        next_submit_at = self.submit_stage_item(executor, queue, active, task_func, submit_delay, next_submit_at)
                    if live_block is not None:
                        live_block.update(self.format_parallel_stage_progress(stats['done'], total, stats['failed'], len(active)))

        return stats

    def submit_stage_item(
        self,
        executor: cf.ThreadPoolExecutor,
        queue: List[str],
        active: Dict[cf.Future, str],
        task_func: Callable[[str], Any],
        submit_delay: float,
        next_submit_at: float,
    ) -> float:
        if submit_delay > 0:
            now = time.monotonic()
            if now < next_submit_at:
                time.sleep(next_submit_at - now)
        item = queue.pop(0)
        active[executor.submit(task_func, item)] = item
        return time.monotonic() + max(submit_delay, 0.0)

    def format_standardization_progress(self, done: int, total: int, linked_to_ip: int, unresolved_assets: int) -> str:
        total = max(total, 1)
        width = 24
        filled = min(width, int((done / total) * width))
        bar = "#" * filled + "-" * (width - filled)
        return f"[{bar}] {done}/{total} done | linked {linked_to_ip} | unresolved {unresolved_assets}"

    def format_parallel_stage_progress(self, done: int, total: int, failed: int, active_count: int) -> str:
        total = max(total, 1)
        width = 24
        filled = min(width, int((done / total) * width))
        bar = "#" * filled + "-" * (width - filled)
        ok_count = max(done - failed, 0)
        return f"[{bar}] {done}/{total} done | ok {ok_count} | err {failed} | active {active_count}"

    def get_httpx_submit_delay(self) -> float:
        raw = os.environ.get("ASSET_PIPELINE_HTTPX_SUBMIT_DELAY_MS", "500").strip()
        try:
            delay_ms = int(raw)
        except ValueError:
            delay_ms = 500
        if delay_ms < 0:
            delay_ms = 0
        return delay_ms / 1000.0

    def init_report(self, assets: List[Any], run_config: RunConfig, target_domain: Optional[str] = None) -> Dict[str, Any]:
        groups, unresolved_assets, unmapped_assets = self.build_dependency_groups(assets, target_domain)
        summary = {
            "mode": "ip-centric",
            "generated-at": dt.datetime.now().isoformat(timespec="seconds"),
            "assets-total": len(assets),
            "domains-total": sum(1 for asset in assets if asset.target_type == "domain"),
            "subdomains-total": sum(1 for asset in assets if asset.target_type == "subdomain"),
            "direct-ip-inputs-total": sum(1 for asset in assets if asset.target_type == "ip"),
            "ip-groups-total": len(groups),
            "unresolved-assets-total": len(unresolved_assets),
            "unmapped-assets-total": len(unmapped_assets),
            "ports-scanned": "1-65535" if run_config.full_scan else run_config.ports,
            "full-port-scan": run_config.full_scan,
            "cdncheck-enabled": True,
            "cdncheck-matched-ip-groups": 0,
            "ports-stage-ran-for-ip-groups": 0,
            "httpx-stage-ran-for-targets": 0,
            "ip-groups-skipped-by-cdn": 0,
        }
        return {
            "summary": summary,
            "ips": groups,
            "unresolved-assets": unresolved_assets,
            "unmapped-assets": unmapped_assets,
        }

    def build_dependency_groups(
        self,
        assets: List[Any],
        target_domain: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        groups_by_ip: Dict[str, Dict[str, Any]] = {}
        unresolved_assets: List[Dict[str, Any]] = []
        unmapped_assets: List[Dict[str, Any]] = []
        normalized_target_domain = (target_domain or "").strip().lower()

        for asset in assets:
            if asset.target_type == "ip":
                group = groups_by_ip.setdefault(asset.target, self.empty_ip_group(asset.target))
                group["input-ip-assets"].append(self.build_direct_ip_asset_entry(asset))
                continue

            if not asset.target_ip:
                unresolved_assets.append(self.build_unresolved_asset_entry(asset))
                continue

            group = groups_by_ip.setdefault(asset.target_ip, self.empty_ip_group(asset.target_ip))
            if asset.target_type == "domain":
                self.append_unique_httpx_asset(group["domains"], self.build_httpx_asset_entry(asset))
            elif asset.target_type == "subdomain":
                self.append_unique_httpx_asset(group["subdomains"], self.build_httpx_asset_entry(asset))
            else:
                unmapped_assets.append(self.build_unmapped_asset_entry(asset, "unsupported-target-type"))

        return list(groups_by_ip.values()), unresolved_assets, unmapped_assets

    def empty_ip_group(self, ip_value: str) -> Dict[str, Any]:
        return {
            "ip": ip_value,
            "input-ip-assets": [],
            "domains": [],
            "subdomains": [],
            "result-cdncheck": [],
            "result-ports": [],
        }

    def build_direct_ip_asset_entry(self, asset: Any) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"target": asset.target}
        if asset.notes:
            entry["notes"] = asset.notes
        return entry

    def build_httpx_asset_entry(self, asset: Any) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"target": asset.target, "result-httpx": []}
        if asset.notes:
            entry["notes"] = asset.notes
        return entry

    def append_unique_httpx_asset(self, collection: List[Dict[str, Any]], entry: Dict[str, Any]) -> Dict[str, Any]:
        target = str(entry.get("target", "")).strip().lower()
        for existing in collection:
            if str(existing.get("target", "")).strip().lower() == target:
                self.merge_asset_notes(existing, entry)
                return existing
        collection.append(entry)
        return entry

    def merge_asset_notes(self, existing: Dict[str, Any], incoming: Dict[str, Any]) -> None:
        existing_note = str(existing.get("notes", "")).strip()
        incoming_note = str(incoming.get("notes", "")).strip()
        if not incoming_note or incoming_note == existing_note:
            return
        if not existing_note:
            existing["notes"] = incoming_note
            return
        parts = [part.strip() for part in existing_note.split(";") if part.strip()]
        if incoming_note not in parts:
            parts.append(incoming_note)
            existing["notes"] = "; ".join(parts)

    def extract_asset_host(self, value: str) -> str:
        value = str(value).strip()
        if not value:
            return ""
        if value.startswith(("http://", "https://", "//")):
            return self.extract_url_host(value)
        return value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip().rstrip(".").lower()

    def extract_url_host(self, value: str) -> str:
        value = str(value).strip()
        if not value:
            return ""
        parse_value = "https:" + value if value.startswith("//") else value
        if not parse_value.startswith(("http://", "https://")):
            parse_value = "https://" + parse_value
        parsed = urllib.parse.urlparse(parse_value)
        return (parsed.hostname or "").strip().rstrip(".").lower()

    def build_unresolved_asset_entry(self, asset: Any) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "target": asset.target,
            "target-type": asset.target_type,
            "reason": "dns-not-resolved",
            "result-httpx": [{"status": "not-run", "reason": "target-ip-unresolved"}],
        }
        if asset.notes:
            entry["notes"] = asset.notes
        return entry

    def build_unmapped_asset_entry(self, asset: Any, reason: str) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "target": asset.target,
            "target-type": asset.target_type,
            "reason": reason,
            "result-httpx": [{"status": "not-run", "reason": reason}],
        }
        if asset.notes:
            entry["notes"] = asset.notes
        if getattr(asset, "target_ip", None):
            entry["target-ip"] = asset.target_ip
        return entry

    def persist_report(self, report: Optional[Dict[str, Any]], output_path: Any) -> None:
        if report is None:
            return

        diagnostic_payload = {
            "summary": report.get("summary", {}),
            "ips": [self.serialize_ip_group(group) for group in report.get("ips", []) if isinstance(group, dict)],
            "unresolved-assets": [self.serialize_unresolved_asset(item) for item in report.get("unresolved-assets", []) if isinstance(item, dict)],
            "unmapped-assets": [self.serialize_unmapped_asset(item) for item in report.get("unmapped-assets", []) if isinstance(item, dict)],
        }
        diagnostic_path = output_path.with_name(f"{output_path.stem}_pipeline{output_path.suffix}")
        self.atomic_write_json(diagnostic_path, diagnostic_payload)

        import_payload = self.build_recon_import_payload(report)
        self.atomic_write_json(output_path, import_payload)

    def atomic_write_json(self, output_path: Path, payload: Dict[str, Any]) -> None:
        temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(output_path)

    def build_recon_import_payload(self, report: Dict[str, Any]) -> Dict[str, Any]:
        assets: List[Dict[str, Any]] = []
        relations: List[Dict[str, Any]] = []
        bindings: List[Dict[str, Any]] = []
        asset_ids: Dict[Tuple[str, str], int] = {}

        def add_asset(
            value: str,
            asset_type: str,
            notes: str = "",
            ports: Optional[List[Dict[str, Any]]] = None,
            status_code: Optional[int] = None,
        ) -> int:
            key = (asset_type, value.strip().lower())
            if key in asset_ids:
                asset_id = asset_ids[key]
                existing = assets[asset_id - 1]
                if asset_type != "ip" and isinstance(status_code, int) and "statusCode" not in existing:
                    existing["statusCode"] = status_code
                return asset_id
            asset_id = len(assets) + 1
            item: Dict[str, Any] = {"id": asset_id, "value": value, "type": asset_type}
            if notes.strip():
                item["notes"] = notes.strip()
            if asset_type == "ip" and ports:
                item["ports"] = ports
            if asset_type != "ip" and isinstance(status_code, int):
                item["statusCode"] = status_code
            assets.append(item)
            asset_ids[key] = asset_id
            return asset_id

        for group in report.get("ips", []):
            if not isinstance(group, dict):
                continue
            ip_value = str(group.get("ip", "")).strip()
            if not ip_value:
                continue
            ports = self.recon_ports_from_group(group)
            ip_notes = self.recon_asset_notes(self.first_group_ip_notes(group), group)
            ip_id = add_asset(ip_value, "ip", ip_notes, ports)

            domain_entries = [entry for entry in group.get("domains", []) if isinstance(entry, dict)]
            subdomain_entries = [entry for entry in group.get("subdomains", []) if isinstance(entry, dict)]
            host_ids: Dict[str, int] = {}

            for entry in domain_entries:
                host = self.extract_asset_host(str(entry.get("target", "")))
                if not host:
                    continue
                host_notes = self.recon_asset_notes(str(entry.get("notes", "")), group)
                host_id = add_asset(host, "domain", host_notes, status_code=self.httpx_status_code(entry))
                host_ids[host] = host_id
                relations.append(self.recon_relation(ip_id, host_id, "HOSTS"))
                self.append_host_port_bindings(bindings, host_id, ip_id, ports)

            for entry in subdomain_entries:
                host = self.extract_asset_host(str(entry.get("target", "")))
                if not host:
                    continue
                host_notes = self.recon_asset_notes(str(entry.get("notes", "")), group)
                host_id = add_asset(host, "subdomain", host_notes, status_code=self.httpx_status_code(entry))
                host_ids[host] = host_id
                parent_id = self.find_parent_domain_id(host, host_ids)
                if parent_id is not None:
                    relations.append(self.recon_relation(parent_id, host_id, "HAS_SUBDOMAIN"))
                else:
                    relations.append(self.recon_relation(ip_id, host_id, "HOSTS"))
                self.append_host_port_bindings(bindings, host_id, ip_id, ports)

        for item in report.get("unresolved-assets", []):
            if not isinstance(item, dict):
                continue
            target = str(item.get("target", "")).strip()
            asset_type = str(item.get("target-type", "")).strip()
            if target and asset_type in {"domain", "subdomain"}:
                add_asset(target, asset_type, str(item.get("notes", "")), status_code=self.httpx_status_code(item))

        return {"assets": assets, "relations": self.normalize_primary_relations(relations), "portBindings": self.unique_dicts(bindings)}

    def recon_ports_from_group(self, group: Dict[str, Any]) -> List[Dict[str, Any]]:
        ports: List[Dict[str, Any]] = []
        for record in group.get("result-ports", []):
            if not isinstance(record, dict) or not isinstance(record.get("port"), int):
                continue
            item: Dict[str, Any] = {
                "port": record["port"],
                "protocol": str(record.get("protocol") or "tcp"),
                "state": str(record.get("status") or "unknown"),
            }
            for key in ("service", "version"):
                value = record.get(key)
                if isinstance(value, str) and value.strip():
                    item[key] = value.strip()
            ports.append(item)
        return ports

    def first_group_ip_notes(self, group: Dict[str, Any]) -> str:
        for item in group.get("input-ip-assets", []):
            if isinstance(item, dict) and isinstance(item.get("notes"), str) and item["notes"].strip():
                return item["notes"].strip()
        return ""

    def recon_asset_notes(self, raw_notes: str, group: Dict[str, Any]) -> str:
        found = self.recon_found_sources(raw_notes)
        status = self.recon_infrastructure_status(group)
        return f"found: {found} | status: {status}"

    def recon_found_sources(self, raw_notes: str) -> str:
        parts = [part.strip() for part in str(raw_notes or "").split(";") if part.strip()]
        ignored = {"theHarvester", "certificate-transparency", "dns-bruteforce"}
        normalized: List[str] = []
        for part in parts:
            if part in ignored:
                continue
            display = {
                "Certificate Transparency": "Certificate Transparency (crt.sh)",
                "DNS bruteforce": "Gobuster DNS bruteforce",
            }.get(part, part)
            if display not in normalized:
                normalized.append(display)
        return ", ".join(normalized) if normalized else "pipeline discovery"

    def recon_infrastructure_status(self, group: Dict[str, Any]) -> str:
        records = group.get("result-cdncheck", [])
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, dict):
                    continue
                record_type = str(record.get("type", "")).strip().lower()
                if record_type not in {"cdn", "cloud", "waf"}:
                    continue
                provider = str(record.get("provider", "")).strip()
                if provider and provider.lower() != "null":
                    return provider.replace("-", " ").title()
                return record_type.upper() if record_type == "waf" else record_type.title()
        return "On-premises"

    def recon_relation(self, parent_id: int, child_id: int, relation_type: str) -> Dict[str, Any]:
        return {"parentAssetId": parent_id, "childAssetId": child_id, "relationType": relation_type, "isPrimary": True}

    def append_host_port_bindings(self, bindings: List[Dict[str, Any]], asset_id: int, ip_id: int, ports: List[Dict[str, Any]]) -> None:
        # Port bindings represent services that are actually reachable on a related IP.
        # Filtered/unknown ports remain on the IP asset, but are not copied to every host.
        for port in ports:
            if str(port.get("state", "")).lower() != "open":
                continue
            bindings.append({"assetId": asset_id, "ipAssetId": ip_id, "port": port["port"], "protocol": port.get("protocol", "tcp"), "bindingSource": "MANUAL"})

    def httpx_status_code(self, asset_entry: Dict[str, Any]) -> Optional[int]:
        records = asset_entry.get("result-httpx", [])
        if not isinstance(records, list):
            return None
        for record in records:
            if not isinstance(record, dict):
                continue
            value = record.get("status-code")
            if isinstance(value, int) and 100 <= value <= 599:
                return value
            if isinstance(value, str) and value.isdigit():
                parsed = int(value)
                if 100 <= parsed <= 599:
                    return parsed
        return None

    def find_parent_domain_id(self, host: str, host_ids: Dict[str, int]) -> Optional[int]:
        candidates = [candidate for candidate in host_ids if host.endswith(f".{candidate}")]
        if not candidates:
            return None
        parent = max(candidates, key=len)
        return host_ids[parent]

    def normalize_primary_relations(self, relations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique = self.unique_dicts(relations)
        primary_children: set[int] = set()
        for relation in unique:
            child_id = int(relation.get("childAssetId", 0))
            relation["isPrimary"] = child_id not in primary_children
            primary_children.add(child_id)
        return unique

    def unique_dicts(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for item in items:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    def serialize_ip_group(self, group: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ip": group.get("ip"),
            "input-ip-assets": [self.serialize_direct_asset(item) for item in group.get("input-ip-assets", []) if isinstance(item, dict)],
            "domains": [self.serialize_httpx_asset(item) for item in group.get("domains", []) if isinstance(item, dict)],
            "subdomains": [self.serialize_httpx_asset(item) for item in group.get("subdomains", []) if isinstance(item, dict)],
            "result-cdncheck": group.get("result-cdncheck", []),
            "result-ports": group.get("result-ports", []),
        }

    def serialize_direct_asset(self, item: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {"target": item.get("target")}
        notes = item.get("notes")
        if isinstance(notes, str) and notes.strip():
            result["notes"] = notes.strip()
        return result

    def serialize_httpx_asset(self, item: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {"target": item.get("target")}
        notes = item.get("notes")
        if isinstance(notes, str) and notes.strip():
            result["notes"] = notes.strip()
        result["result-httpx"] = item.get("result-httpx", [])
        return result

    def serialize_unresolved_asset(self, item: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "target": item.get("target"),
            "target-type": item.get("target-type"),
            "reason": item.get("reason"),
            "result-httpx": item.get("result-httpx", []),
        }
        notes = item.get("notes")
        if isinstance(notes, str) and notes.strip():
            result["notes"] = notes.strip()
        return result

    def serialize_unmapped_asset(self, item: Dict[str, Any]) -> Dict[str, Any]:
        result = self.serialize_unresolved_asset(item)
        target_ip = item.get("target-ip")
        if isinstance(target_ip, str) and target_ip.strip():
            result["target-ip"] = target_ip.strip()
        return result

    def run_httpx_single(self, target: str, httpx_path: str) -> Dict[str, Any]:
        args = [
            httpx_path,
            "-u",
            target,
            "-json",
            "-probe",
            "-status-code",
            "-ip",
            "-location",
            "-fr",
            "-include-chain",
            "-silent",
        ]
        completed = run_command(args, label=f"httpx {target}", timeout=900, check=False, show_spinner=False)
        parsed = self.parse_jsonl(completed.stdout)
        return {"records": self.concise_httpx_records(parsed), "target-ip": self.first_httpx_host_ip(parsed)}

    def run_cdncheck_single(self, host: str, cdncheck_path: str) -> List[Dict[str, Any]]:
        args = [cdncheck_path, "-i", host, "-j", "-resp", "-silent"]
        completed = run_command(args, label=f"cdncheck {host}", timeout=300, check=False, show_spinner=False)
        return self.concise_cdncheck_records(self.parse_jsonl(completed.stdout))

    def run_nmap_single(self, host: str, nmap_path: str, run_config: RunConfig) -> List[Dict[str, Any]]:
        if run_config.full_scan:
            return self.run_nmap_full_scan(host, nmap_path)

        args = [nmap_path]
        if self.is_ipv6_target(host):
            args.append("-6")
        args.extend([
            "-Pn", "-n", "-sV", "-T4", "--max-retries", "2",
            "--host-timeout", "10m", "-p", run_config.ports_csv, "-oX", "-", host,
        ])
        completed = run_command(args, label=f"nmap {host}", timeout=660, check=False, show_spinner=False)
        return self.concise_nmap_ports(
            self.parse_nmap_xml(
                completed.stdout,
                include_closed=True,
                expand_extraports=True,
                requested_ports=set(run_config.ports),
            )
        )

    def run_nmap_full_scan(self, host: str, nmap_path: str) -> List[Dict[str, Any]]:
        discovery_args = [nmap_path]
        if self.is_ipv6_target(host):
            discovery_args.append("-6")
        discovery_args.extend([
            "-Pn", "-n", "-p-", "-T4", "--min-rate", "1000",
            "--max-retries", "2", "--host-timeout", "15m", "-oX", "-", host,
        ])
        discovery = run_command(
            discovery_args, label=f"nmap full discovery {host}", timeout=960,
            check=False, show_spinner=False,
        )
        discovered = self.concise_nmap_ports(
            self.parse_nmap_xml(discovery.stdout, include_closed=False, expand_extraports=False)
        )
        open_ports = sorted({
            int(record["port"]) for record in discovered
            if isinstance(record, dict) and isinstance(record.get("port"), int)
            and str(record.get("status", "")).lower() == "open"
        })
        if not open_ports:
            return discovered

        service_args = [nmap_path]
        if self.is_ipv6_target(host):
            service_args.append("-6")
        service_args.extend([
            "-Pn", "-n", "-sV", "-T4", "--max-retries", "2",
            "--host-timeout", "5m", "-p", ",".join(str(port) for port in open_ports),
            "-oX", "-", host,
        ])
        try:
            service_scan = run_command(
                service_args, label=f"nmap service detection {host}", timeout=360,
                check=False, show_spinner=False,
            )
            enriched = self.concise_nmap_ports(
                self.parse_nmap_xml(service_scan.stdout, include_closed=False, expand_extraports=False)
            )
            merged = self.merge_nmap_discovery_and_services(discovered, enriched)
            return [
                record for record in merged
                if record.get("summary") is True or str(record.get("status", "")).lower() == "open"
            ]
        except Exception:
            return [
                record for record in discovered
                if record.get("summary") is True or str(record.get("status", "")).lower() == "open"
            ]

    def merge_nmap_discovery_and_services(
        self, discovery: List[Dict[str, Any]], services: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        service_index = {
            (record.get("port"), record.get("protocol", "tcp")): record
            for record in services if isinstance(record, dict) and isinstance(record.get("port"), int)
        }
        merged: List[Dict[str, Any]] = []
        for record in discovery:
            item = dict(record)
            detail = service_index.get((record.get("port"), record.get("protocol", "tcp")))
            if detail:
                for key in ("service", "version"):
                    value = detail.get(key)
                    if value not in (None, ""):
                        item[key] = value
            merged.append(item)
        return self.concise_nmap_ports(merged)

    def is_ipv6_target(self, value: str) -> bool:
        try:
            parsed_ip = ipaddress.ip_address(value)
            return parsed_ip.version == 6
        except ValueError:
            pass

        try:
            parsed_network = ipaddress.ip_network(value, strict=False)
            return parsed_network.version == 6
        except ValueError:
            return False

    def concise_httpx_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        concise: List[Dict[str, Any]] = []
        seen: set[Tuple[Any, ...]] = set()
        for record in records:
            final_url = record.get("final_url")
            item: Dict[str, Any] = {
                "url": final_url if isinstance(final_url, str) and final_url.strip() else record.get("url"),
                "status-code": record.get("status_code"),
            }
            if self.httpx_has_redirect(record):
                item["redirect"] = True
            item = {key: value for key, value in item.items() if value not in (None, "", [], {})}
            if not item:
                continue
            key_tuple = tuple((k, json.dumps(v, sort_keys=True, ensure_ascii=False)) for k, v in sorted(item.items()))
            if key_tuple not in seen:
                seen.add(key_tuple)
                concise.append(item)
        return concise

    def httpx_has_redirect(self, record: Dict[str, Any]) -> bool:
        chain_status_codes = record.get("chain_status_codes")
        if isinstance(chain_status_codes, list) and len(chain_status_codes) > 1:
            return True

        chain = record.get("chain")
        if isinstance(chain, list) and len(chain) > 1:
            return True

        final_url = str(record.get("final_url", "")).strip()
        base_url = str(record.get("url", "")).strip()
        if final_url and base_url and final_url != base_url:
            return True

        return False

    def first_httpx_host_ip(self, records: List[Dict[str, Any]]) -> Optional[str]:
        for record in records:
            host_ip = record.get("host_ip")
            if isinstance(host_ip, str) and host_ip.strip():
                return host_ip.strip()
        return None

    def concise_cdncheck_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        concise: List[Dict[str, Any]] = []
        seen: set[Tuple[Any, ...]] = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            typed = self.parse_cdncheck_record(record)
            for item in typed:
                key_tuple = tuple((k, json.dumps(v, sort_keys=True, ensure_ascii=False)) for k, v in sorted(item.items()))
                if key_tuple not in seen:
                    seen.add(key_tuple)
                    concise.append(item)
        return concise

    def parse_cdncheck_record(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        explicit_type = str(record.get("type", "")).strip().lower()
        if explicit_type in {"cdn", "cloud", "waf"}:
            entry: Dict[str, Any] = {"type": explicit_type}
            provider = self.first_text_value(record, ["value", "provider", "name", "matched", "response", f"{explicit_type}_name", f"{explicit_type}-name"])
            if provider:
                entry["provider"] = provider
            entries.append(entry)
            return entries

        for flag_key, entry_type, provider_keys in [
            ("cdn", "cdn", ["cdn-name", "cdn_name", "provider", "value", "response"]),
            ("cloud", "cloud", ["cloud-name", "cloud_name", "provider", "value", "response"]),
            ("waf", "waf", ["waf-name", "waf_name", "provider", "value", "response"]),
        ]:
            if not self.record_bool(record, flag_key):
                continue
            entry = {"type": entry_type}
            provider = self.first_text_value(record, provider_keys)
            if provider and provider.lower() not in {"true", "false"}:
                entry["provider"] = provider
            entries.append(entry)
        return entries

    def parse_nmap_xml(
        self,
        raw_text: str,
        *,
        include_closed: bool = False,
        expand_extraports: bool = False,
        requested_ports: Optional[set[int]] = None,
    ) -> List[Dict[str, Any]]:
        if not raw_text.strip():
            return []
        try:
            root = ET.fromstring(raw_text)
        except ET.ParseError:
            return []

        results: List[Dict[str, Any]] = []
        scanned_ports = self.nmap_scanned_ports(root)
        if requested_ports:
            scanned_ports["tcp"] = set(requested_ports)

        for host_el in root.findall("host"):
            ports_parent = host_el.find("ports")
            if ports_parent is None:
                continue

            explicit_by_protocol: Dict[str, set[int]] = {}
            for port_el in ports_parent.findall("port"):
                state_el = port_el.find("state")
                if state_el is None:
                    continue
                raw_state = (state_el.attrib.get("state") or "").strip().lower()
                state = self.normalize_nmap_port_state(raw_state, include_closed=include_closed)
                try:
                    port = int(port_el.attrib.get("portid", "0"))
                except ValueError:
                    continue
                protocol = (port_el.attrib.get("protocol") or "tcp").strip().lower()
                explicit_by_protocol.setdefault(protocol, set()).add(port)
                if state is None:
                    continue
                item: Dict[str, Any] = {"port": port, "protocol": protocol, "status": state}
                service_el = port_el.find("service")
                if service_el is not None:
                    service_name = self.pick_service_name(service_el)
                    version_text = self.build_service_version(service_el)
                    if service_name and service_name.lower() not in {"unknown", "tcpwrapped"}:
                        item["service"] = service_name
                    if version_text:
                        item["version"] = version_text
                results.append(item)

            for extra_el in ports_parent.findall("extraports"):
                raw_state = (extra_el.attrib.get("state") or "").strip().lower()
                state = self.normalize_nmap_port_state(raw_state, include_closed=include_closed)
                if state is None:
                    continue
                try:
                    count = int(extra_el.attrib.get("count", "0"))
                except ValueError:
                    count = 0
                if count <= 0:
                    continue

                if expand_extraports:
                    # Selected/custom profiles are intentionally small. Reconstruct
                    # only the actually requested ports so every selected port gets
                    # an explicit Recon state without ever expanding a full -p- scan.
                    for protocol, selected in scanned_ports.items():
                        omitted = sorted(selected - explicit_by_protocol.get(protocol, set()))
                        for port in omitted:
                            results.append({"port": port, "protocol": protocol, "status": state})
                    continue

                # Full scans keep mass states as one compact diagnostic record.
                results.append({
                    "summary": True,
                    "status": state,
                    "raw-state": raw_state or state,
                    "count": count,
                })
        return results

    def nmap_scanned_ports(self, root: ET.Element) -> Dict[str, set[int]]:
        scanned: Dict[str, set[int]] = {}
        for scaninfo in root.findall("scaninfo"):
            protocol = (scaninfo.attrib.get("protocol") or "tcp").strip().lower()
            services = (scaninfo.attrib.get("services") or "").strip()
            if not services:
                continue
            scanned.setdefault(protocol, set()).update(self.expand_nmap_port_spec(services))
        return scanned

    def expand_nmap_port_spec(self, value: str) -> set[int]:
        ports: set[int] = set()
        for token in str(value or "").split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                start_text, end_text = token.split("-", 1)
                try:
                    start_port = int(start_text)
                    end_port = int(end_text)
                except ValueError:
                    continue
                if 0 <= start_port <= end_port <= 65535:
                    ports.update(range(start_port, end_port + 1))
                continue
            try:
                port = int(token)
            except ValueError:
                continue
            if 0 <= port <= 65535:
                ports.add(port)
        return ports

    def normalize_nmap_port_state(self, raw_state: str, *, include_closed: bool = False) -> Optional[str]:
        state = str(raw_state or "").strip().lower()
        if state == "open":
            return "open"
        if state == "filtered":
            return "filtered"
        if state == "closed":
            return "closed" if include_closed else None
        if state:
            return "unknown"
        return None

    def pick_service_name(self, service_el: ET.Element) -> Optional[str]:
        product = (service_el.attrib.get("product") or "").strip()
        name = (service_el.attrib.get("name") or "").strip()
        tunnel = (service_el.attrib.get("tunnel") or "").strip()
        if product:
            return product
        if tunnel and name:
            return f"{tunnel}/{name}"
        if name:
            return name
        return None

    def build_service_version(self, service_el: ET.Element) -> Optional[str]:
        pieces: List[str] = []
        version = (service_el.attrib.get("version") or "").strip()
        extrainfo = (service_el.attrib.get("extrainfo") or "").strip()
        ostype = (service_el.attrib.get("ostype") or "").strip()
        if version:
            pieces.append(version)
        if extrainfo:
            pieces.append(extrainfo)
        if ostype:
            pieces.append(ostype)
        return " | ".join(pieces) if pieces else None

    def concise_nmap_ports(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        concise: List[Dict[str, Any]] = []
        seen: set[Tuple[Any, ...]] = set()
        for record in records:
            if record.get("summary") is True:
                item = {
                    "summary": True,
                    "status": str(record.get("status") or "unknown"),
                    "raw-state": str(record.get("raw-state") or record.get("status") or "unknown"),
                    "count": int(record.get("count") or 0),
                }
                notes = record.get("notes")
                if isinstance(notes, str) and notes.strip():
                    item["notes"] = notes.strip()
                if item["count"] <= 0:
                    continue
            else:
                port = record.get("port")
                status = record.get("status")
                if port is None or not status:
                    continue
                item = {"port": int(port), "protocol": str(record.get("protocol") or "tcp"), "status": str(status)}
                service = record.get("service")
                version = record.get("version")
                notes = record.get("notes")
                if isinstance(service, str) and service.strip():
                    item["service"] = service.strip()
                if isinstance(version, str) and version.strip():
                    item["version"] = version.strip()
                if isinstance(notes, str) and notes.strip():
                    item["notes"] = notes.strip()
            key_tuple = tuple((k, json.dumps(v, sort_keys=True, ensure_ascii=False)) for k, v in sorted(item.items()))
            if key_tuple not in seen:
                seen.add(key_tuple)
                concise.append(item)
        concise.sort(key=lambda x: (x.get("summary") is True, int(x.get("port", 0))))
        return concise

    def first_text_value(self, record: Dict[str, Any], keys: List[str]) -> Optional[str]:
        for key in keys:
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def parse_jsonl(self, raw_text: str) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
        return records

    def build_ip_group_map(self, ip_groups: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        return {str(group.get("ip")): group for group in ip_groups if isinstance(group, dict) and group.get("ip")}

    def iter_httpx_assets(self, report: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        for group in report.get("ips", []):
            if not isinstance(group, dict):
                continue
            for key in ("domains", "subdomains"):
                for asset in group.get(key, []):
                    if not isinstance(asset, dict):
                        continue
                    yield asset


    def collect_resolved_http_targets(self, report: Dict[str, Any]) -> List[str]:
        targets: List[str] = []
        seen: set[str] = set()
        for asset in self.iter_httpx_assets(report):
            target = str(asset.get("target", "")).strip()
            if target and target not in seen:
                seen.add(target)
                targets.append(target)
        return targets

    def apply_httpx_single_result(self, report: Dict[str, Any], target: str, payload: Dict[str, Any]) -> None:
        records = payload.get("records", []) if isinstance(payload, dict) else []
        final_records = records if records else [{"status": "no-http-response"}]
        for asset in self.iter_httpx_assets(report):
            if asset.get("target") == target:
                asset["result-httpx"] = final_records

    def apply_cdncheck_single_result(self, report: Dict[str, Any], cdn_map: Dict[str, List[Dict[str, Any]]], ip_value: str, records: List[Dict[str, Any]]) -> None:
        actual_records = records if records else []
        final_records = actual_records if actual_records else [self.empty_cdncheck_record()]
        cdn_map[ip_value] = actual_records
        for group in report.get("ips", []):
            if isinstance(group, dict) and group.get("ip") == ip_value:
                group["result-cdncheck"] = final_records
                break

    def apply_ports_single_result(self, report: Dict[str, Any], ip_value: str, records: List[Dict[str, Any]]) -> None:
        final_records = records if records else [{"status": "no-open-or-filtered-ports-detected"}]
        for group in report.get("ips", []):
            if isinstance(group, dict) and group.get("ip") == ip_value:
                group["result-ports"] = final_records
                break

    def initialize_port_scan_notes(self, report: Dict[str, Any], cdn_map: Dict[str, List[Dict[str, Any]]], attempted_ips: List[str]) -> None:
        attempted_set = set(attempted_ips)
        for group in report.get("ips", []):
            if not isinstance(group, dict):
                continue
            ip_value = str(group.get("ip", "")).strip()
            if not ip_value or ip_value in attempted_set:
                continue
            reason = self.first_cdn_reason(cdn_map.get(ip_value, [])) or "not-eligible-for-port-scan"
            group["result-ports"] = [{"status": "not-scanned", "reason": reason}]

    def first_cdn_reason(self, cdn_records: List[Dict[str, Any]]) -> Optional[str]:
        for record in cdn_records:
            record_type = str(record.get("type", "")).strip().lower()
            if record_type not in {"cdn", "cloud", "waf"}:
                continue
            provider = str(record.get("provider", "")).strip()
            if provider:
                return f"{record_type} detected: {provider}"
            return f"{record_type} detected"
        return None

    def should_skip_ports_for_cdn(self, cdn_records: List[Dict[str, Any]]) -> bool:
        return self.first_cdn_reason(cdn_records) is not None

    def has_cdn_detection(self, cdn_records: List[Dict[str, Any]]) -> bool:
        return self.first_cdn_reason(cdn_records) is not None

    def empty_cdncheck_record(self) -> Dict[str, Any]:
        return {"type": "null", "provider": "null"}

    def update_runtime_summary(self, report: Dict[str, Any], cdn_map: Dict[str, List[Dict[str, Any]]], run_port_ips: List[str], httpx_targets: List[str]) -> None:
        summary = report.setdefault("summary", {})
        summary["cdncheck-matched-ip-groups"] = sum(1 for records in cdn_map.values() if self.has_cdn_detection(records))
        summary["ports-stage-ran-for-ip-groups"] = len(run_port_ips)
        summary["httpx-stage-ran-for-targets"] = len(httpx_targets)
        summary["ip-groups-skipped-by-cdn"] = sum(1 for records in cdn_map.values() if self.should_skip_ports_for_cdn(records))

    def finalize_report_summary(self, report: Dict[str, Any]) -> None:
        summary = report.setdefault("summary", {})
        summary["generated-at"] = dt.datetime.now().isoformat(timespec="seconds")
        summary["resolved-ip-groups-total"] = len([group for group in report.get("ips", []) if isinstance(group, dict) and group.get("ip")])
        summary["unresolved-assets-total"] = len([item for item in report.get("unresolved-assets", []) if isinstance(item, dict)])
        summary["unmapped-assets-total"] = len([item for item in report.get("unmapped-assets", []) if isinstance(item, dict)])

    def record_bool(self, record: Dict[str, Any], key: str) -> bool:
        value = record.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes"}
        return False


_orchestrator = PipelineOrchestratorService()
console_main = _orchestrator.console_main
