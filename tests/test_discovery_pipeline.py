import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from asset_pipeline.services.input_service import InputService
from asset_pipeline.services.orchestrator_service import PipelineOrchestratorService
from asset_pipeline.services.tool_service import ToolService
from asset_pipeline.shared import InputValidationError, RunConfig


class DiscoveryPipelineTests(unittest.TestCase):
    def setUp(self):
        self.orchestrator = PipelineOrchestratorService()

    def test_optional_tools_follow_dns_configuration(self):
        enabled = RunConfig(ports=[80, 443], dns_bruteforce_profile="medium")
        disabled = RunConfig(ports=[80, 443], dns_bruteforce_profile="disabled")
        self.assertEqual(ToolService().selected_tool_names(enabled), ["theharvester", "httpx", "cdncheck", "nmap", "gobuster"])
        self.assertEqual(ToolService().selected_tool_names(disabled), ["theharvester", "httpx", "cdncheck", "nmap"])

    def test_merge_discovery_sources_deduplicates_and_preserves_notes(self):
        payload = self.orchestrator.merge_discovered_assets(
            {
                "theHarvester": [{"value": "api.example.com", "type": "subdomain"}],
                "certificate-transparency": [{"value": "api.example.com", "type": "subdomain"}],
            },
            "example.com",
        )
        self.assertEqual(len(payload), 2)
        api = next(item for item in payload if item["value"] == "api.example.com")
        self.assertIn("theHarvester", api["notes"])
        self.assertIn("certificate-transparency", api["notes"])

    def test_status_filter_removes_hosts_outside_allowlist(self):
        report = {"ips": [{"ip": "198.51.100.1", "input-ip-assets": [], "domains": [
            {"target": "example.com", "result-httpx": [{"status-code": 200}]},
            {"target": "blocked.example.com", "result-httpx": [{"status-code": 403}]},
        ], "subdomains": []}]}
        removed = self.orchestrator.apply_http_status_filter(report, [200])
        self.assertEqual(removed, 1)
        self.assertEqual([item["target"] for item in report["ips"][0]["domains"]], ["example.com"])

    def test_status_class_selection_expands_ranges(self):
        service = InputService()
        with patch("builtins.input", side_effect=["3", "2xx 3xx"]):
            with redirect_stdout(io.StringIO()):
                codes = service.configure_status_codes()
        self.assertEqual(len(codes), 200)
        self.assertIn(200, codes)
        self.assertIn(399, codes)
        self.assertNotIn(400, codes)
        self.assertEqual(RunConfig(ports=[443], status_codes=codes).status_filter_display, "2xx 3xx")

    def test_status_class_rejects_invalid_value(self):
        service = InputService()
        with patch("builtins.input", side_effect=["3", "2xx 6xx"]):
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(InputValidationError):
                    service.configure_status_codes()

    def test_custom_wordlist_requires_one_dns_label_per_line(self):
        service = InputService()
        with tempfile.TemporaryDirectory() as directory:
            valid = Path(directory) / "valid.txt"
            valid.write_text("api\nadmin-panel\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                service.validate_custom_wordlist(valid)
            invalid = Path(directory) / "invalid.txt"
            invalid.write_text("https://api.example.com\n", encoding="utf-8")
            with self.assertRaises(InputValidationError):
                service.validate_custom_wordlist(invalid)

    def test_theharvester_urls_are_not_exported_as_assets(self):
        raw = {"hosts": ["api.example.com"], "urls": ["https://api.example.com/private"]}
        assets = self.orchestrator.convert_theharvester_json_to_assets("example.com", raw)
        self.assertEqual({item["type"] for item in assets}, {"domain", "subdomain"})


    def test_full_nmap_scan_uses_two_pass_strategy(self):
        discovery_xml = """<?xml version='1.0'?><nmaprun><host><ports>
        <port protocol='tcp' portid='80'><state state='open'/></port>
        <port protocol='tcp' portid='443'><state state='filtered'/></port>
        </ports></host></nmaprun>"""
        service_xml = """<?xml version='1.0'?><nmaprun><host><ports>
        <port protocol='tcp' portid='80'><state state='open'/><service name='http' product='nginx' version='1.24'/></port>
        </ports></host></nmaprun>"""
        completed = [
            subprocess.CompletedProcess([], 0, discovery_xml, ""),
            subprocess.CompletedProcess([], 0, service_xml, ""),
        ]
        with patch("asset_pipeline.services.orchestrator_service.run_command", side_effect=completed) as mocked:
            records = self.orchestrator.run_nmap_single("198.51.100.5", "/usr/bin/nmap", RunConfig(ports=[], full_scan=True))
        self.assertEqual(mocked.call_count, 2)
        first_args = mocked.call_args_list[0].args[0]
        second_args = mocked.call_args_list[1].args[0]
        self.assertIn("-p-", first_args)
        self.assertNotIn("-sV", first_args)
        self.assertIn("--host-timeout", first_args)
        self.assertIn("-sV", second_args)
        self.assertIn("80", second_args)
        self.assertNotIn("443", second_args[-4])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "open")
        self.assertEqual(records[0]["service"], "nginx")

    def test_nmap_port_states_are_normalized_for_recon(self):
        xml = """<?xml version='1.0'?><nmaprun><host><ports>
        <port protocol='tcp' portid='22'><state state='open'/></port>
        <port protocol='tcp' portid='25'><state state='closed'/></port>
        <port protocol='tcp' portid='53'><state state='filtered'/></port>
        <port protocol='tcp' portid='161'><state state='open|filtered'/></port>
        <port protocol='tcp' portid='8080'><state state='unfiltered'/></port>
        </ports></host></nmaprun>"""
        records = self.orchestrator.concise_nmap_ports(
            self.orchestrator.parse_nmap_xml(xml, include_closed=True, expand_extraports=True)
        )
        by_port = {record["port"]: record for record in records}
        self.assertEqual(by_port[22]["status"], "open")
        self.assertEqual(by_port[25]["status"], "closed")
        self.assertEqual(by_port[53]["status"], "filtered")
        self.assertEqual(by_port[161]["status"], "unknown")
        self.assertEqual(by_port[8080]["status"], "unknown")

    def test_nmap_extraports_are_kept_as_compact_summary(self):
        xml = """<?xml version='1.0'?><nmaprun>
        <scaninfo type='syn' protocol='tcp' numservices='4' services='80-83'/>
        <host><ports>
          <extraports state='filtered' count='3'/>
          <port protocol='tcp' portid='80'><state state='open'/></port>
        </ports></host></nmaprun>"""
        records = self.orchestrator.concise_nmap_ports(self.orchestrator.parse_nmap_xml(xml))
        ports = [record for record in records if isinstance(record.get("port"), int)]
        summaries = [record for record in records if record.get("summary") is True]
        self.assertEqual(ports, [{"port": 80, "protocol": "tcp", "status": "open"}])
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["status"], "filtered")
        self.assertEqual(summaries[0]["count"], 3)

    def test_recon_export_supports_all_selected_profile_states(self):
        group = {"result-ports": [
            {"port": 22, "protocol": "tcp", "status": "open"},
            {"port": 25, "protocol": "tcp", "status": "closed"},
            {"port": 53, "protocol": "tcp", "status": "filtered"},
            {"port": 161, "protocol": "udp", "status": "unknown"},
        ]}
        ports = self.orchestrator.recon_ports_from_group(group)
        self.assertEqual([item["state"] for item in ports], ["open", "closed", "filtered", "unknown"])
        self.assertNotIn("notes", ports[3])

    def test_selected_profile_expands_only_requested_extraports(self):
        xml = """<?xml version='1.0'?><nmaprun>
        <scaninfo type='syn' protocol='tcp' numservices='3' services='22,80,443'/>
        <host><ports>
          <extraports state='closed' count='2'/>
          <port protocol='tcp' portid='443'><state state='open'/></port>
        </ports></host></nmaprun>"""
        records = self.orchestrator.concise_nmap_ports(
            self.orchestrator.parse_nmap_xml(
                xml,
                include_closed=True,
                expand_extraports=True,
                requested_ports={22, 80, 443},
            )
        )
        by_port = {record["port"]: record["status"] for record in records}
        self.assertEqual(by_port, {22: "closed", 80: "closed", 443: "open"})

    def test_mocked_end_to_end_pipeline_writes_import_contract(self):
        class FakeInputService(InputService):
            def resolve_host_ip(self, host):
                return "198.51.100.27"

        class FakeOrchestrator(PipelineOrchestratorService):
            def run_theharvester_stage(self, **kwargs):
                return ({}, Path(kwargs["raw_output_base_path"]).with_suffix(".json"), [
                    {"value": "example.com", "type": "domain"},
                    {"value": "api.example.com", "type": "subdomain"},
                ], 0)
            def run_certificate_transparency_stage(self, target_domain):
                return [{"value": "admin.example.com", "type": "subdomain"}]
            def run_httpx_single(self, target, httpx_path):
                return {"records": [{"url": f"https://{target}", "status-code": 200}]}
            def run_cdncheck_single(self, host, cdncheck_path):
                return []
            def run_nmap_single(self, host, nmap_path, run_config):
                return [{"port": 443, "protocol": "tcp", "status": "open", "service": "HTTPS"}]

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            orchestrator = FakeOrchestrator(input_service=FakeInputService())
            report = orchestrator.run_pipeline(
                "example.com",
                {"theharvester": "fake", "httpx": "fake", "cdncheck": "fake", "nmap": "fake"},
                RunConfig(ports=[443]), output, Path(directory) / "raw", [],
            )
            payload = orchestrator.build_recon_import_payload(report)
            self.assertEqual(set(payload), {"assets", "relations", "portBindings"})
            self.assertFalse(any(asset["type"] == "url" for asset in payload["assets"]))
            self.assertTrue(any(asset["type"] == "ip" and asset.get("ports") for asset in payload["assets"]))

    def test_dns_bruteforce_uses_visible_paced_gobuster(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "dns.txt"
            wordlist.write_text("www\napi\n", encoding="utf-8")
            completed = subprocess.CompletedProcess([], 0, "Found: api.example.com\n", "")
            with patch.object(self.orchestrator, "detect_wildcard_dns", return_value=[]), \
                 patch.object(self.orchestrator, "run_command_with_live_progress", return_value=completed) as mocked:
                with redirect_stdout(io.StringIO()):
                    assets = self.orchestrator.run_dns_bruteforce_stage("example.com", "/usr/bin/gobuster", wordlist)
            command = mocked.call_args.kwargs["command"]
            self.assertIn("--delay", command)
            delay = command[command.index("--delay") + 1]
            self.assertEqual(delay, "250ms")
            self.assertIn("-t", command)
            self.assertEqual(command[command.index("-t") + 1], "1")
            self.assertEqual([item["value"] for item in assets], ["api.example.com"])


    def test_dns_bruteforce_skips_wildcard_dns(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "dns.txt"
            wordlist.write_text("www\napi\n", encoding="utf-8")
            with patch.object(self.orchestrator, "detect_wildcard_dns", return_value=["31.44.9.64"]), \
                 patch.object(self.orchestrator, "run_command_with_live_progress") as mocked:
                with redirect_stdout(io.StringIO()):
                    assets = self.orchestrator.run_dns_bruteforce_stage("example.com", "/usr/bin/gobuster", wordlist)
            self.assertEqual(assets, [])
            mocked.assert_not_called()



if __name__ == "__main__":
    unittest.main()
