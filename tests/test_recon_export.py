import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from asset_pipeline.services.orchestrator_service import PipelineOrchestratorService
from asset_pipeline.shared import RunConfig


class ReconExportTests(unittest.TestCase):
    def test_full_scan_selection_alias(self):
        config = RunConfig(ports=[], full_scan=True)
        self.assertEqual(config.ports_csv, "-")
        self.assertEqual(config.ports_display, "full scan (1-65535)")

    def test_recon_export_without_url_assets(self):
        report = {
            "summary": {},
            "ips": [{
                "ip": "198.51.100.27",
                "input-ip-assets": [{"target": "198.51.100.27", "notes": "API gateway VIP"}],
                "domains": [{"target": "example.com", "result-httpx": [{"status-code": 200}]}],
                "subdomains": [{"target": "api.example.com", "result-httpx": [{"status-code": 201}]}],
                "result-cdncheck": [],
                "result-ports": [
                    {"port": 80, "protocol": "tcp", "status": "open", "service": "nginx"},
                    {"port": 443, "protocol": "tcp", "status": "open", "service": "HTTPS"},
                ],
            }],
            "unresolved-assets": [],
            "unmapped-assets": [],
        }
        payload = PipelineOrchestratorService().build_recon_import_payload(report)
        self.assertEqual(set(payload), {"assets", "relations", "portBindings"})
        self.assertEqual([asset["type"] for asset in payload["assets"]], ["ip", "domain", "subdomain"])
        self.assertEqual(payload["assets"][1]["statusCode"], 200)
        self.assertEqual(payload["assets"][2]["statusCode"], 201)
        self.assertTrue(any(r["relationType"] == "HOSTS" for r in payload["relations"]))
        self.assertTrue(any(r["relationType"] == "HAS_SUBDOMAIN" for r in payload["relations"]))
        self.assertTrue(all(r["relationType"] in {"HOSTS", "HAS_SUBDOMAIN"} for r in payload["relations"]))
        self.assertTrue(all(b["bindingSource"] == "MANUAL" for b in payload["portBindings"]))
        self.assertEqual(payload["assets"][0]["notes"], "found: API gateway VIP | status: On-premises")
        self.assertEqual(payload["assets"][1]["notes"], "found: pipeline discovery | status: On-premises")

    def test_recon_notes_include_cloud_provider(self):
        report = {
            "summary": {},
            "ips": [{
                "ip": "203.0.113.10",
                "input-ip-assets": [{"target": "203.0.113.10", "notes": "theHarvester ips; theHarvester"}],
                "domains": [],
                "subdomains": [{"target": "api.example.com", "notes": "theHarvester hosts; Certificate Transparency; certificate-transparency"}],
                "result-cdncheck": [{"type": "waf", "provider": "cloudflare"}],
                "result-ports": [{"status": "not-scanned", "reason": "waf detected: cloudflare"}],
            }],
            "unresolved-assets": [],
            "unmapped-assets": [],
        }
        payload = PipelineOrchestratorService().build_recon_import_payload(report)
        self.assertEqual(payload["assets"][0]["notes"], "found: theHarvester ips | status: Cloudflare")
        self.assertEqual(payload["assets"][1]["notes"], "found: theHarvester hosts, Certificate Transparency (crt.sh) | status: Cloudflare")

    def test_port_bindings_include_only_open_ports(self):
        bindings = []
        ports = [
            {"port": 80, "protocol": "tcp", "state": "open"},
            {"port": 443, "protocol": "tcp", "state": "filtered"},
            {"port": 8080, "protocol": "tcp", "state": "unknown"},
        ]
        PipelineOrchestratorService().append_host_port_bindings(bindings, 2, 1, ports)
        self.assertEqual(bindings, [{
            "assetId": 2, "ipAssetId": 1, "port": 80,
            "protocol": "tcp", "bindingSource": "MANUAL",
        }])


if __name__ == "__main__":
    unittest.main()
