# Asset Toolchain Pipeline

Asset Toolchain Pipeline is a console-based reconnaissance pipeline for collecting, enriching, and structuring external assets around IP groups.

The project starts from a single target domain, runs **theHarvester**, keeps a compact raw OSINT snapshot, converts discovered hosts/IPs/URLs into internal assets, then runs **cdncheck**, **httpx**, and **nmap** to build a final IP-centric JSON report.

---

## 1. Download, install, and run

### Requirements

- Linux environment
- Python 3.10+
- Git
- Internet access for first-time tool installation
- Optional but recommended: `uv` for theHarvester source installation
- Optional but recommended: Go toolchain for ProjectDiscovery tool fallback installation
- `nmap` available in PATH, or a Debian/Ubuntu system where it can be installed through `apt`

The Python project itself uses the standard library only. External recon tools are checked and installed by the pipeline when they are missing.

### Download and run

Clone the repository:

```bash
git clone git@github.com:eZer-Net/asset-toolchain-pipeline.git
cd asset-toolchain-pipeline
```

### Run with a target argument

```bash
python3 app.py example.com
```

### Run interactively

```bash
python3 app.py
```

Interactive mode asks for the domain:

```text
Add target domain:
> example.com
```

After the target is selected, the pipeline asks for ports. Press Enter to keep the default port set, or provide a comma-separated list such as:

```text
80,443,8080,8443
```

### Tool installation behavior

The pipeline checks these tools:

```text
theHarvester
httpx
cdncheck
nmap
```

If theHarvester is missing, it is cloned into:

```text
bin/theHarvester
```

The project uses the official source repository:

```text
https://github.com/laramies/theHarvester.git
```

For source-based theHarvester installation, the preferred setup path is:

```text
uv sync
```

If `uv` is unavailable, the project tries to create a local `.venv` and install dependencies through `pip`.

API keys are optional. When environment variables are present, the pipeline writes `api-keys.yaml` for theHarvester automatically. Examples:

```bash
export THEHARVESTER_SHODAN_KEY="..."
export THEHARVESTER_GITHUB_TOKEN="..."
export THEHARVESTER_HUNTER_KEY="..."
export THEHARVESTER_SECURITYTRAILS_KEY="..."
export THEHARVESTER_CENSYS_ID="..."
export THEHARVESTER_CENSYS_SECRET="..."
```

A generic JSON-based format is also supported:

```bash
export THEHARVESTER_API_KEYS_JSON='{"shodan":{"key":"..."},"hunter":{"key":"..."}}'
```

---

## 2. Output files and report architecture

Each successful run leaves only two user-facing files in `Results/`:

```text
Results/<target>-theharvester.json
Results/<target>_<YYYYMMDD_HHMMSS>.json
```

The native theHarvester `*.json` and `*.xml` files are generated in a temporary directory outside `Results/`, parsed, converted into the canonical project format, and removed automatically.

### 2.1. `Results/<target>-theharvester.json`

This is a compact raw-style theHarvester snapshot that mirrors the important console sections.

Structure:

```json
{
  "ASNS found": {
    "count": 0,
    "items": []
  },
  "Interesting Urls found": {
    "count": 0,
    "items": []
  },
  "LinkedIn users found": {
    "count": 0,
    "items": []
  },
  "IPs found": {
    "count": 0,
    "items": []
  },
  "Emails found": {
    "count": 0,
    "items": []
  },
  "Hosts found": {
    "count": 0,
    "items": []
  }
}
```

No service wrapper is added here. There is no `meta`, `raw`, `normalized`, or `stderr` block. Each section stores a count and a de-duplicated list of values.

### 2.2. `Results/<target>_<YYYYMMDD_HHMMSS>.json`

This is the final IP-centric enrichment report.

Top-level structure:

```json
{
  "summary": {},
  "ips": [],
  "unresolved-assets": [],
  "unmapped-assets": []
}
```

The `ips` block is grouped by resolved IP:

```text
ips[]
├── ip
├── input-ip-assets[]
├── domains[]
│   ├── target
│   ├── result-httpx[]
│   └── urls[]
│       ├── target
│       └── result-httpx[]
├── subdomains[]
│   ├── target
│   ├── result-httpx[]
│   └── urls[]
│       ├── target
│       └── result-httpx[]
├── result-cdncheck[]
└── result-ports[]
```

URL assets are nested under the domain or subdomain that owns their hostname. If a URL hostname was not already present as a host asset, the pipeline creates a synthetic domain/subdomain node and attaches the URL there.

Assets that cannot be resolved through DNS go into:

```text
unresolved-assets[]
```

Assets that cannot be mapped into the dependency graph go into:

```text
unmapped-assets[]
```

This prevents data loss when an input does not fit the normal `IP -> domain/subdomain -> url` model.

### nmap scan skipping

The nmap stage does not scan every resolved IP. IP groups detected by cdncheck as `cdn`, `cloud`, or `waf` are skipped intentionally.

Reason: port-scanning CDN/WAF/cloud edge IPs usually describes the provider edge, not the target application's origin infrastructure.

In the console:

```text
scan-ips   : IP groups that will be sent to nmap
skipped-cdn: IP groups skipped because cdncheck matched cdn/cloud/waf
workers    : maximum number of parallel nmap processes
```

---

## 3. Project architecture

```text
asset-toolchain-pipeline/
├── app.py
│   └── Main Python entrypoint. Use `python3 app.py <domain>` or `python3 app.py`.
│
├── main.py
│   └── Compatibility entrypoint that delegates to `app.py`.
│
├── requirements.txt
│   └── Python dependency marker. The core project is standard-library only.
│
├── README.md
│   └── Project usage, output contract, and architecture documentation.
│
├── Results/
│   ├── .gitkeep
│   ├── <target>-theharvester.json
│   └── <target>_<YYYYMMDD_HHMMSS>.json
│       └── Runtime output directory. Only the two report artifacts should remain here after a run.
│
├── bin/
│   ├── theHarvester/
│   ├── httpx
│   └── cdncheck
│       └── Local tool directory. Created/populated automatically when tools are missing.
│
├── examples/
│   ├── assets.example.json
│   └── theharvester.env.example
│       └── Example legacy input and example theHarvester API-key environment variables.
│
├── docs/
│   ├── MICROSERVICES_RU.md
│   └── PIPELINE_RU.md
│       └── Additional Russian notes from earlier project iterations.
│
├── services/
│   ├── input_service/main.py
│   ├── tool_service/main.py
│   └── orchestrator_service/main.py
│       └── Service-level compatibility wrappers.
│
└── src/
    ├── pipeline.py
    │   └── Small compatibility layer that exposes `console_main`.
    │
    └── asset_pipeline/
        ├── __init__.py
        │   └── Package marker.
        │
        ├── shared.py
        │   └── Shared constants, dataclasses, process runner, progress UI, signal handling, and installer helpers.
        │
        └── services/
            ├── __init__.py
            │   └── Services package marker.
            │
            ├── input_service.py
            │   └── Domain input, port selection, asset normalization, DNS resolving, and output path building.
            │
            ├── tool_service.py
            │   └── Tool discovery, local installation, theHarvester source setup, and API-key file generation.
            │
            └── orchestrator_service.py
                └── Main pipeline orchestration: theHarvester, standardization, cdncheck, httpx, nmap, and final JSON persistence.
```

### Runtime flow

```text
User domain
  ↓
theHarvester OSINT
  ↓
Results/<target>-theharvester.json
  ↓
Asset conversion and DNS resolution
  ↓
IP dependency graph
  ↓
cdncheck
  ↓
httpx
  ↓
nmap, excluding cdn/cloud/waf IP groups
  ↓
Results/<target>_<YYYYMMDD_HHMMSS>.json
```
