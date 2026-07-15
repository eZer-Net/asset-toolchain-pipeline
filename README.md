# Asset Toolchain Pipeline

Automated Recon pipeline for discovering IP addresses, domains, and subdomains, then building an infrastructure hierarchy and exporting it to the Pentester Dashboard format.

Input:

```text
example.com
```

Output:

A ready-to-import Recon JSON compatible with Pentester Dashboard.

---

# Quick Start

Requirements: Linux, Python 3.10+, Git and an Internet connection for the first run.

```bash
git clone https://github.com/eZer-Net/asset-toolchain-pipeline.git
cd asset-toolchain-pipeline
python3 app.py example.com
```

The pipeline checks required tools and downloads missing components into `bin/`. Reports are saved to `Results/`.

Use only against systems you own or are authorized to test.

---

# Features

* Passive domain and subdomain discovery
* Active DNS brute-force
* IP address resolution
* HTTP Status Code validation
* CDN/WAF detection
* TCP port scanning
* Asset relationship generation
* Recon JSON export

---

# Tools

| Tool                              | Purpose                                      |
| --------------------------------- | -------------------------------------------- |
| theHarvester                      | Passive asset discovery                      |
| Certificate Transparency (crt.sh) | Certificate Transparency subdomain discovery |
| Gobuster                          | Paced DNS brute-force with visible progress  |
| SecLists                          | Gobuster wordlists                           |
| httpx                             | HTTP validation and Status Code detection    |
| cdncheck                          | CDN/WAF detection                            |
| Nmap                              | TCP port scanning                            |

---

## DNS brute-force rate

Gobuster runs with one worker and a fixed `250ms` delay between DNS requests. Before brute-force starts, the pipeline checks for wildcard DNS. If random subdomains resolve to the same address, the stage is skipped to avoid adding thousands of false-positive assets. The CLI shows elapsed progress and prints the number of processed and discovered subdomains when the stage completes.


# Pipeline

```text
Target Domain
      │
      ▼
Passive Discovery
(theHarvester + crt.sh)
      │
      ▼
Active Discovery
(Gobuster)
      │
      ▼
Merge & Deduplicate
      │
      ▼
DNS Resolve + HTTP Validation
      │
      ▼
Build Asset Relations
      │
      ▼
CDN/WAF Detection
      │
      ▼
Nmap
      │
      ▼
Recon JSON
```

---

# Nmap

Two scanning modes are supported.

### Default / Custom

Scans only the selected ports.

The report stores every detected state:

* open
* closed
* filtered
* unknown

For open ports, the service and version are also detected.

### Full Scan

Scans all TCP ports (`1-65535`).

Only open ports are exported to the final report together with detected service and version information. This keeps the report compact while preserving actionable results.

---

# Report Format

The pipeline generates a Recon JSON file.

Structure:

```text
assets
relations
portBindings
```

### assets

Contains discovered:

* IP addresses
* Domains
* Subdomains

IP assets also include discovered TCP ports.

### relations

Defines relationships between assets.

Supported relation types:

* HOSTS
* HAS_SUBDOMAIN

### portBindings

Maps open IP ports to related domains and subdomains.

---

# Import

The generated Recon JSON can be imported directly into **Pentester Dashboard**, where the infrastructure hierarchy is automatically built and visualized.

https://github.com/eZer-Net/pentester-dashboard
