# AI-RECON — AI Infrastructure Reconnaissance Tool

> **Made by Aryan Giri**  
> Fingerprint · Enumerate · Map the AI Attack Surface

A purpose-built reconnaissance tool for AI/ML infrastructure — the kind Nmap doesn't understand. Where Nmap sees `http-alt` on port 8000, AI-RECON sees Triton, vLLM, or Ollama, queries their APIs, and maps the full attack surface.

---

## Features

| Phase | What It Does |
|-------|-------------|
| **Port Scanning** | Parallel TCP connect scan across 19 AI-specific ports (5000, 6333, 8000–8002, 8080–8082, 8265, 8500–8501, 8888, 9000–9001, 11434, 19530) |
| **HTTP Fingerprinting** | Header analysis, JSON response structure, endpoint naming conventions, error-message fingerprinting |
| **gRPC Detection** | HTTP/2 preface probe for Triton (8001), TF Serving (8500), Qdrant (6334), Milvus (19530) |
| **Metadata Enumeration** | Pulls experiments, model registries, artifact URIs, user IDs from MLflow; collections from Qdrant/Weaviate/Chroma; kernels + notebooks from Jupyter; model lists from Ollama/Triton/TorchServe |
| **Vulnerability Flags** | Maps findings to known CVEs (CVE-2023-48022, CVE-2024-1558, CVE-2024-28224, ShellTorch, etc.) |
| **ATLAS Mapping** | Every port finding tagged with its MITRE ATLAS technique ID |
| **JSON Export** | Full structured report for pipeline integration |
| **CIDR Support** | Scan entire subnets with one command |

---

## Installation

```bash
pip install requests rich
```

No other dependencies. Pure Python 3.10+.

---

## Usage

```bash
# Basic scan — all AI ports against a single host
python ai_recon.py -t 10.10.45.12

# With full metadata enumeration
python ai_recon.py -t 10.10.45.12 --enumerate

# Save JSON report
python ai_recon.py -t 10.10.45.12 --enumerate --output report.json

# Specific ports only
python ai_recon.py -t 192.168.1.10 --ports 5000,8000,8888

# Scan entire subnet
python ai_recon.py -t 10.10.45.0/24

# Adjust timing
python ai_recon.py -t 10.10.45.15 --timeout 5 --threads 100
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t / --target` | required | IP, hostname, or CIDR (e.g. `10.0.0.0/24`) |
| `-p / --ports` | all AI ports | Comma-separated port list |
| `--timeout` | 2.0s | TCP/HTTP connection timeout |
| `--threads` | 50 | Parallel scan threads |
| `--enumerate` | off | Run metadata enumeration phase |
| `--output` | off | Write JSON report to file |
| `--no-banner` | off | Suppress ASCII banner |

---

## Port Reference

| Port | Service | Category |
|------|---------|----------|
| 5000 | MLflow Tracking Server | ML Lifecycle |
| 6333 | Qdrant HTTP | Vector DB |
| 6334 | Qdrant gRPC | Vector DB |
| 8000 | Triton / vLLM / Chroma | Model Serving |
| 8001 | Triton gRPC | Model Serving |
| 8002 | Triton Prometheus | Metrics |
| 8080 | TorchServe / Weaviate | Model Serving |
| 8081 | TorchServe Management API | Model Serving |
| 8082 | TorchServe Prometheus | Metrics |
| 8265 | Ray Dashboard / Job API | Orchestration |
| 8500 | TensorFlow Serving gRPC | Model Serving |
| 8501 | TensorFlow Serving HTTP | Model Serving |
| 8888 | Jupyter Notebook | Dev Environment |
| 9000 | MinIO S3 API | Object Storage |
| 9001 | MinIO Console | Object Storage |
| 11434 | Ollama LLM Runtime | LLM Serving |
| 19530 | Milvus gRPC | Vector DB |

---

## MITRE ATLAS Mapping

| Finding Type | ATLAS Technique |
|-------------|----------------|
| Port scanning AI services | AML.T0006 — Active Scanning |
| Model registry enumeration | AML.T0007 — Discover ML Artifacts |
| LLM endpoint identification | AML.T0014 — Discover ML Model Family |
| Supply chain exposure | AML.T0010 — ML Supply Chain Compromise |

---

## JSON Report Structure

```json
{
  "meta": { "tool": "AI-RECON", "author": "Aryan Giri", "target": "...", "timestamp": "..." },
  "open_ports":    { "5000": { "service": "MLflow", "category": "ML Lifecycle", ... } },
  "fingerprints":  { "5000": { "framework": "MLflow Tracking", "confidence": "HIGH", ... } },
  "enumeration":   { "5000": [ { "label": "Experiments", "artifact_uris": [...], "users": [...] } ] },
  "vulnerabilities": { "5000": [ { "cve": "CVE-2024-1558", "severity": "CRITICAL", ... } ] }
}
```

---

## Legal

For use in authorised penetration tests, red team engagements, and closed lab environments only.

---

*Made by Aryan Giri*
