#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║              AI-RECON  —  AI Infrastructure Scanner              ║
║         Fingerprint · Enumerate · Map the AI Attack Surface      ║
║                      Made by Aryan Giri                          ║
╚═══════════════════════════════════════════════════════════════════╝

Usage:
    python ai_recon.py -t <target_ip>
    python ai_recon.py -t 192.168.1.10 --enumerate --output report.json
    python ai_recon.py -t 192.168.1.0/24 --phase scan
    python ai_recon.py -t 10.0.0.5 --ports 5000,8000,8888 --timeout 3
"""

import argparse
import concurrent.futures
import json
import socket
import sys
import time
import ipaddress
from datetime import datetime
from typing import Optional

import requests
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ─────────────────────────────────────────────
#  CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────

VERSION = "1.0.0"
AUTHOR  = "Aryan Giri"

# All AI/ML infrastructure ports with service metadata
AI_PORTS = {
    # ── Model Serving ──
    8000:  {"service": "Triton / vLLM / Ollama / Chroma", "category": "Model Serving",       "proto": "HTTP"},
    8001:  {"service": "Triton gRPC",                      "category": "Model Serving",       "proto": "gRPC"},
    8002:  {"service": "Triton Prometheus Metrics",        "category": "Metrics",             "proto": "HTTP"},
    8080:  {"service": "TorchServe / Weaviate",            "category": "Model Serving",       "proto": "HTTP"},
    8081:  {"service": "TorchServe Management API",        "category": "Model Serving",       "proto": "HTTP"},
    8082:  {"service": "TorchServe Prometheus Metrics",    "category": "Metrics",             "proto": "HTTP"},
    8500:  {"service": "TensorFlow Serving gRPC",          "category": "Model Serving",       "proto": "gRPC"},
    8501:  {"service": "TensorFlow Serving HTTP",          "category": "Model Serving",       "proto": "HTTP"},
    11434: {"service": "Ollama LLM Runtime",               "category": "LLM Serving",         "proto": "HTTP"},
    # ── Orchestration / Experiment Tracking ──
    5000:  {"service": "MLflow Tracking Server",           "category": "ML Lifecycle",        "proto": "HTTP"},
    8265:  {"service": "Ray Dashboard / Job API",          "category": "Orchestration",       "proto": "HTTP"},
    # ── Vector Databases ──
    6333:  {"service": "Qdrant HTTP",                      "category": "Vector DB",           "proto": "HTTP"},
    6334:  {"service": "Qdrant gRPC",                      "category": "Vector DB",           "proto": "gRPC"},
    19530: {"service": "Milvus gRPC",                      "category": "Vector DB",           "proto": "gRPC"},
    # ── Notebooks & Storage ──
    8888:  {"service": "Jupyter Notebook / Lab",           "category": "Dev Environment",     "proto": "HTTP"},
    9000:  {"service": "MinIO S3 API",                     "category": "Object Storage",      "proto": "HTTP"},
    9001:  {"service": "MinIO Console",                    "category": "Object Storage",      "proto": "HTTP"},
    # ── Standard Web (Kubeflow, etc.) ──
    80:    {"service": "Kubeflow / HTTP",                  "category": "Orchestration",       "proto": "HTTP"},
    443:   {"service": "Kubeflow / HTTPS",                 "category": "Orchestration",       "proto": "HTTPS"},
}

# HTTP fingerprint probes: (endpoint, method, expected_keyword, framework_name)
FINGERPRINT_PROBES = {
    8000: [
        ("/v2/health/ready",               "GET",  "triton",              "Triton Inference Server"),
        ("/v2/models",                      "GET",  "platform",            "Triton Inference Server"),
        ("/v1/models",                      "GET",  '"object"',            "vLLM / OpenAI-compat"),
        ("/api/tags",                       "GET",  "models",              "Ollama"),
        ("/api/v1/collections",             "GET",  "collections",         "Chroma DB"),
    ],
    8080: [
        ("/ping",                           "GET",  "healthy",             "TorchServe"),
        ("/models",                         "GET",  "modelName",           "TorchServe"),
        ("/v1/schema",                      "GET",  "classes",             "Weaviate"),
        ("/v1/meta",                        "GET",  "version",             "Weaviate"),
    ],
    8081: [
        ("/models",                         "GET",  "modelName",           "TorchServe Management"),
    ],
    8501: [
        ("/v1/models",                      "GET",  "model_version_status","TensorFlow Serving"),
    ],
    5000: [
        ("/api/2.0/mlflow/experiments/search", "POST", "experiments",     "MLflow Tracking"),
        ("/",                               "GET",  "mlflow",              "MLflow Tracking"),
    ],
    8265: [
        ("/api/jobs/",                      "GET",  "job_id",              "Ray Dashboard"),
        ("/",                               "GET",  "Ray",                 "Ray Dashboard"),
    ],
    6333: [
        ("/collections",                    "GET",  "collections",         "Qdrant"),
        ("/",                               "GET",  "title",               "Qdrant"),
    ],
    8888: [
        ("/api/kernels",                    "GET",  "kernel",              "Jupyter Notebook"),
        ("/api/contents",                   "GET",  "content",             "Jupyter Notebook"),
    ],
    9000: [
        ("/minio/health/live",              "GET",  "",                    "MinIO S3"),
    ],
    9001: [
        ("/",                               "GET",  "minio",               "MinIO Console"),
    ],
    11434: [
        ("/api/tags",                       "GET",  "models",              "Ollama"),
        ("/api/version",                    "GET",  "version",             "Ollama"),
    ],
    8002: [
        ("/metrics",                        "GET",  "nv_inference",        "Triton Prometheus"),
    ],
    8082: [
        ("/metrics",                        "GET",  "ts_",                 "TorchServe Prometheus"),
    ],
}

# Enumeration API paths per service
ENUM_CHAINS = {
    "MLflow Tracking": [
        ("POST", "/api/2.0/mlflow/experiments/search",       "{}",   "Experiments"),
        ("GET",  "/api/2.0/mlflow/registered-models/list",   None,   "Registered Models"),
        ("GET",  "/api/2.0/mlflow/model-versions/search",    None,   "Model Versions (artifact URIs + authors)"),
        ("GET",  "/api/2.0/mlflow/artifacts/list",           None,   "Artifact Files"),
    ],
    "Triton Inference Server": [
        ("GET",  "/v2/models",                               None,   "Loaded Models"),
        ("GET",  "/v2/health/ready",                         None,   "Health"),
    ],
    "vLLM / OpenAI-compat": [
        ("GET",  "/v1/models",                               None,   "Available LLM Models"),
    ],
    "Ollama": [
        ("GET",  "/api/tags",                                None,   "Local Model Tags"),
        ("GET",  "/api/version",                             None,   "Ollama Version"),
    ],
    "Qdrant": [
        ("GET",  "/collections",                             None,   "Vector Collections"),
    ],
    "Weaviate": [
        ("GET",  "/v1/schema",                               None,   "Schema / Classes"),
        ("GET",  "/v1/meta",                                 None,   "Server Meta"),
    ],
    "Chroma DB": [
        ("GET",  "/api/v1/collections",                      None,   "Collections"),
    ],
    "Jupyter Notebook": [
        ("GET",  "/api/kernels",                             None,   "Active Kernels"),
        ("GET",  "/api/contents",                            None,   "Notebook Files"),
    ],
    "TorchServe": [
        ("GET",  "/models",                                  None,   "Loaded Models"),
    ],
    "TorchServe Management": [
        ("GET",  "/models",                                  None,   "All Registered Models"),
    ],
    "Ray Dashboard": [
        ("GET",  "/api/jobs/",                               None,   "Submitted Jobs"),
    ],
}

# ATLAS technique mapping
ATLAS_MAP = {
    "Model Serving":    ("AML.T0014", "Discover ML Model Family"),
    "ML Lifecycle":     ("AML.T0007", "Discover ML Artifacts"),
    "Orchestration":    ("AML.T0006", "Active Scanning"),
    "Vector DB":        ("AML.T0007", "Discover ML Artifacts"),
    "Dev Environment":  ("AML.T0007", "Discover ML Artifacts"),
    "Object Storage":   ("AML.T0010", "ML Supply Chain Compromise"),
    "Metrics":          ("AML.T0006", "Active Scanning"),
    "LLM Serving":      ("AML.T0014", "Discover ML Model Family"),
}

# ─────────────────────────────────────────────
#  RICH THEME
# ─────────────────────────────────────────────

DARK_THEME = Theme({
    "header":     "bold cyan",
    "success":    "bold green",
    "warning":    "bold yellow",
    "danger":     "bold red",
    "info":       "dim white",
    "port":       "bold magenta",
    "service":    "bold cyan",
    "atlas":      "bold yellow",
    "category":   "blue",
    "proto":      "green",
    "vuln":       "bold red on dark_red",
    "enum_key":   "bold white",
    "enum_val":   "dim cyan",
})

console = Console(theme=DARK_THEME)


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

def print_banner():
    banner = Text()
    banner.append("\n")
    banner.append("  ╔══════════════════════════════════════════════════════╗\n", style="cyan")
    banner.append("  ║  ", style="cyan")
    banner.append("AI-RECON", style="bold cyan")
    banner.append("  ·  AI Infrastructure Reconnaissance Tool       ", style="white")
    banner.append("║\n", style="cyan")
    banner.append("  ║  ", style="cyan")
    banner.append(f"  v{VERSION}  ·  Made by {AUTHOR}", style="bold yellow")
    banner.append("                              ║\n", style="cyan")
    banner.append("  ║  ", style="cyan")
    banner.append("  Ports · Fingerprinting · Enumeration · ATLAS Mapping  ", style="dim white")
    banner.append("║\n", style="cyan")
    banner.append("  ╚══════════════════════════════════════════════════════╝\n", style="cyan")
    console.print(banner)


# ─────────────────────────────────────────────
#  PHASE 1 — PORT SCANNER
# ─────────────────────────────────────────────

def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Attempt a TCP connection; return True if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(host: str, ports: list[int], timeout: float, threads: int) -> dict:
    """Parallel TCP port scanner. Returns {port: True/False}."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        future_map = {ex.submit(tcp_connect, host, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(future_map):
            port = future_map[future]
            results[port] = future.result()
    return results


# ─────────────────────────────────────────────
#  PHASE 2 — HTTP FINGERPRINTER
# ─────────────────────────────────────────────

def http_probe(host: str, port: int, path: str, method: str,
               body: Optional[str], timeout: float) -> dict:
    """Single HTTP probe. Returns dict with status, headers, body snippet."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{path}"
    result = {"url": url, "status": None, "headers": {}, "body": "", "error": None}
    try:
        headers = {"Content-Type": "application/json", "User-Agent": "AIRecon/1.0"}
        if method == "POST":
            resp = requests.post(url, data=body, headers=headers,
                                 timeout=timeout, verify=False)
        else:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
        result["status"]  = resp.status_code
        result["headers"] = dict(resp.headers)
        result["body"]    = resp.text[:2000]
    except requests.exceptions.SSLError:
        result["error"] = "SSL"
    except requests.exceptions.ConnectionError:
        result["error"] = "CONN"
    except requests.exceptions.Timeout:
        result["error"] = "TIMEOUT"
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


def fingerprint_service(host: str, port: int, timeout: float) -> dict:
    """
    Run all probes for a given port.
    Returns {'framework': str, 'confidence': str, 'evidence': list, 'headers': dict}
    """
    probes = FINGERPRINT_PROBES.get(port, [])
    findings = []

    for path, method, keyword, framework in probes:
        body = "{}" if method == "POST" else None
        resp = http_probe(host, port, path, method, body, timeout)

        if resp["error"] and resp["error"] not in ("SSL",):
            continue
        if resp["status"] is None:
            continue

        hit = (keyword.lower() in resp["body"].lower()) if keyword else (resp["status"] < 400)
        findings.append({
            "path":      path,
            "status":    resp["status"],
            "keyword":   keyword,
            "hit":       hit,
            "framework": framework,
            "headers":   resp["headers"],
            "body_snip": resp["body"][:400],
        })

    # Pick the framework with most hits
    framework_hits: dict[str, int] = {}
    for f in findings:
        if f["hit"]:
            framework_hits[f["framework"]] = framework_hits.get(f["framework"], 0) + 1

    best_framework = max(framework_hits, key=framework_hits.get) if framework_hits else None

    # Grab server header from any response
    all_headers = {}
    for f in findings:
        all_headers.update(f.get("headers", {}))

    confidence = "HIGH" if (framework_hits.get(best_framework, 0) >= 2) else \
                 "MEDIUM" if best_framework else "LOW"

    # Extra header-based clues
    server_hdr = all_headers.get("Server", "") or all_headers.get("server", "")
    if "torchserve" in server_hdr.lower():
        best_framework = "TorchServe"
        confidence = "HIGH"
    if "uvicorn" in server_hdr.lower() and not best_framework:
        best_framework = "FastAPI / ML Backend (uvicorn)"
        confidence = "MEDIUM"

    return {
        "framework":  best_framework,
        "confidence": confidence,
        "evidence":   [f for f in findings if f["hit"]],
        "server_hdr": server_hdr,
        "all_headers": all_headers,
    }


def check_grpc(host: str, port: int, timeout: float) -> bool:
    """
    Light gRPC presence check — attempt a raw connection and
    look for HTTP/2 preface bytes (PRI * HTTP/2.0).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send the HTTP/2 client preface
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            data = s.recv(64)
            # gRPC servers respond with HTTP/2 SETTINGS frame
            # Magic bytes: starts with 0x00 0x00 frame length or similar
            return len(data) > 0 and data[0:1] in (b'\x00', b'\x01', b'\x04')
    except Exception:
        return False


# ─────────────────────────────────────────────
#  PHASE 3 — ENUMERATOR
# ─────────────────────────────────────────────

def enumerate_service(host: str, port: int, framework: str, timeout: float) -> list[dict]:
    """
    Run the enumeration chain for the identified framework.
    Returns list of {label, status, data_keys, body_snip, artifact_uris, users}.
    """
    chain = ENUM_CHAINS.get(framework, [])
    results = []

    for method, path, body, label in chain:
        resp = http_probe(host, port, path, method, body, timeout)
        if resp["status"] is None:
            continue

        entry = {
            "label":        label,
            "path":         path,
            "status":       resp["status"],
            "data_keys":    [],
            "artifact_uris": [],
            "users":        [],
            "body_snip":    resp["body"][:600],
        }

        # Try JSON parse for rich extraction
        try:
            data = json.loads(resp["body"])
            entry["data_keys"] = list(data.keys()) if isinstance(data, dict) else []

            # Extract artifact URIs (MLflow)
            body_str = resp["body"]
            for line in body_str.splitlines():
                if any(x in line for x in ("s3://", "gs://", "abfs://", "wasbs://", "/artifacts/")):
                    uri = line.strip().strip('"').strip(',')
                    if uri and len(uri) < 200:
                        entry["artifact_uris"].append(uri)

            # Extract user IDs (MLflow model versions)
            if isinstance(data, dict):
                for mv in data.get("model_versions", []):
                    uid = mv.get("user_id") or mv.get("userId")
                    if uid:
                        entry["users"].append(uid)
        except Exception:
            pass

        results.append(entry)

    return results


# ─────────────────────────────────────────────
#  VULNERABILITY FLAGS
# ─────────────────────────────────────────────

VULN_CHECKS = [
    # (framework, path, auth_required, cve, severity, description)
    ("MLflow Tracking",
     "/api/2.0/mlflow/experiments/search",
     False, "CVE-2024-1558 / CVE-2026-2033",
     "CRITICAL",
     "MLflow unauthenticated access + path traversal → RCE possible"),

    ("Jupyter Notebook",
     "/api/kernels",
     False, "No CVE — design issue",
     "CRITICAL",
     "Unauthenticated Jupyter = remote code execution via kernel"),

    ("Ray Dashboard",
     "/api/jobs/",
     False, "CVE-2023-48022",
     "CRITICAL",
     "Ray Job API has no auth by design → arbitrary code execution"),

    ("TorchServe Management",
     "/models",
     False, "CVE-2023-43654 (ShellTorch)",
     "HIGH",
     "Management API allows loading models from arbitrary URLs → RCE"),

    ("Triton Prometheus",
     "/metrics",
     False, "No CVE",
     "MEDIUM",
     "Prometheus metrics leak model names, GPU stats, batch sizes"),

    ("TorchServe Prometheus",
     "/metrics",
     False, "No CVE",
     "MEDIUM",
     "Prometheus metrics expose model names and deployment topology"),

    ("MinIO S3",
     "/",
     False, "No CVE",
     "HIGH",
     "MinIO bucket listing may expose model artifacts (weights, datasets)"),

    ("Ollama",
     "/api/tags",
     False, "CVE-2024-28224",
     "HIGH",
     "Unauthenticated Ollama exposes all local models and allows pull/delete"),
]


def check_vulns(framework: str, port: int, host: str, timeout: float) -> list[dict]:
    """Return applicable vuln flags for an identified framework."""
    hits = []
    for fw, path, auth_needed, cve, severity, desc in VULN_CHECKS:
        if fw.lower() not in (framework or "").lower():
            continue
        resp = http_probe(host, port, path, "GET", None, timeout)
        accessible = (resp["status"] is not None and resp["status"] < 500
                      and resp["error"] is None)
        if accessible and not auth_needed:
            hits.append({
                "cve":      cve,
                "severity": severity,
                "desc":     desc,
                "endpoint": path,
                "status":   resp["status"],
            })
    return hits


# ─────────────────────────────────────────────
#  RICH OUTPUT HELPERS
# ─────────────────────────────────────────────

def severity_color(s: str) -> str:
    return {"CRITICAL": "bold red", "HIGH": "bold orange3",
            "MEDIUM": "bold yellow", "LOW": "dim white"}.get(s, "white")


def confidence_color(c: str) -> str:
    return {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(c, "white")


def print_port_table(open_ports: dict):
    table = Table(title="[header]Open AI Infrastructure Ports[/header]",
                  box=box.ROUNDED, border_style="cyan", show_lines=True)
    table.add_column("Port",     style="port",     width=7)
    table.add_column("Service",  style="service",  width=34)
    table.add_column("Category", style="category", width=20)
    table.add_column("Protocol", style="proto",    width=9)
    table.add_column("ATLAS ID", style="atlas",    width=14)
    table.add_column("Technique",               width=30)

    for port, meta in sorted(open_ports.items()):
        atlas_id, atlas_name = ATLAS_MAP.get(meta["category"], ("AML.T0006", "Active Scanning"))
        table.add_row(
            str(port),
            meta["service"],
            meta["category"],
            meta["proto"],
            atlas_id,
            atlas_name,
        )
    console.print(table)


def print_fingerprint_table(fp_results: dict):
    table = Table(title="[header]Service Fingerprinting Results[/header]",
                  box=box.ROUNDED, border_style="magenta", show_lines=True)
    table.add_column("Port",       style="port",    width=7)
    table.add_column("Framework",  style="service", width=30)
    table.add_column("Confidence", width=10)
    table.add_column("Server Hdr", style="dim",     width=25)
    table.add_column("Evidence Paths",              width=40)

    for port, fp in sorted(fp_results.items()):
        fw  = fp.get("framework") or "[dim]Unknown[/dim]"
        con = fp.get("confidence", "LOW")
        srv = fp.get("server_hdr", "")[:24]
        evid_paths = ", ".join(e["path"] for e in fp.get("evidence", []))[:38]
        table.add_row(
            str(port), fw,
            f"[{confidence_color(con)}]{con}[/]",
            srv or "—", evid_paths or "—"
        )
    console.print(table)


def print_enum_results(port: int, framework: str, enum_data: list[dict]):
    if not enum_data:
        return
    panel_lines = []
    for item in enum_data:
        status_color = "green" if item["status"] < 300 else \
                       "yellow" if item["status"] < 400 else "red"
        panel_lines.append(
            f"  [bold white]▸ {item['label']}[/bold white]  "
            f"[{status_color}]HTTP {item['status']}[/]  "
            f"[dim]{item['path']}[/dim]"
        )
        if item["data_keys"]:
            panel_lines.append(f"    Keys: [cyan]{', '.join(item['data_keys'][:8])}[/cyan]")
        for uri in item["artifact_uris"][:3]:
            panel_lines.append(f"    [bold yellow]ARTIFACT URI:[/bold yellow] [yellow]{uri}[/yellow]")
        for user in item["users"][:5]:
            panel_lines.append(f"    [bold red]USER ID:[/bold red] [red]{user}[/red]")
        if item["body_snip"] and item["status"] < 400:
            snip = item["body_snip"].replace("\n", " ")[:120]
            panel_lines.append(f"    [dim]{snip}…[/dim]")

    console.print(Panel(
        "\n".join(panel_lines),
        title=f"[service]Enumeration · Port {port} · {framework}[/service]",
        border_style="blue",
        padding=(0, 1),
    ))


def print_vuln_table(vuln_results: dict):
    any_vulns = any(v for v in vuln_results.values())
    if not any_vulns:
        console.print("[success]  ✔  No critical vulnerability flags triggered.[/success]")
        return

    table = Table(title="[danger]⚠  Vulnerability Flags[/danger]",
                  box=box.HEAVY, border_style="red", show_lines=True)
    table.add_column("Port",     style="port",  width=7)
    table.add_column("CVE",                     width=28)
    table.add_column("Severity",                width=10)
    table.add_column("Description",             width=55)

    for port, vulns in sorted(vuln_results.items()):
        for v in vulns:
            table.add_row(
                str(port),
                v["cve"],
                f"[{severity_color(v['severity'])}]{v['severity']}[/]",
                v["desc"],
            )
    console.print(table)


def print_summary(target: str, open_ports: dict, fp_results: dict, start_time: float):
    elapsed = time.time() - start_time
    lines = [
        f"  [bold white]Target[/bold white]        : [cyan]{target}[/cyan]",
        f"  [bold white]Scan Time[/bold white]     : {elapsed:.2f}s",
        f"  [bold white]Open AI Ports[/bold white] : [green]{len(open_ports)}[/green]",
        f"  [bold white]Identified[/bold white]    : "
        f"[magenta]{sum(1 for f in fp_results.values() if f.get('framework'))}[/magenta] services fingerprinted",
        "",
        f"  [dim]Made by {AUTHOR}  ·  AI-RECON v{VERSION}[/dim]",
        f"  [dim]Scan completed {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
    ]
    console.print(Panel(
        "\n".join(lines),
        title="[header]Scan Summary[/header]",
        border_style="cyan",
        padding=(0, 1),
    ))


# ─────────────────────────────────────────────
#  JSON EXPORT
# ─────────────────────────────────────────────

def build_json_report(target: str, open_ports: dict, fp_results: dict,
                      enum_results: dict, vuln_results: dict) -> dict:
    return {
        "meta": {
            "tool":    "AI-RECON",
            "version": VERSION,
            "author":  AUTHOR,
            "target":  target,
            "timestamp": datetime.now().isoformat(),
        },
        "open_ports":   {str(k): v for k, v in open_ports.items()},
        "fingerprints": {str(k): v for k, v in fp_results.items()},
        "enumeration":  {str(k): v for k, v in enum_results.items()},
        "vulnerabilities": {str(k): v for k, v in vuln_results.items()},
    }


# ─────────────────────────────────────────────
#  CORE SCAN ORCHESTRATOR
# ─────────────────────────────────────────────

def run_scan(target: str, port_list: list[int], timeout: float,
             threads: int, do_enumerate: bool, output_file: Optional[str]):
    start = time.time()

    # ── Phase 1: Port Scan ──────────────────────────────────────
    console.rule("[header]Phase 1 · Port Scanning[/header]")

    open_raw = {}
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {len(port_list)} AI ports…", total=len(port_list))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            fut_map = {ex.submit(tcp_connect, target, p, timeout): p for p in port_list}
            for fut in concurrent.futures.as_completed(fut_map):
                port = fut_map[fut]
                open_raw[port] = fut.result()
                progress.advance(task)

    open_ports = {p: AI_PORTS[p] for p in sorted(open_raw) if open_raw[p] and p in AI_PORTS}

    if not open_ports:
        console.print("[warning]  No AI infrastructure ports found open.[/warning]")
    else:
        print_port_table(open_ports)

    # ── Phase 2: Fingerprinting ─────────────────────────────────
    console.rule("[header]Phase 2 · HTTP Fingerprinting[/header]")

    fp_results: dict = {}
    http_ports = [p for p in open_ports if open_ports[p]["proto"] in ("HTTP", "HTTPS")]

    with Progress(SpinnerColumn(style="magenta"),
                  TextColumn("{task.description}"),
                  BarColumn(bar_width=40, style="magenta"),
                  TextColumn("{task.percentage:>3.0f}%"),
                  console=console) as prog:
        task2 = prog.add_task("Fingerprinting services…", total=max(len(http_ports), 1))
        for port in http_ports:
            prog.update(task2, description=f"Probing :{port}…")
            fp_results[port] = fingerprint_service(target, port, timeout)
            # gRPC check for known gRPC ports
            if AI_PORTS[port]["proto"] == "gRPC":
                is_grpc = check_grpc(target, port, timeout)
                fp_results[port]["grpc_confirmed"] = is_grpc
            prog.advance(task2)

    # Also check gRPC-only ports
    grpc_ports = [p for p in open_ports if open_ports[p]["proto"] == "gRPC" and p not in fp_results]
    for port in grpc_ports:
        fp_results[port] = {
            "framework": f"{AI_PORTS[port]['service']} (gRPC)",
            "confidence": "MEDIUM",
            "evidence":  [],
            "server_hdr": "",
            "grpc_confirmed": check_grpc(target, port, timeout),
        }

    print_fingerprint_table(fp_results)

    # ── Phase 3: Enumeration ────────────────────────────────────
    enum_results: dict = {}

    if do_enumerate:
        console.rule("[header]Phase 3 · Metadata Enumeration[/header]")
        for port, fp in fp_results.items():
            fw = fp.get("framework")
            if not fw:
                continue
            # Match to enum chain (fuzzy)
            matched_fw = next((k for k in ENUM_CHAINS if k.lower() in fw.lower()), None)
            if matched_fw:
                console.print(f"  [info]Enumerating[/info] :{port} [{matched_fw}]…")
                data = enumerate_service(target, port, matched_fw, timeout)
                enum_results[port] = data
                print_enum_results(port, matched_fw, data)

    # ── Phase 4: Vulnerability Flags ────────────────────────────
    console.rule("[header]Phase 4 · Vulnerability Flags[/header]")

    vuln_results: dict = {}
    for port, fp in fp_results.items():
        fw = fp.get("framework")
        if fw:
            vulns = check_vulns(fw, port, target, timeout)
            if vulns:
                vuln_results[port] = vulns

    print_vuln_table(vuln_results)

    # ── Summary ─────────────────────────────────────────────────
    console.rule("[header]Summary[/header]")
    print_summary(target, open_ports, fp_results, start)

    # ── JSON Export ─────────────────────────────────────────────
    report = build_json_report(target, open_ports, fp_results, enum_results, vuln_results)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"\n  [success]✔  Report saved →[/success] [cyan]{output_file}[/cyan]\n")

    return report


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="ai_recon",
        description=f"AI Infrastructure Reconnaissance Tool — Made by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai_recon.py -t 10.10.45.0/24
  python ai_recon.py -t 10.10.45.15 --enumerate
  python ai_recon.py -t 192.168.1.10 --ports 5000,8000,8888 --output report.json
  python ai_recon.py -t 10.10.0.5 --timeout 5 --threads 100
        """
    )
    p.add_argument("-t", "--target",   required=True,
                   help="Target IP, hostname, or CIDR range (e.g. 10.10.0.0/24)")
    p.add_argument("-p", "--ports",    default=None,
                   help="Comma-separated port list (default: all AI ports)")
    p.add_argument("--timeout",        type=float, default=2.0,
                   help="Connection timeout in seconds (default: 2)")
    p.add_argument("--threads",        type=int,   default=50,
                   help="Parallel threads (default: 50)")
    p.add_argument("--enumerate",      action="store_true",
                   help="Run metadata enumeration after fingerprinting")
    p.add_argument("--output",         default=None,
                   help="Save JSON report to file")
    p.add_argument("--no-banner",      action="store_true",
                   help="Suppress ASCII banner")
    return p.parse_args()


def expand_targets(target_str: str) -> list[str]:
    """Expand CIDR or return single host."""
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [target_str]


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    args = parse_args()

    if not args.no_banner:
        print_banner()

    # Build port list
    if args.ports:
        try:
            port_list = [int(x.strip()) for x in args.ports.split(",")]
        except ValueError:
            console.print("[danger]Invalid port list. Use comma-separated integers.[/danger]")
            sys.exit(1)
    else:
        port_list = list(AI_PORTS.keys())

    # Expand targets
    targets = expand_targets(args.target)

    if len(targets) > 1:
        console.print(f"  [info]CIDR expanded to[/info] [bold]{len(targets)}[/bold] hosts\n")

    all_reports = {}

    for target in targets:
        if len(targets) > 1:
            console.rule(f"[bold cyan]Target: {target}[/bold cyan]")
        report = run_scan(
            target=target,
            port_list=port_list,
            timeout=args.timeout,
            threads=args.threads,
            do_enumerate=args.enumerate,
            output_file=args.output if len(targets) == 1 else None,
        )
        all_reports[target] = report

    # Multi-target JSON dump
    if args.output and len(targets) > 1:
        with open(args.output, "w") as f:
            json.dump(all_reports, f, indent=2, default=str)
        console.print(f"\n  [success]✔  Combined report saved →[/success] [cyan]{args.output}[/cyan]\n")


if __name__ == "__main__":
    main()
