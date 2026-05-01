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
    python ai_recon.py -t 192.168.1.0/24
    python ai_recon.py -t 10.0.0.5 --ports 5000,8000,8888 --timeout 3
"""

import argparse
import asyncio
import concurrent.futures
import json
import random
import socket
import ssl
import struct
import sys
import time
import ipaddress
from datetime import datetime
from typing import Optional

import aiohttp
import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ─────────────────────────────────────────────
#  CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────

VERSION = "1.3.0"
AUTHOR  = "Aryan Giri"
DEFAULT_MAX_CIDR = 512  # Safety cap — refuse to scan CIDRs with more hosts than this

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
# ─────────────────────────────────────────────
#  FINGERPRINT PROBE TABLE
# ─────────────────────────────────────────────
# Each probe: (path, method, match_fn, signal_weight, framework_name)
#
# match_fn  : callable(body: str, headers: dict) -> bool
#             Evaluated against the HTTP response body (str) and headers (dict).
#             Keep match criteria SPECIFIC — avoid generic JSON shapes.
# signal_weight:
#   3 = definitive  (unique string / header that only this framework emits)
#   2 = strong      (highly distinctive endpoint + response combo)
#   1 = weak        (path exists, but response shape is common)
#
# Confidence is derived from weighted score totals, not raw hit counts.
# ─────────────────────────────────────────────

def _body(b: str, *phrases: str) -> bool:
    """All phrases must appear in body (case-insensitive)."""
    bl = b.lower()
    return all(p.lower() in bl for p in phrases)

def _body_any(b: str, *phrases: str) -> bool:
    """Any phrase must appear in body (case-insensitive)."""
    bl = b.lower()
    return any(p.lower() in bl for p in phrases)

def _hdr(h: dict, key: str, value: str) -> bool:
    """Header key contains value (case-insensitive)."""
    return value.lower() in h.get(key, h.get(key.lower(), "")).lower()


FINGERPRINT_PROBES: dict[int, list[tuple]] = {
    # ── port 8000: Triton / vLLM / Ollama / Chroma ───────────────
    8000: [
        # ── Triton v2 server metadata — the canonical modern fingerprint.
        # GET /v2 returns {"name":"triton","version":"2.x","extensions":[...]}
        # "name":"triton" is set by Triton itself and is not part of the
        # KServe standard, so no other KServe-compatible server emits it.
        # Weight=3: this is a single definitive identifier.
        # NOTE: The old NV-Status header check was for the v1 API (Triton ≤1.13).
        # Modern v2 deployments never send NV-Status. It is NOT used here.
        ("/v2", "GET",
         lambda b, h: _body(b, '"name"', '"triton"') and _body(b, '"extensions"'),
         3, "Triton Inference Server"),

        # Triton: /v2/models lists loaded models; the "platform" field
        # (e.g., "tensorflow_graphdef", "pytorch_libtorch") is a Triton
        # model-repository convention not required by KServe itself.
        ("/v2/models", "GET",
         lambda b, h: _body(b, '"platform"') and _body(b, '"versions"'),
         2, "Triton Inference Server"),

        # Triton: /v2/health/ready → HTTP 200 + empty body + text/plain.
        # This is the KServe standard; other compliant servers also implement
        # it, so on its own it's a weak signal. Only count it if the body is
        # truly empty (non-Triton servers often add JSON or HTML).
        ("/v2/health/ready", "GET",
         lambda b, h: len(b.strip()) == 0 and h.get("Content-Type", h.get("content-type", "")).startswith("text/plain"),
         1, "Triton Inference Server"),

        # vLLM / OpenAI-compat: /v1/models returns {"object":"list","data":[...]}
        # Require BOTH "object" AND "data" AND the list shape to avoid false hits.
        ("/v1/models", "GET",
         lambda b, h: _body(b, '"object"', '"data"') and
                      _body_any(b, '"object": "list"', '"object":"list"'),
         3, "vLLM / OpenAI-compat"),

        # Ollama: /api/tags returns {"models":[{"name":...,"digest":...}]}
        # "digest" is Ollama-specific; generic APIs don't have it here.
        ("/api/tags", "GET",
         lambda b, h: _body(b, '"models"', '"digest"'),
         3, "Ollama"),

        # Chroma: /api/v1/collections returns a JSON array of collection objects.
        # The endpoint path itself is Chroma-specific at port 8000.
        ("/api/v1/collections", "GET",
         lambda b, h: _body(b, '"name"', '"metadata"') and resp_is_json_array(b),
         2, "Chroma DB"),
    ],

    # ── port 8080: TorchServe / Weaviate ─────────────────────────
    8080: [
        # TorchServe: /ping returns exactly {"status":"Healthy"}
        ("/ping", "GET",
         lambda b, h: _body(b, '"status"', '"healthy"'),
         3, "TorchServe"),

        # TorchServe: model list contains "modelName" key
        ("/models", "GET",
         lambda b, h: _body(b, '"modelName"'),
         2, "TorchServe"),

        # Weaviate: /v1/schema returns {"classes":[...]} — "classes" array is Weaviate-specific
        ("/v1/schema", "GET",
         lambda b, h: _body(b, '"classes"') and _body_any(b, '"vectorizer"', '"moduleConfig"'),
         3, "Weaviate"),

        # Weaviate: /v1/meta exposes "hostname", "modules", "version"
        ("/v1/meta", "GET",
         lambda b, h: _body(b, '"hostname"', '"modules"', '"version"'),
         2, "Weaviate"),
    ],

    # ── port 8081: TorchServe Management ─────────────────────────
    8081: [
        ("/models", "GET",
         lambda b, h: _body(b, '"modelName"'),
         3, "TorchServe Management"),
    ],

    # ── port 8501: TensorFlow Serving ────────────────────────────
    8501: [
        # TF Serving: "model_version_status" is unique to TF Serving responses
        ("/v1/models", "GET",
         lambda b, h: _body(b, '"model_version_status"'),
         3, "TensorFlow Serving"),
    ],

    # ── port 5000: MLflow ─────────────────────────────────────────
    5000: [
        # MLflow search endpoint returns {"experiments":[...]}
        ("/api/2.0/mlflow/experiments/search", "POST",
         lambda b, h: _body(b, '"experiments"'),
         3, "MLflow Tracking"),

        # MLflow UI root references "mlflow" in page content or X-Frame-Options
        ("/", "GET",
         lambda b, h: _body(b, "mlflow") or _hdr(h, "x-content-type-options", ""),
         1, "MLflow Tracking"),
    ],

    # ── port 8265: Ray ────────────────────────────────────────────
    8265: [
        # Ray job API returns list of job objects with "job_id" and "status"
        ("/api/jobs/", "GET",
         lambda b, h: _body(b, '"job_id"', '"status"'),
         3, "Ray Dashboard"),

        # Ray root UI contains "ray" in title or body
        ("/", "GET",
         lambda b, h: _body(b, "ray dashboard") or _body(b, '"ray_version"'),
         2, "Ray Dashboard"),
    ],

    # ── port 6333: Qdrant ─────────────────────────────────────────
    6333: [
        # Qdrant: /collections returns {"result":{"collections":[...]}}
        ("/collections", "GET",
         lambda b, h: _body(b, '"result"', '"collections"'),
         3, "Qdrant"),

        # Qdrant root returns {"title":"qdrant - vector search engine"}
        ("/", "GET",
         lambda b, h: _body(b, "qdrant"),
         2, "Qdrant"),
    ],

    # ── port 8888: Jupyter ────────────────────────────────────────
    8888: [
        # Jupyter /api/kernels returns a JSON array of kernel specs
        ("/api/kernels", "GET",
         lambda b, h: _body(b, '"kernel_id"') or
                      (_body(b, '"name"') and _body(b, '"last_activity"')),
         3, "Jupyter Notebook"),

        # Jupyter /api/contents lists files; "type": "notebook" is distinctive
        ("/api/contents", "GET",
         lambda b, h: _body(b, '"content"', '"type"') and _body(b, '"path"'),
         2, "Jupyter Notebook"),
    ],

    # ── port 9000: MinIO ──────────────────────────────────────────
    9000: [
        # MinIO health endpoint returns 200 with empty body
        ("/minio/health/live", "GET",
         lambda b, h: True,   # endpoint path is MinIO-specific; 200 = present
         2, "MinIO S3"),
    ],

    # ── port 9001: MinIO Console ──────────────────────────────────
    9001: [
        ("/", "GET",
         lambda b, h: _body(b, "minio"),
         2, "MinIO Console"),
    ],

    # ── port 11434: Ollama ────────────────────────────────────────
    11434: [
        # Ollama /api/tags has "digest" field — definitive identifier
        ("/api/tags", "GET",
         lambda b, h: _body(b, '"models"', '"digest"'),
         3, "Ollama"),

        # /api/version returns {"version":"0.x.x"} — simple but unique on this port
        ("/api/version", "GET",
         lambda b, h: _body(b, '"version"') and resp_is_simple_json(b),
         2, "Ollama"),
    ],

    # ── port 8002: Triton Prometheus ─────────────────────────────
    8002: [
        # Triton metrics: "nv_inference_" prefix is unique to Triton's Prometheus output
        ("/metrics", "GET",
         lambda b, h: "nv_inference_" in b,
         3, "Triton Prometheus"),
    ],

    # ── port 8082: TorchServe Prometheus ─────────────────────────
    8082: [
        # TorchServe metrics: "ts_" prefix in Prometheus exposition format
        ("/metrics", "GET",
         lambda b, h: b.startswith("# HELP ts_") or "ts_inference_" in b,
         3, "TorchServe Prometheus"),
    ],
}


def resp_is_json_array(body: str) -> bool:
    """True if the response body is a JSON array at the top level."""
    try:
        return isinstance(json.loads(body), list)
    except Exception:
        return False


def resp_is_simple_json(body: str) -> bool:
    """True if the response is a flat JSON object (not deeply nested)."""
    try:
        d = json.loads(body)
        return isinstance(d, dict) and all(not isinstance(v, (dict, list)) for v in d.values())
    except Exception:
        return False

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


# ─────────────────────────────────────────────
#  PHASE 2 — ASYNC HTTP FINGERPRINTER
# ─────────────────────────────────────────────

def _make_ssl_ctx(verify: bool) -> ssl.SSLContext:
    """Return an SSL context. verify=False skips cert validation (self-signed certs)."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


async def async_http_probe(session: aiohttp.ClientSession,
                           host: str, port: int,
                           path: str, method: str,
                           body: Optional[str],
                           timeout: float,
                           retries: int = 1) -> dict:
    """
    Async HTTP probe with retry + jitter on transient failures.

    Uses aiohttp so all port probes within a phase run concurrently
    instead of waiting for each one sequentially. The session's SSL
    context is configured externally via _make_ssl_ctx().

    POST requests are sent with json= equivalent (aiohttp json= kwarg)
    so Content-Type is set correctly without manual header injection.
    """
    scheme = "https" if port == 443 else "http"
    url    = f"{scheme}://{host}:{port}{path}"
    result = {"url": url, "status": None, "headers": {}, "body": "", "error": None}
    hdrs   = {"User-Agent": f"AIRecon/{VERSION}"}

    for attempt in range(retries + 1):
        try:
            to = aiohttp.ClientTimeout(total=timeout)
            if method == "POST":
                json_body = json.loads(body) if isinstance(body, str) else ({} if body is None else body)
                async with session.post(url, json=json_body, headers=hdrs, timeout=to) as resp:
                    result["status"]  = resp.status
                    result["headers"] = dict(resp.headers)
                    result["body"]    = (await resp.text())[:2000]
                    result["error"]   = None
            else:
                async with session.get(url, headers=hdrs, timeout=to) as resp:
                    result["status"]  = resp.status
                    result["headers"] = dict(resp.headers)
                    result["body"]    = (await resp.text())[:2000]
                    result["error"]   = None
            return result

        except aiohttp.ServerFingerprintMismatch:
            result["error"] = "SSL"
            return result  # cert error won't recover on retry

        except (aiohttp.ClientConnectorError, aiohttp.ServerConnectionError):
            result["error"] = "CONN"
            if attempt < retries:
                await asyncio.sleep(random.uniform(0.1, 0.4))

        except asyncio.TimeoutError:
            result["error"] = "TIMEOUT"
            if attempt < retries:
                await asyncio.sleep(random.uniform(0.1, 0.4))

        except Exception as e:
            result["error"] = str(e)[:60]
            return result

    return result


# ── Thin sync wrapper for callers that aren't inside an async context ──────────
def http_probe(host: str, port: int, path: str, method: str,
               body: Optional[str], timeout: float,
               verify: bool = False, retries: int = 1) -> dict:
    """
    Synchronous HTTP probe used only for risk-flag checks (Phase 4).
    All fingerprinting (Phase 2) and enumeration (Phase 3) use the async path.
    """
    scheme = "https" if port == 443 else "http"
    url    = f"{scheme}://{host}:{port}{path}"
    result = {"url": url, "status": None, "headers": {}, "body": "", "error": None}
    hdrs   = {"User-Agent": f"AIRecon/{VERSION}"}

    for attempt in range(retries + 1):
        try:
            if method == "POST":
                json_body = json.loads(body) if isinstance(body, str) else ({} if body is None else body)
                resp = requests.post(url, json=json_body, headers=hdrs,
                                     timeout=timeout, verify=verify)
            else:
                resp = requests.get(url, headers=hdrs, timeout=timeout, verify=verify)
            result.update(status=resp.status_code,
                          headers=dict(resp.headers),
                          body=resp.text[:2000],
                          error=None)
            return result
        except requests.exceptions.SSLError:
            result["error"] = "SSL"; return result
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            result["error"] = "TIMEOUT" if isinstance(e, requests.exceptions.Timeout) else "CONN"
            if attempt < retries:
                time.sleep(random.uniform(0.1, 0.4))
        except Exception as e:
            result["error"] = str(e)[:60]; return result

    return result


async def _fingerprint_port(session: aiohttp.ClientSession,
                             host: str, port: int, timeout: float) -> tuple[int, dict]:
    """Async helper: probe one port and return (port, fingerprint_result)."""
    probes   = FINGERPRINT_PROBES.get(port, [])
    findings = []

    probe_tasks = [
        async_http_probe(session, host, port, path,
                         method, "{}" if method == "POST" else None,
                         timeout, retries=1)
        for path, method, *_ in probes
    ]
    responses = await asyncio.gather(*probe_tasks, return_exceptions=True)

    for (path, method, match_fn, weight, framework), resp in zip(probes, responses):
        if isinstance(resp, Exception) or resp.get("error") not in (None, "SSL"):
            continue
        if resp.get("status") is None:
            continue
        try:
            matched = match_fn(resp["body"], resp["headers"])
        except Exception:
            matched = False
        findings.append({"path": path, "status": resp["status"], "weight": weight,
                          "hit": matched, "framework": framework,
                          "headers": resp["headers"], "body_snip": resp["body"][:400]})

    # Weighted scoring
    fw_scores: dict[str, int] = {}
    for f in findings:
        if f["hit"]:
            fw_scores[f["framework"]] = fw_scores.get(f["framework"], 0) + f["weight"]

    best = max(fw_scores, key=fw_scores.get) if fw_scores else None
    score = fw_scores.get(best, 0)
    confidence = "HIGH" if score >= 3 else "MEDIUM" if score >= 1 else "LOW"

    all_headers: dict = {}
    for f in findings:
        all_headers.update(f.get("headers", {}))
    server_hdr = all_headers.get("Server", "") or all_headers.get("server", "")

    if "torchserve" in server_hdr.lower():
        best, confidence = "TorchServe", "HIGH"
    if "uvicorn" in server_hdr.lower() and not best:
        best, confidence = "FastAPI / ML Backend (uvicorn)", "MEDIUM"

    return port, {
        "framework":   best,
        "confidence":  confidence,
        "score":       score,
        "evidence":    [f for f in findings if f["hit"]],
        "server_hdr":  server_hdr,
        "all_headers": all_headers,
    }


async def fingerprint_all_ports(host: str, http_ports: list[int],
                                 timeout: float, verify: bool) -> dict:
    """
    Run fingerprinting probes against all open HTTP ports concurrently.

    All port probes fire in parallel via asyncio.gather() — a host with
    6 open AI ports takes ~1× timeout instead of 6× timeout.
    """
    ssl_ctx = _make_ssl_ctx(verify)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_fingerprint_port(session, host, p, timeout) for p in http_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    fp: dict = {}
    for item in results:
        if isinstance(item, Exception):
            continue
        port, data = item
        fp[port] = data
    return fp


async def _enumerate_port(session: aiohttp.ClientSession,
                           host: str, port: int,
                           framework: str, timeout: float) -> tuple[int, list]:
    """Async helper: run the enumeration chain for one port."""
    chain   = ENUM_CHAINS.get(framework, [])
    fw_extr = _EXTRACTORS.get(framework, {})
    results = []

    tasks = [
        async_http_probe(session, host, port, path,
                         method, body, timeout, retries=1)
        for method, path, body, label in chain
    ]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    for (method, path, body, label), resp in zip(chain, responses):
        if isinstance(resp, Exception) or resp.get("status") is None:
            continue
        entry = {"label": label, "path": path, "status": resp["status"],
                 "parsed": {}, "raw_keys": [], "body_snip": resp["body"][:400]}
        if resp["status"] < 400:
            try:
                data = json.loads(resp["body"])
                entry["raw_keys"] = list(data.keys()) if isinstance(data, dict) else ["<array>"]
                extractor = fw_extr.get(label)
                if extractor:
                    entry["parsed"] = extractor(data)
            except Exception:
                pass
        results.append(entry)

    return port, results


async def enumerate_all_ports(host: str,
                               port_fw_map: dict[int, str],
                               timeout: float, verify: bool) -> dict:
    """
    Run all enumeration chains concurrently across all identified services.
    """
    ssl_ctx   = _make_ssl_ctx(verify)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _enumerate_port(session, host, port, fw, timeout)
            for port, fw in port_fw_map.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    enum: dict = {}
    for item in results:
        if isinstance(item, Exception):
            continue
        port, data = item
        enum[port] = data
    return enum


def check_grpc(host: str, port: int, timeout: float) -> str:
    """
    Two-stage gRPC detection:

    Stage 1 — HTTP/2 preface heuristic (fast, no dependencies).
    Stage 2 — gRPC Server Reflection (RFC 7540 + proto3 binary framing).

    If reflection succeeds, we return 'reflection_ok' plus the service list.
    If the preface lands but reflection is refused, we return 'likely'.
    If nothing responds, we return 'no_response' or 'unknown'.

    Reflection protocol (grpc.reflection.v1alpha.ServerReflection):
      - Send a ServerReflectionRequest with list_services=''
      - The server streams back ServerReflectionResponse messages
      - Each response is length-prefixed: 1 compressed-flag byte + 4-byte big-endian length

    This replicates what `grpcurl -plaintext <host>:<port> list` does at the
    wire level, without requiring grpcurl to be installed.
    """
    # ── Stage 1: HTTP/2 preface ──────────────────────────────────
    preface_ok = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            data = s.recv(64)
            # SETTINGS frame type = 0x04, at offset 3 in the 9-byte frame header
            if len(data) >= 4 and data[3:4] in (b'\x04', b'\x07', b'\x00', b'\x01'):
                preface_ok = True
    except Exception:
        return "unknown"

    if not preface_ok:
        return "no_response"

    # ── Stage 2: gRPC Server Reflection ──────────────────────────
    # Build a minimal HTTP/2 + gRPC reflection request by hand.
    # We need: SETTINGS, HEADERS (with :method POST etc.), DATA (the proto body).
    #
    # The ServerReflectionRequest proto (field 7 = list_services, string ""):
    #   Field 7, wire type 2 (length-delimited), empty string → bytes: 0x3a 0x00
    #
    # gRPC data frame: 0x00 (not compressed) + 4-byte big-endian length + proto bytes
    try:
        proto_body   = b'\x3a\x00'                          # list_services: ""
        grpc_frame   = b'\x00' + struct.pack('>I', len(proto_body)) + proto_body

        # Minimal HTTP/2 frames to bootstrap a gRPC stream (plaintext only).
        # We use the http2 preface + a SETTINGS frame + HEADERS + DATA.
        # For simplicity we use the http/1.1 upgrade trick that some gRPC
        # servers accept, but fall back gracefully if not.
        #
        # Practical approach: open a raw TCP socket, send the full HTTP/2
        # client preface, then a HEADERS frame (with hpack-encoded headers),
        # then a DATA frame containing the gRPC body.
        #
        # Minimal HPACK-encoded headers for gRPC reflection:
        #   :method POST, :scheme http, :path /grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
        #   content-type application/grpc, te trailers
        #
        # Rather than implement a full HPACK encoder, we use the "never indexed"
        # literal representation (0x10 prefix) for each header.

        def hpack_literal(name: bytes, value: bytes) -> bytes:
            """HPACK literal header, never indexed (RFC 7541 §6.2.3)."""
            def encode_str(s: bytes) -> bytes:
                return bytes([len(s)]) + s   # no Huffman, length prefix
            return b'\x10' + encode_str(name) + encode_str(value)

        hpack_block = (
            b'\x84'                                          # :method POST  (indexed, table[4])
            + b'\x86'                                        # :scheme http  (indexed, table[6])
            + hpack_literal(b':path',
                            b'/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo')
            + hpack_literal(b':authority', host.encode())
            + hpack_literal(b'content-type', b'application/grpc')
            + hpack_literal(b'te',           b'trailers')
        )

        # HTTP/2 HEADERS frame (type=0x01, flags=0x04 END_HEADERS, stream_id=1)
        def h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
            length = len(payload)
            return (struct.pack('>I', length)[1:]           # 3-byte length
                    + bytes([ftype, flags])
                    + struct.pack('>I', stream_id & 0x7FFFFFFF)
                    + payload)

        client_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        settings_frame = h2_frame(0x04, 0x00, 0, b'')       # empty SETTINGS
        headers_frame  = h2_frame(0x01, 0x04, 1, hpack_block)
        data_frame     = h2_frame(0x00, 0x01, 1, grpc_frame) # END_STREAM

        wire = client_preface + settings_frame + headers_frame + data_frame

        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(wire)

            # Read up to 4 KB of response — enough to see service names
            response = b''
            while len(response) < 4096:
                chunk = s.recv(1024)
                if not chunk:
                    break
                response += chunk
                # Stop once we see 'ServerReflectionInfo' or a known service name
                if b'ServerReflection' in response or b'grpc.' in response:
                    break

        # Parse service names from the gRPC response stream.
        # Each gRPC message: 1-byte compressed flag + 4-byte length + proto body.
        # We scan for printable ASCII strings that look like service names.
        services = []
        # Simple heuristic: find null-terminated or length-prefixed strings
        # containing dots (proto service names are dot-separated)
        text = response.decode('utf-8', errors='replace')
        for word in text.split():
            if '.' in word and all(c.isprintable() for c in word) and len(word) > 4:
                clean = ''.join(c for c in word if c.isalnum() or c in './_-')
                if clean and clean not in services:
                    services.append(clean[:80])

        if services:
            return f"reflection_ok: {', '.join(services[:6])}"
        if b'grpc' in response.lower() or len(response) > 9:
            return "likely"
        return "likely"

    except Exception:
        # Reflection refused or server doesn't support it — preface succeeded though
        return "likely"


# ─────────────────────────────────────────────
#  PHASE 3 — ENUMERATOR
# ─────────────────────────────────────────────

def _extract_mlflow_experiments(data: dict) -> dict:
    """Pull experiment names + IDs from MLflow experiments/search response."""
    exps = data.get("experiments", [])
    return {
        "count": len(exps),
        "names": [e.get("name") for e in exps if e.get("name")][:10],
        "ids":   [e.get("experiment_id") for e in exps if e.get("experiment_id")][:10],
    }


def _extract_mlflow_models(data: dict) -> dict:
    """Pull model names + latest versions from registered-models/list."""
    models = data.get("registered_models", [])
    return {
        "count":  len(models),
        "names":  [m.get("name") for m in models if m.get("name")][:10],
        "stages": list({
            v.get("current_stage") for m in models
            for v in m.get("latest_versions", [])
            if v.get("current_stage")
        }),
    }


def _extract_mlflow_versions(data: dict) -> dict:
    """Pull artifact URIs and creator IDs from model-versions/search."""
    mvs = data.get("model_versions", [])
    return {
        "count":         len(mvs),
        "artifact_uris": list({mv.get("source") for mv in mvs if mv.get("source")})[:8],
        "user_ids":      list({mv.get("user_id") for mv in mvs if mv.get("user_id")})[:8],
        "run_ids":       list({mv.get("run_id") for mv in mvs if mv.get("run_id")})[:5],
    }


def _extract_triton_models(data: dict) -> dict:
    """Pull model names from Triton /v2/models response."""
    models = data.get("models", []) if isinstance(data, dict) else []
    return {
        "count": len(models),
        "names": [m.get("name") for m in models if isinstance(m, dict) and m.get("name")][:10],
    }


def _extract_ollama_tags(data: dict) -> dict:
    """Pull model names + sizes from Ollama /api/tags response."""
    models = data.get("models", [])
    return {
        "count": len(models),
        "names": [m.get("name") for m in models if m.get("name")][:10],
        "sizes": [m.get("size") for m in models if m.get("size")][:10],
    }


def _extract_qdrant_collections(data: dict) -> dict:
    """Pull collection names from Qdrant /collections response."""
    cols = data.get("result", {}).get("collections", [])
    return {
        "count": len(cols),
        "names": [c.get("name") for c in cols if c.get("name")][:10],
    }


def _extract_weaviate_schema(data: dict) -> dict:
    """Pull class names + vectorisers from Weaviate /v1/schema."""
    classes = data.get("classes", [])
    return {
        "count":       len(classes),
        "class_names": [c.get("class") for c in classes if c.get("class")][:10],
        "vectorizers": list({c.get("vectorizer") for c in classes if c.get("vectorizer")})[:5],
    }


def _extract_jupyter_kernels(data) -> dict:
    """Pull kernel names + states from Jupyter /api/kernels."""
    if not isinstance(data, list):
        return {}
    return {
        "count":         len(data),
        "kernel_names":  list({k.get("name") for k in data if k.get("name")})[:10],
        "execution_states": list({
            k.get("execution_state") for k in data if k.get("execution_state")
        })[:5],
    }


def _extract_jupyter_contents(data: dict) -> dict:
    """Pull notebook filenames from Jupyter /api/contents."""
    content = data.get("content", []) if isinstance(data, dict) else []
    if not isinstance(content, list):
        return {}
    notebooks = [f.get("name") for f in content
                 if isinstance(f, dict) and str(f.get("name", "")).endswith(".ipynb")]
    return {
        "notebook_count": len(notebooks),
        "names":          notebooks[:10],
    }


def _extract_vllm_models(data: dict) -> dict:
    """Pull model IDs from vLLM /v1/models response."""
    models = data.get("data", []) if isinstance(data, dict) else []
    return {
        "count": len(models),
        "ids":   [m.get("id") for m in models if m.get("id")][:10],
    }


def _extract_ray_jobs(data) -> dict:
    """Pull job IDs + statuses from Ray /api/jobs/ response."""
    jobs = data if isinstance(data, list) else data.get("jobs", [])
    return {
        "count":    len(jobs),
        "job_ids":  [j.get("job_id") or j.get("submission_id") for j in jobs
                     if isinstance(j, dict)][:10],
        "statuses": list({j.get("status") for j in jobs if isinstance(j, dict)
                          and j.get("status")})[:5],
    }


# Map framework → extractor function per enum step label
_EXTRACTORS: dict[str, dict[str, callable]] = {
    "MLflow Tracking": {
        "Experiments":                      _extract_mlflow_experiments,
        "Registered Models":                _extract_mlflow_models,
        "Model Versions (artifact URIs + authors)": _extract_mlflow_versions,
    },
    "Triton Inference Server": {
        "Loaded Models": _extract_triton_models,
    },
    "vLLM / OpenAI-compat": {
        "Available LLM Models": _extract_vllm_models,
    },
    "Ollama": {
        "Local Model Tags": _extract_ollama_tags,
    },
    "Qdrant": {
        "Vector Collections": _extract_qdrant_collections,
    },
    "Weaviate": {
        "Schema / Classes": _extract_weaviate_schema,
    },
    "Jupyter Notebook": {
        "Active Kernels":  _extract_jupyter_kernels,
        "Notebook Files":  _extract_jupyter_contents,
    },
    "Ray Dashboard": {
        "Submitted Jobs": _extract_ray_jobs,
    },
}




# ─────────────────────────────────────────────
#  RISK FLAGS  (not exploit verification)
# ─────────────────────────────────────────────
#
# These are exposure indicators, not proof of exploitability.
# Each entry checks: is this endpoint reachable without authentication?
# If yes, we flag the *known risk pattern* associated with that service.
# The CVE references are informational context — this tool does NOT
# verify whether the specific vulnerable version is running.
#
# Schema: (framework_substr, probe_path, reference, severity, risk_description)

RISK_FLAGS = [
    ("MLflow Tracking",
     "/api/2.0/mlflow/experiments/search",
     "Ref: CVE-2024-1558, CVE-2026-2033",
     "CRITICAL",
     "Endpoint reachable without auth. Unauthenticated MLflow exposes full "
     "experiment/model registry. Referenced CVEs cover path traversal and "
     "RCE in certain versions — version not confirmed by this tool."),

    ("Jupyter Notebook",
     "/api/kernels",
     "Design risk (no single CVE)",
     "CRITICAL",
     "Kernel API reachable without auth. Unauthenticated Jupyter allows "
     "arbitrary code execution via kernel creation. No exploit needed."),

    ("Ray Dashboard",
     "/api/jobs/",
     "Ref: CVE-2023-48022",
     "CRITICAL",
     "Job API reachable without auth. Ray's job submission API had no "
     "authentication by design — arbitrary workload execution possible. "
     "Patch status not confirmed by this tool."),

    ("TorchServe Management",
     "/models",
     "Ref: CVE-2023-43654 (ShellTorch)",
     "HIGH",
     "Management API reachable without auth. Allows registering models from "
     "arbitrary URLs; model loading executes handler code. "
     "Version not confirmed by this tool."),

    ("Triton Prometheus",
     "/metrics",
     "No CVE — information exposure",
     "MEDIUM",
     "Prometheus /metrics reachable externally. Leaks loaded model names, "
     "GPU utilisation, and batch sizes — useful for topology mapping."),

    ("TorchServe Prometheus",
     "/metrics",
     "No CVE — information exposure",
     "MEDIUM",
     "Prometheus /metrics reachable externally. Exposes model names and "
     "deployment topology without authentication."),

    ("MinIO S3",
     "/minio/health/live",
     "No CVE — misconfiguration",
     "HIGH",
     "MinIO health endpoint reachable. If bucket ACLs are public, "
     "model artifacts (weights, datasets) may be listable/downloadable."),

    ("Ollama",
     "/api/tags",
     "Ref: CVE-2024-28224",
     "HIGH",
     "Model tag API reachable without auth. Exposes all locally installed "
     "models; unauthenticated Ollama may also allow model pull/delete. "
     "Version not confirmed by this tool."),
]


def check_risk_flags(framework: str, port: int, host: str, timeout: float) -> list[dict]:
    """
    Check exposure risk flags for an identified framework.

    A flag fires when: (a) framework name matches, AND
    (b) the probe endpoint returns HTTP < 400 (i.e. actually accessible).

    401 / 403 = protected → NOT flagged.
    200 / 301 / 302       = exposed  → flagged.

    Results are risk indicators, not verified exploits. Always confirm
    manually and check exact service versions before reporting as exploitable.
    """
    hits = []
    for fw, path, reference, severity, desc in RISK_FLAGS:
        if fw.lower() not in (framework or "").lower():
            continue
        resp = http_probe(host, port, path, "GET", None, timeout, retries=1)
        exposed = (
            resp["status"] is not None
            and resp["status"] < 400       # 401/403 = auth present → skip
            and resp["error"] is None
        )
        if exposed:
            hits.append({
                "reference": reference,
                "severity":  severity,
                "desc":      desc,
                "endpoint":  path,
                "status":    resp["status"],
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
    table.add_column("Port",           style="port",    width=7)
    table.add_column("Framework",      style="service", width=28)
    table.add_column("Confidence",                      width=10)
    table.add_column("gRPC Heuristic",                  width=16)
    table.add_column("Server Hdr",     style="dim",     width=22)
    table.add_column("Evidence Paths",                  width=34)

    grpc_color = {"likely": "green", "no_response": "dim", "unknown": "yellow"}

    for port, fp in sorted(fp_results.items()):
        fw   = fp.get("framework") or "[dim]Unknown[/dim]"
        con  = fp.get("confidence", "LOW")
        grpc = fp.get("grpc_heuristic", "—")
        srv  = fp.get("server_hdr", "")[:21]
        evid_paths = ", ".join(e["path"] for e in fp.get("evidence", []))[:32]

        # reflection_ok carries a service list — color it bold green, truncate for table
        if isinstance(grpc, str) and grpc.startswith("reflection_ok"):
            grpc_display = f"[bold green]reflect ✔[/bold green]"
        elif grpc == "—":
            grpc_display = "[dim]—[/dim]"
        else:
            grpc_display = f"[{grpc_color.get(grpc, 'dim')}]{grpc}[/]"
        table.add_row(
            str(port), fw,
            f"[{confidence_color(con)}]{con}[/]",
            grpc_display, srv or "—", evid_paths or "—",
        )
    console.print(table)


def print_enum_results(port: int, framework: str, enum_data: list[dict]):
    if not enum_data:
        return
    panel_lines = []
    for item in enum_data:
        sc = item["status"]
        status_color = "green" if sc < 300 else "yellow" if sc < 400 else "red"

        panel_lines.append(
            f"  [bold white]▸ {item['label']}[/bold white]  "
            f"[{status_color}]HTTP {sc}[/]  "
            f"[dim]{item['path']}[/dim]"
        )

        parsed = item.get("parsed", {})
        if parsed:
            # Render each extracted field on its own indented line
            for key, val in parsed.items():
                key_label = key.replace("_", " ").title()
                if isinstance(val, list):
                    if val:
                        panel_lines.append(
                            f"    [bold cyan]{key_label}:[/bold cyan] "
                            + ", ".join(str(v) for v in val)
                        )
                elif val not in (None, "", 0):
                    color = "bold yellow" if any(
                        kw in key for kw in ("uri", "id", "token", "secret", "key")
                    ) else "cyan"
                    panel_lines.append(f"    [{color}]{key_label}:[/] {val}")
        elif item.get("raw_keys"):
            # Fallback: just show top-level JSON keys
            panel_lines.append(
                f"    [dim]Keys: {', '.join(item['raw_keys'][:8])}[/dim]"
            )

        if not parsed and item["body_snip"] and sc < 400:
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
        console.print("[success]  ✔  No exposure risk flags triggered.[/success]")
        return

    table = Table(
        title="[danger]⚠  Exposure Risk Flags  (indicators only — verify versions manually)[/danger]",
        box=box.HEAVY, border_style="red", show_lines=True,
    )
    table.add_column("Port",      style="port",  width=7)
    table.add_column("Reference",                width=32)
    table.add_column("Severity",                 width=10)
    table.add_column("Risk Description",         width=60)

    for port, flags in sorted(vuln_results.items()):
        for v in flags:
            table.add_row(
                str(port),
                v["reference"],
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
             threads: int, do_enumerate: bool, output_file: Optional[str],
             verify: bool = False):
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

    if http_ports:
        # All HTTP ports are probed concurrently via aiohttp / asyncio.gather().
        # console.status() is a simple spinner — async bursts complete as a
        # collective result, so per-item progress bars aren't meaningful here.
        with console.status("[magenta]Fingerprinting services asynchronously…[/magenta]"):
            fp_results = asyncio.run(
                fingerprint_all_ports(target, http_ports, timeout, verify=verify)
            )

    # gRPC detection — runs after HTTP phase, uses raw sockets (no aiohttp)
    # Stage 1: HTTP/2 preface; Stage 2: gRPC reflection if preface succeeds.
    for port in open_ports:
        if open_ports[port]["proto"] == "gRPC":
            grpc_result = check_grpc(target, port, timeout)
            if port in fp_results:
                fp_results[port]["grpc_heuristic"] = grpc_result
            else:
                # Pure gRPC port — build a fingerprint entry from reflection result
                services_note = ""
                if grpc_result.startswith("reflection_ok"):
                    services_note = grpc_result[len("reflection_ok: "):]
                fp_results[port] = {
                    "framework":      (f"gRPC ({services_note})"
                                       if services_note
                                       else f"{AI_PORTS[port]['service']} (gRPC)"),
                    "confidence":     "HIGH" if grpc_result.startswith("reflection_ok") else "LOW",
                    "evidence":       [],
                    "server_hdr":     "",
                    "grpc_heuristic": grpc_result,
                    "score":          0,
                }

    print_fingerprint_table(fp_results)

    # ── Phase 3: Enumeration ────────────────────────────────────
    enum_results: dict = {}

    if do_enumerate:
        console.rule("[header]Phase 3 · Metadata Enumeration[/header]")

        # Build port→framework map for services that have an enumeration chain.
        # Fuzzy-match the identified framework name against ENUM_CHAINS keys.
        port_fw_map: dict[int, str] = {}
        for port, fp in fp_results.items():
            fw = fp.get("framework")
            if not fw:
                continue
            matched_fw = next((k for k in ENUM_CHAINS if k.lower() in fw.lower()), None)
            if matched_fw:
                port_fw_map[port] = matched_fw
                console.print(f"  [info]Queued[/info] :{port} [{matched_fw}]")

        if port_fw_map:
            with console.status("[blue]Executing enumeration chains concurrently…[/blue]"):
                enum_results = asyncio.run(
                    enumerate_all_ports(target, port_fw_map, timeout, verify=verify)
                )
            # Print gathered results after the async burst completes
            for port, data in enum_results.items():
                print_enum_results(port, port_fw_map[port], data)

    # ── Phase 4: Exposure Risk Flags ─────────────────────────────
    console.rule("[header]Phase 4 · Exposure Risk Flags[/header]")

    vuln_results: dict = {}
    for port, fp in fp_results.items():
        fw = fp.get("framework")
        if fw:
            flags = check_risk_flags(fw, port, target, timeout)
            if flags:
                vuln_results[port] = flags

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
    p.add_argument("--no-verify",      action="store_true",
                   help="Disable TLS certificate verification (self-signed certs)")
    p.add_argument("--max-cidr",       type=int, default=DEFAULT_MAX_CIDR,
                   help=f"Max hosts to scan in a CIDR range (default: {DEFAULT_MAX_CIDR})")
    return p.parse_args()


def expand_targets(target_str: str, max_cidr: int = DEFAULT_MAX_CIDR) -> list[str]:
    """
    Expand a CIDR range into individual host IPs, or validate/return a
    single hostname/IP.

    max_cidr is passed in explicitly — no global state mutation needed.

    Raises SystemExit on:
    - CIDR ranges exceeding max_cidr (safety cap against accidental large scans)
    - Targets that are neither a valid IP, CIDR, nor a resolvable hostname
    """
    # Try CIDR first
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > max_cidr:
            console.print(
                f"[danger]CIDR {target_str} expands to {len(hosts)} hosts, "
                f"which exceeds the safety cap of {max_cidr}.\n"
                f"Use a smaller range, or raise the cap with --max-cidr.[/danger]"
            )
            sys.exit(1)
        return [str(ip) for ip in hosts]
    except ValueError:
        pass  # Not a CIDR — treat as hostname or bare IP

    # Validate hostname / IP
    try:
        socket.getaddrinfo(target_str, None)
        return [target_str]
    except socket.gaierror:
        console.print(
            f"[danger]Cannot resolve target: '{target_str}'\n"
            f"Provide a valid IP address, hostname, or CIDR range.[/danger]"
        )
        sys.exit(1)


def main():
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

    # Expand targets — cap passed directly, no global mutation
    targets = expand_targets(args.target, max_cidr=args.max_cidr)

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
            verify=not args.no_verify,
        )
        all_reports[target] = report

    # Multi-target JSON dump
    if args.output and len(targets) > 1:
        with open(args.output, "w") as f:
            json.dump(all_reports, f, indent=2, default=str)
        console.print(f"\n  [success]✔  Combined report saved →[/success] [cyan]{args.output}[/cyan]\n")


if __name__ == "__main__":
    main()
