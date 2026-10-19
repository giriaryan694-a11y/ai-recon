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
    python ai_recon.py -t 10.0.0.5 --ports 5000,8000,8000-8100 --timeout 3
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

VERSION = "1.4.0"
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
    80:    {"service": "HTTP / reverse proxy (port hint)",  "category": "Web / Gateway",       "proto": "HTTP"},
    443:   {"service": "HTTP / HTTPS reverse proxy",        "category": "Web / Gateway",       "proto": "HTTPS"},
}

# Port numbers are hints only. These extra ports are common in local model
# runtimes, demos, API gateways, notebooks and AI workflow UIs. The service
# identity is determined by protocol/application evidence, never by port alone.
EXTRA_AI_PORT_HINTS = {
    1234:  {"service": "LM Studio / Local LLM API (hint)", "category": "LLM Serving", "proto": "HTTP"},
    3000:  {"service": "AI Web UI / frontend (hint)",       "category": "AI UI",       "proto": "HTTP"},
    4000:  {"service": "LiteLLM / API proxy (hint)",       "category": "LLM Gateway", "proto": "HTTP"},
    5001:  {"service": "AI API / app (hint)",              "category": "AI Application", "proto": "HTTP"},
    7860:  {"service": "Gradio / model UI (hint)",         "category": "AI UI",       "proto": "HTTP"},
    7861:  {"service": "Gradio / model UI (hint)",         "category": "AI UI",       "proto": "HTTP"},
    8088:  {"service": "AI workflow / web UI (hint)",      "category": "AI UI",       "proto": "HTTP"},
    8188:  {"service": "ComfyUI / image workflow (hint)",  "category": "AI UI",       "proto": "HTTP"},
    8443:  {"service": "HTTPS application (hint)",         "category": "Web / Gateway", "proto": "HTTPS"},
    9090:  {"service": "Metrics / application API (hint)", "category": "Metrics",      "proto": "HTTP"},
    9443:  {"service": "HTTPS application (hint)",         "category": "Web / Gateway", "proto": "HTTPS"},
    50051: {"service": "gRPC service (hint)",              "category": "RPC",          "proto": "gRPC"},
}
AI_PORTS.update(EXTRA_AI_PORT_HINTS)

# Smart profile balances AI-specific ports with common web/API/database ports.
# `broad` adds 1-1024 and common AI/data-plane ports. `all` is an explicit,
# exhaustive TCP connect scan of 1-65535. --ports overrides the profile.
COMMON_EXTRA_PORTS = {
    21, 22, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 587, 631, 636, 873, 902, 993, 995, 1080, 1433, 1521, 2049,
    2181, 2375, 2376, 3000, 3001, 3306, 3389, 4000, 4001, 4040, 4222, 4443,
    5000, 5001, 5005, 5432, 5555, 5601, 5672, 5900, 5984, 6379, 6443, 7001,
    7077, 7474, 7687, 7777, 7860, 7861, 8000, 8001, 8002, 8008, 8080, 8081,
    8082, 8088, 8089, 8090, 8188, 8200, 8443, 8500, 8501, 8502, 8600, 8686,
    8787, 8888, 9000, 9001, 9090, 9091, 9200, 9300, 9411, 9443, 9999, 10000,
    10250, 10255, 11211, 11434, 1234, 15000, 15672, 16686, 18080, 19530,
    27017, 30000, 50051, 50052,
}
SMART_PORTS = sorted(set(AI_PORTS) | COMMON_EXTRA_PORTS)
BROAD_PORTS = sorted(set(range(1, 1025)) | set(AI_PORTS) | COMMON_EXTRA_PORTS)
ALL_TCP_PORTS = list(range(1, 65536))


def parse_port_spec(spec: str) -> list[int]:
    """Parse comma-separated ports/ranges such as `22,80,8000-8010` or `all`."""
    if spec.strip().lower() in {"all", "1-65535", "1:65535"}:
        return ALL_TCP_PORTS.copy()
    ports: set[int] = set()
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        sep = "-" if "-" in item else (":" if ":" in item else None)
        try:
            if sep:
                left, right = item.split(sep, 1)
                start_port, end_port = int(left), int(right)
                if start_port > end_port:
                    raise ValueError(f"descending port range: {item}")
                if start_port < 1 or end_port > 65535:
                    raise ValueError(f"port range out of bounds: {item}")
                ports.update(range(start_port, end_port + 1))
            else:
                port = int(item)
                if not 1 <= port <= 65535:
                    raise ValueError(f"port out of range: {port}")
                ports.add(port)
        except ValueError as exc:
            raise ValueError(f"invalid port specification '{item}': {exc}") from exc
    if not ports:
        raise ValueError("port specification is empty")
    return sorted(ports)


def port_metadata(port: int) -> dict:
    """Return a port hint, not an asserted service identity."""
    return AI_PORTS.get(port, {
        "service": "Unknown TCP service (fingerprint required)",
        "category": "Unclassified",
        "proto": "TCP",
    })

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
    """Case-insensitive response-header value match."""
    wanted_key, wanted_value = key.lower(), value.lower()
    for header_name, header_value in (h or {}).items():
        normalized = str(header_name).lower()
        key_matches = normalized == wanted_key or (
            wanted_key.startswith("x-") and normalized.startswith(wanted_key + "-")
        )
        if key_matches and wanted_value in str(header_value).lower():
            return True
    return False


_SENSITIVE_RESPONSE_HEADERS = {
    "set-cookie", "cookie", "authorization", "proxy-authorization",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
}


def sanitize_headers(headers: dict) -> dict:
    """Redact response headers that might carry session or API credentials."""
    return {
        key: ("[REDACTED]" if str(key).lower() in _SENSITIVE_RESPONSE_HEADERS else value)
        for key, value in (headers or {}).items()
    }


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
         2, "OpenAI-compatible API"),

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
        # Opportunistic only: documented REST model-status paths require a
        # known model name, so do not guess names or claim a generic model list.
        ("/v1/models", "GET",
         lambda b, h: _body(b, '"model_version_status"'),
         2, "TensorFlow Serving"),
    ],

    # ── port 5000: MLflow ─────────────────────────────────────────
    5000: [
        # MLflow search endpoint returns {"experiments":[...]}
        ("/api/2.0/mlflow/experiments/search", "POST",
         lambda b, h: _body(b, '"experiments"'),
         3, "MLflow Tracking"),

        # MLflow UI root references "mlflow" in page content or X-Frame-Options
        ("/", "GET",
         lambda b, h: _body(b, "mlflow"),
         2, "MLflow Tracking"),
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
        # A successful health endpoint alone is not enough: other apps and
        # reverse proxies may return 200 for arbitrary paths. Require an
        # identifying MinIO header or response marker.
        ("/minio/health/live", "GET",
         lambda b, h: _hdr(h, "server", "minio") or _hdr(h, "x-minio", "") or _body_any(b, "minio"),
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

        # Version-only JSON is too generic to identify Ollama reliably; /api/tags is preferred.
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



# Port-agnostic application fingerprints. These are deliberately read-only GETs
# except MLflow's documented POST search endpoint, which sends an empty query.
# This table is applied to every HTTP(S) service discovered on any scanned port.
GLOBAL_FINGERPRINT_PROBES: list[tuple] = [
    ("/v1/models", "GET",
     lambda b, h: _openai_models_shape(b), 2, "OpenAI-compatible API"),
    ("/api/tags", "GET",
     lambda b, h: _ollama_tags_shape(b), 2, "Ollama"),
    ("/v2", "GET",
     lambda b, h: _body(b, '"name"', '"triton"', '"extensions"'), 3, "Triton Inference Server"),
    ("/v2/models", "GET",
     lambda b, h: _body(b, '"platform"', '"versions"'), 2, "Triton Inference Server"),
    ("/info", "GET",
     lambda b, h: _tgi_info_shape(b), 3, "Hugging Face Text Generation Inference"),
    ("/api/v2/heartbeat", "GET",
     lambda b, h: _body_any(b, "nanosecond heartbeat", "heartbeat"), 2, "Chroma DB"),
    ("/api/v1/collections", "GET",
     lambda b, h: _body(b, '"name"', '"metadata"') and resp_is_json_array(b), 2, "Chroma DB"),
    ("/collections", "GET",
     lambda b, h: _qdrant_collections_shape(b), 3, "Qdrant"),
    ("/v1/schema", "GET",
     lambda b, h: _weaviate_schema_shape(b), 3, "Weaviate"),
    ("/v1/meta", "GET",
     lambda b, h: _weaviate_meta_shape(b), 2, "Weaviate"),
    ("/api/version", "GET",
     lambda b, h: _ray_version_shape(b), 3, "Ray Dashboard"),
    ("/api/2.0/mlflow/experiments/search", "POST",
     lambda b, h: _mlflow_search_shape(b), 3, "MLflow Tracking"),
    ("/ping", "GET",
     lambda b, h: _body(b, '"status"', '"healthy"'), 3, "TorchServe"),
    ("/models", "GET",
     lambda b, h: _body(b, '"modelName"'), 2, "TorchServe"),
    ("/api", "GET",
     lambda b, h: _jupyter_api_shape(b), 2, "Jupyter Notebook"),
    ("/config", "GET",
     lambda b, h: _gradio_config_shape(b), 2, "Gradio"),
    ("/openapi.json", "GET",
     lambda b, h: _openapi_ai_signature(b), 2, "AI/ML OpenAPI service"),
    ("/api/v1/ping", "GET",
     lambda b, h: _body_any(b, "pong"), 2, "Flowise-like API"),
    ("/system_stats", "GET",
     lambda b, h: _body(b, '"system"', '"devices"') and _body_any(b, "comfyui", "pytorch_version", "comfyui_version"),
     3, "ComfyUI"),
    ("/_stcore/health", "GET",
     lambda b, h: _hdr(h, "server", "streamlit") or _body(b, "streamlit"), 2, "Streamlit"),
    ("/metrics", "GET",
     lambda b, h: "nv_inference_" in b, 3, "Triton Prometheus"),
    ("/metrics", "GET",
     lambda b, h: b.startswith("# HELP ts_") or "ts_inference_" in b, 3, "TorchServe Prometheus"),
    ("/minio/health/live", "GET",
     lambda b, h: _hdr(h, "server", "minio") or _hdr(h, "x-minio", ""), 2, "MinIO S3"),
]


def _json_value(body: str):
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None


def _openai_models_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and data.get("object") == "list" and isinstance(data.get("data"), list)


def _ollama_tags_shape(body: str) -> bool:
    data = _json_value(body)
    if not isinstance(data, dict) or not isinstance(data.get("models"), list):
        return False
    models = data.get("models", [])
    return not models or any(isinstance(m, dict) and ("digest" in m or "modified_at" in m) for m in models)


def _tgi_info_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and "model_id" in data and any(
        k in data for k in ("model_sha", "max_input_length", "max_total_tokens")
    )


def _qdrant_collections_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and isinstance(data.get("result"), dict) and isinstance(
        data["result"].get("collections"), list
    )


def _weaviate_schema_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and isinstance(data.get("classes"), list) and (
        "vectorizer" in body.lower() or "moduleconfig" in body.lower()
    )


def _weaviate_meta_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and all(k in data for k in ("hostname", "modules", "version"))


def _ray_version_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and "ray_version" in data and "ray_commit" in data


def _mlflow_search_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and isinstance(data.get("experiments"), list)


def _jupyter_api_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and "version" in data and "version_info" in data


def _gradio_config_shape(body: str) -> bool:
    data = _json_value(body)
    return isinstance(data, dict) and "components" in data and "dependencies" in data and "version" in data


def _openapi_ai_signature(body: str) -> bool:
    low = body.lower()
    # OpenAPI title/path text is only considered AI-related when it contains a
    # recognized engine/runtime token; generic Swagger JSON is not enough.
    return "openapi" in low and any(token in low for token in (
        "vllm", "litellm", "llama.cpp", "llamacpp", "text-generation-inference",
        "huggingface", "mlflow", "torchserve", "bentoml", "xinference", "sglang",
    ))


def root_fingerprint_hits(body: str, headers: dict, status: Optional[int] = None) -> list[dict]:
    """Return weighted product-level matches from root HTML/banner text."""
    text = (body or "").lower()
    hits = []
    rules = [
        ("Ollama", ("ollama is running",), 3),
        ("LocalAI", ("localai", "local-ai"), 3),
        ("Xinference", ("xinference",), 3),
        ("SGLang", ("sglang",), 3),
        ("vLLM", ("vllm",), 3),
        ("Hugging Face Text Generation Inference", ("text generation inference", "huggingface/tgi"), 3),
        ("Open WebUI", ("open webui", "open-webui"), 3),
        ("ComfyUI", ("comfyui",), 3),
        ("Stable Diffusion WebUI", ("stable diffusion webui", "automatic1111"), 3),
        ("Gradio", ("gradio-app", "gradio-container"), 2),
        ("Streamlit", ("streamlit", "_stcore"), 2),
        ("MLflow Tracking", ("mlflow",), 2),
        ("Jupyter Notebook", ("jupyter notebook", "jupyterlab"), 2),
        ("LiteLLM Proxy", ("litellm",), 3),
        ("Flowise", ("flowise",), 3),
        ("Langflow", ("langflow",), 3),
        ("Dify", ("dify",), 3),
        ("AnythingLLM", ("anythingllm",), 3),
        ("BentoML", ("bentoml",), 3),
        ("MinIO Console", ("minio browser", "minio console"), 3),
    ]
    for framework, markers, weight in rules:
        if any(marker in text for marker in markers):
            hits.append({"path": "/", "status": status, "weight": weight,
                         "hit": True, "framework": framework,
                         "headers": headers, "body_snip": (body or "")[:400]})
    return hits


def _probes_for_port(port: int) -> list[tuple]:
    """Merge local and cross-port signatures, deduplicating by path/method/name."""
    merged = []
    seen = set()
    for probe in list(FINGERPRINT_PROBES.get(port, [])) + GLOBAL_FINGERPRINT_PROBES:
        key = (probe[0], probe[1], probe[4])
        if key not in seen:
            seen.add(key)
            merged.append(probe)
    return merged

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
        ("GET",  "/api/2.0/mlflow/registered-models/search", None,   "Registered Models"),
        ("GET",  "/api/2.0/mlflow/model-versions/search",    None,   "Model Versions (artifact URIs + authors)"),
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
        ("GET",  "/api/v2/tenants/default_tenant/databases/default_database/collections", None, "Collections (v2 API)"),
        ("GET",  "/api/v1/collections",                      None,   "Collections (legacy API)"),
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
    "OpenAI-compatible API": [
        ("GET", "/v1/models", None, "Available Models"),
    ],
    "vLLM": [
        ("GET", "/v1/models", None, "Available Models"),
        ("GET", "/version", None, "Server Version"),
    ],
    "llama.cpp Server": [
        ("GET", "/v1/models", None, "Available Models"),
        ("GET", "/props", None, "Runtime Metadata"),
    ],
    "Hugging Face Text Generation Inference": [
        ("GET", "/info", None, "Runtime Info"),
    ],
    "ComfyUI": [
        ("GET", "/system_stats", None, "Runtime / Device Metadata"),
    ],
    "Gradio": [
        ("GET", "/config", None, "Interface Configuration"),
    ],
    "LiteLLM Proxy": [
        ("GET", "/health/liveliness", None, "Proxy Health"),
        ("GET", "/v1/models", None, "Available Models"),
    ],
    "LocalAI": [
        ("GET", "/v1/models", None, "Available Models"),
    ],
    "SGLang": [
        ("GET", "/v1/models", None, "Available Models"),
    ],
    "Xinference": [
        ("GET", "/v1/models", None, "Available Models"),
    ],
    "LM Studio": [
        ("GET", "/v1/models", None, "Available Models"),
    ],
    "Open WebUI": [
        # Open WebUI documents this API route; it may require bearer auth.
        ("GET", "/api/models", None, "Configured Models"),
    ],
    "Streamlit": [
        ("GET", "/_stcore/health", None, "Health"),
    ],
    "Flowise": [
        ("GET", "/api/v1/ping", None, "API Health"),
    ],
    "Stable Diffusion WebUI": [
        ("GET", "/sdapi/v1/sd-models", None, "Available Checkpoints"),
    ],
}

# Contextual mapping based on the current MITRE ATLAS 2026.09 data release.
# These labels describe analogous scan activities, not proof of adversary behavior.
ATLAS_SCAN_TECHNIQUE = ("AML.T0006", "Active Scanning")
ATLAS_ARTIFACT_TECHNIQUE = ("AML.T0006.000", "Active Scanning: Enumerate Hosted AI Resources")
ATLAS_METADATA_TECHNIQUE = ("AML.T0006.001", "Active Scanning: Query Platform Metadata APIs")
ATLAS_INFRA_TECHNIQUE = ("AML.T0006.002", "Active Scanning: Scan for Exposed AI Infrastructure")
ATLAS_CONTEXT_NOTE = (
    "Contextual mapping only. Scanner output does not establish adversary activity, "
    "and a software fingerprint alone does not prove that a technique occurred."
)

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



def _url_host(host: str) -> str:
    """Bracket IPv6 literals for URL authority syntax without changing DNS names."""
    value = host.strip()
    if value.startswith("[") and value.endswith("]"):
        return value
    try:
        parsed = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return value
    return f"[{value}]" if parsed.version == 6 else value


def _make_ssl_ctx(verify: bool) -> ssl.SSLContext:
    """Return a TLS context; certificate verification is enabled by default."""
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
                           retries: int = 1,
                           scheme: Optional[str] = None) -> dict:
    """
    Async HTTP probe with retry + jitter on transient failures.

    Uses aiohttp so all port probes within a phase run concurrently
    instead of waiting for each one sequentially. The session's SSL
    context is configured externally via _make_ssl_ctx().

    POST requests are sent with json= equivalent (aiohttp json= kwarg)
    so Content-Type is set correctly without manual header injection.
    """
    scheme = scheme or ("https" if port == 443 else "http")
    url    = f"{scheme}://{_url_host(host)}:{port}{path}"
    result = {"url": url, "scheme": scheme, "status": None, "headers": {}, "body": "", "error": None}
    hdrs   = {"User-Agent": f"AIRecon/{VERSION}"}

    for attempt in range(retries + 1):
        try:
            to = aiohttp.ClientTimeout(total=timeout)
            if method == "POST":
                json_body = json.loads(body) if isinstance(body, str) else ({} if body is None else body)
                async with session.post(url, json=json_body, headers=hdrs, timeout=to,
                                        allow_redirects=False) as resp:
                    result["status"]  = resp.status
                    result["headers"] = dict(resp.headers)
                    result["body"]    = (await resp.text())[:2000]
                    result["error"]   = None
            else:
                async with session.get(url, headers=hdrs, timeout=to,
                                       allow_redirects=False) as resp:
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
               verify: bool = True, retries: int = 1,
               scheme: Optional[str] = None) -> dict:
    """
    Synchronous HTTP probe used only for risk-flag checks (Phase 4).
    All fingerprinting (Phase 2) and enumeration (Phase 3) use the async path.
    """
    scheme = scheme or ("https" if port == 443 else "http")
    url    = f"{scheme}://{_url_host(host)}:{port}{path}"
    result = {"url": url, "scheme": scheme, "status": None, "headers": {}, "body": "", "error": None}
    hdrs   = {"User-Agent": f"AIRecon/{VERSION}"}

    for attempt in range(retries + 1):
        try:
            if method == "POST":
                json_body = json.loads(body) if isinstance(body, str) else ({} if body is None else body)
                resp = requests.post(url, json=json_body, headers=hdrs,
                                     timeout=timeout, verify=verify, allow_redirects=False)
            else:
                resp = requests.get(url, headers=hdrs, timeout=timeout, verify=verify,
                                    allow_redirects=False)
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


async def _detect_http_scheme(session: aiohttp.ClientSession, host: str, port: int,
                              timeout: float) -> tuple[Optional[str], Optional[dict]]:
    """Try the likely HTTP scheme first and switch on protocol-mismatch evidence."""
    preferred = ["https", "http"] if port in {443, 4443, 8443, 9443} else ["http", "https"]
    responses = []
    for scheme in preferred:
        response = await async_http_probe(session, host, port, "/", "GET", None,
                                          timeout, retries=0, scheme=scheme)
        if response.get("status") is None or response.get("error") is not None:
            continue
        status = int(response["status"])
        responses.append((scheme, response))

        headers = response.get("headers", {})
        location = str(headers.get("Location", headers.get("location", "")) or "")
        # Do not follow redirects. A redirect to HTTPS is a reason to probe TLS
        # directly on this same host/port, never to contact the redirect host.
        if (scheme == "http" and status in {301, 302, 303, 307, 308}
                and location.lower().startswith("https://")):
            continue

        # These statuses commonly mean that a TLS listener received clear HTTP.
        if status in {400, 426}:
            continue
        return scheme, response

    # If only protocol-mismatch responses were seen, leave the port for the
    # non-HTTP banner/TLS probe rather than mislabelling it as an HTTP service.
    usable = [item for item in responses if item[1].get("status") not in {400, 426}]
    if usable:
        return usable[-1] if usable[-1][0] == "https" else usable[0]
    return None, None


async def _fingerprint_port(session: aiohttp.ClientSession,
                            host: str, port: int, timeout: float) -> tuple[int, Optional[dict]]:
    """Fingerprint an HTTP(S) application without assuming its port number."""
    scheme, root = await _detect_http_scheme(session, host, port, timeout)
    if not scheme or not root:
        return port, None

    probes = _probes_for_port(port)
    tasks = [
        async_http_probe(session, host, port, path, method,
                         "{}" if method == "POST" else None,
                         timeout, retries=0, scheme=scheme)
        for path, method, *_ in probes
    ]
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    findings = []
    root_hits = root_fingerprint_hits(root.get("body", ""),
                                      sanitize_headers(root.get("headers", {})),
                                      root.get("status"))
    findings.extend(root_hits)

    for (path, method, match_fn, weight, framework), resp in zip(probes, responses):
        if isinstance(resp, Exception) or resp.get("status") is None or resp.get("error"):
            continue
        try:
            matched = bool(match_fn(resp.get("body", ""), resp.get("headers", {})))
        except Exception:
            matched = False
        if matched:
            findings.append({
                "path": path, "status": resp["status"], "weight": weight,
                "hit": True, "framework": framework,
                "headers": sanitize_headers(resp.get("headers", {})),
                "body_snip": resp.get("body", "")[:400],
            })

    # Refine generic OpenAI-compatible fingerprints using explicit engine tokens.
    for finding in findings:
        if finding.get("framework") == "OpenAI-compatible API":
            marker = (finding.get("body_snip", "") + " " +
                      json.dumps(finding.get("headers", {}))).lower()
            if "llamacpp" in marker or "llama.cpp" in marker:
                finding["framework"] = "llama.cpp Server"
            elif "vllm" in marker:
                finding["framework"] = "vLLM"
            elif "lm studio" in marker or "lmstudio" in marker:
                finding["framework"] = "LM Studio"
            elif "litellm" in marker:
                finding["framework"] = "LiteLLM Proxy"
            elif "sglang" in marker:
                finding["framework"] = "SGLang"

    fw_scores: dict[str, int] = {}
    for finding in findings:
        fw = finding.get("framework")
        if finding.get("hit") and fw:
            fw_scores[fw] = fw_scores.get(fw, 0) + int(finding.get("weight", 0))

    # A strong, specific signature should win over generic root-page branding.
    priority = {
        "Triton Inference Server": 10, "Ollama": 10, "Hugging Face Text Generation Inference": 10,
        "TorchServe": 10, "TorchServe Management": 10, "TensorFlow Serving": 10,
        "Qdrant": 10, "Weaviate": 10, "Chroma DB": 10, "MLflow Tracking": 10,
        "Ray Dashboard": 10, "OpenAI-compatible API": 4,
    }
    best = max(fw_scores, key=lambda name: (fw_scores[name], priority.get(name, 5))) if fw_scores else None
    score = fw_scores.get(best, 0) if best else 0

    all_headers = sanitize_headers(root.get("headers", {}))
    for finding in findings:
        all_headers.update(finding.get("headers", {}))
    server_hdr = all_headers.get("Server", all_headers.get("server", ""))
    if not best and "torchserve" in server_hdr.lower():
        best, score = "TorchServe", 3
    elif not best and "uvicorn" in server_hdr.lower():
        best, score = "Uvicorn / ASGI application (AI identity unconfirmed)", 1

    confidence = "HIGH" if score >= 3 else "MEDIUM" if score >= 1 else "LOW"
    # Generic API compatibility is not engine identification, cap its confidence.
    if best == "OpenAI-compatible API":
        confidence = "MEDIUM"

    # Keep the endpoint that caused each positive match as the principal evidence.
    evidence = [f for f in findings if f.get("hit")]
    result = {
        "framework": best,
        "confidence": confidence,
        "score": score,
        "scheme": scheme,
        "evidence": evidence[:30],
        "server_hdr": server_hdr,
        "all_headers": all_headers,
        "root_status": root.get("status"),
        "root_title_hint": root.get("body", "")[:160].replace("\n", " "),
    }
    return port, result


async def fingerprint_all_ports(host: str, ports: list[int],
                                timeout: float, verify: bool) -> dict:
    """Attempt HTTP and HTTPS fingerprinting on every open port, independent of port number."""
    ssl_ctx = _make_ssl_ctx(verify)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=100, limit_per_host=40)
    async with aiohttp.ClientSession(connector=connector) as session:
        port_semaphore = asyncio.Semaphore(20)

        async def bounded_probe(port: int):
            async with port_semaphore:
                return await _fingerprint_port(session, host, port, timeout)

        results = await asyncio.gather(*(bounded_probe(p) for p in ports), return_exceptions=True)

    fingerprints: dict[int, dict] = {}
    for item in results:
        if isinstance(item, Exception):
            continue
        port, data = item
        if data is not None:
            fingerprints[port] = data
    return fingerprints


async def _enumerate_port(session: aiohttp.ClientSession,
                           host: str, port: int,
                           framework: str, timeout: float,
                           scheme: Optional[str] = None) -> tuple[int, list]:
    """Async helper: run the enumeration chain for one port."""
    chain   = ENUM_CHAINS.get(framework, [])
    fw_extr = _EXTRACTORS.get(framework, {})
    results = []

    tasks = [
        async_http_probe(session, host, port, path,
                         method, body, timeout, retries=1, scheme=scheme)
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
                               timeout: float, verify: bool,
                               scheme_map: Optional[dict[int, str]] = None) -> dict:
    """
    Run all enumeration chains concurrently across all identified services.
    """
    ssl_ctx   = _make_ssl_ctx(verify)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _enumerate_port(session, host, port, fw, timeout,
                            (scheme_map or {}).get(port))
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
    """Detect a plaintext HTTP/2 listener; this alone does not prove gRPC or reflection."""
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    # Empty client SETTINGS frame, length=0, type=SETTINGS, stream=0.
    settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 1.0))
            sock.sendall(preface + settings)
            response = sock.recv(256)
        # HTTP/2 frame header: 3-byte length, type, flags, 4-byte stream ID.
        if len(response) >= 9 and response[3] == 0x04 and response[5:9] == b"\x00\x00\x00\x00":
            return "http2_detected (gRPC possible; service identity unconfirmed)"
        if response.startswith(b"HTTP/"):
            return "http1_detected"
        return "no_response"
    except (OSError, socket.timeout):
        return "no_response"


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
    """Pull registered model names + latest versions from registered-models/search."""
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


def _extract_triton_models(data) -> dict:
    """Pull model names from Triton's v2 model-list response (normally a JSON array)."""
    if isinstance(data, list):
        models = data
    elif isinstance(data, dict):
        models = data.get("models", [])
    else:
        models = []
    if not isinstance(models, list):
        return {}
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


def _extract_chroma_collections(data) -> dict:
    """Summarize Chroma collection records without dumping full metadata."""
    collections = data if isinstance(data, list) else data.get("collections", []) if isinstance(data, dict) else []
    if not isinstance(collections, list):
        return {}
    names = [item.get("name") for item in collections if isinstance(item, dict) and item.get("name")]
    return {"count": len(collections), "names": names[:20]}


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


def _extract_model_items(data) -> dict:
    """Extract model identifiers from common API list wrappers without retaining full objects."""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = next((data.get(key) for key in ("data", "models", "items")
                      if isinstance(data.get(key), list)), [])
    else:
        items = []
    names = []
    for item in items:
        if isinstance(item, dict):
            name = item.get("id") or item.get("name") or item.get("model_name")
            if name:
                names.append(str(name))
        elif isinstance(item, str):
            names.append(item)
    return {"count": len(items), "names": names[:20]}


def _extract_ray_jobs(data) -> dict:
    """Pull job IDs + statuses from Ray's list response, which varies by API version."""
    if isinstance(data, list):
        jobs = data
    elif isinstance(data, dict) and isinstance(data.get("jobs"), list):
        jobs = data["jobs"]
    elif isinstance(data, dict):
        jobs = []
        for job_id, value in data.items():
            if isinstance(value, dict):
                item = dict(value)
                item.setdefault("job_id", job_id)
                jobs.append(item)
    else:
        jobs = []
    return {
        "count": len(jobs),
        "job_ids": [j.get("job_id") or j.get("submission_id") for j in jobs
                    if isinstance(j, dict) and (j.get("job_id") or j.get("submission_id"))][:10],
        "statuses": list({j.get("status") for j in jobs if isinstance(j, dict) and j.get("status")})[:5],
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
    "Chroma DB": {
        "Collections (v2 API)": _extract_chroma_collections,
        "Collections (legacy API)": _extract_chroma_collections,
        "Collections": _extract_chroma_collections,
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
    "OpenAI-compatible API": {
        "Available Models": _extract_vllm_models,
    },
    "vLLM": {
        "Available Models": _extract_vllm_models,
    },
    "llama.cpp Server": {
        "Available Models": _extract_vllm_models,
    },
    "LocalAI": {"Available Models": _extract_vllm_models},
    "SGLang": {"Available Models": _extract_vllm_models},
    "Xinference": {"Available Models": _extract_vllm_models},
    "LM Studio": {"Available Models": _extract_vllm_models},
    "Open WebUI": {"Configured Models": _extract_model_items},
    "Stable Diffusion WebUI": {"Available Checkpoints": _extract_model_items},
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
     "Review CVE-2024-1558 and CVE-2026-2033 for the exact installed version",
     "HIGH",
     "The read-only experiment-search API returned data without an authentication challenge. "
     "This indicates an exposed tracking surface; the referenced CVEs are version-specific and are not verified here."),
    ("Jupyter Notebook",
     "/api/kernels",
     "Exposure indicator — Jupyter API authentication review",
     "MEDIUM",
     "The kernels API returned a JSON list without an authentication challenge. This alone does not prove unauthenticated kernel creation or code execution."),
    ("Ray Dashboard",
     "/api/jobs/",
     "Review CVE-2023-48022 and Ray security configuration",
     "HIGH",
     "The Ray Jobs API returned job-list data without an authentication challenge. Job submission exposure can be high risk; version/configuration and exploitability were not verified."),
    ("TorchServe",
     "/models",
     "Review CVE-2023-43654 (affected TorchServe versions < 0.8.2)",
     "HIGH",
     "The model-management endpoint returned a TorchServe-like model list without an authentication challenge. Version and registration permissions were not verified."),
    ("Ollama",
     "/api/tags",
     "Review CVE-2024-28224 against the exact Ollama version and deployment context",
     "MEDIUM",
     "The model-tags endpoint returned model metadata without an authentication challenge. This does not establish that the historical DNS-rebinding issue is present."),
]


def check_risk_flags(framework: str, port: int, host: str, timeout: float,
                     verify: bool = True, scheme: Optional[str] = None) -> list[dict]:
    """Check a few exposure indicators. These are not exploit or CVE verification."""
    fw_low = (framework or "").lower()
    hits = []
    for fw, path, reference, severity, desc in RISK_FLAGS:
        if fw.lower() not in fw_low:
            continue
        # MLflow's documented experiment-search endpoint is POST, not GET.
        method = "POST" if "mlflow" in fw.lower() else "GET"
        body = "{}" if method == "POST" else None
        resp = http_probe(host, port, path, method, body, timeout,
                          verify=verify, retries=0, scheme=scheme)
        status = resp.get("status")
        if status != 200 or resp.get("error") is not None:
            continue
        response_body = resp.get("body", "")
        parsed = _json_value(response_body)
        # Require an endpoint-specific response shape, not just HTTP 200.
        if "mlflow" in fw.lower():
            signature_ok = isinstance(parsed, dict) and isinstance(parsed.get("experiments"), list)
        elif "jupyter" in fw.lower():
            signature_ok = isinstance(parsed, list)
        elif "ray" in fw.lower():
            signature_ok = isinstance(parsed, (list, dict)) and (
                isinstance(parsed, list) or "jobs" in parsed or "job_id" in response_body
            )
        elif "torchserve" in fw.lower():
            signature_ok = isinstance(parsed, (list, dict)) and (
                "modelname" in response_body.lower() or isinstance(parsed, list) or "models" in parsed
            )
        elif "ollama" in fw.lower():
            signature_ok = isinstance(parsed, dict) and isinstance(parsed.get("models"), list)
        else:
            signature_ok = False
        if signature_ok:
            hits.append({
                "reference": reference,
                "severity": severity,
                "desc": desc,
                "endpoint": path,
                "status": status,
                "scheme": scheme or ("https" if port == 443 else "http"),
                "verification": "Exposure indicator only; version-specific vulnerability not verified.",
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
    compact = (console.width or 120) < 112
    table = Table(title="[header]Open TCP Ports / Port Hints[/header]",
                  box=box.ROUNDED, border_style="cyan", show_lines=False)
    table.add_column("Port", style="port", width=5, no_wrap=True)
    table.add_column("Service / Hint", style="service", width=25 if compact else 32, overflow="fold")
    table.add_column("Category", style="category", width=13 if compact else 18, overflow="fold")
    table.add_column("Proto", style="proto", width=6, no_wrap=True)
    table.add_column("ATLAS", style="atlas", width=10 if compact else 14, no_wrap=True)
    if not compact:
        table.add_column("Technique", width=28, overflow="fold")

    for port, meta in sorted(open_ports.items()):
        atlas_id, atlas_name = ATLAS_SCAN_TECHNIQUE
        row = [str(port), meta["service"], meta["category"], meta["proto"], atlas_id]
        if not compact:
            row.append(atlas_name)
        table.add_row(*row)
    console.print(table)


def print_fingerprint_table(fp_results: dict):
    compact = (console.width or 120) < 112
    table = Table(title="[header]Service Fingerprinting Results[/header]",
                  box=box.ROUNDED, border_style="magenta", show_lines=False)
    table.add_column("Port", style="port", width=5, no_wrap=True)
    table.add_column("Service / Framework", style="service", width=24 if compact else 28, overflow="fold")
    table.add_column("Conf.", width=7, no_wrap=True)
    table.add_column("Scheme", width=7, no_wrap=True)
    table.add_column("Evidence", width=20 if compact else 28, overflow="fold")
    if not compact:
        table.add_column("Server Header", style="dim", width=22, overflow="fold")

    for port, fp in sorted(fp_results.items()):
        framework = fp.get("framework") or "Unknown HTTP service"
        confidence = fp.get("confidence", "LOW")
        scheme = fp.get("scheme", "—")
        evidence_paths = ", ".join(e.get("path", "?") for e in fp.get("evidence", []))[:45]
        row = [
            str(port), framework,
            f"[{confidence_color(confidence)}]{confidence}[/]",
            scheme,
            evidence_paths or "—",
        ]
        if not compact:
            row.append((fp.get("server_hdr") or "—")[:35])
        table.add_row(*row)
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
        f"  [bold white]Open TCP Ports[/bold white] : [green]{len(open_ports)}[/green]",
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
            "atlas_context": {
                "port_and_service_discovery": {
                    "id": ATLAS_SCAN_TECHNIQUE[0],
                    "name": ATLAS_SCAN_TECHNIQUE[1],
                    "note": ATLAS_CONTEXT_NOTE,
                },
                "hosted_ai_resource_enumeration": {
                    "id": ATLAS_ARTIFACT_TECHNIQUE[0],
                    "name": ATLAS_ARTIFACT_TECHNIQUE[1],
                    "relevance": "Potentially relevant only if results actually identify hosted AI resources.",
                    "note": ATLAS_CONTEXT_NOTE,
                },
                "platform_metadata_api_queries": {
                    "id": ATLAS_METADATA_TECHNIQUE[0],
                    "name": ATLAS_METADATA_TECHNIQUE[1],
                    "relevance": "Potentially relevant when supported APIs return inventory or model metadata.",
                    "note": ATLAS_CONTEXT_NOTE,
                },
                "exposed_ai_infrastructure_scan": {
                    "id": ATLAS_INFRA_TECHNIQUE[0],
                    "name": ATLAS_INFRA_TECHNIQUE[1],
                    "relevance": "Describes the infrastructure-discovery activity, not proof of a misconfiguration.",
                    "note": ATLAS_CONTEXT_NOTE,
                },
            },
        },
        "open_ports":   {str(k): v for k, v in open_ports.items()},
        "fingerprints": {str(k): v for k, v in fp_results.items()},
        "enumeration":  {str(k): v for k, v in enum_results.items()},
        "vulnerabilities": {str(k): v for k, v in vuln_results.items()},
    }


# ─────────────────────────────────────────────
#  CORE SCAN ORCHESTRATOR
# ─────────────────────────────────────────────

def _recv_banner(host: str, port: int, timeout: float) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 0.6))
            try:
                return sock.recv(512)
            except (socket.timeout, OSError):
                return b""
    except OSError:
        return b""


def _probe_redis(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 0.8))
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            data = sock.recv(512)
        upper = data.upper()
        if data.startswith(b"+PONG"):
            return "Redis (RESP)"
        if data.startswith(b"-NOAUTH") or data.startswith(b"-ERR"):
            return "Redis (RESP; authentication/command policy may apply)"
    except OSError:
        pass
    return None


def _probe_postgres(host: str, port: int, timeout: float) -> Optional[str]:
    # PostgreSQL SSLRequest: 8-byte packet; server responds with S or N.
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 0.8))
            sock.sendall(struct.pack("!II", 8, 80877103))
            response = sock.recv(1)
        if response in (b"S", b"N"):
            return "PostgreSQL protocol"
    except OSError:
        pass
    return None


def _probe_tls(host: str, port: int, timeout: float) -> Optional[dict]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        try:
            ipaddress.ip_address(host)
            server_name = None
        except ValueError:
            server_name = host
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(min(timeout, 1.0))
            with context.wrap_socket(raw, server_hostname=server_name) as wrapped:
                cert = wrapped.getpeercert()
                alpn = wrapped.selected_alpn_protocol()
                identified_name = "HTTP/2 over TLS (gRPC possible)" if alpn == "h2" else "TLS service (application protocol unidentified)"
                return {
                    "framework": identified_name,
                    "confidence": "LOW",
                    "score": 0,
                    "scheme": "tls",
                    "evidence": [{"path": "TLS handshake", "status": None, "weight": 1,
                                  "hit": True, "framework": "TLS service",
                                  "headers": {}, "body_snip": ""}],
                    "server_hdr": "",
                    "all_headers": {},
                    "tls_version": wrapped.version(),
                    "tls_alpn": alpn,
                    "cipher": (wrapped.cipher() or [None])[0],
                    "certificate_subject": cert.get("subject", []) if cert else [],
                }
    except (OSError, ssl.SSLError, ValueError):
        return None


def fingerprint_tcp_service(host: str, port: int, timeout: float) -> Optional[dict]:
    """Low-impact banner/protocol fingerprints for non-HTTP TCP listeners."""
    banner = _recv_banner(host, port, timeout)
    text = banner.decode("utf-8", errors="replace").strip()
    lower = text.lower()
    framework = None
    confidence = "LOW"
    if text.startswith("SSH-"):
        framework, confidence = "SSH service", "HIGH"
    elif text.startswith("220") and ("ftp" in lower or "filezilla" in lower or "vsftpd" in lower):
        framework, confidence = "FTP service", "HIGH"
    elif text.startswith("220") and ("smtp" in lower or "esmtp" in lower or "mail" in lower):
        framework, confidence = "SMTP service", "HIGH"
    elif len(banner) >= 6 and banner[4:5] == b"\x0a" and all(32 <= b < 127 or b in (0, 10, 13) for b in banner[5:30]):
        # MySQL protocol-10 greeting has a packet header, protocol byte, then version string.
        version = banner[5:].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        if version and any(ch.isdigit() for ch in version):
            framework, confidence = f"MySQL-compatible database ({version[:40]})", "HIGH"

    if framework is None:
        framework = _probe_redis(host, port, timeout)
        if framework:
            confidence = "HIGH"
    if framework is None:
        framework = _probe_postgres(host, port, timeout)
        if framework:
            confidence = "HIGH"
    grpc_hint = None
    if framework is None:
        grpc_hint = check_grpc(host, port, timeout)
        if grpc_hint.startswith("http2_detected"):
            framework, confidence = "HTTP/2 service (gRPC possible)", "LOW"
    if framework:
        return {
            "framework": framework, "confidence": confidence, "score": 3,
            "scheme": "tcp", "evidence": [{"path": "TCP banner/protocol probe",
            "status": None, "weight": 3, "hit": True, "framework": framework,
            "headers": {}, "body_snip": text[:300]}],
            "server_hdr": "", "all_headers": {}, "banner": text[:300],
            **({"grpc_heuristic": grpc_hint} if grpc_hint else {}),
        }

    tls_result = _probe_tls(host, port, timeout)
    if tls_result:
        return tls_result

    # gRPC commonly rides HTTP/2. The heuristic is purposely not reported as
    # confirmed gRPC unless application-level service reflection is available.
    if port in AI_PORTS and AI_PORTS[port].get("proto") == "gRPC":
        return {
            "framework": "gRPC / HTTP/2 service (unconfirmed)", "confidence": "LOW",
            "score": 0, "scheme": "tcp", "evidence": [], "server_hdr": "",
            "all_headers": {},
        }
    if text:
        return {
            "framework": "TCP banner (service unclassified)", "confidence": "LOW",
            "score": 0, "scheme": "tcp", "evidence": [{"path": "TCP banner",
            "status": None, "weight": 1, "hit": True, "framework": "TCP banner",
            "headers": {}, "body_snip": text[:300]}],
            "server_hdr": "", "all_headers": {}, "banner": text[:300],
        }
    return None


def run_scan(target: str, port_list: list[int], timeout: float,
             threads: int, do_enumerate: bool, output_file: Optional[str],
             verify: bool = True):
    start = time.time()

    console.rule("[header]Phase 1 · TCP Port Scanning[/header]")
    open_raw = {}
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {len(port_list)} TCP ports…", total=len(port_list))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {executor.submit(tcp_connect, target, port, timeout): port for port in port_list}
            for future in concurrent.futures.as_completed(future_map):
                port = future_map[future]
                try:
                    open_raw[port] = bool(future.result())
                except Exception:
                    open_raw[port] = False
                progress.advance(task)

    open_ports = {port: port_metadata(port) for port, is_open in sorted(open_raw.items()) if is_open}
    if not open_ports:
        console.print("[warning]  No open TCP ports found in the selected scan scope.[/warning]")
    else:
        print_port_table(open_ports)

    console.rule("[header]Phase 2 · Port-Agnostic Service Fingerprinting[/header]")
    fp_results: dict[int, dict] = {}
    if open_ports:
        with console.status("[magenta]Trying HTTP/HTTPS and application signatures on all open ports…[/magenta]"):
            fp_results = asyncio.run(
                fingerprint_all_ports(target, list(open_ports.keys()), timeout, verify=verify)
            )
        # Banner/protocol checks fill the gaps for non-HTTP services.
        remaining = [port for port in open_ports if port not in fp_results]
        if remaining:
            with console.status("[magenta]Fingerprinting non-HTTP TCP services…[/magenta]"):
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, 50)) as executor:
                    future_map = {executor.submit(fingerprint_tcp_service, target, port, timeout): port
                                  for port in remaining}
                    for future in concurrent.futures.as_completed(future_map):
                        port = future_map[future]
                        try:
                            result = future.result()
                            if result:
                                fp_results[port] = result
                        except Exception:
                            continue

    # Add hints for well-known gRPC ports only when no stronger fingerprint exists.
    for port, meta in open_ports.items():
        if port not in fp_results and meta.get("proto") == "gRPC":
            fp_results[port] = {
                "framework": "gRPC service (application identity unconfirmed)",
                "confidence": "LOW", "score": 0, "scheme": "tcp", "evidence": [],
                "server_hdr": "", "all_headers": {},
            }
    print_fingerprint_table(fp_results)

    enum_results: dict = {}
    port_fw_map: dict[int, str] = {}
    scheme_map = {port: data.get("scheme", "http") for port, data in fp_results.items()}
    if do_enumerate:
        console.rule("[header]Phase 3 · Opt-in Metadata Enumeration[/header]")
        for port, fp in fp_results.items():
            framework = fp.get("framework")
            if not framework:
                continue
            matched_fw = next((key for key in ENUM_CHAINS if key.lower() in framework.lower()), None)
            if matched_fw:
                port_fw_map[port] = matched_fw
                console.print(f"  [info]Queued[/info] :{port} [{matched_fw}] via {scheme_map.get(port, 'http')}://")
        if port_fw_map:
            with console.status("[blue]Executing read-oriented enumeration chains concurrently…[/blue]"):
                enum_results = asyncio.run(
                    enumerate_all_ports(target, port_fw_map, timeout, verify=verify, scheme_map=scheme_map)
                )
            for port, data in enum_results.items():
                print_enum_results(port, port_fw_map[port], data)

    console.rule("[header]Phase 4 · Exposure Indicators (not CVE verification)[/header]")
    vuln_results: dict = {}
    for port, fp in fp_results.items():
        framework = fp.get("framework")
        if framework:
            flags = check_risk_flags(framework, port, target, timeout,
                                     verify=verify, scheme=scheme_map.get(port))
            if flags:
                vuln_results[port] = flags
    print_vuln_table(vuln_results)

    console.rule("[header]Summary[/header]")
    print_summary(target, open_ports, fp_results, start)

    report = build_json_report(target, open_ports, fp_results, enum_results, vuln_results)
    report["meta"]["scan_scope"] = {
        "ports_requested": len(port_list),
        "open_ports_found": len(open_ports),
        "fingerprints_found": len(fp_results),
        "port_agnostic_fingerprinting": True,
        "tls_certificate_verification": verify,
    }
    if output_file:
        with open(output_file, "w", encoding="utf-8") as output_handle:
            json.dump(report, output_handle, indent=2, default=str)
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
  python ai_recon.py -t 10.10.45.15                         # smart AI + common ports
  python ai_recon.py -t 10.10.45.15 --scan-profile broad    # 1-1024 + AI/common extras
  python ai_recon.py -t 10.10.45.15 --ports 1-65535         # all TCP ports
  python ai_recon.py -t 10.10.45.15 -p 3000,4000,5000-5100
  python ai_recon.py -t 10.10.45.15 --enumerate --output report.json
        """
    )
    p.add_argument("-t", "--target",   required=True,
                   help="Target IP, hostname, or CIDR range (e.g. 10.10.0.0/24)")
    p.add_argument("-p", "--ports", default=None,
                   help="Ports/ranges, e.g. 22,80,3000-3100; 'all' means 1-65535 (overrides profile)")
    p.add_argument("--scan-profile", choices=("smart", "broad", "all"), default="smart",
                   help="TCP profile: smart (AI + common ports), broad (1-1024 + extras), all (1-65535; slower/noisier)")
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
                   help="Disable TLS certificate verification (use only for lab/self-signed targets)")
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
        host_count = network.num_addresses - (2 if network.version == 4 and network.prefixlen < 31 else
                                                1 if network.version == 6 and network.prefixlen < 127 else 0)
        if host_count > max_cidr:
            console.print(
                f"[danger]CIDR {target_str} expands to {host_count} hosts, "
                f"which exceeds the safety cap of {max_cidr}.\n"
                f"Use a smaller range, or raise the cap with --max-cidr.[/danger]"
            )
            sys.exit(1)
        return [str(ip) for ip in network.hosts()]
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

    # Suppress InsecureRequestWarning only when the user explicitly opts out of
    # TLS verification. When verify=True (the default), requests' warnings are
    # left intact so legitimate cert errors aren't silently swallowed.
    if args.no_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not args.no_banner:
        print_banner()

    if args.timeout <= 0:
        console.print("[danger]--timeout must be greater than zero.[/danger]")
        sys.exit(2)
    if args.threads < 1:
        console.print("[danger]--threads must be at least 1.[/danger]")
        sys.exit(2)
    if args.max_cidr < 1:
        console.print("[danger]--max-cidr must be at least 1.[/danger]")
        sys.exit(2)

    # Explicit ports override profile selection. Profiles are visible in report metadata.
    try:
        if args.ports:
            port_list = parse_port_spec(args.ports)
            selected_profile = "explicit"
        elif args.scan_profile == "all":
            port_list = ALL_TCP_PORTS.copy()
            selected_profile = "all"
        elif args.scan_profile == "broad":
            port_list = BROAD_PORTS.copy()
            selected_profile = "broad"
        else:
            port_list = SMART_PORTS.copy()
            selected_profile = "smart"
    except ValueError as exc:
        console.print(f"[danger]Invalid port specification: {exc}[/danger]")
        sys.exit(2)

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
        report.setdefault("meta", {})["scan_scope"]["profile"] = selected_profile
        all_reports[target] = report

    # Multi-target JSON dump
    if args.output and len(targets) > 1:
        with open(args.output, "w") as f:
            json.dump(all_reports, f, indent=2, default=str)
        console.print(f"\n  [success]✔  Combined report saved →[/success] [cyan]{args.output}[/cyan]\n")


if __name__ == "__main__":
    main()
