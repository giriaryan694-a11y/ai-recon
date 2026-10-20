# AI-RECON

**AI/ML Infrastructure Reconnaissance · Fingerprint · Enumerate · Map**  
Made by Aryan Giri · Version **1.4.0**

AI-RECON is a Python-based, evidence-driven reconnaissance tool for discovering AI/ML services across a selected TCP port scope. It combines port scanning with application-level probes so service identification does **not** depend on a service running on its conventional port. It is intended to complement tools such as Nmap, not replace them.

> **Authorised use only.** Run it against systems you own, isolated labs, or targets explicitly in scope for an engagement. Even read-only discovery can expose internal model names, registry metadata, notebook names, and infrastructure details.

## What changed in v1.4.0

- **Port-agnostic HTTP/HTTPS fingerprinting:** after finding an open TCP port, the tool tries a likely HTTP scheme and falls back to the other scheme when the connection or response suggests a protocol mismatch. It checks API response shapes, product endpoints, root-page markers, headers, and metrics regardless of conventional service port.
- **More scan coverage:** choose a smart profile, a broader common-port profile, an all-TCP-port scan, or explicit comma-separated ports and ranges.
- **Non-HTTP protocol fingerprints:** low-impact banner/protocol checks for SSH, FTP/SMTP banners, MySQL greetings, Redis RESP, PostgreSQL SSL negotiation, TLS/ALPN, and plaintext HTTP/2. HTTP/2 alone is not treated as proof of gRPC or a specific application.
- **Broader AI/ML discovery:** signatures cover model-serving APIs, OpenAI-compatible endpoints, local-model runtimes, model registries, vector stores, notebooks, metrics, workflow interfaces, and selected AI web UIs where evidence is visible.
- **Opt-in metadata enumeration:** `--enumerate` runs read-oriented service API queries and extracts compact summaries of models, collections, experiments, registry entries, kernels, checkpoints, or runtime metadata where supported.
- **More cautious exposure flags:** the scanner reports accessible endpoints as exposure indicators. It does not claim that a CVE is exploitable or that a vulnerable version is present unless separately verified.
- **Safer transport handling:** redirects are not followed, TLS certificate verification is enabled by default, and common credential-bearing response headers are redacted from reports.

## Requirements

- Python 3.10+
- Dependencies:

```bash
python -m pip install aiohttp requests rich
```

On Windows, use `py -m pip install aiohttp requests rich` if `python` is not the Python launcher on your system.

## Quick start

```bash
# Smart profile: AI/ML-related ports plus a curated set of common ports
python ai_recon.py -t 192.168.1.20

# Enumerate supported, exposed metadata endpoints and save a JSON report
python ai_recon.py -t 192.168.1.20 --enumerate --output report.json

# Scan explicit ports, including ranges
python ai_recon.py -t 192.168.1.20 --ports 22,80,443,3000-3100,5000,8000-8100

# Broader scan: TCP ports 1-1024 plus curated AI/common service ports
python ai_recon.py -t 192.168.1.20 --scan-profile broad

# All TCP ports: slower and noisier; use only with clear authorisation
python ai_recon.py -t 192.168.1.20 --scan-profile all --timeout 1

# Explicitly disable certificate checks for a lab using self-signed TLS
python ai_recon.py -t 192.168.1.20 --no-verify

# Scan a small authorised subnet
python ai_recon.py -t 192.168.1.0/24 --enumerate --output subnet-report.json
```

`192.168.1.20` and the subnet above are examples. Replace them with an in-scope system or lab target.

## Scan profiles

| Option | Scope | When to use it |
|---|---|---|
| `--scan-profile smart` | Default. A curated list of AI/ML ports plus common web, database, container, and service ports. | Fast initial inventory. It can miss services on unusual ports. |
| `--scan-profile broad` | TCP ports `1-1024`, plus curated AI/common ports outside that range. | Wider discovery without scanning every TCP port. |
| `--scan-profile all` | TCP ports `1-65535`. | Thorough port coverage when time and scope allow. Expect more traffic and a longer run. |
| `--ports 3000,5000-5100` | Only the supplied ports/ranges. Overrides the profile. | Targeted scans, unusual deployments, or follow-up checks. |

The smart profile currently scans **about 100 curated ports**; profile contents can change as signatures evolve. A port number is only a hint, never proof of the software listening there. For the broadest port coverage, use `--scan-profile all` or `--ports 1-65535`.

## CLI reference

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | Required | IPv4/IPv6 address, hostname, or CIDR range. |
| `-p`, `--ports` | None | Comma-separated ports/ranges, e.g. `80,443,3000-3100`; accepts `all`. Overrides `--scan-profile`. |
| `--scan-profile` | `smart` | `smart`, `broad`, or `all`. |
| `--timeout` | `2.0` seconds | Per-connection/probe timeout. Must be greater than zero. |
| `--threads` | `50` | Concurrent TCP connection workers. Must be at least one. |
| `--enumerate` | Off | Run supported read-oriented service metadata queries after fingerprinting. |
| `--output` | None | Write the JSON report to this path. For a CIDR scan, one combined JSON report is written. |
| `--no-banner` | Off | Suppress the startup banner. |
| `--no-verify` | Off | Disable TLS certificate verification. Use only where justified, such as a lab with a self-signed certificate. |
| `--max-cidr` | `512` hosts | Safety cap for a CIDR expansion. A larger scope requires an explicit higher cap. |

## Detection model

### 1. TCP discovery

A TCP connect scan identifies open ports in the selected range. Known port numbers display **hints**, not confirmed identities. Unrecognised open ports remain in the report and are still fingerprinted.

### 2. Application/service fingerprinting

For each open port, AI-RECON tries the likely HTTP scheme and switches to the other scheme when the connection fails, looks like a protocol mismatch, or redirects to HTTPS. This is independent of the port number, so an HTTP API on a high/custom port can still be fingerprinted. It then evaluates specific evidence, including:

- Distinctive API paths and response schemas, such as Ollama model tags, OpenAI-compatible model lists, Triton v2 metadata, Qdrant collections, Weaviate schema, Ray version metadata, and MLflow experiment search.
- Runtime or UI indicators for services such as Text Generation Inference, ComfyUI, Gradio, Streamlit, Open WebUI, LiteLLM, and selected AI workflow interfaces.
- Service headers and metric-name prefixes where they provide meaningful evidence.
- TCP protocol behavior and banners if application-level HTTP fingerprinting does not identify the listener.

**OpenAI-compatible is an API shape, not a model-engine identity.** vLLM, SGLang, LM Studio, llama.cpp, LocalAI, and other services may expose compatible routes. AI-RECON only names a specific engine when another signal supports that conclusion; otherwise it reports an OpenAI-compatible API.

### 3. Optional metadata enumeration

`--enumerate` sends read-oriented requests only. It does not attempt model inference, create notebooks/kernels, submit Ray jobs, register models, change configuration, or exploit a vulnerability. Some service query APIs use `POST` for search, such as MLflow experiment search; the tool sends an empty search body to that documented read-oriented endpoint.

Enumeration depends on API availability, authentication policy, permissions, path prefixes, and software version. A `401`, `403`, `404`, or empty response may prevent metadata retrieval without disproving that a service exists.

### 4. Exposure indicators

The report's `vulnerabilities` object is a set of **risk/exposure indicators**, not a verified vulnerability list. A reachable endpoint does not prove that a historical CVE applies, that the version is vulnerable, or that exploitation is possible. Confirm exact versions, configuration, authentication, and current advisories before treating a finding as a vulnerability.

## Confidence and accuracy notes

Confidence is a heuristic summary of weighted signature evidence:

- **HIGH:** one or more strong, product-specific signatures matched.
- **MEDIUM:** a useful but less definitive response shape or page marker matched.
- **LOW:** protocol or generic service evidence only; product identity is not confirmed.

These labels are not statistical probabilities. Reverse proxies, API gateways, WAFs, custom path prefixes, authentication, disabled endpoints, response transformations, and product changes can create false negatives or false positives. A successful TLS handshake identifies TLS, not the application behind it. Plaintext HTTP/2 is only evidence that HTTP/2 is present; gRPC and service reflection are not confirmed by that alone.

TLS verification is enabled by default. With an invalid/self-signed certificate, the tool may identify the TLS listener but not fingerprint its HTTP API. `--no-verify` permits that inspection while weakening certificate validation; reserve it for targets where you understand the trade-off.

HTTP probes are intentionally bounded and redirects are not followed, to avoid sending subsequent requests to an unrelated redirect destination. The `smart` profile is not exhaustive. All-port scans and larger CIDRs can take substantially longer and generate more network traffic.

## JSON report

The report contains:

- `meta`: tool/version, target, timestamp, and scan scope.
- `open_ports`: open TCP ports and their port-based hints.
- `fingerprints`: detected service/framework, confidence, evidence paths, response headers (sensitive headers redacted), and protocol/TLS hints where available.
- `enumeration`: supported endpoint statuses and extracted metadata summaries.
- `vulnerabilities`: qualified exposure indicators and context for manual verification.

Reports may include internal model names, experiment names/IDs, collection names, artifact URIs, notebook names, and runtime metadata. Store and share them like sensitive security assessment output. Header redaction is not a guarantee that every response body or URI is free of secrets.

## MITRE ATLAS mapping

The port table labels the scan behavior as **AML.T0006 — Active Scanning**. The JSON report also documents contextual links to the current ATLAS sub-techniques **AML.T0006.000 — Enumerate Hosted AI Resources**, **AML.T0006.001 — Query Platform Metadata APIs**, and **AML.T0006.002 — Scan for Exposed AI Infrastructure**. These describe analogous scan activities; they are **context labels, not vulnerability findings or proof of adversary activity**. The former category-to-technique mapping was removed because a product category alone does not justify assigning an adversary technique. The latest release verified for this update is MITRE ATLAS data **2026.09** (released 15 September 2026). Verify current names and IDs on the [official ATLAS site](https://atlas.mitre.org/) before formal reporting.

## Current coverage and limitations

Fingerprints currently target common AI/ML infrastructure patterns, including:

- **Model serving and LLM APIs:** Triton, Ollama, Text Generation Inference, TorchServe, OpenAI-compatible serving, plus signatures that may identify vLLM, llama.cpp, LM Studio, LocalAI, SGLang, and Xinference when visible.
- **Model lifecycle and orchestration:** MLflow and Ray.
- **Vector databases:** Qdrant, Weaviate, and Chroma.
- **Developer/runtime tools:** Jupyter, Gradio, Streamlit, and ComfyUI.
- **Related AI interfaces and gateways:** LiteLLM, Open WebUI, Flowise, and selected Stable Diffusion WebUI signatures.
- **Adjacent infrastructure:** MinIO, SSH, common database protocols, TLS, and HTTP/2 hints.

This list is not a guarantee that every version or installation can be identified. For example, TensorFlow Serving's documented REST model-status endpoint requires a model name; AI-RECON does not guess model names just to force a fingerprint. Services hidden behind a reverse proxy or authenticated API may require an in-scope, credentialed assessment to identify fully.

## Research references

The fingerprint and endpoint choices were reviewed against official or project-maintained documentation, including:

- [vLLM OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [NVIDIA Triton HTTP/REST and gRPC protocols](https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/protocol/README.html)
- [Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [MLflow REST API](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [TensorFlow Serving REST API](https://github.com/tensorflow/serving/blob/master/tensorflow_serving/g3doc/api_rest.md)
- [Qdrant interfaces](https://qdrant.tech/documentation/interfaces/)
- [Weaviate API](https://docs.weaviate.io/weaviate/api)
- [Hugging Face Text Generation Inference API](https://huggingface.co/docs/text-generation-inference/en/reference/api_reference)
- [Chroma API implementation](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [Open WebUI API reference](https://docs.openwebui.com/reference/api-endpoints/)
- [MITRE ATLAS](https://atlas.mitre.org/)

## Contributions and community feedback

AI/ML infrastructure evolves quickly, and keeping fingerprints accurate takes more than one person watching every new project release. Contributions, corrections, and field reports are welcome.

### Help expand AI/ML coverage

Please open an issue to suggest **new tools, utilities, services, and platforms used in modern AI/ML infrastructure**. Examples include model-serving runtimes, inference gateways, agent frameworks, vector databases, model registries, orchestration systems, GPU/runtime management tools, observability stacks, and emerging deployment utilities.

When possible, include:

- **Project name and official documentation/repository**.
- **What it does** and where it commonly appears in an AI/ML deployment.
- **Observable indicators** such as documented ports, protocols, headers, routes, response shapes, or version endpoints.
- **A safe way to verify the fingerprint**, ideally using a local instance, test fixture, or sanitised sample response.
- **Relevant versions and deployment notes**, including reverse-proxy or custom-port behaviour.

### Report failures and recommend improvements

If AI-RECON misses a service, misidentifies one, produces a false positive, fails to enumerate an expected read-only endpoint, or behaves unexpectedly, please **open an issue**. Recommendations for better accuracy, coverage, performance, output quality, and usability are also useful.

For a useful report, include:

1. AI-RECON version and Python version.
2. The scan profile or relevant command-line options used. **Remove credentials, tokens, private hostnames/IPs, and other sensitive details before posting.**
3. Expected behaviour versus actual behaviour.
4. Sanitised output, error messages, or minimal reproduction steps.
5. The service/product name and version, if known, plus documentation that supports the expected behaviour.

Please test only against systems you own or are explicitly authorised to assess. Do not attach raw scan reports, secrets, customer data, or private infrastructure details to public issues. If a report may expose a security vulnerability or sensitive information, avoid publishing details publicly and use an appropriate private disclosure channel instead.

Issues are the best place to discuss proposed fingerprints and recommendations before implementation. Pull requests with focused changes, clear evidence, and safe test cases are welcome too. A port number alone is not proof of a service identity; contributions should prefer reproducible evidence and clearly state uncertainty.

## Legal

Use only on infrastructure you own or are explicitly authorised to assess. The operator is responsible for scope, permission, data handling, and reporting.

---

*Made by Aryan Giri*
