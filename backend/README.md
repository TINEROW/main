# Harpocrates Video Service

Flask service for video proof packaging, steganographic metadata extraction,
and local developer proof tooling.

## Steganography

`POST /api/stego/embed` accepts a video and JSON metadata, then returns an
embedded `video/mp4` artifact. The encoder writes two layers:

- border encoding for lossy-transcode-tolerant recovery
- LSB encoding as a secondary fallback

Response headers include the source video hash, embedded video hash, and
canonical metadata hash. The frontend registers the embedded video hash on
Stellar.

`POST /api/stego/extract` reads the embedded artifact, hashes the received file,
and returns extracted Harpocrates metadata when present.

## Noir Developer Worker

`POST /api/noir/silent-witness` generates video-specific Silent Witness proof
artifacts using the local WSL Noir toolchain.

The request must include `videoHash`, `credentialSecret`, and
`nullifierSecret`.

Environment override:

```text
NOIR_PROOF_TIMEOUT_SECONDS=180
```

The product flow now uses browser-side Noir JS and bb.js, so user-entered
private seeds stay in the browser. This endpoint is kept for local parity tests,
debugging, and CI-style proof generation.

## Privacy-Safe Service Metrics

`GET /metrics` exposes service workload, latency, status code distributions, and bounded upload-size metrics in standard Prometheus format.

### Privacy Guarantees

- Metric labels strictly record generic HTTP attributes: HTTP `method`, parameterized route rule `endpoint` (e.g., `/api/proofs/by-video/<video_hash>`), and HTTP `status`.
- Filenames, video hashes, metadata hashes, wallet addresses, proof payload data, and secret seeds are strictly excluded.
- Upload sizes are recorded in bounded histogram buckets.

### Endpoint Protection

- `METRICS_ENABLED`: Enable or disable the metrics endpoint (`true`/`false`, default `true`). Returns `404` when disabled.
- `METRICS_TOKEN`: Optional authentication token. When set, requests must provide `Authorization: Bearer <METRICS_TOKEN>` or header `X-Metrics-Token: <METRICS_TOKEN>`.
- `METRICS_PATH`: Endpoint URI path (defaults to `/metrics`).

### Prometheus Scraping Configuration

Example `prometheus.yml` snippet:

```yaml
scrape_configs:
  - job_name: 'harpocrates-backend'
    scrape_interval: 15s
    metrics_path: '/metrics'
    authorization:
      credentials: 'secret-scraping-token' # matches METRICS_TOKEN
    static_configs:
      - targets: ['127.0.0.1:5050']
```

## Run

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app.py
```

The service listens on `http://127.0.0.1:5050`.

## Runtime Configuration

```text
APP_ENV=development
HOST=127.0.0.1
PORT=5050
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
MAX_CONTENT_LENGTH=262144000
MAX_METADATA_BYTES=16384
SECURITY_HEADERS_ENABLED=true
EXPOSE_METADATA_HEADER=false
METRICS_ENABLED=true
METRICS_TOKEN=secret-scraping-token
METRICS_PATH=/metrics
NOIR_WORKER_ENABLED=true
NOIR_PROOF_TIMEOUT_SECONDS=180
DATABASE_URL=postgresql://...
VERIFIER_CACHE_MAX_SIZE=10000
VERIFIER_CACHE_POSITIVE_TTL_SECONDS=86400.0
VERIFIER_CACHE_NEGATIVE_TTL_SECONDS=300.0
```

Production notes:

- Set `APP_ENV=production`.
- Set `NOIR_WORKER_ENABLED=false` unless this service is intentionally acting as a hardened prover.
- Keep `EXPOSE_METADATA_HEADER=false`; extracted metadata is available through `/api/stego/extract`.
- Protect the `/metrics` endpoint in production by configuring `METRICS_TOKEN` or restricting access at the reverse proxy/ingress layer.
- Avoid wildcard CORS. `CORS_ORIGINS=*` requires `ALLOW_WILDCARD_CORS=true`.
- Uploaded files are processed in temporary directories and removed after each request.

## Health

```text
GET /health   liveness only
GET /ready    database, ffmpeg/ffprobe, and local worker readiness
GET /metrics  privacy-safe Prometheus metrics endpoint
```

## Verifier Proof Cache

`verifier_cache.py` memoizes Noir verifier results with positive and negative
TTLs. Cache keys are **domain-separated**: a SHA-256 digest over the versioned
cryptographic domain tag `harpocrates:verifier-cache:v1` followed by
length-prefixed `domain`, `network`, `circuit_version`, `verifier_version`,
`proof_hex`, and `public_inputs_hex` fields. Length-prefixed framing makes the
payload injective over the field tuple, so separator-like characters in any
field cannot shift a boundary and collide two distinct results. Proof and
public-input hex are case- and whitespace-canonicalized so the same proof
cannot fragment into case-variant entries.

Bump `CACHE_KEY_DOMAIN_TAG` (e.g. to `...:v2`) whenever the key field layout
changes: it orphans every previously cached entry instead of silently reusing
results derived under a different scheme. Keys are digests only — proof
material is never stored in plaintext or logged.

## Test

```powershell
python -m unittest test_app.py test_stego.py
```

The service uses temporary files while processing and does not persist uploaded
source videos.

