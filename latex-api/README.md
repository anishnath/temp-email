# LaTeX Compilation REST API

Instance 2 in a two-instance architecture. Receives LaTeX source from Instance 1 (JSP/Servlet), compiles via pdflatex, returns job status, logs via SSE, and PDF bytes. **Not publicly exposed** — only called by Instance 1 internally.

## Tech Stack

- **Language**: Go 1.22+
- **Framework**: net/http (standard library)
- **Queue**: Buffered Go channels + goroutine worker pool
- **Storage**: Local filesystem `/tmp/latex-jobs/`
- **LaTeX**: pdflatex (TeX Live)

## Project Structure

```
latex-api/
├── cmd/main.go           # entry point
├── config/config.go      # env configuration
├── internal/
│   ├── api/              # HTTP handlers
│   │   ├── compile.go   # POST /api/compile
│   │   ├── jobs.go      # GET /api/jobs/{id}/status
│   │   ├── pdf.go       # GET /api/jobs/{id}/pdf
│   │   ├── logs.go      # GET /api/jobs/{id}/logs (SSE)
│   │   └── upload.go    # POST /api/upload
│   ├── compiler/        # pdflatex + sanitizer + log parser
│   ├── filestore/       # temp dirs, cleanup
│   └── model/           # CompileJob, registry
├── queue/                # worker pool
├── go.mod
├── Makefile
└── Dockerfile
```

## Configuration (Environment)

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP port | 8080 |
| `LATEX_TEMP_DIR` | Temp directory root | /tmp/latex-jobs |
| `LATEX_TIMEOUT_SECONDS` | Compile timeout | 30 |
| `WORKER_POOL_SIZE` | Worker goroutines | 4 |
| `CLEANUP_AFTER_MINUTES` | Cleanup delay after job | 60 |
| `MAX_SOURCE_SIZE_KB` | Max source size | 512 |

## Quick Start

```bash
# Build and run (binds to 127.0.0.1:8080 only)
make build && ./bin/latex-api

# Or
make run
```

## API Examples (curl)

### 1. Compile LaTeX

```bash
curl -X POST http://127.0.0.1:8080/api/compile \
  -H "Content-Type: application/json" \
  -d '{"source": "\\documentclass{article}\\begin{document}Hello World\\end{document}"}'
```

Response:
```json
{"jobId": "550e8400-e29b-41d4-a716-446655440000"}
```

### 2. Check Job Status

```bash
curl http://127.0.0.1:8080/api/jobs/550e8400-e29b-41d4-a716-446655440000/status
```

Response:
```json
{"jobId":"550e8400-e29b-41d4-a716-446655440000","status":"done"}
```

### 3. Stream Logs (SSE)

```bash
curl -N http://127.0.0.1:8080/api/jobs/550e8400-e29b-41d4-a716-446655440000/logs
```

### 4. Download PDF

```bash
curl -O -J http://127.0.0.1:8080/api/jobs/550e8400-e29b-41d4-a716-446655440000/pdf
```

### 5. Upload Image

```bash
curl -X POST http://127.0.0.1:8080/api/upload \
  -F "file=@figure1.png"
```

Response:
```json
{"fileId":"uuid","filename":"figure1.png"}
```

## Error Responses

All errors return JSON:

```json
{"error": "job not found", "code": "JOB_NOT_FOUND"}
```

| Code | HTTP | Description |
|------|------|-------------|
| BAD_REQUEST | 400 | Invalid JSON, sanitizer rejection |
| JOB_NOT_FOUND | 404 | Unknown job ID |
| PDF_NOT_READY | 404 | Job not done, or PDF missing |
| SANITIZER_REJECTED | 400 | Dangerous LaTeX commands |
| METHOD_NOT_ALLOWED | 405 | Wrong HTTP method |

## Security

- pdflatex runs with `-no-shell-escape`
- Source sanitized before any disk write
- Each job in isolated temp dir
- API binds to `127.0.0.1` only (internal use)
