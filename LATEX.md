# LaTeX Compilation REST API

The LaTeX API compiles LaTeX source using pdflatex and returns job status, logs via SSE, and PDF bytes. It is **served from the main temp-email process** and uses the same server port.

## Tech Stack

- **Language**: Go
- **Framework**: net/http (standard library)
- **Queue**: Buffered Go channels + goroutine worker pool
- **Storage**: Local filesystem `/tmp/latex-jobs/`
- **LaTeX**: pdflatex (TeX Live)

## Prerequisites

- `pdflatex` must be installed (e.g. `texlive-base`, `texlive-latex-base`, or `texlive-full`)

## Configuration (Environment)

| Variable | Description | Default |
|----------|-------------|---------|
| `LATEX_TEMP_DIR` | Temp directory root | /tmp/latex-jobs |
| `LATEX_TIMEOUT_SECONDS` | Compile timeout | 30 |
| `LATEX_WORKER_POOL_SIZE` | Worker goroutines | 4 |
| `LATEX_CLEANUP_AFTER_MINUTES` | Cleanup delay after job completes | 60 |
| `LATEX_UPLOAD_CLEANUP_MINUTES` | Cleanup delay after file upload | 60 (or same as above) |
| `LATEX_MAX_SOURCE_SIZE_KB` | Max source size | 512 |

## API Endpoints

### POST /api/latex/compile

Submit LaTeX source for compilation.

**Request:**
```json
{
  "source": "\\documentclass{article}\\begin{document}Hello World\\end{document}"
}
```

Optional `fileIds` — include uploaded figures in the compile (from `POST /api/latex/upload`):
```json
{
  "source": "\\documentclass{article}\\usepackage{graphicx}\\begin{document}\\includegraphics{diagram.png}\\end{document}",
  "fileIds": ["uuid-from-upload"]
}
```

**Response:**
```json
{"jobId": "550e8400-e29b-41d4-a716-446655440000"}
```

### GET /api/latex/jobs/{jobId}/status

Get current job status.

**Response:**
```json
{"jobId": "550e8400-e29b-41d4-a716-446655440000", "status": "done"}
```

When done with warnings (PDF produced despite pdflatex exiting non-zero — N possible causes: missing file, overfull/underfull box, font substitution, citation warnings, etc.):
```json
{"jobId": "...", "status": "done", "warning": "Image or file not found: diagram.jpg"}
```

Status values: `pending`, `compiling`, `done`, `error`

### GET /api/latex/jobs/{jobId}/logs

Server-Sent Events stream of compilation logs. Streams log lines and a final status event.

### GET /api/latex/jobs/{jobId}/pdf

Download the compiled PDF. Returns 404 if job is not done or PDF not ready.

### POST /api/latex/upload

Upload an image file for use in LaTeX documents.

**Request:** `multipart/form-data` with `file` field

**Response:**
```json
{"fileId": "uuid", "filename": "figure1.png"}
```

## Caller Integration Instructions

For Instance 1 (JSP/Servlet) or any client calling this API:

### Flow

1. **Submit** → `POST /api/latex/compile` with JSON `{"source": "..."}`
2. **Get jobId** from response
3. **Monitor** → Poll `GET /api/latex/jobs/{jobId}/status` OR stream `GET /api/latex/jobs/{jobId}/logs` (SSE)
4. **Download** → When `status` is `done`, fetch `GET /api/latex/jobs/{jobId}/pdf`
5. **Clean up** → Download within `LATEX_CLEANUP_AFTER_MINUTES` (default 60) before temp files are removed

### Status handling

| status   | Action |
|----------|--------|
| `pending`   | Job queued, wait and poll again (or use logs SSE) |
| `compiling` | Compilation in progress, keep polling or streaming logs |
| `done`      | **Download PDF** at `/api/latex/jobs/{jobId}/pdf`. Check optional `warning` if present. |
| `error`     | No PDF. Show `message` to user. |

### When `status` is `done`

- **PDF is available** — always fetch it.
- **Optional `warning`** — if present, PDF was produced despite issues (missing image, overfull box, etc.). Optionally show the warning to the user; PDF is still valid.
- **No `warning`** — clean compile.

### When `status` is `error`

- No PDF. Use the `message` (from logs SSE final event) or poll status; the error is not always in the status body. For errors, the logs SSE sends `{"status":"error","message":"..."}`.

### Images in LaTeX

1. Upload image → `POST /api/latex/upload` with `file` field.
2. Response gives `fileId` and `filename`.
3. Compile with `fileIds` → `POST /api/latex/compile` with `{"source": "...", "fileIds": ["fileId"]}`.
4. Reference the file in LaTeX by `filename` (e.g. `\includegraphics{diagram.png}`).

### Timeouts

- Compilation times out after `LATEX_TIMEOUT_SECONDS` (default 30s).
- On timeout, job becomes `error` with no PDF.
- Poll/SSE clients: set a reasonable timeout (e.g. 60s) for the logs stream.

### Example sequence

```
1. POST /api/latex/compile → {"jobId": "abc-123"}
2. GET /api/latex/jobs/abc-123/status → {"jobId":"abc-123","status":"compiling"}
3. (poll again)
4. GET /api/latex/jobs/abc-123/status → {"jobId":"abc-123","status":"done"}
5. GET /api/latex/jobs/abc-123/pdf → 200 OK, application/pdf (download bytes)
```

## curl Examples

### 1. Compile LaTeX

```bash
curl -X POST http://localhost:8080/api/latex/compile \
  -H "Content-Type: application/json" \
  -d '{"source": "\\documentclass{article}\\begin{document}Hello World\\end{document}"}'
```

### 2. Check Job Status

```bash
curl http://localhost:8080/api/latex/jobs/{jobId}/status
```

### 3. Stream Logs (SSE)

```bash
curl -N http://localhost:8080/api/latex/jobs/{jobId}/logs
```

### 4. Download PDF

```bash
curl -O -J http://localhost:8080/api/latex/jobs/{jobId}/pdf
```

### 5. Upload Image

```bash
curl -X POST http://localhost:8080/api/latex/upload \
  -F "file=@figure1.png"
```

## Error Responses

All errors return JSON:

```json
{"error": "job not found", "code": "JOB_NOT_FOUND"}
```

| Code | HTTP | Description |
|------|------|-------------|
| BAD_REQUEST | 400 | Invalid JSON, missing source, sanitizer rejection |
| JOB_NOT_FOUND | 404 | Unknown job ID |
| PDF_NOT_READY | 404 | Job not done, or PDF missing |
| SANITIZER_REJECTED | 400 | Dangerous LaTeX commands blocked |
| SOURCE_TOO_LARGE | 400 | Source exceeds max size |
| METHOD_NOT_ALLOWED | 405 | Wrong HTTP method |

## Security

- pdflatex runs with `-no-shell-escape`
- Source sanitized before any disk write
- Blocked commands: `\write18`, `\input{/`, `\openin`, `\catcode`, `\immediate`, `\openout`, `enableWrite18`, `shell-escape`
- Each job isolated in its own temp dir
