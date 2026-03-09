# LaTeX & TikZ Compilation REST API

The LaTeX API compiles LaTeX source (PDF) or TikZ snippets (SVG). It is **served from the main temp-email process** and uses the same server port.

## Tech Stack

- **Language**: Go
- **Framework**: net/http (standard library)
- **Queue**: Buffered Go channels + goroutine worker pool
- **Storage**: Local filesystem `/tmp/latex-jobs/`
- **LaTeX**: pdflatex (TeX Live) for full documents
- **TikZ**: latex + dvisvgm for SVG output

## Prerequisites

- **LaTeX**: `pdflatex` (e.g. `texlive-base` or `texlive-latex-base`)
- **TikZ (SVG)**: `latex` and `dvisvgm` (e.g. `texlive-latex-base`, `dvisvgm`). Set `TEXMFDIST` and `TEXMFCNF` if dvisvgm cannot find them (e.g. `/usr/local/texlive/2025basic/texmf-dist`)

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

Download the compiled PDF (LaTeX jobs only). Returns 404 if job is not done or PDF not ready.

### POST /api/latex/tikz/compile

Compile a TikZ snippet to SVG.

**Request (simple mode — inner content only):**
```json
{
  "tikz": "\\draw (0,0) -- (1,1); \\fill circle (2pt);",
  "fileIds": [],
  "packages": ["amsmath"],
  "tikzLibraries": ["decorations.pathmorphing"],
  "border": "2pt"
}
```

**Request (raw mode — paste from documentation):**
```json
{
  "raw": "\\usetikzlibrary{angles,calc,quotes}\n\\begin{tikzpicture}[angle radius=.75cm]\n  \\node (A) at (-2,0) {$A$};\n  \\draw (A) -- (B);\n\\end{tikzpicture}",
  "fileIds": []
}
```

- `tikz` or `raw` (one required): Use `tikz` for inner content only; use `raw` to paste full blocks from docs (`\usetikzlibrary{...}`, `\begin{tikzpicture}[opts]...\end{tikzpicture}`). Cannot use both.
- `raw`: Full pasted block. API extracts `\usetikzlibrary`, `\usepackage`, and the `\begin{tikzpicture}...\end{tikzpicture}` block (including options like `[angle radius=.75cm]`).
- `fileIds` (optional): Upload IDs to copy into job dir.
- `packages` (optional): Extra `\usepackage{pkg}` (ignored when `raw` is used; parsed from raw instead).
- `tikzLibraries` (optional): Extra libraries; merged with those parsed from `raw` when both provided.
- `border` (optional): Reserved for future use.

**Response:** Same as LaTeX compile: `{"jobId": "..."}`

**Output:** SVG at `GET /api/latex/jobs/{jobId}/svg` (not PDF).

### GET /api/latex/jobs/{jobId}/svg

Download the compiled SVG (TikZ jobs only). Returns 404 if job is not done or SVG not ready.

### POST /api/latex/upload

Upload an image file for use in LaTeX documents.

**Request:** `multipart/form-data` with `file` field

**Response:**
```json
{"fileId": "uuid", "filename": "figure1.png"}
```

## Frontend (FE) Guidelines

### What the user enters

| Mode | User input | Output type |
|------|------------|-------------|
| **LaTeX** | Full document: `\documentclass{article}...\begin{document}...\end{document}` | PDF |
| **TikZ** | TikZ snippet only: `\draw (0,0) -- (1,1);` (no `\begin{tikzpicture}` wrapper) | SVG |

- **LaTeX**: User provides a complete, compilable document. Include `\usepackage{graphicx}` and `\includegraphics{filename}` if using images.
- **TikZ**: User provides only the content inside `\begin{tikzpicture}...\end{tikzpicture}`. The API wraps it automatically. Base libraries: `arrows`, `arrows.meta`, `positioning`, `calc`, `shapes.geometric`, `trees`. User can add more via `packages` and `tikzLibraries`.

### Which API to call

| User action | API call |
|-------------|----------|
| Compile LaTeX document | `POST /api/latex/compile` with `{"source": "..."}` |
| Compile TikZ diagram | `POST /api/latex/tikz/compile` with `{"tikz": "...", "packages": [], "tikzLibraries": []}` |
| Upload image for LaTeX | `POST /api/latex/upload` (multipart, `file` field) |
| Check compile status | `GET /api/latex/jobs/{jobId}/status` |
| Stream logs (optional) | `GET /api/latex/jobs/{jobId}/logs` (SSE) |
| Download PDF (LaTeX jobs) | `GET /api/latex/jobs/{jobId}/pdf` |
| Download SVG (TikZ jobs) | `GET /api/latex/jobs/{jobId}/svg` |

### FE flow (recommended)

1. **Submit** → `POST` to `/api/latex/compile` (LaTeX) or `/api/latex/tikz/compile` (TikZ).
2. **Get jobId** from `{"jobId": "..."}` response.
3. **Poll status** → `GET /api/latex/jobs/{jobId}/status` every 1–2s until `status` is `done` or `error`. Alternatively, use SSE `GET /api/latex/jobs/{jobId}/logs` for live logs; the final event includes `status` and `pdfUrl`/`svgUrl`.
4. **Download** → When `status` is `done`:
   - LaTeX: fetch `/api/latex/jobs/{jobId}/pdf` and display or offer download.
   - TikZ: fetch `/api/latex/jobs/{jobId}/svg` and embed or display (e.g. `<img src=".../svg">` or inline SVG).
5. **Handle warning** → If `warning` is present, optionally show it; output is still valid.

### JSON escaping (important)

- In JSON, a literal backslash must be escaped: `"\\"` → `\`.
- LaTeX/TikZ commands use backslashes: `\draw`, `\node`, `\documentclass`.
- **Example**: TikZ `\draw (0,0) -- (1,1);` in the request body becomes `"tikz": "\\draw (0,0) -- (1,1);"`.
- When building the JSON in JavaScript: `JSON.stringify({ tikz: "\\draw (0,0) -- (1,1);" })` — the string already contains `\draw`, so it serializes correctly.

### Images in LaTeX (optional flow)

1. User chooses an image file → `POST /api/latex/upload` with `FormData` / `file`.
2. Response: `{"fileId": "...", "filename": "diagram.png"}`.
3. User compiles → `POST /api/latex/compile` with `{"source": "....\\includegraphics{diagram.png}...", "fileIds": ["fileId"]}`.
4. Use the `filename` from the upload response in `\includegraphics{filename}`.

### Error handling (what to show the user)

| status | User message / action |
|--------|------------------------|
| `error` | Show error from `warning` or status body; no PDF/SVG. |
| `done` + `warning` | Output is ready; optionally show warning (e.g. "Compiled with warnings"). |
| 400 BAD_REQUEST | Show `error` from JSON (e.g. "source is required", " sanitizer rejected"). |
| 404 JOB_NOT_FOUND | "Job not found" or expired. |
| 404 PDF_NOT_READY / SVG_NOT_READY | Job not done yet; keep polling. |

### Timeouts and limits

- Compilation timeout: ~30s (configurable).
- Poll/SSE timeout: use ~60s client-side.
- Max source size: 512 KB (configurable).
- Output files cleaned after 60 minutes; user should download before then.

---

## Frontend: TikZ Only

Dedicated FE guide for building a TikZ diagram editor/viewer. Output is always SVG.

### User input (two modes)

| Mode | User enters | API field |
|------|-------------|-----------|
| **Simple** | Inner content only (no wrapper) | `tikz` |
| **Raw paste** | Full block from docs: `\usetikzlibrary{...}\begin{tikzpicture}[opts]...\end{tikzpicture}` | `raw` |

**Simple mode:** User types `\draw (0,0) -- (2,1);` → send `{"tikz": "\\draw (0,0) -- (2,1);"}`.

**Raw paste mode:** User pastes directly from TikZ/PGF documentation, e.g.:
```
\usetikzlibrary {angles,calc,quotes}
\begin{tikzpicture}[angle radius=.75cm]
  \node (A) at (-2,0) [red,left] {$A$};
  \draw (A) -- (B);
\end{tikzpicture}
```
Send as `{"raw": "\\usetikzlibrary{angles,calc,quotes}\\n\\begin{tikzpicture}[angle radius=.75cm]..."}`. API extracts libraries, packages, and the tikzpicture block (including options).

### API calls (TikZ flow)

| Step | Method | Endpoint | When |
|------|--------|----------|------|
| 1 | POST | `/api/latex/tikz/compile` | On user "Compile" / "Preview" |
| 2 | GET | `/api/latex/jobs/{jobId}/status` | Poll every 1–2s until `done` or `error` |
| 3 | GET | `/api/latex/jobs/{jobId}/svg` | When `status === "done"` |

### Request body

**Simple mode:**
```json
{
  "tikz": "\\draw (0,0) -- (2,1); \\node at (1,0.5) {$x$};",
  "packages": ["amsmath"],
  "tikzLibraries": ["arrows.meta"],
  "fileIds": []
}
```

**Raw paste mode:** User pastes full block from docs.
```json
{
  "raw": "\\usetikzlibrary{angles,calc,quotes}\n\\begin{tikzpicture}[angle radius=.75cm]\n  \\node (A) at (-2,0) {$A$};\n  ...\n\\end{tikzpicture}",
  "fileIds": []
}
```

- **tikz** or **raw** (one required): Simple inner content vs full pasted block.
- **packages** (optional): `\usepackage{pkg}` (ignored when using `raw`).
- **tikzLibraries** (optional): Merged with libraries parsed from `raw`.
- **fileIds** (optional): Upload IDs if diagram references images.

### Displaying the SVG

- **Option A**: `<img src="/api/latex/jobs/{jobId}/svg">` — simple, works for most cases.
- **Option B**: Fetch SVG as text, parse, inline as `<svg>...</svg>` — allows styling/CSS.
- **Option C**: Use SVG URL in `<object>` or `<embed>`.

### JSON escaping (critical)

In JSON, each LaTeX backslash is doubled:

| User types | Send in `tikz` |
|------------|----------------|
| `\draw` | `"\\draw"` |
| `\node at (1,0) {$x^2$};` | `"\\node at (1,0) {$x^2$};"` |

JavaScript example:
```javascript
const tikz = userInput;  // user typed \draw (0,0) -- (1,1);
fetch('/api/latex/tikz/compile', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ tikz, packages: ['amsmath'], tikzLibraries: [] })
});
```

### Built-in TikZ libraries (no need to list)

- `arrows`, `arrows.meta`, `positioning`, `calc`, `shapes.geometric`, `trees`

### Common extra libraries

| Library | Use case |
|---------|----------|
| `decorations.pathmorphing` | Snake, zigzag paths |
| `decorations.markings` | Arrows, marks on paths |
| `backgrounds` | Background layers |
| `shapes` | More node shapes |
| `fit` | Fit nodes around others |
| `pgfplots` (package) | Data plots |

### Error handling (TikZ)

| HTTP | Code | Show user |
|------|------|-----------|
| 400 | BAD_REQUEST | `error` from body (e.g. "invalid package name", "tikz is required") |
| 404 | JOB_NOT_FOUND | "Job not found" |
| 404 | SVG_NOT_READY | Keep polling |
| 200 + `status: "error"` | — | `warning` or error message from status body |
| 200 + `status: "done"` + `warning` | — | SVG ready; optionally show warning |

### Minimal FE flow

```
1. User edits TikZ in textarea
2. On compile: POST /api/latex/tikz/compile → jobId
3. Poll GET /api/latex/jobs/{jobId}/status every 1.5s
4. When status === "done" → set <img src=".../jobs/{jobId}/svg">
5. When status === "error" → show error to user
```

---

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
| `done`      | **Download** at `/api/latex/jobs/{jobId}/pdf` (LaTeX) or `/api/latex/jobs/{jobId}/svg` (TikZ). Check optional `warning` if present. |
| `error`     | No output. Show `message` to user. |

### When `status` is `done`

- **LaTeX jobs**: PDF is available at `/api/latex/jobs/{jobId}/pdf`.
- **TikZ jobs**: SVG is available at `/api/latex/jobs/{jobId}/svg`.
- **Optional `warning`** — if present, output was produced despite issues. Optionally show the warning; output is still valid.
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

### 4b. Compile TikZ to SVG (simple mode)

```bash
# In JSON, use \\ for each LaTeX backslash
curl -X POST http://localhost:8080/api/latex/tikz/compile \
  -H "Content-Type: application/json" \
  -d '{"tikz": "\\draw[->] (0,0) -- (2,1); \\draw (1,0) circle (0.5); \\node at (1,-1) {TikZ};"}'
```

### 4b2. Compile TikZ (raw paste from documentation)

```bash
# Paste full block including \usetikzlibrary and \begin{tikzpicture}[opts]...\end{tikzpicture}
curl -X POST http://localhost:8080/api/latex/tikz/compile \
  -H "Content-Type: application/json" \
  -d '{"raw": "\\usetikzlibrary{angles,quotes}\n\\begin{tikzpicture}[angle radius=1cm]\n  \\coordinate (A) at (0,0);\n  \\coordinate (B) at (2,0);\n  \\coordinate (C) at (1,1);\n  \\draw (A) -- (B) -- (C) -- cycle;\n  \\pic [\"60 deg\", draw] {angle = B--A--C};\n\\end{tikzpicture}"}'
```

### 4c. Download SVG (TikZ jobs)

```bash
curl -O -J http://localhost:8080/api/latex/jobs/{jobId}/svg
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
| PDF_NOT_READY | 404 | Job not done, or PDF missing (LaTeX) |
| SVG_NOT_READY | 404 | Job not done, or SVG missing (TikZ) |
| SANITIZER_REJECTED | 400 | Dangerous LaTeX commands blocked |
| SOURCE_TOO_LARGE | 400 | Source exceeds max size |
| METHOD_NOT_ALLOWED | 405 | Wrong HTTP method |

## Security

- pdflatex runs with `-no-shell-escape`
- Source sanitized before any disk write
- Blocked commands: `\write18`, `\input{/`, `\openin`, `\catcode`, `\immediate`, `\openout`, `enableWrite18`, `shell-escape`
- Each job isolated in its own temp dir
