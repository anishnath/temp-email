# SEO crawl API

Site-wide SEO audit (SEOnaut-compatible rules) backed by **SQLite**. The crawler runs the same page + multipage issue reporters as the upstream project; this API exposes **JSON** only (no SEOnaut web UI, translations, or charts).

## Prerequisites

- Main API process (`cmd/api`) runs with `EMAIL_DOMAIN` set (see `config/.env` or env).
- **SQLite** file for crawl data (see environment below). The parent directory is created automatically if missing.
- **Outbound HTTPS** from the server to the sites you crawl.

## Environment (`SEO_*`)

Loaded at process startup. Defaults are conservative for a free/public service. See `internal/seocrawl/config/env.go` for clamps.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SEO_DB_PATH` | `data/seo.sqlite` | SQLite database path |
| `SEO_DB_MAX_OPEN_CONNS` | `1` | SQLite pool size |
| `SEO_CRAWLER_USER_AGENT` | `Mozilla/5.0 (compatible; SEOCrawlBot/1.0)` | HTTP `User-Agent` |
| `SEO_CRAWL_MAX_URLS` | `20000` | Max page reports per crawl (capped in code) |
| `SEO_HTTP_CLIENT_TIMEOUT_SEC` | `10` | Per-request HTTP timeout |
| `SEO_CRAWL_MAX_RUNTIME_HOURS` | `2` | Max wall-clock crawl duration |
| `SEO_CRAWL_RANDOM_DELAY_MAX_MS` | `1500` | Random delay 0…N ms before each fetch |
| `SEO_CRAWL_WORKER_THREADS` | `2` | Parallel fetch workers |
| `SEO_HTML_MAX_BODY_BYTES` | `10485760` | Max body read when parsing a page |
| `SEO_DOM_MAX_NODES` | `1500` | Threshold for `ERROR_DOM_SIZE` |
| `SEO_LAST_CRAWLS_LIMIT` | `5` | Internal padding for “last crawls” (rarely used by API clients) |

Copy from `config/.env.example` if you use a `config/.env` file.

## Client flow (what you need to do)

1. **Start a crawl** — `POST /api/seo/crawl` with a JSON body. You receive `crawl_id` and `project_id` immediately; the crawl continues **in the background**.
2. **Poll status** — `GET /api/seo/crawl/{id}` until `crawling` is `false`. While `true`, the crawl is still running; `total_urls` / issue counts may stay at zero until the run finishes.
3. *(Optional)* **Cancel** — `POST /api/seo/crawl/{id}/cancel` to abort a running crawl early. The crawler stops cleanly and the DB is updated.
4. **Fetch findings** — `GET /api/seo/crawl/{id}/findings` for issue types × **distinct page counts** per severity (`critical` / `alert` / `warning`).
5. **List URLs for one issue** — `GET /api/seo/crawl/{id}/issues/pages?type=ERROR_TYPE` (e.g. `ERROR_EMPTY_TITLE`). Optional `limit` (default 200, max 500). Each page in the response has an `id`.
6. **Inspect evidence** — `GET /api/seo/crawl/{id}/page/{page_id}` for the full raw evidence of one page: title text, TTFB, all images with alt, hreflangs, and the list of issue types that fired on it. Use the `id` from step 5.

**History** — `GET /api/seo/crawls?url=https://example.com` lists all past crawls for a site (or all crawls without a filter) so you can track improvement over time.

**Issue type strings** match SEOnaut / `issue_types.type` (e.g. `ERROR_LONG_TITLE`, `ERROR_MISSING_HSTS`). There is no bundled human-readable title/description in JSON; the reference SEOnaut **web** app adds those via translation files.

**Security:** If this API is exposed publicly, treat it like any URL-fetching tool: **rate limit**, **authenticate**, and consider **allowlists** — clients can request arbitrary URLs (SSRF risk).

**CORS:** Browser clients must use an origin allowed in `cmd/api/main.go` (`allowedOrigins`).

## Endpoints

### GET /api/seo/crawls

List recent crawls, optionally filtered by seed URL. Useful for building a history/dashboard view.

```bash
# All crawls (newest first, default limit 20)
curl "http://localhost:8080/api/seo/crawls"

# Only crawls for a specific site
curl "http://localhost:8080/api/seo/crawls?url=https://example.com&limit=10"
```

**Query**

| Param | Required | Description |
|-------|----------|-------------|
| `url` | no | Exact project URL to filter by |
| `limit` | no | Max rows (default 20, max 200) |

**Response 200:**

```json
{
  "count": 2,
  "crawls": [
    {
      "crawl_id": 5,
      "project_id": 3,
      "url": "https://example.com",
      "started_at": "2026-04-09 12:00:00",
      "finished_at": "2026-04-09 12:03:14",
      "crawling": false,
      "total_urls": 42,
      "total_issues": 87,
      "critical_issues": 2,
      "alert_issues": 21,
      "warning_issues": 64
    },
    {
      "crawl_id": 3,
      "project_id": 3,
      "url": "https://example.com",
      "started_at": "2026-04-08 09:11:00",
      "finished_at": "2026-04-08 09:14:22",
      "crawling": false,
      "total_urls": 40,
      "total_issues": 91,
      "critical_issues": 3,
      "alert_issues": 24,
      "warning_issues": 64
    }
  ]
}
```

`crawling: true` means the crawl is still running (no `finished_at`).

### POST /api/seo/crawl

Start a crawl from a seed URL (multi-page crawl within the same rules as SEOnaut: same host / options, robots, sitemap options, etc.).

```bash
curl -X POST http://localhost:8080/api/seo/crawl \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "ignore_robots_txt": false,
    "follow_nofollow": false,
    "include_noindex": false,
    "crawl_sitemap": false,
    "allow_subdomains": false,
    "check_external_links": false,
    "user_agent": ""
  }'
```

**Request fields**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | yes | Seed URL (HTTPS recommended) |
| `ignore_robots_txt` | bool | no | Ignore robots.txt |
| `follow_nofollow` | bool | no | Follow links marked `nofollow` |
| `include_noindex` | bool | no | Include URLs with `noindex` |
| `crawl_sitemap` | bool | no | Also crawl URLs from sitemap |
| `allow_subdomains` | bool | no | Allow subdomains of the seed host |
| `check_external_links` | bool | no | HEAD external links for status (heavier) |
| `user_agent` | string | no | Override crawler User-Agent for this project |

**Response 200:**

```json
{
  "crawl_id": 1,
  "project_id": 1
}
```

### GET /api/seo/crawl/{id}

Crawl progress and aggregate issue counts (from the crawl row).

```bash
curl http://localhost:8080/api/seo/crawl/1
```

**Response 200:**

```json
{
  "crawl_id": 1,
  "project_id": 1,
  "crawling": false,
  "total_urls": 10,
  "total_issues": 70,
  "critical_issues": 0,
  "alert_issues": 14,
  "warning_issues": 56,
  "robotstxt_exists": true,
  "sitemap_exists": true
}
```

Poll until `crawling` is `false` before relying on final counts.

### POST /api/seo/crawl/{id}/cancel

Abort a crawl that is currently running. The crawler drains its current request cleanly, writes the partial results to the database, and marks the crawl as finished (`crawling` becomes `false`). Safe to call on an already-finished crawl — `stopped` will be `false` and no error is returned.

```bash
curl -X POST http://localhost:8080/api/seo/crawl/5/cancel
```

**Response 200:**

```json
{
  "crawl_id": 5,
  "stopped": true,
  "message": "crawl stopped"
}
```

If the crawl was already finished:

```json
{
  "crawl_id": 5,
  "stopped": false,
  "message": "crawl was not running (already finished or not found)"
}
```

`stopped: false` is **not** an error — it just means there was nothing to cancel.

### GET /api/seo/crawl/{id}/findings

Issue types grouped by severity with **distinct page counts** per type (same idea as SEOnaut’s issue groups).

```bash
curl http://localhost:8080/api/seo/crawl/1/findings
```

**Response 200:**

```json
{
  "crawl_id": 1,
  "project_id": 1,
  "critical": [],
  "alert": [
    { "error_type": "ERROR_LONG_TITLE", "priority": 2, "count": 6 }
  ],
  "warning": [
    { "error_type": "ERROR_MISSING_HSTS", "priority": 3, "count": 10 }
  ],
  "note": "Use GET /api/seo/crawl/{id}/issues/pages?type=ERROR_TYPE to list affected URLs for one issue type."
}
```

`priority`: `1` = critical, `2` = alert, `3` = warning (SEOnaut convention).

### GET /api/seo/crawl/{id}/issues/pages

List pages that have a specific **issue type** (`issue_types.type`).

```bash
curl "http://localhost:8080/api/seo/crawl/1/issues/pages?type=ERROR_LONG_TITLE&limit=50"
```

**Query**

| Param | Required | Description |
|-------|----------|-------------|
| `type` | yes | Issue type string, e.g. `ERROR_EMPTY_TITLE` |
| `limit` | no | Max rows (default 200, max 500) |

**Response 200:**

```json
{
  "crawl_id": 1,
  "issue_type": "ERROR_LONG_TITLE",
  "page_count": 6,
  "pages": [
    {
      "id": 42,
      "url": "https://example.com/page",
      "title": "Example",
      "status_code": 200
    }
  ]
}
```

### GET /api/seo/crawl/{id}/page/{page_id}

Return the full **evidence payload** for one crawled page — every stored field value plus images (with alt text), hreflang tags, and the complete list of SEO issue types detected on that page.

Use this to show customers *why* a flag was raised: e.g. the exact too-long title, the TTFB milliseconds, which images have no alt text.

```bash
# page_id comes from the "id" field in /issues/pages response
curl http://localhost:8080/api/seo/crawl/1/page/42
```

**Response 200:**

```json
{
  "crawl_id": 1,
  "page_id": 42,
  "url": "https://example.com/about",
  "status_code": 200,
  "redirect_url": "",
  "content_type": "text/html; charset=utf-8",
  "media_type": "text/html",
  "lang": "en",
  "title": "About Us — A Very Long Title That Exceeds The Recommended Sixty Character Limit",
  "title_length": 79,
  "description": "We make things.",
  "description_length": 16,
  "robots": "index,follow",
  "noindex": false,
  "nofollow": false,
  "canonical": "https://example.com/about",
  "h1": "About Us",
  "h2": "Our Story",
  "words": 240,
  "size_bytes": 18432,
  "depth": 1,
  "ttfb_ms": 620,
  "in_sitemap": false,
  "blocked_by_robotstxt": false,
  "images": [
    { "url": "https://example.com/img/hero.jpg", "alt": "" },
    { "url": "https://example.com/img/logo.png", "alt": "Company Logo" }
  ],
  "images_missing_alt_count": 1,
  "hreflangs": [],
  "issues": [
    "ERROR_LONG_TITLE",
    "ERROR_SLOW_RESPONSE_TIME",
    "ERROR_IMAGES_WITHOUT_ALT_ATTRIBUTE"
  ]
}
```

**Evidence-to-issue mapping guide:**

| Issue type | Relevant field(s) |
|------------|-------------------|
| `ERROR_LONG_TITLE` / `ERROR_SHORT_TITLE` | `title`, `title_length` |
| `ERROR_EMPTY_TITLE` | `title` (empty string) |
| `ERROR_LONG_DESCRIPTION` / `ERROR_SHORT_DESCRIPTION` | `description`, `description_length` |
| `ERROR_EMPTY_DESCRIPTION` | `description` (empty string) |
| `ERROR_IMAGES_WITHOUT_ALT_ATTRIBUTE` | `images` array (entries where `alt` is `""`) |
| `ERROR_SLOW_RESPONSE_TIME` | `ttfb_ms` |
| `ERROR_TOO_MUCH_CRAWL_DEPTH` | `depth` |
| `ERROR_30x` / `ERROR_40x` / `ERROR_50x` | `status_code`, `redirect_url` |
| `ERROR_CANONICAL` | `canonical` vs `url` |
| `ERROR_NOINDEX` | `noindex` |
| `ERROR_HTTP_URL` | `url` (starts with `http://`) |
| `ERROR_MISSING_HSTS` / `ERROR_INSECURE_SCHEME` | `url`, page headers (detected during crawl) |
| `ERROR_HREFLANG` | `hreflangs` array |
| `ERROR_LITTLE_CONTENT` | `words` |
| `ERROR_DOM_SIZE` | `size_bytes` (node count stored indirectly) |

The complete set of possible `issues` strings is defined in `internal/seocrawl/issues/errors/errors.go`.

## Errors

| HTTP | Meaning |
|------|---------|
| 400 | Bad JSON, missing `url`, missing `type` on `issues/pages`, invalid `id` or `page_id` |
| 404 | Unknown `crawl_id`, or `page_id` does not belong to this crawl |
| 500 | Database or internal error |

`POST /cancel` on an already-finished crawl returns **200** with `stopped: false` — not a 404.

## Local test script

`./test_seo_crawl_api.sh` exercises every endpoint end-to-end:

1. Starts `cmd/api` on port **18080** (default) with `SEO_CRAWL_MAX_URLS=4`
2. `GET /api/seo/crawls` — confirms history is empty on a fresh DB
3. `POST /api/seo/crawl` — starts the main crawl
4. `GET /api/seo/crawl/{id}` — polls until `crawling` is `false`
5. `GET /api/seo/crawl/{id}/findings` — prints all issue groups
6. `GET /api/seo/crawl/{id}/issues/pages` — lists pages for the first issue type
7. `GET /api/seo/crawl/{id}/page/{page_id}` — full evidence for the first affected page
8. `GET /api/seo/crawls?url=SEED_URL` — history now shows the finished crawl
9. `POST /api/seo/crawl` — starts a second crawl to test cancellation
10. `POST /api/seo/crawl/{id}/cancel` — aborts the second crawl
11. `GET /api/seo/crawl/{id}` — confirms `crawling` is `false` after cancel

Override with env vars before running:

```bash
SERVER_PORT=9090 SEED_URL=https://yoursite.com ./test_seo_crawl_api.sh
```

Available overrides: `EMAIL_DOMAIN`, `SERVER_PORT`, `SEO_DB_PATH`, `SEED_URL`, `SEO_CRAWL_MAX_URLS`.

## Relationship to SEOnaut (reference)

The **audit engine** (crawler + reporters + SQLite schema) follows the SEOnaut model. The **reference app’s web UI** adds translations, charts, exports, auth, and HTML pages — **not** duplicated here. This document is **API-only**.
