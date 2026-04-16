# Structured Data Extract API

Extracts all structured data from a URL — **JSON-LD, Microdata, RDFa, and meta tags** — in one request. No validation is performed server-side; all testing and scoring happens on the client.

## Why client-side validation?

The server's only job is to bypass CORS and parse the raw HTML. The client receives the extracted data and runs its own validation rules (Schema.org property checks, Google preset rules, Twitter/OG card checks, etc.).

## `@graph` is flattened for you

Many sites (including schema.org itself) wrap multiple items in a `@graph` block:

```json
{ "@context": "https://schema.org", "@graph": [ {"@type":"Article"}, {"@type":"Person"} ] }
```

The server promotes each `@graph` item to the top-level `jsonld` array and injects `@context` into each item. The client always receives a flat list — no special `@graph` handling required:

```json
[
  { "@context": "https://schema.org", "@type": "Article", ... },
  { "@context": "https://schema.org", "@type": "Person",  ... }
]
```

## Endpoint

### `POST /api/structured-data/extract`

Fetch a URL and extract all structured data from it.

**Request:**
```json
{ "url": "https://example.com" }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | yes | Publicly reachable page URL |

**Response 200:**
```json
{
  "url": "https://example.com",
  "fetched_at": "2026-04-16T10:00:00Z",
  "jsonld": [
    {
      "@context": "https://schema.org",
      "@type": "Article",
      "headline": "My Article",
      "author": {
        "@type": "Person",
        "name": "Jane Doe"
      },
      "datePublished": "2026-01-01"
    }
  ],
  "microdata": [
    {
      "type": "https://schema.org/Product",
      "id": "",
      "properties": {
        "name": "Widget Pro",
        "sku": "SKU-123",
        "offers": {
          "type": "https://schema.org/Offer",
          "properties": {
            "price": "9.99",
            "priceCurrency": "USD"
          }
        }
      }
    }
  ],
  "rdfa": [
    {
      "type": "schema:Person",
      "id": "https://example.com/john",
      "properties": {
        "schema:name": "John Smith",
        "schema:url": "https://example.com/john"
      }
    }
  ],
  "metatags": {
    "og:title": "My Page",
    "og:type": "article",
    "og:image": "https://example.com/image.jpg",
    "og:url": "https://example.com",
    "twitter:card": "summary_large_image",
    "twitter:site": "@handle",
    "description": "Page description"
  }
}
```

**Error responses:**

| Code | Meaning |
|------|---------|
| `400` | Missing or empty `url`, or invalid JSON body |
| `422` | URL not reachable, DNS failure, or HTTP 4xx/5xx from target |
| `504` | Fetch timed out (30s limit) |

## Response fields

### `jsonld` — `array`

Each element is the raw parsed JSON-LD object exactly as found in the page's `<script type="application/ld+json">` tags. If a script block contains a top-level array, its items are flattened into the `jsonld` array.

Always an array (empty `[]` if none found).

### `microdata` — `array of items`

Each item has:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `itemtype` attribute value (usually a Schema.org URL) |
| `id` | string | `itemid` attribute value (if present) |
| `properties` | object | Map of `itemprop` name → value |

Property values are:
- `string` — for simple text, `href`, `src`, `datetime`, `content` values
- nested `item` object — when the property element also has `itemscope`
- `array` — when the same `itemprop` name appears multiple times

Only top-level items are in the array. Nested items appear as property values.

### `rdfa` — `array of items`

Same shape as `microdata`. Items are elements with a `typeof` attribute. Properties are child elements with a `property` attribute. Values come from `content`, `href`, `src`, `resource`, or text content.

### `metatags` — `object`

Flat key → value map of all `<meta>` tags:
- `<meta property="og:title" content="...">` → `"og:title": "..."`
- `<meta name="twitter:card" content="...">` → `"twitter:card": "..."`
- `<meta name="description" content="...">` → `"description": "..."`

## Client usage examples

### Check if a page has JSON-LD

```js
const { jsonld } = await extract(url);
const hasJsonLd = jsonld.length > 0;
```

### Find a specific schema type

`@graph` is already flattened, so just loop `jsonld[]` directly.
Note: `@type` can be a string or an array — always normalise:

```js
// Safe helper — works whether @type is string or array
const getTypes = item => [].concat(item['@type'] || []);

const article = jsonld.find(item => getTypes(item).includes('Article'));
```

### Check Open Graph tags

```js
const { metatags } = await extract(url);
const ogTags = {
  title:       metatags['og:title'],
  description: metatags['og:description'],
  image:       metatags['og:image'],
  type:        metatags['og:type'],
};
const missing = Object.entries(ogTags)
  .filter(([, v]) => !v)
  .map(([k]) => k);
```

### Validate Schema.org properties

```js
const { jsonld } = await extract(url);
const product = jsonld.find(i => i['@type'] === 'Product');

const required = ['name', 'image', 'description', 'offers'];
const missing  = required.filter(p => !product?.[p]);
const passed   = required.filter(p =>  product?.[p]);
```

### Check Twitter card

```js
const { metatags } = await extract(url);
const card = metatags['twitter:card'];
// valid values: summary | summary_large_image | app | player
const validCards = ['summary', 'summary_large_image', 'app', 'player'];
const valid = validCards.includes(card);
```

## Quick test

```bash
curl -X POST http://localhost:7080/api/structured-data/extract \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://airhorner.com/"}' | jq '{
    jsonld:    (.jsonld | length),
    microdata: (.microdata | length),
    rdfa:      (.rdfa | length),
    metatags:  (.metatags | keys)
  }'
```

## End-to-end test script

```bash
chmod +x test_structured_data_api.sh
./test_structured_data_api.sh
```

Tests cover: error cases (bad JSON, missing URL, unreachable host), real pages with JSON-LD, microdata, RDFa, and Open Graph / Twitter meta tags.

## Implementation notes

- Fetch timeout: **30 seconds**
- Max page size: **5 MB**
- User-Agent: `Mozilla/5.0 (compatible; StructuredDataBot/1.0)`
- Follows HTTP redirects automatically
- All four arrays/objects are always present in the response (never `null`)
- JSON-LD `@graph` blocks are flattened — each item is promoted to the top-level `jsonld` array with `@context` inherited
- JSON-LD top-level arrays are also flattened — each element becomes a separate item in `jsonld`
- Microdata `itemprop` supports space-separated multiple names (per spec)
- No caching, no storage — every call fetches fresh from the target URL
- JavaScript-rendered structured data is **not** captured (raw HTML only, no JS execution)
