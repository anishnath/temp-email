package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// ── HTML fixtures ─────────────────────────────────────────────────────────────

const sdHTMLFull = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="description" content="A test page">
  <meta property="og:title" content="OG Title">
  <meta property="og:type" content="article">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:site" content="@testhandle">
  <script type="application/ld+json">
  {"@context":"https://schema.org","@type":"Article","headline":"Test Article","author":{"@type":"Person","name":"Jane Doe"}}
  </script>
  <script type="application/ld+json">
  [{"@context":"https://schema.org","@type":"BreadcrumbList","name":"Home"}]
  </script>
</head>
<body>
  <div itemscope itemtype="https://schema.org/Product">
    <span itemprop="name">Widget</span>
    <span itemprop="sku">SKU-123</span>
    <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
      <span itemprop="price">9.99</span>
      <span itemprop="priceCurrency">USD</span>
    </div>
  </div>
  <div vocab="https://schema.org/" typeof="Person">
    <span property="name">John Smith</span>
    <a property="url" href="https://example.com/john">Profile</a>
  </div>
</body>
</html>`

// ── JSON-LD ───────────────────────────────────────────────────────────────────

func TestExtractJSONLD_singleObject(t *testing.T) {
	doc := parseHTML(t, `<html><head>
		<script type="application/ld+json">{"@type":"Article","headline":"Hello"}</script>
	</head></html>`)

	items := extractJSONLD(doc)
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(items[0], &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["@type"] != "Article" {
		t.Errorf("@type: want 'Article', got %v", obj["@type"])
	}
	if obj["headline"] != "Hello" {
		t.Errorf("headline: want 'Hello', got %v", obj["headline"])
	}
}

func TestExtractJSONLD_topLevelArray(t *testing.T) {
	doc := parseHTML(t, `<html><head>
		<script type="application/ld+json">[{"@type":"A"},{"@type":"B"}]</script>
	</head></html>`)

	items := extractJSONLD(doc)
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
}

func TestExtractJSONLD_multipleScripts(t *testing.T) {
	doc := parseHTML(t, `<html><head>
		<script type="application/ld+json">{"@type":"Article"}</script>
		<script type="application/ld+json">{"@type":"BreadcrumbList"}</script>
	</head></html>`)

	items := extractJSONLD(doc)
	if len(items) != 2 {
		t.Fatalf("want 2, got %d", len(items))
	}
}

func TestExtractJSONLD_graphFlattened(t *testing.T) {
	doc := parseHTML(t, `<html><head>
		<script type="application/ld+json">{
			"@context": "https://schema.org",
			"@graph": [
				{"@type": "Article", "headline": "First"},
				{"@type": "Person",  "name": "Jane"}
			]
		}</script>
	</head></html>`)

	items := extractJSONLD(doc)
	if len(items) != 2 {
		t.Fatalf("@graph: want 2 flattened items, got %d", len(items))
	}
	// Each item should have inherited @context
	for i, raw := range items {
		var obj map[string]interface{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("item %d unmarshal: %v", i, err)
		}
		if obj["@context"] == nil {
			t.Errorf("item %d missing @context after @graph flattening", i)
		}
		if obj["@type"] == nil {
			t.Errorf("item %d missing @type", i)
		}
	}
}

func TestExtractJSONLD_graphNestedInArray(t *testing.T) {
	doc := parseHTML(t, `<html><head>
		<script type="application/ld+json">[
			{"@context":"https://schema.org","@type":"BreadcrumbList"},
			{"@context":"https://schema.org","@graph":[{"@type":"Article"}]}
		]</script>
	</head></html>`)

	items := extractJSONLD(doc)
	// BreadcrumbList + Article from @graph = 2
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
}

func TestExtractJSONLD_invalidJSONSkipped(t *testing.T) {
	doc := parseHTML(t, `<html><head>
		<script type="application/ld+json">not valid json</script>
		<script type="application/ld+json">{"@type":"Valid"}</script>
	</head></html>`)

	items := extractJSONLD(doc)
	if len(items) != 1 {
		t.Fatalf("want 1 (invalid skipped), got %d", len(items))
	}
}

func TestExtractJSONLD_empty(t *testing.T) {
	doc := parseHTML(t, `<html><head></head></html>`)
	items := extractJSONLD(doc)
	if len(items) != 0 {
		t.Errorf("want 0, got %d", len(items))
	}
}

// ── Meta tags ─────────────────────────────────────────────────────────────────

func TestExtractMetatags_ogAndTwitter(t *testing.T) {
	doc := parseHTML(t, `<html><head>
		<meta property="og:title" content="My Title">
		<meta property="og:type" content="article">
		<meta name="twitter:card" content="summary">
		<meta name="description" content="Page desc">
	</head></html>`)

	tags := extractMetatags(doc)
	cases := map[string]string{
		"og:title":     "My Title",
		"og:type":      "article",
		"twitter:card": "summary",
		"description":  "Page desc",
	}
	for k, want := range cases {
		if tags[k] != want {
			t.Errorf("%s: want %q, got %q", k, want, tags[k])
		}
	}
}

func TestExtractMetatags_empty(t *testing.T) {
	doc := parseHTML(t, `<html><head></head></html>`)
	tags := extractMetatags(doc)
	if len(tags) != 0 {
		t.Errorf("want empty, got %v", tags)
	}
}

// ── Microdata ─────────────────────────────────────────────────────────────────

func TestExtractMicrodata_flatItem(t *testing.T) {
	doc := parseHTML(t, `<html><body>
		<div itemscope itemtype="https://schema.org/Product">
			<span itemprop="name">Widget</span>
			<span itemprop="sku">SKU-123</span>
		</div>
	</body></html>`)

	items := extractMicrodata(doc)
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	item := items[0]
	if item.Type != "https://schema.org/Product" {
		t.Errorf("type: want Product URL, got %q", item.Type)
	}
	if item.Properties["name"] != "Widget" {
		t.Errorf("name: want 'Widget', got %v", item.Properties["name"])
	}
	if item.Properties["sku"] != "SKU-123" {
		t.Errorf("sku: want 'SKU-123', got %v", item.Properties["sku"])
	}
}

func TestExtractMicrodata_nestedItem(t *testing.T) {
	doc := parseHTML(t, `<html><body>
		<div itemscope itemtype="https://schema.org/Product">
			<span itemprop="name">Widget</span>
			<div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
				<span itemprop="price">9.99</span>
			</div>
		</div>
	</body></html>`)

	items := extractMicrodata(doc)
	if len(items) != 1 {
		t.Fatalf("want 1 top-level item, got %d", len(items))
	}

	offers, ok := items[0].Properties["offers"]
	if !ok {
		t.Fatal("missing 'offers' property")
	}
	nested, ok := offers.(sdItem)
	if !ok {
		t.Fatalf("offers should be sdItem, got %T", offers)
	}
	if nested.Type != "https://schema.org/Offer" {
		t.Errorf("nested type: got %q", nested.Type)
	}
	if nested.Properties["price"] != "9.99" {
		t.Errorf("price: want '9.99', got %v", nested.Properties["price"])
	}
}

func TestExtractMicrodata_multipleValues(t *testing.T) {
	doc := parseHTML(t, `<html><body>
		<div itemscope itemtype="https://schema.org/Thing">
			<span itemprop="tag">go</span>
			<span itemprop="tag">api</span>
		</div>
	</body></html>`)

	items := extractMicrodata(doc)
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	tags, ok := items[0].Properties["tag"].([]interface{})
	if !ok {
		t.Fatalf("tag should be []interface{}, got %T: %v", items[0].Properties["tag"], items[0].Properties["tag"])
	}
	if len(tags) != 2 {
		t.Errorf("want 2 tags, got %d", len(tags))
	}
}

func TestExtractMicrodata_empty(t *testing.T) {
	doc := parseHTML(t, `<html><body><p>no microdata</p></body></html>`)
	items := extractMicrodata(doc)
	if len(items) != 0 {
		t.Errorf("want 0, got %d", len(items))
	}
}

// ── RDFa ──────────────────────────────────────────────────────────────────────

func TestExtractRDFa_flatItem(t *testing.T) {
	doc := parseHTML(t, `<html><body>
		<div typeof="schema:Person">
			<span property="schema:name">Alice</span>
			<a property="schema:url" href="https://alice.example.com">Alice</a>
		</div>
	</body></html>`)

	items := extractRDFa(doc)
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	if items[0].Type != "schema:Person" {
		t.Errorf("type: want 'schema:Person', got %q", items[0].Type)
	}
	if items[0].Properties["schema:name"] != "Alice" {
		t.Errorf("name: want 'Alice', got %v", items[0].Properties["schema:name"])
	}
	if items[0].Properties["schema:url"] != "https://alice.example.com" {
		t.Errorf("url: want href value, got %v", items[0].Properties["schema:url"])
	}
}

func TestExtractRDFa_contentAttribute(t *testing.T) {
	doc := parseHTML(t, `<html><body>
		<div typeof="schema:Event">
			<meta property="schema:startDate" content="2026-05-01">
		</div>
	</body></html>`)

	items := extractRDFa(doc)
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	if items[0].Properties["schema:startDate"] != "2026-05-01" {
		t.Errorf("startDate: want '2026-05-01', got %v", items[0].Properties["schema:startDate"])
	}
}

// ── Handler ───────────────────────────────────────────────────────────────────

func TestPostStructuredDataExtract_missingURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/structured-data/extract",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	PostStructuredDataExtract(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestPostStructuredDataExtract_invalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/structured-data/extract",
		strings.NewReader(`not-json`))
	rr := httptest.NewRecorder()
	PostStructuredDataExtract(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestPostStructuredDataExtract_localServer(t *testing.T) {
	// Spin up a local HTTP server serving sdHTMLFull.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(sdHTMLFull))
	}))
	defer ts.Close()

	body := `{"url":"` + ts.URL + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/structured-data/extract",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	PostStructuredDataExtract(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result sdResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// JSON-LD: 1 object + 1 array item = 2 total
	if len(result.JSONLD) != 2 {
		t.Errorf("jsonld: want 2, got %d", len(result.JSONLD))
	}

	// Microdata: 1 Product (Offer is nested)
	if len(result.Microdata) != 1 {
		t.Errorf("microdata: want 1, got %d", len(result.Microdata))
	}

	// RDFa: 1 Person
	if len(result.RDFa) != 1 {
		t.Errorf("rdfa: want 1, got %d", len(result.RDFa))
	}

	// Metatags
	if result.Metatags["og:title"] != "OG Title" {
		t.Errorf("og:title: want 'OG Title', got %q", result.Metatags["og:title"])
	}
	if result.Metatags["twitter:card"] != "summary_large_image" {
		t.Errorf("twitter:card: want 'summary_large_image', got %q", result.Metatags["twitter:card"])
	}
}

// ── Helper ────────────────────────────────────────────────────────────────────

func parseHTML(t *testing.T, src string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("html.Parse: %v", err)
	}
	return doc
}
