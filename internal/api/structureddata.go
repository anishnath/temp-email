package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const sdFetchTimeout = 30 * time.Second
const sdMaxBodyBytes = 5 << 20 // 5 MB

// ── Types ─────────────────────────────────────────────────────────────────────

type sdRequest struct {
	URL string `json:"url"`
}

type sdResult struct {
	URL       string            `json:"url"`
	FetchedAt string            `json:"fetched_at"`
	JSONLD    []json.RawMessage `json:"jsonld"`
	Microdata []sdItem          `json:"microdata"`
	RDFa      []sdItem          `json:"rdfa"`
	Metatags  map[string]string `json:"metatags"`
}

// sdItem represents one microdata or RDFa item.
// Properties values are strings, nested sdItems, or []interface{} when multiple.
type sdItem struct {
	Type       string                 `json:"type,omitempty"`
	ID         string                 `json:"id,omitempty"`
	Properties map[string]interface{} `json:"properties"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// PostStructuredDataExtract fetches a URL and returns all structured data
// (JSON-LD, microdata, RDFa, meta tags) as raw JSON for the client to validate.
//
// POST /api/structured-data/extract
func PostStructuredDataExtract(w http.ResponseWriter, r *http.Request) {
	var req sdRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), sdFetchTimeout)
	defer cancel()

	body, err := sdFetch(ctx, req.URL)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "fetch timed out", http.StatusGatewayTimeout)
			return
		}
		http.Error(w, "fetch failed: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		http.Error(w, "html parse failed", http.StatusUnprocessableEntity)
		return
	}

	result := sdResult{
		URL:       req.URL,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		JSONLD:    extractJSONLD(doc),
		Microdata: extractMicrodata(doc),
		RDFa:      extractRDFa(doc),
		Metatags:  extractMetatags(doc),
	}
	// Always return arrays/objects, never null
	if result.JSONLD == nil {
		result.JSONLD = []json.RawMessage{}
	}
	if result.Microdata == nil {
		result.Microdata = []sdItem{}
	}
	if result.RDFa == nil {
		result.RDFa = []sdItem{}
	}
	if result.Metatags == nil {
		result.Metatags = map[string]string{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// ── Fetch ─────────────────────────────────────────────────────────────────────

func sdFetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; StructuredDataBot/1.0; +https://github.com)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, sdMaxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ── JSON-LD extraction ────────────────────────────────────────────────────────

func extractJSONLD(doc *html.Node) []json.RawMessage {
	var results []json.RawMessage
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, a := range n.Attr {
				if a.Key == "type" &&
					strings.EqualFold(strings.TrimSpace(a.Val), "application/ld+json") {
					if n.FirstChild != nil {
						content := strings.TrimSpace(n.FirstChild.Data)
						if len(content) > 0 {
							results = append(results, flattenJSONLD(content)...)
						}
					}
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return results
}

// flattenJSONLD parses a JSON-LD script block and returns individual items.
// It handles:
//   - Single object:  { ... }
//   - Top-level array: [ {...}, {...} ]
//   - @graph:  { "@context": "...", "@graph": [ {...}, {...} ] }
//     → each @graph item is promoted to the top level and inherits @context.
func flattenJSONLD(content string) []json.RawMessage {
	var results []json.RawMessage

	if strings.HasPrefix(content, "[") {
		// Top-level array — flatten each element, recursing for @graph inside each.
		var arr []json.RawMessage
		if json.Unmarshal([]byte(content), &arr) == nil {
			for _, item := range arr {
				results = append(results, flattenJSONLD(string(item))...)
			}
		}
		return results
	}

	if !json.Valid([]byte(content)) {
		return results
	}

	// Parse as object to check for @graph.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &obj); err != nil {
		return results
	}

	graphRaw, hasGraph := obj["@graph"]
	if !hasGraph {
		results = append(results, json.RawMessage(content))
		return results
	}

	// Expand @graph: each item inherits @context and @id from the wrapper.
	var graphItems []json.RawMessage
	if err := json.Unmarshal(graphRaw, &graphItems); err != nil {
		// @graph is not an array — return as-is.
		results = append(results, json.RawMessage(content))
		return results
	}

	contextRaw := obj["@context"] // may be nil
	for _, item := range graphItems {
		var itemObj map[string]json.RawMessage
		if err := json.Unmarshal(item, &itemObj); err != nil {
			results = append(results, item)
			continue
		}
		// Inject @context into each item if it doesn't already have one.
		if contextRaw != nil {
			if _, hasCtx := itemObj["@context"]; !hasCtx {
				itemObj["@context"] = contextRaw
			}
		}
		merged, err := json.Marshal(itemObj)
		if err != nil {
			results = append(results, item)
			continue
		}
		results = append(results, json.RawMessage(merged))
	}
	return results
}

// ── Meta tags extraction ──────────────────────────────────────────────────────

func extractMetatags(doc *html.Node) map[string]string {
	result := map[string]string{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			attrs := sdAttrMap(n.Attr)
			content := attrs["content"]
			// Open Graph / schema.org / other property-based meta
			if key := attrs["property"]; key != "" && content != "" {
				result[key] = content
			}
			// Standard name-based meta (description, twitter:*, etc.)
			if key := attrs["name"]; key != "" && content != "" {
				if _, exists := result[key]; !exists {
					result[key] = content
				}
			}
			// itemprop meta (used in some schemas)
			if key := attrs["itemprop"]; key != "" && content != "" {
				if _, exists := result[key]; !exists {
					result[key] = content
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return result
}

// ── Microdata extraction ──────────────────────────────────────────────────────

func extractMicrodata(doc *html.Node) []sdItem {
	var items []sdItem
	// Only collect top-level items (itemscope without itemprop on the same element).
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attrs := sdAttrMap(n.Attr)
			_, hasScope := attrs["itemscope"]
			_, hasProp := attrs["itemprop"]
			if hasScope && !hasProp {
				item := sdItem{
					Type:       strings.TrimSpace(attrs["itemtype"]),
					ID:         attrs["itemid"],
					Properties: map[string]interface{}{},
				}
				collectMicrodataProps(n, &item)
				items = append(items, item)
				return // children handled inside collectMicrodataProps
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return items
}

func collectMicrodataProps(n *html.Node, item *sdItem) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		attrs := sdAttrMap(c.Attr)
		propNames, hasProp := attrs["itemprop"]
		_, hasScope := attrs["itemscope"]

		if hasProp {
			var value interface{}
			if hasScope {
				// Nested item — value is the item, don't recurse further for props.
				nested := sdItem{
					Type:       strings.TrimSpace(attrs["itemtype"]),
					ID:         attrs["itemid"],
					Properties: map[string]interface{}{},
				}
				collectMicrodataProps(c, &nested)
				value = nested
			} else {
				value = getMicrodataValue(c, attrs)
				// Recurse into non-scope itemprop elements for flat microdata patterns.
				collectMicrodataProps(c, item)
			}
			// itemprop can be space-separated list of property names.
			for _, name := range strings.Fields(propNames) {
				sdAppendProp(item, name, value)
			}
		} else if !hasScope {
			// Plain container — keep looking for itemprop descendants.
			collectMicrodataProps(c, item)
		}
		// hasScope && !hasProp: separate top-level item, skip.
	}
}

func getMicrodataValue(n *html.Node, attrs map[string]string) string {
	switch n.Data {
	case "meta":
		return attrs["content"]
	case "audio", "embed", "iframe", "img", "source", "track", "video":
		return attrs["src"]
	case "a", "area", "link":
		return attrs["href"]
	case "object":
		return attrs["data"]
	case "data", "meter":
		return attrs["value"]
	case "time":
		if dt := attrs["datetime"]; dt != "" {
			return dt
		}
		return sdTextContent(n)
	default:
		return sdTextContent(n)
	}
}

// ── RDFa extraction ───────────────────────────────────────────────────────────

func extractRDFa(doc *html.Node) []sdItem {
	var items []sdItem
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attrs := sdAttrMap(n.Attr)
			typeof, hasType := attrs["typeof"]
			_, hasProp := attrs["property"]
			if hasType && !hasProp {
				item := sdItem{
					Type:       strings.TrimSpace(typeof),
					ID:         sdCoalesce(attrs["resource"], attrs["about"]),
					Properties: map[string]interface{}{},
				}
				collectRDFaProps(n, &item)
				items = append(items, item)
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return items
}

func collectRDFaProps(n *html.Node, item *sdItem) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		attrs := sdAttrMap(c.Attr)
		propNames, hasProp := attrs["property"]
		typeof, hasType := attrs["typeof"]

		if hasProp {
			var value interface{}
			if hasType {
				nested := sdItem{
					Type:       strings.TrimSpace(typeof),
					ID:         sdCoalesce(attrs["resource"], attrs["about"]),
					Properties: map[string]interface{}{},
				}
				collectRDFaProps(c, &nested)
				value = nested
			} else {
				value = getRDFaValue(c, attrs)
				collectRDFaProps(c, item)
			}
			for _, name := range strings.Fields(propNames) {
				sdAppendProp(item, name, value)
			}
		} else if !hasType {
			collectRDFaProps(c, item)
		}
	}
}

func getRDFaValue(n *html.Node, attrs map[string]string) string {
	if v := attrs["content"]; v != "" {
		return v
	}
	if v := attrs["href"]; v != "" {
		return v
	}
	if v := attrs["src"]; v != "" {
		return v
	}
	if v := attrs["resource"]; v != "" {
		return v
	}
	if v := attrs["datetime"]; v != "" {
		return v
	}
	return sdTextContent(n)
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// sdAppendProp adds a value to an item property, converting to []interface{}
// when a second value arrives for the same key.
func sdAppendProp(item *sdItem, name string, value interface{}) {
	existing, exists := item.Properties[name]
	if !exists {
		item.Properties[name] = value
	} else if arr, ok := existing.([]interface{}); ok {
		item.Properties[name] = append(arr, value)
	} else {
		item.Properties[name] = []interface{}{existing, value}
	}
}

func sdAttrMap(attrs []html.Attribute) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		m[a.Key] = a.Val
	}
	return m
}

func sdTextContent(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(b.String())
}

func sdCoalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
