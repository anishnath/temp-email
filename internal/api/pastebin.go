package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"temp-email/internal/pastebin"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var pastebinService *pastebin.Service

// InitPastebin initializes the pastebin service. Call from main. Returns nil if config is incomplete.
func InitPastebin() error {
	cfg := pastebin.LoadConfig()
	if cfg.Storage == "r2" && cfg.R2AccessKeyID == "" {
		return nil
	}
	svc, err := pastebin.NewService(cfg)
	if err != nil {
		return err
	}
	pastebinService = svc
	return nil
}

func pastebinError(w http.ResponseWriter, errMsg, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}{Error: errMsg, Code: code})
}

func pastebinNotAvailable(w http.ResponseWriter) {
	pastebinError(w, "pastebin service not configured", "SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)
}

// PostPastebinKeys handles POST /api/pastebin/keys.
func PostPastebinKeys(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	rawKey, keyID, err := pastebinService.CreateAPIKey(r.Context())
	if err != nil {
		pastebinError(w, err.Error(), "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"apiKey": rawKey,
		"keyID":  keyID,
	})
}

// GetPastebinHealth handles GET /api/pastebin/health.
func GetPastebinHealth(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinError(w, "pastebin service not configured", "SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)
		return
	}
	if err := pastebinService.HealthCheck(r.Context()); err != nil {
		pastebinError(w, err.Error(), "HEALTH_CHECK_FAILED", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// GetPastebinStats handles GET /api/pastebin/stats.
func GetPastebinStats(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	st, err := pastebinService.GetStats(r.Context())
	if err != nil {
		pastebinError(w, err.Error(), "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(st)
}

// StartPastebinCleanup starts the background cleanup goroutine. No-op if pastebin not configured.
func StartPastebinCleanup() {
	if pastebinService == nil {
		return
	}
	cfg := pastebin.LoadConfig()
	interval := time.Duration(cfg.CleanupIntervalMin) * time.Minute
	pastebinService.StartCleanup(interval)
}

// PastebinCreateRequest is the JSON body for text paste.
type PastebinCreateRequest struct {
	Content       string `json:"content"`
	Title         string `json:"title"`
	Syntax        string `json:"syntax"`
	Expiry        string `json:"expiry"`
	Visibility    string `json:"visibility"`
	BurnAfterRead bool   `json:"burnAfterRead"`
	Slug          string `json:"slug"`
	Passphrase    string `json:"passphrase"`
}

// PostPastebin handles POST /api/pastebin for text (JSON) or file (multipart).
func PostPastebin(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	ct := r.Header.Get("Content-Type")
	var req pastebin.CreateRequest
	if strings.HasPrefix(ct, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			pastebinError(w, "failed to read body", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		var j PastebinCreateRequest
		if err := json.Unmarshal(body, &j); err != nil {
			pastebinError(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		j.Content = strings.TrimSpace(j.Content)
		if j.Content == "" {
			pastebinError(w, "content is required", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		apiKeyID := resolveAPIKey(r)
		req = pastebin.CreateRequest{
			Content:       []byte(j.Content),
			Title:         j.Title,
			Syntax:        j.Syntax,
			Expiry:        j.Expiry,
			Visibility:    j.Visibility,
			BurnAfterRead: j.BurnAfterRead,
			Slug:          strings.TrimSpace(j.Slug),
			Passphrase:    j.Passphrase,
			SessionID:     getPastebinSessionID(r),
			APIKeyID:      apiKeyID,
		}
	} else if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			pastebinError(w, "failed to parse multipart form", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			pastebinError(w, "file field is required", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			pastebinError(w, "failed to read file", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		filename := header.Filename
		if filename == "" {
			filename = "upload"
		}
		req = pastebin.CreateRequest{
			Content:     data,
			Filename:    filename,
			ContentType: header.Header.Get("Content-Type"),
			Title:       r.FormValue("title"),
			Expiry:      r.FormValue("expiry"),
			Visibility:  r.FormValue("visibility"),
			Passphrase:  r.FormValue("passphrase"),
			IsFile:      true,
			SessionID:   getPastebinSessionID(r),
			APIKeyID:    resolveAPIKey(r),
		}
	} else {
		pastebinError(w, "Content-Type must be application/json or multipart/form-data", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	// Ensure session cookie for "my pastes"
	sid := getPastebinSessionID(r)
	if sid == "" && req.SessionID == "" {
		sid = uuid.New().String()
		http.SetCookie(w, &http.Cookie{
			Name:     "pastebin_sid",
			Value:    sid,
			Path:     "/",
			MaxAge:   86400 * 365,
			SameSite: http.SameSiteLaxMode,
		})
		req.SessionID = sid
	}

	resp, err := pastebinService.Create(r.Context(), &req)
	if err != nil {
		switch {
		case err == pastebin.ErrContentTooLarge:
			pastebinError(w, "content too large", "CONTENT_TOO_LARGE", http.StatusRequestEntityTooLarge)
		case err == pastebin.ErrBlocked:
			pastebinError(w, "content blocked", "CONTENT_BLOCKED", http.StatusForbidden)
		case err == pastebin.ErrSlugTaken:
			pastebinError(w, "slug already taken", "SLUG_TAKEN", http.StatusConflict)
		default:
			pastebinError(w, err.Error(), "INTERNAL_ERROR", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func resolveAPIKey(r *http.Request) string {
	raw := r.Header.Get("X-API-Key")
	if raw == "" {
		return ""
	}
	if pastebinService == nil {
		return ""
	}
	id, err := pastebinService.ResolveAPIKey(r.Context(), raw)
	if err != nil {
		return ""
	}
	return id
}

func getPastebinSessionID(r *http.Request) string {
	c, err := r.Cookie("pastebin_sid")
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

// GetPastebin handles GET /api/pastebin/{id}.
func GetPastebin(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		pastebinError(w, "paste not found", "NOT_FOUND", http.StatusNotFound)
		return
	}
	passphrase := r.URL.Query().Get("passphrase")
	p, err := pastebinService.Get(r.Context(), id, passphrase)
	if err != nil {
		if err == pastebin.ErrNotFound {
			pastebinError(w, "paste not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		if err == pastebin.ErrExpired {
			pastebinError(w, "paste expired", "EXPIRED", http.StatusGone)
			return
		}
		if err == pastebin.ErrBurned {
			pastebinError(w, "paste already viewed", "BURNED", http.StatusGone)
			return
		}
		if err == pastebin.ErrPassphraseRequired {
			pastebinError(w, "passphrase required", "PASSPHRASE_REQUIRED", http.StatusForbidden)
			return
		}
		if err == pastebin.ErrWrongPassphrase {
			pastebinError(w, "wrong passphrase", "WRONG_PASSPHRASE", http.StatusForbidden)
			return
		}
		pastebinError(w, err.Error(), "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	out := map[string]interface{}{
		"id":        p.ID,
		"type":      p.Type,
		"title":     p.Title,
		"syntax":    p.Syntax,
		"size":      p.Size,
		"viewCount": p.ViewCount,
		"createdAt": p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if p.ExpiresAt != nil {
		out["expiresAt"] = p.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if p.Type == "file" {
		out["filename"] = p.Filename
		out["contentType"] = p.ContentType
	}
	if p.Type == "text" {
		out["content"] = string(p.Content)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// GetPastebinRaw handles GET /api/pastebin/{id}/raw.
func GetPastebinRaw(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	passphrase := r.URL.Query().Get("passphrase")
	p, err := pastebinService.Get(r.Context(), id, passphrase)
	if err != nil {
		if err == pastebin.ErrNotFound {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err == pastebin.ErrExpired || err == pastebin.ErrBurned {
			http.Error(w, "gone", http.StatusGone)
			return
		}
		if err == pastebin.ErrPassphraseRequired {
			http.Error(w, "passphrase required", http.StatusForbidden)
			return
		}
		if err == pastebin.ErrWrongPassphrase {
			http.Error(w, "wrong passphrase", http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ct := p.ContentType
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	if p.Type == "file" && p.Filename != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+p.Filename+`"`)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(p.Content)
}

// DeletePastebin handles DELETE /api/pastebin/{id}.
func DeletePastebin(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		pastebinError(w, "paste not found", "NOT_FOUND", http.StatusNotFound)
		return
	}
	token := r.Header.Get("X-Delete-Token")
	if token == "" {
		token = r.URL.Query().Get("deleteToken")
	}
	if token == "" {
		pastebinError(w, "delete token required", "FORBIDDEN", http.StatusForbidden)
		return
	}
	err := pastebinService.Delete(r.Context(), id, token)
	if err != nil {
		if err == pastebin.ErrNotFound {
			pastebinError(w, "paste not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		pastebinError(w, err.Error(), "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetPastebinRecent handles GET /api/pastebin/recent.
func GetPastebinRecent(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	list, err := pastebinService.ListRecent(r.Context(), limit, offset)
	if err != nil {
		pastebinError(w, err.Error(), "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	cfg := pastebin.LoadConfig()
	out := make([]map[string]interface{}, len(list))
	for i, m := range list {
		out[i] = map[string]interface{}{
			"id":        m.ID,
			"type":      m.Type,
			"title":     m.Title,
			"syntax":    m.Syntax,
			"size":      m.Size,
			"viewCount": m.ViewCount,
			"createdAt": m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			"url":       cfg.BaseURL + "/api/pastebin/" + m.ID,
		}
		if m.ExpiresAt != nil {
			out[i]["expiresAt"] = m.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"pastes": out})
}

// GetPastebinMine handles GET /api/pastebin/mine.
func GetPastebinMine(w http.ResponseWriter, r *http.Request) {
	if pastebinService == nil {
		pastebinNotAvailable(w)
		return
	}
	sessionID := getPastebinSessionID(r)
	apiKeyID := resolveAPIKey(r)
	if sessionID == "" && apiKeyID == "" {
		pastebinError(w, "session or API key required", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	list, err := pastebinService.ListMine(r.Context(), sessionID, apiKeyID, limit, offset)
	if err != nil {
		pastebinError(w, err.Error(), "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	cfg := pastebin.LoadConfig()
	out := make([]map[string]interface{}, len(list))
	for i, m := range list {
		out[i] = map[string]interface{}{
			"id":        m.ID,
			"type":      m.Type,
			"title":     m.Title,
			"syntax":    m.Syntax,
			"size":      m.Size,
			"viewCount": m.ViewCount,
			"createdAt": m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			"url":       cfg.BaseURL + "/api/pastebin/" + m.ID,
		}
		if m.ExpiresAt != nil {
			out[i]["expiresAt"] = m.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"pastes": out})
}
