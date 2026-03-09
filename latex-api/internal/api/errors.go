package api

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is the standard error JSON shape.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeError(w http.ResponseWriter, errMsg, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg, Code: code})
}
