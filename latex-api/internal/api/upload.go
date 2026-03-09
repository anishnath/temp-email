package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"latex-api/config"

	"github.com/google/uuid"
)

// UploadResponse is returned after successful upload.
type UploadResponse struct {
	FileID   string `json:"fileId"`
	Filename string `json:"filename"`
}

func HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, "failed to parse multipart form", "BAD_REQUEST", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, "missing or invalid file field", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileID := uuid.New().String()
	filename := header.Filename
	if filename == "" {
		filename = "upload"
	}

	baseDir := "/tmp/latex-jobs/uploads"
	if cfg := config.Load(); cfg != nil {
		baseDir = cfg.LatexTempDir + "/uploads"
	}
	uploadDir := filepath.Join(baseDir, fileID)
	if err := os.MkdirAll(uploadDir, 0750); err != nil {
		writeError(w, "failed to create upload directory", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	targetPath := filepath.Join(uploadDir, filename)
	out, err := os.Create(targetPath)
	if err != nil {
		writeError(w, "failed to create file", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		writeError(w, "failed to write file", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(UploadResponse{
		FileID:   fileID,
		Filename: filename,
	})
}
