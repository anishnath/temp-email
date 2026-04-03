package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"temp-email/internal/arduino"
)

// GetArduinoLibrariesOverview returns bundled/allowlist metadata (no subprocess).
// GET /api/arduino-libraries
func GetArduinoLibrariesOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := arduino.LoadConfig()
	docker := strings.TrimSpace(cfg.DockerImage) != ""
	mode := "host"
	if docker {
		mode = "docker"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":                    true,
		"mode":                       mode,
		"dockerImage":                cfg.DockerImage,
		"bundledDockerLibraries":     arduino.SortedBundledDockerLibraryNames(),
		"coreBundledLibraries":       append([]string(nil), arduino.CoreBundledLibraryIDs...),
		"extraInstallable":           arduino.ExtraInstallableLibraryMap(),
		"supportedBoardFQBNs":        arduino.PublicBoardFQBNList(),
		"enforceBoardAllowlist":      arduino.EnforceBoardAllowlist(),
		"dockerCompileAllowlistNote": "When mode is docker, POST /api/arduino-compile libraries[] must use names from bundledDockerLibraries, coreBundledLibraries, or extraInstallable.",
	})
}

// GetArduinoLibrariesInstalled runs arduino-cli lib list --format json (Docker image or host).
// GET /api/arduino-libraries/installed
func GetArduinoLibrariesInstalled(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := arduino.LoadConfig()
	raw, err := arduino.LibListJSON(r.Context(), cfg)
	if err != nil {
		writeLibJSON(w, http.StatusBadGateway, map[string]interface{}{
			"success": false,
			"error":   "cli_failed",
			"message": err.Error(),
		})
		return
	}
	var payload interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeLibJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"raw":     string(raw),
			"warning": "output was not valid JSON",
		})
		return
	}
	writeLibJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"libraries": payload,
	})
}

// GetArduinoLibrariesSearch runs arduino-cli lib search (requires network).
// GET /api/arduino-libraries/search?q=neo
func GetArduinoLibrariesSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q, err := arduino.SanitizeLibSearchQuery(r.URL.Query().Get("q"))
	if err != nil {
		writeLibJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "validation",
			"message": err.Error(),
		})
		return
	}
	cfg := arduino.LoadConfig()
	raw, err := arduino.LibSearchJSON(r.Context(), cfg, q)
	if err != nil {
		writeLibJSON(w, http.StatusBadGateway, map[string]interface{}{
			"success": false,
			"error":   "cli_failed",
			"message": err.Error(),
		})
		return
	}
	dockerMode := strings.TrimSpace(cfg.DockerImage) != ""
	payload, annErr := annotateSearchResults(raw, dockerMode)
	if annErr != nil {
		writeLibJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"query":   q,
			"raw":     string(raw),
			"warning": "could not annotate results: " + annErr.Error(),
		})
		return
	}
	writeLibJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"query":   q,
		"results": payload,
	})
}

func annotateSearchResults(raw []byte, dockerMode bool) (interface{}, error) {
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err == nil {
		annotateSearchArray(arr, dockerMode)
		return arr, nil
	}
	var wrap struct {
		Libraries []map[string]interface{} `json:"libraries"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, err
	}
	if wrap.Libraries == nil {
		return nil, fmt.Errorf("unexpected search JSON shape")
	}
	annotateSearchArray(wrap.Libraries, dockerMode)
	return map[string]interface{}{"libraries": wrap.Libraries}, nil
}

func annotateSearchArray(arr []map[string]interface{}, dockerMode bool) {
	for i := range arr {
		name, _ := arr[i]["name"].(string)
		if dockerMode {
			arr[i]["allowedOnServer"] = arduino.LibraryAllowedForDockerCompile(name)
		}
	}
}

// ArduinoLibraryInstallRequest is the JSON body for POST /api/arduino-libraries/install.
type ArduinoLibraryInstallRequest struct {
	Library string `json:"library"`
}

// PostArduinoLibraryInstall runs arduino-cli lib install on the host (optional; mutates CLI data dir).
// Disabled when ARDUINO_DOCKER_IMAGE is set. Requires ARDUINO_LIB_INSTALL_ENABLED=true.
// If ARDUINO_LIB_INSTALL_REQUIRE_ALLOWLIST is true (default), library must pass Docker compile allowlist.
// POST /api/arduino-libraries/install
func PostArduinoLibraryInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !arduinoLibInstallEnabled() {
		writeLibJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "disabled",
			"message": "Set ARDUINO_LIB_INSTALL_ENABLED=true on the server. Host-only; not available when ARDUINO_DOCKER_IMAGE is set.",
		})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeLibJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "read_body"})
		return
	}
	defer r.Body.Close()
	var req ArduinoLibraryInstallRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeLibJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid_json"})
		return
	}
	lib := strings.TrimSpace(req.Library)
	if lib == "" {
		writeLibJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "validation",
			"message": "library is required",
		})
		return
	}
	cfg := arduino.LoadConfig()
	if strings.TrimSpace(cfg.DockerImage) != "" {
		writeLibJSON(w, http.StatusConflict, map[string]interface{}{
			"success": false,
			"error":   "docker_mode",
			"message": "Host lib install is disabled when ARDUINO_DOCKER_IMAGE is set. Pass libraries in POST /api/arduino-compile instead.",
		})
		return
	}
	if arduinoLibInstallRequireAllowlist() && !arduino.LibraryAllowedForDockerCompile(lib) {
		writeLibJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "not_allowlisted",
			"message": "Library is not on the server allowlist (bundled Docker names + extraInstallable). Set ARDUINO_LIB_INSTALL_REQUIRE_ALLOWLIST=false to allow any registry name.",
		})
		return
	}
	out, err := arduino.LibInstall(r.Context(), cfg, lib)
	if err != nil {
		writeLibJSON(w, http.StatusBadGateway, map[string]interface{}{
			"success": false,
			"error":   "install_failed",
			"message": err.Error(),
		})
		return
	}
	writeLibJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"library": lib,
		"output":  strings.TrimSpace(string(out)),
	})
}

func arduinoLibInstallEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ARDUINO_LIB_INSTALL_ENABLED")), "true")
}

func arduinoLibInstallRequireAllowlist() bool {
	v := strings.TrimSpace(os.Getenv("ARDUINO_LIB_INSTALL_REQUIRE_ALLOWLIST"))
	if v == "" {
		return true
	}
	return strings.EqualFold(v, "true") || v == "1"
}

func writeLibJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
