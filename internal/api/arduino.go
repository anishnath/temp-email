package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"temp-email/internal/arduino"
)

// ArduinoCompileRequest is the JSON body for POST /api/arduino-compile.
// Optional files: extra sketch-folder sources (e.g. .h, .cpp, other .ino tabs). Basenames only.
// Either set sketch (sketch.ino) or include sketch.ino inside files.
type ArduinoCompileRequest struct {
	Sketch    string               `json:"sketch"`
	Files     []arduino.SketchFile `json:"files,omitempty"`
	Board     string               `json:"board"`
	Libraries []string             `json:"libraries"`
}

// PostArduinoCompile handles POST /api/arduino-compile.
// On success: outputFormat is "hex", "uf2", or "bin" (RFC 4648 base64 for uf2/bin).
// ESP32 may also set mergedBin (base64 of sketch.ino.merged.bin) when the build produces it.
func PostArduinoCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeArduinoJSON(w, http.StatusBadRequest, arduino.Response{
			Success: false, Error: "validation", Message: "failed to read body",
		})
		return
	}
	defer r.Body.Close()

	var req ArduinoCompileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeArduinoJSON(w, http.StatusBadRequest, arduino.Response{
			Success: false, Error: "validation", Message: "invalid JSON",
		})
		return
	}

	cfg := arduino.LoadConfig()
	compileReq := &arduino.Request{
		Sketch:    req.Sketch,
		Files:     req.Files,
		Board:     req.Board,
		Libraries: req.Libraries,
	}
	// ESP32 boards: use job store so artifacts stay on disk (jobId returned, not 4MB base64)
	if arduino.IsESP32Board(req.Board) {
		compileReq.JobStore = getJobStore()
	}
	resp := arduino.Compile(r.Context(), cfg, compileReq)

	if !resp.Success && resp.Error == "validation" {
		writeArduinoJSON(w, http.StatusBadRequest, resp)
		return
	}
	if !resp.Success && strings.Contains(resp.RawOutput, "arduino-cli not found") {
		writeArduinoJSON(w, http.StatusServiceUnavailable, resp)
		return
	}
	// Container runtime reachable but daemon/socket missing (common on macOS).
	if !resp.Success && resp.Error == "compile" && arduinoContainerRuntimeUnavailable(resp.RawOutput) {
		writeArduinoJSON(w, http.StatusServiceUnavailable, resp)
		return
	}
	writeArduinoJSON(w, http.StatusOK, resp)
}

func arduinoContainerRuntimeUnavailable(raw string) bool {
	s := strings.ToLower(raw)
	return strings.Contains(s, "cannot connect to podman") ||
		strings.Contains(s, "unable to connect to podman") ||
		strings.Contains(s, "cannot connect to the docker daemon")
}

func writeArduinoJSON(w http.ResponseWriter, status int, resp arduino.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
