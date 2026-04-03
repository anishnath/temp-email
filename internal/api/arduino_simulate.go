package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"temp-email/internal/arduino"
)

// Global QEMU manager + job store (initialized lazily).
var (
	qemuMgr      *arduino.QemuManager
	jobStore     *arduino.JobStore
	qemuInitOnce sync.Once
)

func initQemuServices() {
	qemuMgr = arduino.NewQemuManager(arduino.LoadQemuConfig())
	jobStore = arduino.DefaultJobStoreConfig()
	jobStore.Start()
}

func getQemuManager() *arduino.QemuManager {
	qemuInitOnce.Do(initQemuServices)
	return qemuMgr
}

func getJobStore() *arduino.JobStore {
	qemuInitOnce.Do(initQemuServices)
	return jobStore
}

// ── POST /api/arduino-simulate/start ──
// Body: { "id": "session-id", "board": "esp32:esp32:esp32c3", "jobId": "abc123" }
//   OR  { "id": "session-id", "board": "...", "firmware": "<base64>" }  (legacy)
//
// jobId: references a compile job from the job store (no binary transfer)
// firmware: base64 merged.bin (legacy fallback — large payload)

type simulateStartRequest struct {
	ID       string `json:"id"`
	Board    string `json:"board"`
	JobID    string `json:"jobId,omitempty"`    // preferred: reference compile job
	Firmware string `json:"firmware,omitempty"` // legacy: base64 merged.bin
}

func PostArduinoSimulateStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "read body failed"})
		return
	}
	defer r.Body.Close()

	var req simulateStartRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid JSON"})
		return
	}
	if req.ID == "" || req.Board == "" {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id and board are required"})
		return
	}
	if req.JobID == "" && req.Firmware == "" {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "jobId or firmware is required"})
		return
	}

	mgr := getQemuManager()
	ch := sseChannels.getOrCreate(req.ID)

	eventCallback := func(ev arduino.QemuEvent) {
		data, _ := json.Marshal(ev)
		// Recover from send-on-closed-channel if stop races with event delivery
		defer func() { recover() }()
		select {
		case ch <- string(data):
		default:
		}
	}

	if req.JobID != "" {
		// Job-based flow: look up firmware on disk (no binary transfer)
		store := getJobStore()
		fwPath, err := store.GetMergedBinPath(req.JobID)
		if err != nil {
			// Try .bin fallback
			fwPath, err = store.GetBinPath(req.JobID)
			if err != nil {
				writeSimJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "job firmware not found: " + err.Error()})
				return
			}
		}
		store.MarkConsumed(req.JobID)
		err = mgr.StartFromFile(r.Context(), req.ID, req.Board, fwPath, eventCallback)
	} else {
		// Legacy flow: base64 firmware in request body
		err = mgr.StartInstance(r.Context(), req.ID, req.Board, req.Firmware, eventCallback)
	}

	if err != nil {
		writeSimJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	writeSimJSON(w, http.StatusOK, map[string]interface{}{"success": true, "id": req.ID})
}

// ── POST /api/arduino-simulate/stop ──

func PostArduinoSimulateStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "read body failed"})
		return
	}
	defer r.Body.Close()

	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.ID == "" {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id is required"})
		return
	}

	mgr := getQemuManager()
	mgr.StopInstance(req.ID)
	sseChannels.remove(req.ID)

	writeSimJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ── POST /api/arduino-simulate/input ──

func PostArduinoSimulateInput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "read body failed"})
		return
	}
	defer r.Body.Close()

	var req struct {
		ID   string `json:"id"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.ID == "" {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id and data required"})
		return
	}

	mgr := getQemuManager()
	if err := mgr.SendSerial(req.ID, []byte(req.Data)); err != nil {
		writeSimJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	writeSimJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ── GET /api/arduino-simulate/stream?id=session-id ──

func GetArduinoSimulateStream(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"id query param required"}`, http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := sseChannels.getOrCreate(id)
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			// Client disconnected (tab closed, network drop, etc.)
			// Auto-stop the QEMU instance — no point running without a listener.
			mgr := getQemuManager()
			if mgr.IsRunning(id) {
				mgr.StopInstance(id)
			}
			sseChannels.remove(id)
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ── SSE channel registry ──

type sseChannelMap struct {
	mu       sync.Mutex
	channels map[string]chan string
}

var sseChannels = &sseChannelMap{channels: make(map[string]chan string)}

func (m *sseChannelMap) getOrCreate(id string) chan string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.channels[id]; ok {
		return ch
	}
	ch := make(chan string, 100)
	m.channels[id] = ch
	return ch
}

func (m *sseChannelMap) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.channels[id]; ok {
		close(ch)
		delete(m.channels, id)
	}
}

func writeSimJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
