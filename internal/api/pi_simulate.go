package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"temp-email/internal/arduino"
)

var (
	piMgr     *arduino.PiManager
	piMgrOnce sync.Once
)

func getPiManager() *arduino.PiManager {
	piMgrOnce.Do(func() {
		piMgr = arduino.NewPiManager(arduino.LoadPiConfig())
	})
	return piMgr
}

// ── POST /api/pi-simulate/start ──
// Body: { "id": "session-id" }
// Boots a Raspberry Pi 3 QEMU instance (uses pre-configured SD image).

func PostPiSimulateStart(w http.ResponseWriter, r *http.Request) {
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

	mgr := getPiManager()
	ch := sseChannels.getOrCreate(req.ID)

	err = mgr.StartInstance(r.Context(), req.ID, func(ev arduino.QemuEvent) {
		defer func() { recover() }()
		data, _ := json.Marshal(ev)
		select {
		case ch <- string(data):
		default:
		}
	})
	if err != nil {
		writeSimJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	writeSimJSON(w, http.StatusOK, map[string]interface{}{"success": true, "id": req.ID})
}

// ── POST /api/pi-simulate/stop ──

func PostPiSimulateStop(w http.ResponseWriter, r *http.Request) {
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

	mgr := getPiManager()
	mgr.StopInstance(req.ID)
	sseChannels.remove(req.ID)

	writeSimJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ── POST /api/pi-simulate/input ──
// Body: { "id": "session-id", "data": "ls\n" }

func PostPiSimulateInput(w http.ResponseWriter, r *http.Request) {
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

	mgr := getPiManager()
	if err := mgr.SendSerial(req.ID, []byte(req.Data)); err != nil {
		writeSimJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	writeSimJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ── POST /api/pi-simulate/gpio ──
// Body: { "id": "session-id", "pin": 17, "state": 1 }

func PostPiSimulateGPIO(w http.ResponseWriter, r *http.Request) {
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
		ID    string `json:"id"`
		Pin   int    `json:"pin"`
		State int    `json:"state"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.ID == "" {
		writeSimJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "id, pin, state required"})
		return
	}

	mgr := getPiManager()
	if err := mgr.SendGPIO(req.ID, req.Pin, req.State); err != nil {
		writeSimJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	writeSimJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ── GET /api/pi-simulate/stream?id=session-id ──
// Same SSE pattern as Arduino simulate. Reuses sseChannels.

func GetPiSimulateStream(w http.ResponseWriter, r *http.Request) {
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
			// Client disconnected — auto-stop Pi instance
			mgr := getPiManager()
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
