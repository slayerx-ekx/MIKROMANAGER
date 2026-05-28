package api

import (
	"encoding/json"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetNMSLayout(c *gin.Context) {
	raw, err := h.userRepo.GetGlobalNMSLayout()
	if err != nil {
		respond(c, 500, false, "Gagal ambil layout NMS: "+err.Error(), nil)
		return
	}
	// Backward-compatibility: bootstrap global layout from latest user layout if still empty.
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "[]" || strings.TrimSpace(raw) == "null" {
		if legacy, legacyErr := h.userRepo.GetLatestUserNMSLayout(); legacyErr == nil {
			legacy = strings.TrimSpace(legacy)
			if legacy != "" && legacy != "[]" && legacy != "null" {
				raw = legacy
				_ = h.userRepo.UpsertGlobalNMSLayout(raw)
			}
		}
	}
	layoutMode := "auto"
	var payload struct {
		Widgets    interface{} `json:"widgets"`
		LayoutMode string      `json:"layout_mode"`
		History    interface{} `json:"history"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err == nil && payload.Widgets != nil {
		if strings.TrimSpace(payload.LayoutMode) != "" {
			layoutMode = strings.TrimSpace(payload.LayoutMode)
		}
		history := payload.History
		if history == nil {
			history = map[string]interface{}{}
		}
		respond(c, 200, true, "OK", gin.H{"widgets": payload.Widgets, "layout_mode": layoutMode, "history": history})
		return
	}
	var widgets interface{}
	if err := json.Unmarshal([]byte(raw), &widgets); err != nil || widgets == nil {
		widgets = []interface{}{}
	}
	respond(c, 200, true, "OK", gin.H{"widgets": widgets, "layout_mode": layoutMode, "history": map[string]interface{}{}})
}

func (h *Handler) SaveNMSLayout(c *gin.Context) {
	var req struct {
		Widgets    json.RawMessage `json:"widgets" binding:"required"`
		LayoutMode string          `json:"layout_mode"`
		History    json.RawMessage `json:"history"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respond(c, 400, false, "Payload tidak valid", nil)
		return
	}
	if !json.Valid(req.Widgets) {
		respond(c, 400, false, "Format widgets harus JSON valid", nil)
		return
	}
	layoutMode := strings.TrimSpace(req.LayoutMode)
	if layoutMode == "" {
		layoutMode = "auto"
	}
	history := req.History
	if len(history) > 0 && !json.Valid(history) {
		respond(c, 400, false, "Format history harus JSON valid", nil)
		return
	}
	if len(history) == 0 {
		history = json.RawMessage(`{}`)
	}
	payload := gin.H{
		"widgets":     json.RawMessage(req.Widgets),
		"layout_mode": layoutMode,
		"history":     json.RawMessage(history),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		respond(c, 400, false, "Format layout NMS tidak valid", nil)
		return
	}
	layout := strings.TrimSpace(string(encoded))
	if layout == "" || layout == "null" {
		layout = `{"widgets":[],"layout_mode":"auto"}`
	}
	if err := h.userRepo.UpsertGlobalNMSLayout(layout); err != nil {
		respond(c, 500, false, "Gagal simpan layout NMS: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "Layout NMS tersimpan", nil)
}
