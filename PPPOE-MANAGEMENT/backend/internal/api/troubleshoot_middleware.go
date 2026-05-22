package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"mikrotik-ppp-management/internal/models"

	"github.com/gin-gonic/gin"
)

type troubleshootCaptureWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *troubleshootCaptureWriter) Write(data []byte) (int, error) {
	if w.body != nil && w.body.Len() < 8192 {
		_, _ = w.body.Write(data)
	}
	return w.ResponseWriter.Write(data)
}

func (h *Handler) TroubleshootCaptureMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || h.troubleshootRepo == nil {
			c.Next()
			return
		}
		writer := &troubleshootCaptureWriter{ResponseWriter: c.Writer, body: bytes.NewBuffer(nil)}
		c.Writer = writer
		c.Next()
		h.captureTroubleshootFailure(c, writer)
	}
}

func (h *Handler) captureTroubleshootFailure(c *gin.Context, writer *troubleshootCaptureWriter) {
	if c == nil || writer == nil {
		return
	}
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	if shouldSkipTroubleshootCapture(path) {
		return
	}

	status := writer.Status()
	message := ""
	success := true
	if writer.body != nil && writer.body.Len() > 0 {
		var payload struct {
			Success *bool       `json:"success"`
			Message string      `json:"message"`
			Error   string      `json:"error"`
			Data    interface{} `json:"data"`
		}
		if err := json.Unmarshal(writer.body.Bytes(), &payload); err == nil {
			if payload.Success != nil {
				success = *payload.Success
			}
			message = strings.TrimSpace(firstNonEmptyString(payload.Message, payload.Error))
		}
	}
	if status < 400 && success {
		return
	}
	if message == "" {
		message = http.StatusText(status)
		if message == "" {
			message = "API request failed"
		}
	}

	level := "warn"
	lowerMessage := strings.ToLower(message)
	if status >= 500 || status == 0 ||
		strings.Contains(lowerMessage, "failed") ||
		strings.Contains(lowerMessage, "gagal") ||
		strings.Contains(lowerMessage, "error") ||
		strings.Contains(lowerMessage, "timeout") {
		level = "error"
	}

	logItem := &models.TroubleshootLog{
		Level:   level,
		Source:  troubleshootSourceFromPath(path),
		Scope:   c.Request.Method + " " + path,
		Message: message,
		Details: buildTroubleshootDetails(c, status),
	}
	h.enrichTroubleshootRouter(c, logItem)

	go func() {
		if err := h.troubleshootRepo.InsertLog(logItem); err != nil {
			log.Printf("failed to write troubleshoot log: %v", err)
		}
	}()
}

func shouldSkipTroubleshootCapture(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	return strings.Contains(path, "/troubleshoot/logs") ||
		strings.Contains(path, "/sync/logs") ||
		strings.Contains(path, "/auth/me")
}

func troubleshootSourceFromPath(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "/routers"):
		return "router_management"
	case strings.Contains(p, "/nms/"):
		return "nms"
	case strings.Contains(p, "/user-monitoring/"):
		return "user_monitoring"
	case strings.Contains(p, "/traffic/"):
		return "traffic_monitor"
	case strings.Contains(p, "/pppoe/") || strings.Contains(p, "/monitoring/secrets") || strings.Contains(p, "/monitoring/disconnect"):
		return "pppoe_management"
	case strings.Contains(p, "/sync/"):
		return "sync"
	case strings.Contains(p, "/noc/"):
		return "noc_tools"
	case strings.Contains(p, "/olts") || strings.Contains(p, "/onus/"):
		return "olt_noc"
	case strings.Contains(p, "/users"):
		return "user_management"
	case strings.Contains(p, "/system/"):
		return "system"
	default:
		return "api"
	}
}

func buildTroubleshootDetails(c *gin.Context, status int) string {
	details := map[string]interface{}{
		"status": status,
		"method": c.Request.Method,
		"path":   c.Request.URL.Path,
		"query":  c.Request.URL.RawQuery,
	}
	if fullPath := c.FullPath(); fullPath != "" {
		details["route"] = fullPath
	}
	if username, ok := c.Get("username"); ok {
		details["user"] = username
	}
	if role, ok := c.Get("role"); ok {
		details["role"] = role
	}
	params := map[string]string{}
	for _, p := range c.Params {
		params[p.Key] = p.Value
	}
	if len(params) > 0 {
		details["params"] = params
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Sprintf("status=%d method=%s path=%s", status, c.Request.Method, c.Request.URL.Path)
	}
	return string(raw)
}

func (h *Handler) enrichTroubleshootRouter(c *gin.Context, logItem *models.TroubleshootLog) {
	if h == nil || h.routerRepo == nil || logItem == nil || c == nil {
		return
	}
	path := strings.ToLower(c.FullPath())
	if !(strings.Contains(path, "/routers/:id") ||
		strings.Contains(path, "/traffic/:id") ||
		strings.Contains(path, "/nms/:id") ||
		strings.Contains(path, "/noc/ping/:id") ||
		strings.Contains(path, "/user-monitoring/:id")) {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		return
	}
	logItem.RouterID = &id
	if router, err := h.routerRepo.GetByID(id); err == nil && router != nil {
		logItem.RouterName = router.Name
		logItem.RouterIP = router.IPAddress
	}
}
