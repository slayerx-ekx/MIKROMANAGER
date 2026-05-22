package handler

import (
	"net/http"
	"strconv"

	"mikrotik-ppp-management/internal/model"
	"mikrotik-ppp-management/internal/service"

	"github.com/gin-gonic/gin"
)

type OLTHandler struct {
	service *service.OLTService
}

func NewOLTHandler(service *service.OLTService) *OLTHandler {
	return &OLTHandler{service: service}
}

func (h *OLTHandler) CreateOLT(c *gin.Context) {
	var req model.OLT
	if err := c.ShouldBindJSON(&req); err != nil {
		respond(c, http.StatusBadRequest, false, "Invalid input", nil)
		return
	}
	if err := h.service.CreateOLT(&req); err != nil {
		respond(c, http.StatusBadRequest, false, err.Error(), nil)
		return
	}
	respond(c, http.StatusCreated, true, "OLT berhasil dibuat", req)
}

func (h *OLTHandler) GetOLTs(c *gin.Context) {
	olts, err := h.service.ListOLTs()
	if err != nil {
		respond(c, http.StatusInternalServerError, false, err.Error(), nil)
		return
	}
	respond(c, http.StatusOK, true, "OK", olts)
}

func (h *OLTHandler) GetOLT(c *gin.Context) {
	olt, err := h.service.GetOLT(parseID(c.Param("id")))
	if err != nil {
		respond(c, http.StatusNotFound, false, "OLT tidak ditemukan", nil)
		return
	}
	respond(c, http.StatusOK, true, "OK", olt)
}

func (h *OLTHandler) UpdateOLT(c *gin.Context) {
	id := parseID(c.Param("id"))
	var req model.OLT
	if err := c.ShouldBindJSON(&req); err != nil {
		respond(c, http.StatusBadRequest, false, "Invalid input", nil)
		return
	}
	if err := h.service.UpdateOLT(id, &req); err != nil {
		respond(c, http.StatusBadRequest, false, err.Error(), nil)
		return
	}
	req.ID = id
	respond(c, http.StatusOK, true, "OLT berhasil diperbarui", req)
}

func (h *OLTHandler) DeleteOLT(c *gin.Context) {
	if err := h.service.DeleteOLT(parseID(c.Param("id"))); err != nil {
		respond(c, http.StatusInternalServerError, false, err.Error(), nil)
		return
	}
	respond(c, http.StatusOK, true, "OLT berhasil dihapus", nil)
}

func (h *OLTHandler) TestConnection(c *gin.Context) {
	var req model.OLTTestConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond(c, http.StatusBadRequest, false, "Invalid input", nil)
		return
	}
	result := h.service.TestConnection(req)
	respond(c, http.StatusOK, result.SNMP || result.Telnet, "Test connection selesai", result)
}

func (h *OLTHandler) GetONUs(c *gin.Context) {
	oltID := parseID(c.Param("id"))
	refresh := c.DefaultQuery("refresh", "true") != "false"
	if refresh {
		status, err := h.service.StartONUSync(oltID)
		if err != nil {
			respond(c, http.StatusInternalServerError, false, "Gagal memulai sync SNMP: "+err.Error(), gin.H{"error": err.Error()})
			return
		}
		onus, cacheErr := h.service.ListONUs(oltID, false)
		if cacheErr != nil {
			respond(c, http.StatusInternalServerError, false, cacheErr.Error(), nil)
			return
		}
		respond(c, http.StatusOK, true, status.Message, onus)
		return
	}
	onus, err := h.service.ListONUs(oltID, false)
	if err != nil {
		respond(c, http.StatusInternalServerError, false, "Gagal mengambil data ONU: "+err.Error(), gin.H{"error": err.Error()})
		return
	}
	respond(c, http.StatusOK, true, "OK", onus)
}

func (h *OLTHandler) StartONUSync(c *gin.Context) {
	status, err := h.service.StartONUSync(parseID(c.Param("id")))
	if err != nil {
		respond(c, http.StatusInternalServerError, false, "Gagal memulai sync SNMP: "+err.Error(), gin.H{"error": err.Error()})
		return
	}
	respond(c, http.StatusAccepted, true, status.Message, status)
}

func (h *OLTHandler) GetONUSyncStatus(c *gin.Context) {
	status := h.service.GetONUSyncStatus(parseID(c.Param("id")))
	respond(c, http.StatusOK, true, status.Message, status)
}

func (h *OLTHandler) GetONUDetail(c *gin.Context) {
	onu, err := h.service.GetONUDetail(c.Param("sn"))
	if err != nil {
		respond(c, http.StatusNotFound, false, "ONU tidak ditemukan", nil)
		return
	}
	respond(c, http.StatusOK, true, "OK", onu)
}

func (h *OLTHandler) GetRawTelnetDump(c *gin.Context) {
	mode := c.DefaultQuery("mode", "quick")
	dump, err := h.service.GetRawTelnetDump(parseID(c.Param("id")), mode)
	if err != nil {
		respond(c, http.StatusInternalServerError, false, "Gagal mengambil raw Telnet OLT: "+err.Error(), nil)
		return
	}
	respond(c, http.StatusOK, true, "OK", dump)
}

func (h *OLTHandler) RunTelnetCommand(c *gin.Context) {
	preset := c.DefaultQuery("preset", "session")
	target := c.Query("target")
	dump, err := h.service.RunTelnetCommand(parseID(c.Param("id")), preset, target)
	if err != nil {
		respond(c, http.StatusInternalServerError, false, "Gagal menjalankan command Telnet OLT: "+err.Error(), nil)
		return
	}
	respond(c, http.StatusOK, true, "OK", dump)
}

func respond(c *gin.Context, code int, success bool, message string, data interface{}) {
	c.JSON(code, gin.H{"success": success, "message": message, "data": data})
}

func parseID(raw string) int {
	id, _ := strconv.Atoi(raw)
	return id
}
