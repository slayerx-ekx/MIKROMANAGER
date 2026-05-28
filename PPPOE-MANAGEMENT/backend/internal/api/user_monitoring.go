package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mikrotik-ppp-management/internal/mikrotik"
	"mikrotik-ppp-management/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetUserMonitoringLayout(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		respond(c, 401, false, "User tidak valid", nil)
		return
	}
	raw, err := h.userRepo.GetUserMonitoringLayout(userID)
	if err != nil {
		respond(c, 500, false, "Gagal ambil layout User Monitoring: "+err.Error(), nil)
		return
	}
	payload := normalizeUserMonitoringLayoutPayload(raw)
	respond(c, 200, true, "OK", payload)
}

func (h *Handler) SaveUserMonitoringLayout(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		respond(c, 401, false, "User tidak valid", nil)
		return
	}
	var req struct {
		Widgets    json.RawMessage `json:"widgets" binding:"required"`
		LayoutMode string          `json:"layout_mode"`
		WallMode   bool            `json:"wall_mode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respond(c, 400, false, "Payload tidak valid", nil)
		return
	}
	if !json.Valid(req.Widgets) {
		respond(c, 400, false, "Format widgets harus JSON valid", nil)
		return
	}
	layoutMode := normalizeUserMonitoringLayoutMode(req.LayoutMode)
	payload := gin.H{
		"widgets":     json.RawMessage(req.Widgets),
		"layout_mode": layoutMode,
		"wall_mode":   req.WallMode,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		respond(c, 400, false, "Format layout User Monitoring tidak valid", nil)
		return
	}
	if err := h.userRepo.UpsertUserMonitoringLayout(userID, string(encoded)); err != nil {
		respond(c, 500, false, "Gagal simpan layout User Monitoring: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "Layout User Monitoring tersimpan", nil)
}

func currentUserID(c *gin.Context) (int, bool) {
	value, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, v > 0
	case int64:
		return int(v), v > 0
	case float64:
		return int(v), v > 0
	default:
		return 0, false
	}
}

func normalizeUserMonitoringLayoutPayload(raw string) gin.H {
	layoutMode := "auto"
	wallMode := false
	var payload struct {
		Widgets    interface{} `json:"widgets"`
		LayoutMode string      `json:"layout_mode"`
		WallMode   bool        `json:"wall_mode"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &payload); err == nil && payload.Widgets != nil {
		if strings.TrimSpace(payload.LayoutMode) != "" {
			layoutMode = normalizeUserMonitoringLayoutMode(payload.LayoutMode)
		}
		return gin.H{"widgets": payload.Widgets, "layout_mode": layoutMode, "wall_mode": payload.WallMode}
	}
	var widgets interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &widgets); err != nil || widgets == nil {
		widgets = []interface{}{}
	}
	return gin.H{"widgets": widgets, "layout_mode": layoutMode, "wall_mode": wallMode}
}

func normalizeUserMonitoringLayoutMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "auto" || value == "1x1" || value == "1x2" || value == "1x3" || value == "2x1" || value == "2x2" || value == "2x3" || value == "3x1" || value == "3x2" || value == "3x3" {
		return value
	}
	return "auto"
}

type userMonSNMPCacheItem struct {
	Items       []models.UserMonitoringPPPInterface
	RouterName  string
	RouterIP    string
	Community   string
	ExpiresAt   time.Time
	CachedAt    time.Time
}

var (
	userMonSNMPCacheMu sync.Mutex
	userMonSNMPCache   = map[int]userMonSNMPCacheItem{}
)

func (h *Handler) GetUserMonitoringPPPInterfaces(c *gin.Context) {
	mode := strings.ToLower(strings.TrimSpace(c.DefaultQuery("mode", "api")))
	if mode == "snmp" {
		h.getUserMonitoringPPPSNMP(c)
		return
	}

	routerID, err := strconv.Atoi(c.Param("id"))
	if err != nil || routerID <= 0 {
		respond(c, 400, false, "Invalid router id", nil)
		return
	}

	router, err := h.routerRepo.GetByID(routerID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}

	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	pppoeBindings, err := client.GetPPPoEInterfaces()
	if err != nil {
		respond(c, 500, false, "Failed to get PPPoE interfaces: "+err.Error(), nil)
		return
	}

	active, err := client.GetActivePPP()
	if err != nil {
		respond(c, 500, false, "Failed to get active PPP: "+err.Error(), nil)
		return
	}

	pppInterfaces, _ := client.GetPPPInterfaces()
	rawIfaces, _ := client.GetInterfaces()

	activeMap := make(map[string]mikrotik.PPPActiveEntry, len(active))
	for _, item := range active {
		if strings.TrimSpace(item.Name) == "" {
			continue
		}
		activeMap[item.Name] = item
	}

	ifaceByUser := make(map[string]map[string]string)
	for _, inf := range pppInterfaces {
		username := firstNonEmptyString(inf["user"], inf["name"], inf["default-name"])
		if username == "" {
			continue
		}
		ifaceByUser[username] = inf
	}
	for _, inf := range rawIfaces {
		if !strings.EqualFold(strings.TrimSpace(inf["type"]), "pppoe-in") {
			continue
		}
		username := firstNonEmptyString(inf["user"], inf["name"], inf["default-name"])
		if username == "" {
			continue
		}
		if existing, ok := ifaceByUser[username]; ok {
			merged := map[string]string{}
			for k, v := range existing {
				merged[k] = v
			}
			for k, v := range inf {
				if strings.TrimSpace(v) != "" {
					merged[k] = v
				}
			}
			ifaceByUser[username] = merged
		} else {
			ifaceByUser[username] = inf
		}
	}

	items := make([]models.UserMonitoringPPPInterface, 0, len(pppoeBindings))
	for _, binding := range pppoeBindings {
		name := firstNonEmptyString(binding["name"], binding["user"], binding["default-name"])
		if name == "" {
			continue
		}
		iface := ifaceByUser[name]
		running := strings.EqualFold(strings.TrimSpace(binding["running"]), "true")
		if !running {
			_, running = activeMap[name]
		}
		disabled := isTruthyMikrotik(binding["disabled"])
		dynamic := isTruthyMikrotik(binding["dynamic"])
		flag := pppoeInterfaceFlag(running, dynamic, disabled)
		status := "offline"
		if running {
			status = "online"
		}
		items = append(items, models.UserMonitoringPPPInterface{
			Name:         name,
			Type:         firstNonEmptyString(binding["type"], iface["type"]),
			Service:      firstNonEmptyString(binding["service"], iface["service"]),
			Flag:         flag,
			Status:       status,
			Running:      running,
			Disabled:     disabled,
			Source:       "api",
			LastLinkDown: firstNonEmptyString(
				iface["last-link-down-time"],
				iface["last-link-down"],
				iface["last-disconnected-time"],
				iface["last-logged-out"],
				iface["last-logout"],
			),
			LastLinkUp: firstNonEmptyString(
				iface["last-link-up-time"],
				iface["last-link-up"],
				iface["last-logged-in-time"],
				iface["last-logged-in"],
				iface["last-login"],
			),
		})
	}

	if len(pppoeBindings) == 0 && len(active) > 0 {
		for _, ac := range active {
			iface := ifaceByUser[ac.Name]
			items = append(items, models.UserMonitoringPPPInterface{
				Name:    ac.Name,
				Type:    firstNonEmptyString(iface["type"]),
				Service: firstNonEmptyString(ac.Service, iface["service"]),
				Flag: pppoeInterfaceFlag(
					true,
					isTruthyMikrotik(iface["dynamic"]),
					isTruthyMikrotik(iface["disabled"]),
				),
				Status:  "online",
				Running: true,
				Source:  "api",
				LastLinkDown: firstNonEmptyString(
					iface["last-link-down-time"],
					iface["last-link-down"],
					iface["last-disconnected-time"],
					iface["last-logged-out"],
					iface["last-logout"],
				),
				LastLinkUp: firstNonEmptyString(
					iface["last-link-up-time"],
					iface["last-link-up"],
					iface["last-logged-in-time"],
					iface["last-logged-in"],
					iface["last-login"],
				),
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Running != items[j].Running {
			return !items[i].Running && items[j].Running
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	respond(c, 200, true, "OK", gin.H{
		"router_id":   router.ID,
		"router_name": router.Name,
		"router_ip":   router.IPAddress,
		"total":       len(items),
		"data":        items,
	})
}

func (h *Handler) getUserMonitoringPPPSNMP(c *gin.Context) {
	routerID, err := strconv.Atoi(c.Param("id"))
	if err != nil || routerID <= 0 {
		respond(c, 400, false, "Invalid router id", nil)
		return
	}

	router, err := h.routerRepo.GetByID(routerID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}

	client, usedCommunity, err := connectSNMPWithFallback(router.IPAddress, router.SNMPPort, router.SNMPUser)
	if err != nil {
		if h.respondCachedUserMonSNMP(c, routerID, "SNMP connect sedang lambat, menampilkan cache terakhir") {
			return
		}
		respond(c, 500, false, "SNMP connect failed: "+err.Error(), nil)
		return
	}
	defer client.Conn.Close()

	ifaces, err := getCachedInterfaces(routerID, client, false)
	if err != nil {
		if h.respondCachedUserMonSNMP(c, routerID, "SNMP interface read timeout, menampilkan cache terakhir") {
			return
		}
		respond(c, 500, false, "SNMP read interfaces failed: "+err.Error(), nil)
		return
	}

	selected := make([]snmpIfaceInfo, 0)
	indexMap := make(map[int]snmpIfaceInfo)
	for _, inf := range ifaces {
		if !isPPPoESNMPInterface(inf) {
			continue
		}
		selected = append(selected, inf)
		indexMap[inf.IfIndex] = inf
	}

	sort.Slice(selected, func(i, j int) bool {
		return selected[i].IfIndex < selected[j].IfIndex
	})

	items := make([]models.UserMonitoringPPPInterface, 0, len(selected))
	if len(selected) > 0 {
		oids := []string{".1.3.6.1.2.1.1.3.0"}
		for _, inf := range selected {
			idx := strconv.Itoa(inf.IfIndex)
			oids = append(oids,
				".1.3.6.1.2.1.2.2.1.8."+idx,
				".1.3.6.1.2.1.2.2.1.9."+idx,
			)
		}

		packet, err := getSNMPInChunks(client, oids, 40)
		if err != nil {
			clearPreferredSNMP(router.IPAddress, router.SNMPPort)
			if client.Conn != nil {
				_ = client.Conn.Close()
			}
			retryClient, retryCommunity, retryErr := connectSNMPWithFallback(router.IPAddress, router.SNMPPort, router.SNMPUser)
			if retryErr == nil {
				client = retryClient
				usedCommunity = retryCommunity
				defer client.Conn.Close()
				packet, err = getSNMPInChunks(client, oids, 24)
			}
			if err != nil {
				if h.respondCachedUserMonSNMP(c, routerID, "SNMP timeout, menampilkan cache terakhir") {
					return
				}
				respond(c, 500, false, "SNMP get failed: "+err.Error(), nil)
				return
			}
		}

		sysUpCentis := uint64(0)
		operByIdx := map[int]int{}
		changeByIdx := map[int]uint64{}
		for _, v := range packet.Variables {
			switch {
			case strings.TrimSpace(v.Name) == ".1.3.6.1.2.1.1.3.0":
				sysUpCentis = pduToUint64(v)
			case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.2.2.1.8."):
				operByIdx[oidLastInt(v.Name)] = int(pduToUint64(v))
			case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.2.2.1.9."):
				changeByIdx[oidLastInt(v.Name)] = pduToUint64(v)
			}
		}

		now := time.Now()
		for _, inf := range selected {
			oper := operByIdx[inf.IfIndex]
			if oper == 0 {
				oper = inf.OperStatus
			}
			running := oper == 1
			status := "offline"
			if running {
				status = "online"
			}
			changeTick := changeByIdx[inf.IfIndex]
			lastChange := "-"
			note := "SNMP oper status"
			if changeTick > 0 && sysUpCentis > 0 && sysUpCentis >= changeTick {
				age := time.Duration((sysUpCentis-changeTick)*10) * time.Millisecond
				if age >= 0 {
					lastChange = now.Add(-age).Format("2006-01-02 15:04:05")
					note = "Perubahan interface " + humanizeDuration(age) + " lalu"
				}
			}
			if running {
				note = "Status UP via SNMP"
				if lastChange != "-" {
					note = "UP • berubah " + humanizeDuration(now.Sub(parseLocalDateTime(lastChange))) + " lalu"
				}
			} else if lastChange != "-" {
				note = "DOWN • berubah " + humanizeDuration(now.Sub(parseLocalDateTime(lastChange))) + " lalu"
			}

			items = append(items, models.UserMonitoringPPPInterface{
				Name:       firstNonEmptyString(inf.Name, inf.Description, "if"+strconv.Itoa(inf.IfIndex)),
				Type:       "SNMP Interface",
				Status:     status,
				Running:    running,
				LastChange: lastChange,
				Note:       note,
				Source:     "snmp",
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Running != items[j].Running {
			return !items[i].Running && items[j].Running
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	h.saveCachedUserMonSNMP(routerID, userMonSNMPCacheItem{
		Items:      items,
		RouterName: router.Name,
		RouterIP:   router.IPAddress,
		Community:  usedCommunity,
		CachedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(2 * time.Minute),
	})

	respond(c, 200, true, "OK", gin.H{
		"router_id":   router.ID,
		"router_name": router.Name,
		"router_ip":   router.IPAddress,
		"source":      "snmp",
		"community":   usedCommunity,
		"cached":      false,
		"total":       len(items),
		"data":        items,
	})
}

func (h *Handler) saveCachedUserMonSNMP(routerID int, item userMonSNMPCacheItem) {
	if routerID <= 0 || len(item.Items) == 0 {
		return
	}
	userMonSNMPCacheMu.Lock()
	userMonSNMPCache[routerID] = item
	userMonSNMPCacheMu.Unlock()
}

func (h *Handler) respondCachedUserMonSNMP(c *gin.Context, routerID int, message string) bool {
	userMonSNMPCacheMu.Lock()
	item, ok := userMonSNMPCache[routerID]
	userMonSNMPCacheMu.Unlock()
	if !ok || len(item.Items) == 0 || item.ExpiresAt.Before(time.Now()) {
		return false
	}
	respond(c, 200, true, firstNonEmptyString(strings.TrimSpace(message), "OK"), gin.H{
		"router_id":         routerID,
		"router_name":       item.RouterName,
		"router_ip":         item.RouterIP,
		"source":            "snmp",
		"community":         item.Community,
		"cached":            true,
		"cached_at":         item.CachedAt.Format("2006-01-02 15:04:05"),
		"cache_age_seconds": int(time.Since(item.CachedAt).Seconds()),
		"total":             len(item.Items),
		"data":              item.Items,
	})
	return true
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func isTruthyMikrotik(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "yes" || value == "1"
}

func pppoeInterfaceFlag(running, dynamic, disabled bool) string {
	if disabled {
		return "X"
	}
	if dynamic && running {
		return "DR"
	}
	if running {
		return "R"
	}
	if dynamic {
		return "D"
	}
	return "-"
}

func isPPPoESNMPInterface(inf snmpIfaceInfo) bool {
	name := strings.ToLower(strings.TrimSpace(inf.Name))
	desc := strings.ToLower(strings.TrimSpace(inf.Description))
	alias := strings.ToLower(strings.TrimSpace(inf.Alias))
	if strings.Contains(name, "@") || strings.Contains(desc, "@") || strings.Contains(alias, "@") {
		return true
	}
	if strings.Contains(name, "pppoe") || strings.Contains(desc, "pppoe") || strings.Contains(alias, "pppoe") {
		return true
	}
	if strings.HasPrefix(name, "if") && len(name) > 2 {
		if _, err := strconv.Atoi(name[2:]); err == nil {
			return false
		}
	}
	if strings.HasPrefix(desc, "if") && len(desc) > 2 {
		if _, err := strconv.Atoi(desc[2:]); err == nil {
			return false
		}
	}
	return false
}

func humanizeDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}

func parseLocalDateTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" || v == "-" {
		return time.Time{}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", v, time.Local)
	if err != nil {
		return time.Time{}
	}
	return t
}
