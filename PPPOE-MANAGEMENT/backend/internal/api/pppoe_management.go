package api

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"mikrotik-ppp-management/internal/mikrotik"
	"mikrotik-ppp-management/internal/models"

	"github.com/gin-gonic/gin"
)

type routerPPPoEAggregate struct {
	Router    models.Router
	Entries   []models.PPPSecret
	Reachable bool
	Err       error
}

func (h *Handler) getTargetRouters(routerIDRaw string) ([]models.Router, error) {
	if strings.TrimSpace(routerIDRaw) != "" {
		routerID, err := strconv.Atoi(routerIDRaw)
		if err != nil || routerID <= 0 {
			if err == nil {
				err = errors.New("invalid router id")
			}
			return nil, err
		}
		router, err := h.routerRepo.GetByID(routerID)
		if err != nil {
			return nil, err
		}
		return []models.Router{*router}, nil
	}

	routers, err := h.routerRepo.GetAll()
	if err != nil {
		return nil, err
	}
	active := make([]models.Router, 0, len(routers))
	for _, router := range routers {
		if router.IsActive {
			active = append(active, router)
		}
	}
	return active, nil
}

func (h *Handler) fetchRouterPPPoEEntries(router models.Router) ([]models.PPPSecret, error) {
	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)

	pppoeBindings, err := client.GetPPPoEInterfaces()
	if err != nil {
		return nil, err
	}

	active, err := client.GetActivePPP()
	if err != nil {
		return nil, err
	}

	secrets, err := client.GetPPPSecrets()
	if err != nil {
		secrets = []mikrotik.PPPSecretEntry{}
	}

	secretByUser := make(map[string]mikrotik.PPPSecretEntry, len(secrets))
	for _, sec := range secrets {
		username := strings.TrimSpace(sec.Name)
		if username == "" {
			continue
		}
		secretByUser[username] = sec
	}

	activeByUser := make(map[string]mikrotik.PPPActiveEntry, len(active))
	for _, item := range active {
		username := strings.TrimSpace(item.Name)
		if username == "" {
			continue
		}
		activeByUser[username] = item
	}

	items := make([]models.PPPSecret, 0, len(pppoeBindings))
	seen := map[string]bool{}
	for _, binding := range pppoeBindings {
		username := strings.TrimSpace(firstNonEmptyString(binding["user"], binding["name"], binding["default-name"]))
		if username == "" || seen[username] {
			continue
		}
		seen[username] = true

		sec := secretByUser[username]
		ac, hasActive := activeByUser[username]
		status := "offline"
		if hasActive || strings.EqualFold(strings.TrimSpace(binding["running"]), "true") {
			status = "online"
		}

		remoteAddr := firstNonEmptyString(ac.Address, ac.RemoteAddress, sec.RemoteAddress)
		entry := models.PPPSecret{
			RouterID:      router.ID,
			RouterName:    router.Name,
			RouterIP:      router.IPAddress,
			Username:      username,
			SessionID:     strings.TrimSpace(ac.SessionID),
			IPAddress:     firstNonEmptyString(ac.Address, remoteAddr),
			InterfaceName: firstNonEmptyString(binding["name"], binding["default-name"], binding["actual-interface"], binding["interface"], username),
			Profile:       strings.TrimSpace(sec.Profile),
			Service:       firstNonEmptyString(sec.Service, binding["service"], "pppoe"),
			LocalAddress:  firstNonEmptyString(ac.LocalAddress, sec.LocalAddress),
			RemoteAddress: remoteAddr,
			Uptime:        strings.TrimSpace(ac.Uptime),
			Status:        status,
			CallerID:      strings.TrimSpace(ac.CallerID),
			BytesIn:       ac.BytesIn,
			BytesOut:      ac.BytesOut,
			Disabled:      sec.Disabled,
			MonitoringEnabled: true,
		}
		if hasActive {
			now := time.Now()
			entry.LastSeen = &now
		}
		items = append(items, entry)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Status != items[j].Status {
			return items[i].Status < items[j].Status
		}
		return strings.ToLower(items[i].Username) < strings.ToLower(items[j].Username)
	})
	return items, nil
}

func matchesPPPFilter(item models.PPPSecret, filter models.PPPFilter) bool {
	if strings.TrimSpace(filter.Status) != "" && !strings.EqualFold(strings.TrimSpace(filter.Status), strings.TrimSpace(item.Status)) {
		return false
	}
	if strings.TrimSpace(filter.Profile) != "" {
		want := strings.ToUpper(strings.TrimSpace(filter.Profile))
		got := strings.ToUpper(strings.TrimSpace(item.Profile))
		if want == "ISOLIR" {
			if !strings.Contains(got, "ISOLIR") {
				return false
			}
		} else if !strings.Contains(got, want) {
			return false
		}
	}
	if strings.TrimSpace(filter.InterfaceName) != "" {
		wantIface := strings.ToLower(strings.TrimSpace(filter.InterfaceName))
		if strings.ToLower(strings.TrimSpace(item.InterfaceName)) != wantIface {
			return false
		}
	}
	if strings.TrimSpace(filter.Search) != "" {
		search := strings.ToLower(strings.TrimSpace(filter.Search))
		if !strings.Contains(strings.ToLower(item.Username), search) &&
			!strings.Contains(strings.ToLower(item.IPAddress), search) &&
			!strings.Contains(strings.ToLower(item.InterfaceName), search) &&
			!strings.Contains(strings.ToLower(item.RouterName), search) &&
			!strings.Contains(strings.ToLower(item.RouterIP), search) {
			return false
		}
	}
	return true
}

func (h *Handler) GetPPPoEServers(c *gin.Context) {
	aggregates, err := h.collectPPPoEAggregates(c.Query("router_id"))
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	seen := map[string]bool{}
	items := make([]string, 0)
	for _, agg := range aggregates {
		for _, entry := range agg.Entries {
			name := strings.TrimSpace(entry.InterfaceName)
			if name == "" || seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			items = append(items, name)
		}
	}
	sort.Strings(items)
	respond(c, 200, true, "OK", gin.H{"items": items})
}

func aggregatePPPoERouterStats(router models.Router, entries []models.PPPSecret, reachable bool) models.RouterStatus {
	status := models.RouterStatus{
		RouterID:   router.ID,
		RouterName: router.Name,
		RouterIP:   router.IPAddress,
		IsOnline:   reachable,
		TotalUsers: len(entries),
	}
	for _, item := range entries {
		if strings.EqualFold(item.Status, "online") {
			status.Online++
		} else {
			status.Offline++
		}
		if strings.Contains(strings.ToUpper(strings.TrimSpace(item.Profile)), "ISOLIR") {
			status.Isolir++
		}
	}
	return status
}

func (h *Handler) collectPPPoEAggregates(routerIDRaw string) ([]routerPPPoEAggregate, error) {
	routers, err := h.getTargetRouters(routerIDRaw)
	if err != nil {
		return nil, err
	}
	out := make([]routerPPPoEAggregate, 0, len(routers))
	for _, router := range routers {
		items, fetchErr := h.fetchRouterPPPoEEntries(router)
		out = append(out, routerPPPoEAggregate{
			Router:    router,
			Entries:   items,
			Reachable: fetchErr == nil,
			Err:       fetchErr,
		})
	}
	return out, nil
}

func (h *Handler) GetPPPProfiles(c *gin.Context) {
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
	profiles, err := client.GetPPPProfiles()
	if err != nil {
		respond(c, 500, false, "Failed to get PPP profiles: "+err.Error(), nil)
		return
	}
	sort.Strings(profiles)
	respond(c, 200, true, "OK", gin.H{"router_id": router.ID, "router_ip": router.IPAddress, "profiles": profiles})
}

func (h *Handler) CreatePPPUser(c *gin.Context) {
	var input struct {
		RouterID             int    `json:"router_id" binding:"required"`
		Username             string `json:"username" binding:"required"`
		Password             string `json:"password" binding:"required"`
		Profile              string `json:"profile"`
		Service              string `json:"service"`
		Disabled             bool   `json:"disabled"`
		AddMonitoringBinding bool   `json:"add_monitoring_binding"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	input.Profile = strings.TrimSpace(input.Profile)
	input.Service = strings.ToLower(strings.TrimSpace(input.Service))
	if input.Service == "" {
		input.Service = "pppoe"
	}
	if input.AddMonitoringBinding && input.Service != "pppoe" {
		respond(c, 400, false, "Binding monitoring hanya tersedia untuk service pppoe", nil)
		return
	}

	router, err := h.routerRepo.GetByID(input.RouterID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}

	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	if err := client.AddPPPSecret(input.Username, input.Password, input.Profile, input.Service, input.Disabled); err != nil {
		respond(c, 500, false, "Gagal membuat user PPP: "+err.Error(), nil)
		return
	}

	message := "User PPP berhasil dibuat"
	if input.AddMonitoringBinding {
		if err := client.SyncPPPoEServerBinding("", input.Username, input.Username, true); err != nil {
			go h.syncSvc.SyncRouter(router)
			respond(c, 200, true, "User PPP berhasil dibuat, tetapi binding monitoring gagal: "+err.Error(), gin.H{
				"router_id": router.ID,
				"username":  input.Username,
				"warning":   true,
			})
			return
		}
		message = "User PPP dan binding monitoring berhasil dibuat"
	}

	go h.syncSvc.SyncRouter(router)
	respond(c, 200, true, message, gin.H{
		"router_id":              router.ID,
		"router_ip":              router.IPAddress,
		"username":               input.Username,
		"service":                input.Service,
		"add_monitoring_binding": input.AddMonitoringBinding,
	})
}

func (h *Handler) UpdatePPPUser(c *gin.Context) {
	var input struct {
		RouterID             int    `json:"router_id" binding:"required"`
		OldUsername          string `json:"old_username" binding:"required"`
		Username             string `json:"username" binding:"required"`
		Password             string `json:"password"`
		Profile              string `json:"profile"`
		Service              string `json:"service"`
		Disabled             bool   `json:"disabled"`
		AddMonitoringBinding bool   `json:"add_monitoring_binding"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}

	input.OldUsername = strings.TrimSpace(input.OldUsername)
	input.Username = strings.TrimSpace(input.Username)
	input.Profile = strings.TrimSpace(input.Profile)
	input.Service = strings.ToLower(strings.TrimSpace(input.Service))
	if input.Service == "" {
		input.Service = "pppoe"
	}
	if input.AddMonitoringBinding && input.Service != "pppoe" {
		respond(c, 400, false, "Binding monitoring hanya tersedia untuk service pppoe", nil)
		return
	}

	router, err := h.routerRepo.GetByID(input.RouterID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}

	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	if err := client.UpdatePPPSecret(input.OldUsername, input.Username, input.Password, input.Profile, input.Service, input.Disabled); err != nil {
		respond(c, 500, false, "Gagal mengupdate user PPP: "+err.Error(), nil)
		return
	}
	if err := client.SyncPPPoEServerBinding(input.OldUsername, input.Username, input.Username, input.AddMonitoringBinding); err != nil {
		go h.syncSvc.SyncRouter(router)
		respond(c, 200, true, "User PPP diupdate, tetapi sinkronisasi binding gagal: "+err.Error(), gin.H{
			"router_id": router.ID,
			"username":  input.Username,
			"warning":   true,
		})
		return
	}

	go h.syncSvc.SyncRouter(router)
	respond(c, 200, true, "User PPP berhasil diupdate", gin.H{
		"router_id":              router.ID,
		"username":               input.Username,
		"add_monitoring_binding": input.AddMonitoringBinding,
	})
}

func (h *Handler) DeletePPPUser(c *gin.Context) {
	var input struct {
		RouterID  int    `json:"router_id" binding:"required"`
		Username  string `json:"username" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	input.Username = strings.TrimSpace(input.Username)

	router, err := h.routerRepo.GetByID(input.RouterID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}

	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	if err := client.RemovePPPSecretByName(input.Username); err != nil {
		respond(c, 500, false, "Gagal menghapus user PPP: "+err.Error(), nil)
		return
	}
	if err := client.SyncPPPoEServerBinding(input.Username, input.Username, input.Username, false); err != nil {
		go h.syncSvc.SyncRouter(router)
		respond(c, 200, true, "User PPP dihapus, tetapi binding monitoring gagal dihapus: "+err.Error(), gin.H{
			"router_id": router.ID,
			"username":  input.Username,
			"warning":   true,
		})
		return
	}

	go h.syncSvc.SyncRouter(router)
	respond(c, 200, true, "User PPP berhasil dihapus", gin.H{
		"router_id": router.ID,
		"username":  input.Username,
	})
}
