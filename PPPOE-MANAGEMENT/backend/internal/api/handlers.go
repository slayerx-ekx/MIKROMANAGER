package api

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"mikrotik-ppp-management/internal/mikrotik"
	"mikrotik-ppp-management/internal/models"
	"mikrotik-ppp-management/internal/repository"
	"mikrotik-ppp-management/internal/service"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	userRepo         *repository.UserRepository
	routerRepo       *repository.RouterRepository
	pppRepo          *repository.PPPRepository
	syncRepo         *repository.SyncRepository
	troubleshootRepo *repository.TroubleshootRepository
	trafficRepo      *repository.TrafficRepository
	syncSvc          *service.SyncService
	appTemplate      *template.Template
}

func jakartaLocation() *time.Location {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return time.FixedZone("WIB", 7*3600)
	}
	return loc
}

func toJakartaPtr(ts *time.Time) *time.Time {
	if ts == nil {
		return nil
	}
	loc := jakartaLocation()
	v := ts.In(loc)
	return &v
}

func toJakarta(ts time.Time) time.Time {
	if ts.IsZero() {
		return ts
	}
	return ts.In(jakartaLocation())
}

func formatJakartaPtr(ts *time.Time) *string {
	if ts == nil {
		return nil
	}
	v := toJakarta(*ts).Format(time.RFC3339)
	return &v
}

func formatJakarta(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return toJakarta(ts).Format(time.RFC3339)
}

func NewHandler(
	userRepo *repository.UserRepository,
	routerRepo *repository.RouterRepository,
	pppRepo *repository.PPPRepository,
	syncRepo *repository.SyncRepository,
	troubleshootRepo *repository.TroubleshootRepository,
	trafficRepo *repository.TrafficRepository,
	syncSvc *service.SyncService,
) *Handler {
	return &Handler{
		userRepo: userRepo, routerRepo: routerRepo, pppRepo: pppRepo,
		syncRepo: syncRepo, troubleshootRepo: troubleshootRepo, trafficRepo: trafficRepo, syncSvc: syncSvc,
	}
}

func (h *Handler) SetAppTemplate(t *template.Template) {
	h.appTemplate = t
}

func LoadAppTemplate() (*template.Template, error) {
	candidates := []string{
		filepath.Join("frontend", "templates"),
		filepath.Join("..", "frontend", "templates"),
		filepath.Join("..", "..", "frontend", "templates"),
		filepath.Join("templates"),
	}
	if custom := strings.TrimSpace(os.Getenv("FRONTEND_TEMPLATES_DIR")); custom != "" {
		candidates = append([]string{custom}, candidates...)
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "layouts", "main.html")); err != nil {
			continue
		}
		files := []string{
			filepath.Join(dir, "layouts", "*.html"),
			filepath.Join(dir, "partials", "*.html"),
			filepath.Join(dir, "pages", "*.html"),
		}
		t := template.New("app")
		var err error
		for _, pattern := range files {
			t, err = t.ParseGlob(pattern)
			if err != nil {
				return nil, err
			}
		}
		return t, nil
	}
	return nil, fmt.Errorf("frontend templates not found")
}

func (h *Handler) ServeApp(c *gin.Context) {
	if h.appTemplate == nil {
		respond(c, http.StatusInternalServerError, false, "Frontend template belum dimuat", nil)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := h.appTemplate.ExecuteTemplate(c.Writer, "main", gin.H{}); err != nil {
		c.String(http.StatusInternalServerError, "Failed to render frontend: %v", err)
	}
}

func respond(c *gin.Context, code int, success bool, message string, data interface{}) {
	c.JSON(code, models.APIResponse{Success: success, Message: message, Data: data})
}

// ===== AUTH =====

func (h *Handler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	user, err := h.userRepo.GetByUsername(req.Username)
	if err != nil {
		respond(c, 401, false, "Username atau password salah", nil)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		respond(c, 401, false, "Username atau password salah", nil)
		return
	}
	token, err := GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		respond(c, 500, false, "Failed to generate token", nil)
		return
	}
	h.userRepo.UpdateLastLogin(user.ID)
	respond(c, 200, true, "Login berhasil", models.LoginResponse{
		Token: token, Username: user.Username,
		FullName: user.FullName, Role: user.Role,
	})
}

func (h *Handler) GetMe(c *gin.Context) {
	username, _ := c.Get("username")
	role, _ := c.Get("role")
	userID, _ := c.Get("user_id")
	respond(c, 200, true, "OK", gin.H{"username": username, "role": role, "user_id": userID})
}

// ===== USER MANAGEMENT =====

func (h *Handler) GetUsers(c *gin.Context) {
	users, err := h.userRepo.GetAll()
	if err != nil {
		respond(c, 500, false, "Failed to get users", nil)
		return
	}
	respond(c, 200, true, "OK", users)
}

func (h *Handler) CreateUser(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		FullName string `json:"full_name"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	validRoles := map[string]bool{"super_admin": true, "admin": true, "teknisi": true, "viewer": true}
	if !validRoles[input.Role] {
		input.Role = "teknisi"
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), 10)
	if err != nil {
		respond(c, 500, false, "Failed to hash password", nil)
		return
	}
	user := &models.User{
		Username: input.Username, Password: string(hashed),
		FullName: input.FullName, Role: input.Role, IsActive: true,
	}
	if err := h.userRepo.Create(user); err != nil {
		respond(c, 500, false, "Failed to create user: "+err.Error(), nil)
		return
	}
	user.Password = ""
	respond(c, 201, true, "User created", user)
}

func (h *Handler) UpdateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var input struct {
		Username string `json:"username"`
		FullName string `json:"full_name"`
		Role     string `json:"role"`
		IsActive bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	user := &models.User{ID: id, Username: input.Username, FullName: input.FullName, Role: input.Role, IsActive: input.IsActive}
	if err := h.userRepo.Update(user); err != nil {
		respond(c, 500, false, "Failed to update user: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "User updated", nil)
}

func (h *Handler) ChangePassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	callerID, _ := c.Get("user_id")
	callerRole, _ := c.Get("role")
	var input struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	if len(input.NewPassword) < 6 {
		respond(c, 400, false, "Password minimal 6 karakter", nil)
		return
	}
	if callerID == id {
		user, err := h.userRepo.GetByID(id)
		if err != nil {
			respond(c, 404, false, "User not found", nil)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.OldPassword)); err != nil {
			respond(c, 400, false, "Password lama salah", nil)
			return
		}
	} else if callerRole != "super_admin" {
		respond(c, 403, false, "Tidak memiliki izin", nil)
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), 10)
	if err != nil {
		respond(c, 500, false, "Failed to hash password", nil)
		return
	}
	if err := h.userRepo.UpdatePassword(id, string(hashed)); err != nil {
		respond(c, 500, false, "Failed to update password", nil)
		return
	}
	respond(c, 200, true, "Password berhasil diubah", nil)
}

func (h *Handler) DeleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	callerID, _ := c.Get("user_id")
	if callerID == id {
		respond(c, 400, false, "Tidak bisa menghapus akun sendiri", nil)
		return
	}
	if err := h.userRepo.Delete(id); err != nil {
		respond(c, 500, false, "Failed to delete user", nil)
		return
	}
	respond(c, 200, true, "User deleted", nil)
}

// ===== ROUTERS =====

func (h *Handler) GetRouters(c *gin.Context) {
	filter := models.RouterListFilter{
		Search:  strings.TrimSpace(c.Query("search")),
		Page:    1,
		Limit:   20,
		Summary: c.Query("summary") == "1" || strings.EqualFold(c.Query("summary"), "true"),
	}
	if v, err := strconv.Atoi(strings.TrimSpace(c.Query("page"))); err == nil && v > 0 {
		filter.Page = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(c.Query("limit"))); err == nil && v > 0 {
		filter.Limit = v
	}

	if filter.Summary {
		if filter.Limit <= 0 || filter.Limit > 1000 {
			filter.Limit = 1000
		}
	}

	useListMode := filter.Summary || filter.Search != "" || c.Query("page") != "" || c.Query("limit") != ""
	if !useListMode {
		routers, err := h.routerRepo.GetAll()
		if err != nil {
			respond(c, 500, false, "Failed", nil)
			return
		}
		for i := range routers {
			routers[i].Password = ""
		}
		respond(c, 200, true, "OK", routers)
		return
	}

	routers, total, err := h.routerRepo.List(filter)
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	for i := range routers {
		routers[i].Password = ""
	}
	if filter.Summary {
		respond(c, 200, true, "OK", gin.H{
			"data":  routers,
			"total": total,
		})
		return
	}
	totalPages := 0
	if filter.Limit > 0 {
		totalPages = (total + filter.Limit - 1) / filter.Limit
	}
	respond(c, 200, true, "OK", models.PaginatedResponse{
		Data:       routers,
		Total:      total,
		Page:       filter.Page,
		Limit:      filter.Limit,
		TotalPages: totalPages,
	})
}

func (h *Handler) GetRouter(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	router, err := h.routerRepo.GetByID(id)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	router.Password = ""
	respond(c, 200, true, "OK", router)
}

func (h *Handler) CreateRouter(c *gin.Context) {
	var router models.Router
	if err := c.ShouldBindJSON(&router); err != nil {
		respond(c, 400, false, "Invalid input: "+err.Error(), nil)
		return
	}
	if router.APIPort == 0 {
		router.APIPort = 8728
	}
	if router.SNMPPort == 0 {
		router.SNMPPort = 161
	}
	router.IsActive = true
	if err := h.routerRepo.Create(&router); err != nil {
		respond(c, 500, false, "Failed to create router: "+err.Error(), nil)
		return
	}
	router.Password = ""
	respond(c, 201, true, "Router created", router)
}

func (h *Handler) UpdateRouter(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	existing, err := h.routerRepo.GetByID(id)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	var input models.Router
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	input.ID = id
	if input.Password == "" {
		input.Password = existing.Password
	}
	if input.SNMPPort == 0 {
		input.SNMPPort = existing.SNMPPort
		if input.SNMPPort == 0 {
			input.SNMPPort = 161
		}
	}
	if err := h.routerRepo.Update(&input); err != nil {
		respond(c, 500, false, "Failed to update router", nil)
		return
	}
	respond(c, 200, true, "Router updated", nil)
}

func (h *Handler) DeleteRouter(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := h.routerRepo.Delete(id); err != nil {
		respond(c, 500, false, "Failed to delete router", nil)
		return
	}
	respond(c, 200, true, "Router deleted", nil)
}

func (h *Handler) TestRouterConnection(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	router, err := h.routerRepo.GetByID(id)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	if err := client.TestConnection(); err != nil {
		respond(c, 200, false, "Connection failed: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "Connection successful", nil)
}

func (h *Handler) TestRouterSNMPConnection(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	router, err := h.routerRepo.GetByID(id)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	client, usedCommunity, err := connectSNMPWithFallback(router.IPAddress, router.SNMPPort, router.SNMPUser)
	if err != nil {
		respond(c, 200, false, "SNMP connection failed: "+err.Error(), nil)
		return
	}
	defer client.Conn.Close()

	pkt, getErr := client.Get([]string{".1.3.6.1.2.1.1.1.0"}) // sysDescr.0
	if getErr != nil {
		respond(c, 200, false, "SNMP auth/read failed: "+getErr.Error(), nil)
		return
	}
	sysDescr := ""
	if pkt != nil && len(pkt.Variables) > 0 {
		sysDescr = strings.TrimSpace(pduToString(pkt.Variables[0]))
	}
	port := router.SNMPPort
	if port <= 0 {
		port = 161
	}
	respond(c, 200, true, "SNMP connection successful", gin.H{
		"target":         fmt.Sprintf("%s:%d", router.IPAddress, port),
		"sys_descr":      sysDescr,
		"used_community": usedCommunity,
	})
}

func (h *Handler) SyncRouter(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	router, err := h.routerRepo.GetByID(id)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	if err := h.syncSvc.SyncRouter(router); err != nil {
		respond(c, 500, false, "Sync failed: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "Router synced", nil)
}

// ===== MONITORING =====

func (h *Handler) GetStats(c *gin.Context) {
	aggregates, err := h.collectPPPoEAggregates("")
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	stats := &models.MonitoringStats{}
	for _, agg := range aggregates {
		stats.TotalPelanggan += len(agg.Entries)
		if agg.Reachable {
			stats.ActiveRouters++
		}
		stats.TotalRouters++
		for _, item := range agg.Entries {
			if strings.EqualFold(item.Status, "online") {
				stats.TotalAktif++
			} else {
				stats.TotalOffline++
			}
			if strings.Contains(strings.ToUpper(strings.TrimSpace(item.Profile)), "ISOLIR") {
				stats.ProfileIsolir++
			}
		}
	}
	respond(c, 200, true, "OK", stats)
}

func (h *Handler) GetPPPSecrets(c *gin.Context) {
	filter := models.PPPFilter{
		RouterID: c.Query("router_id"), Status: c.Query("status"),
		Profile: c.Query("profile"), InterfaceName: c.Query("interface_name"), Search: c.Query("search"),
	}
	filter.Page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	filter.Limit, _ = strconv.Atoi(c.DefaultQuery("limit", "25"))

	aggregates, err := h.collectPPPoEAggregates(filter.RouterID)
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}

	items := make([]models.PPPSecret, 0)
	for _, agg := range aggregates {
		if agg.Err != nil && strings.TrimSpace(filter.RouterID) != "" {
			respond(c, 500, false, "Failed to get PPPoE data: "+agg.Err.Error(), nil)
			return
		}
		for _, item := range agg.Entries {
			if matchesPPPFilter(item, filter) {
				items = append(items, item)
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Status != items[j].Status {
			return items[i].Status < items[j].Status
		}
		if items[i].RouterName != items[j].RouterName {
			return strings.ToLower(items[i].RouterName) < strings.ToLower(items[j].RouterName)
		}
		return strings.ToLower(items[i].Username) < strings.ToLower(items[j].Username)
	})

	total := len(items)
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Limit < 1 {
		filter.Limit = 25
	}
	start := (filter.Page - 1) * filter.Limit
	if start > total {
		start = total
	}
	end := start + filter.Limit
	if end > total {
		end = total
	}
	secrets := items[start:end]
	totalPages := (total + filter.Limit - 1) / filter.Limit
	respond(c, 200, true, "OK", models.PaginatedResponse{
		Data: secrets, Total: total, Page: filter.Page,
		Limit: filter.Limit, TotalPages: totalPages,
	})
}

func (h *Handler) GetRouterStatuses(c *gin.Context) {
	aggregates, err := h.collectPPPoEAggregates("")
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	statuses := make([]models.RouterStatus, 0, len(aggregates))
	for _, agg := range aggregates {
		statuses = append(statuses, aggregatePPPoERouterStats(agg.Router, agg.Entries, agg.Reachable))
	}
	respond(c, 200, true, "OK", statuses)
}

func (h *Handler) GetChartData(c *gin.Context) {
	aggregates, err := h.collectPPPoEAggregates("")
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	data := make([]map[string]interface{}, 0, len(aggregates))
	for _, agg := range aggregates {
		routerStat := aggregatePPPoERouterStats(agg.Router, agg.Entries, agg.Reachable)
		data = append(data, map[string]interface{}{
			"router":  agg.Router.Name,
			"online":  routerStat.Online,
			"offline": routerStat.Offline,
			"isolir":  routerStat.Isolir,
		})
	}
	respond(c, 200, true, "OK", data)
}

func (h *Handler) DisconnectUser(c *gin.Context) {
	var input struct {
		RouterID  int    `json:"router_id"`
		SessionID string `json:"session_id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	router, err := h.routerRepo.GetByID(input.RouterID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	if err := client.DisconnectPPPUser(input.SessionID); err != nil {
		respond(c, 500, false, "Failed to disconnect: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "User disconnected", nil)
}

func (h *Handler) GetUserDetail(c *gin.Context) {
	username := c.Param("username")
	filter := models.PPPFilter{RouterID: c.Query("router_id"), Search: username, Limit: 1, Page: 1}
	secrets, _, err := h.pppRepo.GetAllSecrets(filter)
	if err != nil || len(secrets) == 0 {
		respond(c, 404, false, "User not found", nil)
		return
	}
	respond(c, 200, true, "OK", secrets[0])
}

// ===== SYNC =====

func (h *Handler) SyncAll(c *gin.Context) {
	if h.syncSvc.IsCurrentlySyncing() {
		respond(c, 409, false, "Sync already in progress", nil)
		return
	}
	go h.syncSvc.SyncAllRouters()
	respond(c, 200, true, "Sync started", nil)
}

func (h *Handler) GetSyncSettings(c *gin.Context) {
	s, err := h.syncRepo.GetSettings()
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	respond(c, 200, true, "OK", gin.H{
		"id":                    s.ID,
		"auto_sync_enabled":     s.AutoSyncEnabled,
		"sync_interval_seconds": s.SyncIntervalSeconds,
		"last_sync_at":          formatJakartaPtr(s.LastSyncAt),
		"created_at":            formatJakarta(s.CreatedAt),
		"updated_at":            formatJakarta(s.UpdatedAt),
	})
}

func (h *Handler) UpdateSyncSettings(c *gin.Context) {
	var input struct {
		AutoSyncEnabled     bool `json:"auto_sync_enabled"`
		SyncIntervalSeconds int  `json:"sync_interval_seconds"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	if input.SyncIntervalSeconds < 10 {
		input.SyncIntervalSeconds = 10
	}
	if err := h.syncSvc.UpdateSchedule(input.AutoSyncEnabled, input.SyncIntervalSeconds); err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	respond(c, 200, true, "Settings updated", nil)
}

func (h *Handler) GetSyncStatus(c *gin.Context) {
	s, _ := h.syncRepo.GetSettings()
	respond(c, 200, true, "OK", gin.H{
		"is_syncing":            h.syncSvc.IsCurrentlySyncing(),
		"auto_sync_enabled":     s.AutoSyncEnabled,
		"sync_interval_seconds": s.SyncIntervalSeconds,
		"last_sync_at":          formatJakartaPtr(s.LastSyncAt),
	})
}

func (h *Handler) GetSyncLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	logs, err := h.syncRepo.GetRecentLogs(limit)
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	items := make([]gin.H, 0, len(logs))
	for i := range logs {
		items = append(items, gin.H{
			"id":             logs[i].ID,
			"router_id":      logs[i].RouterID,
			"router_name":    logs[i].RouterName,
			"status":         logs[i].Status,
			"message":        logs[i].Message,
			"duration_ms":    logs[i].DurationMs,
			"records_synced": logs[i].RecordsSynced,
			"created_at":     formatJakarta(logs[i].CreatedAt),
		})
	}
	respond(c, 200, true, "OK", items)
}

func (h *Handler) GetTroubleshootLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	source := strings.TrimSpace(c.Query("source"))
	level := strings.TrimSpace(c.Query("level"))
	search := strings.TrimSpace(c.Query("search"))
	logs, err := h.troubleshootRepo.GetRecentLogs(limit, source, level, search)
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	items := make([]gin.H, 0, len(logs))
	for i := range logs {
		items = append(items, gin.H{
			"id":             logs[i].ID,
			"level":          logs[i].Level,
			"source":         logs[i].Source,
			"scope":          logs[i].Scope,
			"message":        logs[i].Message,
			"details":        logs[i].Details,
			"router_id":      logs[i].RouterID,
			"router_name":    logs[i].RouterName,
			"router_ip":      logs[i].RouterIP,
			"olt_id":         logs[i].OLTID,
			"olt_name":       logs[i].OLTName,
			"olt_ip_address": logs[i].OLTIPAddress,
			"onu_interface":  logs[i].ONUInterface,
			"serial_number":  logs[i].SerialNumber,
			"created_at":     formatJakarta(logs[i].CreatedAt),
		})
	}
	respond(c, 200, true, "OK", items)
}

func (h *Handler) DeleteTroubleshootLogs(c *gin.Context) {
	var input struct {
		IDs []int64 `json:"ids"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	if len(input.IDs) == 0 {
		respond(c, 400, false, "Pilih minimal satu log untuk dihapus", nil)
		return
	}
	deleted, err := h.troubleshootRepo.DeleteLogs(input.IDs)
	if err != nil {
		respond(c, 500, false, "Gagal menghapus log: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "Log berhasil dihapus", gin.H{"deleted": deleted})
}

// ===== TRAFFIC =====

func (h *Handler) GetTrafficLive(c *gin.Context) {
	routerID, _ := strconv.Atoi(c.Param("id"))
	router, err := h.routerRepo.GetByID(routerID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	var ifaceNames []string
	requested := strings.TrimSpace(c.Query("interface"))
	if requested != "" {
		seen := map[string]bool{}
		for _, raw := range strings.Split(requested, ",") {
			name := strings.TrimSpace(raw)
			if name == "" {
				continue
			}
			key := strings.ToLower(name)
			if seen[key] {
				continue
			}
			seen[key] = true
			ifaceNames = append(ifaceNames, name)
		}
	} else {
		ifaces, err := client.GetInterfaces()
		if err != nil {
			respond(c, 500, false, "Cannot connect: "+err.Error(), nil)
			return
		}
		for _, iface := range ifaces {
			if iface["running"] == "true" {
				ifaceNames = append(ifaceNames, iface["name"])
				if len(ifaceNames) >= 10 {
					break
				}
			}
		}
	}
	if len(ifaceNames) == 0 {
		respond(c, 200, true, "No active interfaces", []models.TrafficData{})
		return
	}
	traffic, err := client.GetInterfaceTraffic(ifaceNames)
	if err != nil {
		respond(c, 500, false, "Failed to get traffic: "+err.Error(), nil)
		return
	}
	var result []models.TrafficData
	for _, t := range traffic {
		rxBps, _ := strconv.ParseInt(t["rx-bits-per-second"], 10, 64)
		txBps, _ := strconv.ParseInt(t["tx-bits-per-second"], 10, 64)
		h.trafficRepo.InsertTraffic(routerID, t["name"], rxBps, txBps)
		result = append(result, models.TrafficData{
			InterfaceName: t["name"], RxBps: rxBps, TxBps: txBps,
			RxHuman: formatBps(rxBps), TxHuman: formatBps(txBps),
			RouterName: router.Name, RouterID: routerID,
		})
	}
	respond(c, 200, true, "OK", result)
}

func (h *Handler) GetTrafficHistory(c *gin.Context) {
	routerID, _ := strconv.Atoi(c.Param("id"))
	iface := c.Query("interface")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "60"))
	history, err := h.trafficRepo.GetRecentTraffic(routerID, iface, limit)
	if err != nil {
		respond(c, 500, false, "Failed", nil)
		return
	}
	respond(c, 200, true, "OK", history)
}

// ===== NOC TOOLS =====

func (h *Handler) PingFromRouter(c *gin.Context) {
	routerID, _ := strconv.Atoi(c.Param("id"))
	var input struct {
		Target string `json:"target" binding:"required"`
		Count  int    `json:"count"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respond(c, 400, false, "Invalid input", nil)
		return
	}
	router, err := h.routerRepo.GetByID(routerID)
	if err != nil {
		respond(c, 404, false, "Router not found", nil)
		return
	}
	if input.Count <= 0 || input.Count > 10 {
		input.Count = 4
	}
	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)
	results, err := client.Ping(input.Target, input.Count)
	if err != nil {
		respond(c, 500, false, "Ping failed: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "OK", results)
}

// ===== ONT PROXY =====

func (h *Handler) ProxyONT(c *gin.Context) {
	target := c.Query("target")
	path := c.Query("path")
	if target == "" {
		c.JSON(400, gin.H{"success": false, "message": "Target required"})
		return
	}
	if path == "" || path == "null" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	ontURL := "http://" + target + path

	sess := getOrCreateSession(target)
	client := &http.Client{
		Timeout: 20 * time.Second,
		Jar:     sess.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			req.Host = target
			return nil
		},
	}

	method := c.Request.Method
	var bodyReader io.Reader
	if method == "POST" {
		body, _ := io.ReadAll(c.Request.Body)
		bodyReader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, ontURL, bodyReader)
	if err != nil {
		c.JSON(502, gin.H{"success": false, "message": err.Error()})
		return
	}

	req.Host = target
	req.Header = make(http.Header)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "id-ID,id;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")
	req.Header.Set("Cache-Control", "no-cache")
	if method == "POST" {
		ct := c.GetHeader("Content-Type")
		if ct == "" {
			ct = "application/x-www-form-urlencoded"
		}
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Referer", "http://"+target+"/")
		req.Header.Set("Origin", "http://"+target)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(502, gin.H{"success": false, "message": "Cannot reach ONT: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = guessContentType(path)
	}

	bodyStr := string(respBody)
	if strings.Contains(contentType, "text/html") {
		bodyStr = rewriteONTHTML(bodyStr, target)
	} else if strings.Contains(contentType, "text/css") {
		bodyStr = rewriteONTCSS(bodyStr, target)
	}

	c.Data(resp.StatusCode, contentType, []byte(bodyStr))
}

func (h *Handler) ProxyONTTest(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		respond(c, 400, false, "Target required", nil)
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + target)
	if err != nil {
		respond(c, 200, false, "ONT tidak dapat dijangkau: "+err.Error(), gin.H{"reachable": false})
		return
	}
	defer resp.Body.Close()
	respond(c, 200, true, "ONT dapat dijangkau", gin.H{"reachable": true, "status_code": resp.StatusCode})
}

func (h *Handler) BrowserOpenONT(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		respond(c, 400, false, "Target required", nil)
		return
	}
	ontURL := "http://" + target + "/"
	respond(c, 200, true, "OK", gin.H{
		"novnc_url": "/novnc/vnc.html?autoconnect=true&reconnect=true&resize=scale&path=websockify",
		"ont_url":   ontURL,
	})
}

// ===== HELPERS =====

func guessContentType(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".css"):
		return "text/css"
	case strings.HasSuffix(lower, ".js"):
		return "application/javascript"
	case strings.HasSuffix(lower, ".png"):
		return "image/png"
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(lower, ".gif"):
		return "image/gif"
	case strings.HasSuffix(lower, ".ico"):
		return "image/x-icon"
	default:
		return "text/html; charset=utf-8"
	}
}

func proxyBase(target string) string {
	return "/api/v1/ont/smart?target=" + target + "&path="
}

func rewriteONTHTML(html, target string) string {
	base := proxyBase(target)
	pairs := [][2]string{
		{`src="/`, `src="` + base + `/`},
		{`href="/`, `href="` + base + `/`},
		{`action="/`, `action="` + base + `/`},
		{"src='/", "src='" + base + `/`},
		{"href='/", "href='" + base + `/`},
		{"action='/", "action='" + base + `/`},
		{"url(/", "url(" + base + `/`},
	}
	for _, p := range pairs {
		html = strings.ReplaceAll(html, p[0], p[1])
	}
	inject := `<base href="http://` + target + `/">
<script>
(function(){
var B="` + base + `";
document.addEventListener("click",function(e){
 var a=e.target;while(a&&a.tagName!="A")a=a.parentElement;
 if(!a||!a.href||a.href.indexOf("javascript")>=0)return;
 e.preventDefault();
 var p="/";try{var u=new URL(a.href);p=u.pathname+u.search;}catch(x){p=a.getAttribute("href")||"/";}
 parent.postMessage({type:"ONT_NAV",path:p},"*");
},true);
document.addEventListener("submit",function(e){
 var f=e.target;e.preventDefault();
 var act=f.getAttribute("action")||"/";
 var m=(f.method||"get").toUpperCase();
 var fd=new URLSearchParams(new FormData(f)).toString();
 if(m=="GET")parent.postMessage({type:"ONT_NAV",path:act+(fd?"?"+fd:"")},"*");
 else parent.postMessage({type:"ONT_FORM",action:act,body:fd},"*");
},true);
})();
</script>`

	lower := strings.ToLower(html)
	if i := strings.Index(lower, "<head>"); i >= 0 {
		idx := i + 6
		html = html[:idx] + inject + html[idx:]
	} else if i := strings.Index(lower, "<html"); i >= 0 {
		idx := strings.Index(html[i:], ">") + i + 1
		html = html[:idx] + inject + html[idx:]
	} else {
		html = inject + html
	}
	return html
}

func rewriteONTCSS(css, target string) string {
	base := proxyBase(target)
	css = strings.ReplaceAll(css, "url(/", "url("+base+"/")
	css = strings.ReplaceAll(css, "url('/", "url('"+base+"/")
	css = strings.ReplaceAll(css, `url("/`, `url("`+base+"/")
	return css
}

func formatBps(bps int64) string {
	if bps < 1000 {
		return fmt.Sprintf("%d bps", bps)
	} else if bps < 1000000 {
		return fmt.Sprintf("%.1f Kbps", float64(bps)/1000)
	} else if bps < 1000000000 {
		return fmt.Sprintf("%.2f Mbps", float64(bps)/1000000)
	}
	return fmt.Sprintf("%.2f Gbps", float64(bps)/1000000000)
}
