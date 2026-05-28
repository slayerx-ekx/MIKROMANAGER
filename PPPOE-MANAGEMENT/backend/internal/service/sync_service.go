package service

import (
	"fmt"
	"log"
	"mikrotik-ppp-management/internal/mikrotik"
	"mikrotik-ppp-management/internal/models"
	"mikrotik-ppp-management/internal/repository"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

type SyncService struct {
	routerRepo       *repository.RouterRepository
	pppRepo          *repository.PPPRepository
	syncRepo         *repository.SyncRepository
	troubleshootRepo *repository.TroubleshootRepository
	trafficRepo      *repository.TrafficRepository
	cron             *cron.Cron
	cronEntry        cron.EntryID
	mu               sync.Mutex
	isSyncing        bool
}

func NewSyncService(
	routerRepo *repository.RouterRepository,
	pppRepo *repository.PPPRepository,
	syncRepo *repository.SyncRepository,
	trafficRepo *repository.TrafficRepository,
) *SyncService {
	return &SyncService{
		routerRepo:  routerRepo,
		pppRepo:     pppRepo,
		syncRepo:    syncRepo,
		trafficRepo: trafficRepo,
		cron:        cron.New(),
	}
}

func (s *SyncService) SetTroubleshootRepository(repo *repository.TroubleshootRepository) {
	s.troubleshootRepo = repo
}

func (s *SyncService) Start() {
	settings, err := s.syncRepo.GetSettings()
	if err != nil {
		log.Printf("Failed to get sync settings: %v", err)
		return
	}
	if settings.AutoSyncEnabled {
		s.scheduleCron(settings.SyncIntervalSeconds)
	}
	s.cron.Start()
	log.Printf("Sync service started. Auto: %v, Interval: %ds", settings.AutoSyncEnabled, settings.SyncIntervalSeconds)
}

func (s *SyncService) scheduleCron(intervalSeconds int) {
	if s.cronEntry != 0 {
		s.cron.Remove(s.cronEntry)
	}
	entry, err := s.cron.AddFunc(fmt.Sprintf("@every %ds", intervalSeconds), func() {
		s.SyncAllRouters()
	})
	if err != nil {
		log.Printf("Failed to schedule cron: %v", err)
		return
	}
	s.cronEntry = entry
}

func (s *SyncService) UpdateSchedule(enabled bool, intervalSeconds int) error {
	if err := s.syncRepo.UpdateSettings(&models.SyncSettings{
		AutoSyncEnabled:     enabled,
		SyncIntervalSeconds: intervalSeconds,
	}); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cronEntry != 0 {
		s.cron.Remove(s.cronEntry)
		s.cronEntry = 0
	}
	if enabled {
		s.scheduleCron(intervalSeconds)
	}
	return nil
}

func (s *SyncService) SyncAllRouters() {
	s.mu.Lock()
	if s.isSyncing {
		s.mu.Unlock()
		return
	}
	s.isSyncing = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.isSyncing = false
		s.mu.Unlock()
	}()

	routers, err := s.routerRepo.GetAll()
	if err != nil {
		return
	}
	for _, router := range routers {
		if router.IsActive {
			s.SyncRouter(&router)
		}
	}
	s.syncRepo.UpdateLastSync()
	s.trafficRepo.CleanOld()
}

func (s *SyncService) SyncRouter(router *models.Router) error {
	start := time.Now()
	client := mikrotik.NewClient(router.IPAddress, router.APIPort, router.Username, router.Password)

	// Get active PPP
	activeConns, err := client.GetActivePPP()
	if err != nil {
		dur := int(time.Since(start).Milliseconds())
		s.syncRepo.InsertLog(&models.SyncLog{
			RouterID: &router.ID, RouterName: router.Name,
			Status: "failed", Message: fmt.Sprintf("GetActivePPP failed: %v", err), DurationMs: dur,
		})
		s.writeTroubleshootLog("error", "sync", router, "GetActivePPP failed", err.Error())
		return err
	}

	// Build active map
	activeMap := make(map[string]*mikrotik.PPPActiveEntry)
	for i := range activeConns {
		activeMap[activeConns[i].Name] = &activeConns[i]
	}

	// Get all PPP secrets
	secrets, err := client.GetPPPSecrets()
	if err != nil {
		log.Printf("Warning: GetPPPSecrets failed for %s: %v", router.Name, err)
		s.writeTroubleshootLog("warn", "sync", router, "GetPPPSecrets failed", err.Error())
		secrets = []mikrotik.PPPSecretEntry{}
	}

	// Get PPP interface details (for interface name + last link up/down)
	interfaces, err := client.GetPPPInterfaces()
	if err != nil {
		log.Printf("Warning: GetPPPInterfaces failed for %s: %v", router.Name, err)
		s.writeTroubleshootLog("warn", "sync", router, "GetPPPInterfaces failed", err.Error())
		interfaces = []map[string]string{}
	}
	pppoeIfaces, err := client.GetPPPoEInterfaces()
	if err != nil {
		log.Printf("Warning: GetPPPoEInterfaces failed for %s: %v", router.Name, err)
		s.writeTroubleshootLog("warn", "sync", router, "GetPPPoEInterfaces failed", err.Error())
		pppoeIfaces = []map[string]string{}
	}
	rawIfaces, err := client.GetInterfaces()
	if err != nil {
		log.Printf("Warning: GetInterfaces failed for %s: %v", router.Name, err)
		s.writeTroubleshootLog("warn", "sync", router, "GetInterfaces failed", err.Error())
		rawIfaces = []map[string]string{}
	}
	ifaceByUser := make(map[string]map[string]string)
	for _, inf := range interfaces {
		username := firstFilled(inf["user"], inf["name"], inf["default-name"])
		if username == "" {
			continue
		}
		ifaceByUser[username] = inf
	}
	for _, inf := range rawIfaces {
		if !strings.EqualFold(inf["type"], "pppoe-in") {
			continue
		}
		username := firstFilled(inf["user"], inf["name"], inf["default-name"])
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

	secretByUser := make(map[string]mikrotik.PPPSecretEntry)
	for _, sec := range secrets {
		secretByUser[sec.Name] = sec
	}

	// Build db records — merge bindings with secret and active status
	var dbSecrets []models.PPPSecret
	seen := map[string]bool{}
	for _, binding := range pppoeIfaces {
		username := strings.TrimSpace(firstFilled(binding["user"], binding["name"], binding["default-name"]))
		if username == "" || seen[username] {
			continue
		}
		seen[username] = true

		sec := secretByUser[username]
		
		s := models.PPPSecret{
			RouterID:      router.ID,
			RouterName:    router.Name,
			RouterIP:      router.IPAddress,
			Username:      username,
			InterfaceName: firstFilled(
				binding["name"], binding["default-name"], binding["actual-interface"], binding["interface"], username,
			),
			Profile:       sec.Profile,
			Service:       firstFilled(sec.Service, binding["service"], "pppoe"),
			LocalAddress:  sec.LocalAddress,
			RemoteAddress: sec.RemoteAddress,
			LastLinkDown: firstFilled(
				ifaceByUser[username]["last-link-down-time"],
				ifaceByUser[username]["last-link-down"],
				ifaceByUser[username]["last-disconnected-time"],
				ifaceByUser[username]["last-logged-out"],
				ifaceByUser[username]["last-logout"],
				sec.LastLoggedOut,
			),
			LastLinkUp: firstFilled(
				ifaceByUser[username]["last-link-up-time"],
				ifaceByUser[username]["last-link-up"],
				ifaceByUser[username]["last-logged-in-time"],
				ifaceByUser[username]["last-logged-in"],
				ifaceByUser[username]["last-login"],
			),
			Status:        "offline",
			Disabled:      sec.Disabled,
		}
		if ac, ok := activeMap[username]; ok {
			s.Status = "online"
			s.Uptime = ac.Uptime
			s.IPAddress = ac.Address
			s.RemoteAddress = firstFilled(ac.Address, s.RemoteAddress)
			s.CallerID = ac.CallerID
			s.BytesIn = ac.BytesIn
			s.BytesOut = ac.BytesOut
			now := time.Now()
			s.LastSeen = &now
		} else if strings.EqualFold(strings.TrimSpace(binding["running"]), "true") {
			s.Status = "online"
		}
		dbSecrets = append(dbSecrets, s)
	}

	// If no secrets from router, at least sync active connections
	if len(secrets) == 0 && len(activeConns) > 0 {
		for _, ac := range activeConns {
			now := time.Now()
			dbSecrets = append(dbSecrets, models.PPPSecret{
				RouterID:  router.ID,
				Username:  ac.Name,
				InterfaceName: firstFilled(
					ifaceByUser[ac.Name]["interface"],
					ifaceByUser[ac.Name]["actual-interface"],
					ifaceByUser[ac.Name]["running-on"],
					ifaceByUser[ac.Name]["parent-interface"],
					ifaceByUser[ac.Name]["master-interface"],
				),
				IPAddress: ac.Address,
				Uptime:    ac.Uptime,
				Profile:   ac.Profile,
				Service:   ac.Service,
				RemoteAddress: firstFilled(ac.Address, ifaceByUser[ac.Name]["remote-address"]),
				LastLinkDown: firstFilled(
					ifaceByUser[ac.Name]["last-link-down-time"],
					ifaceByUser[ac.Name]["last-link-down"],
					ifaceByUser[ac.Name]["last-disconnected-time"],
					ifaceByUser[ac.Name]["last-logged-out"],
					ifaceByUser[ac.Name]["last-logout"],
				),
				LastLinkUp: firstFilled(
					ifaceByUser[ac.Name]["last-link-up-time"],
					ifaceByUser[ac.Name]["last-link-up"],
					ifaceByUser[ac.Name]["last-logged-in-time"],
					ifaceByUser[ac.Name]["last-logged-in"],
					ifaceByUser[ac.Name]["last-login"],
				),
				CallerID:  ac.CallerID,
				BytesIn:   ac.BytesIn,
				BytesOut:  ac.BytesOut,
				Status:    "online",
				LastSeen:  &now,
			})
		}
	}

	if err := s.pppRepo.UpsertSecrets(router.ID, dbSecrets); err != nil {
		log.Printf("UpsertSecrets failed for %s: %v", router.Name, err)
		s.writeTroubleshootLog("error", "sync", router, "UpsertSecrets failed", err.Error())
	}

	activeForLog := len(activeConns)
	totalForLog := len(dbSecrets)
	if totalPPPoE, activePPPoE := summarizePPPoEServerUsers(pppoeIfaces, activeConns); totalPPPoE > 0 {
		totalForLog = totalPPPoE
		activeForLog = activePPPoE
	}

	dur := int(time.Since(start).Milliseconds())
	s.syncRepo.InsertLog(&models.SyncLog{
		RouterID: &router.ID, RouterName: router.Name,
		Status:        "success",
		Message:       fmt.Sprintf("Synced %d active, %d total users", activeForLog, totalForLog),
		DurationMs:    dur,
		RecordsSynced: activeForLog,
	})
	log.Printf("Synced %s: %d active / %d total, %dms", router.Name, activeForLog, totalForLog, dur)
	return nil
}

func (s *SyncService) IsCurrentlySyncing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isSyncing
}

func (s *SyncService) writeTroubleshootLog(level, source string, router *models.Router, message, details string) {
	if s == nil || s.troubleshootRepo == nil || router == nil {
		return
	}
	routerID := router.ID
	if err := s.troubleshootRepo.InsertLog(&models.TroubleshootLog{
		Level:      level,
		Source:     source,
		Scope:      "router_sync",
		Message:    message,
		Details:    details,
		RouterID:   &routerID,
		RouterName: router.Name,
		RouterIP:   router.IPAddress,
	}); err != nil {
		log.Printf("Failed to write troubleshoot log for %s: %v", router.Name, err)
	}
}

func firstFilled(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func summarizePPPoEServerUsers(pppoeIfaces []map[string]string, activeConns []mikrotik.PPPActiveEntry) (int, int) {
	activeSet := make(map[string]struct{}, len(activeConns))
	for _, ac := range activeConns {
		name := strings.ToLower(strings.TrimSpace(ac.Name))
		if name != "" {
			activeSet[name] = struct{}{}
		}
	}

	userSet := make(map[string]struct{})
	activeCount := 0
	for _, row := range pppoeIfaces {
		user := strings.ToLower(strings.TrimSpace(row["user"]))
		if user == "" {
			continue
		}
		if _, exists := userSet[user]; exists {
			continue
		}
		userSet[user] = struct{}{}
		if _, online := activeSet[user]; online {
			activeCount++
		}
	}
	return len(userSet), activeCount
}
