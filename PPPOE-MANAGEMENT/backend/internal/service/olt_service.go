package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"mikrotik-ppp-management/internal/model"
	"mikrotik-ppp-management/internal/models"
	"mikrotik-ppp-management/internal/repository"
	oltsnmp "mikrotik-ppp-management/internal/snmp"

	"github.com/sirupsen/logrus"
)

type OLTService struct {
	repo            *repository.OLTRepository
	troubleshootRepo *repository.TroubleshootRepository
	snmp            *oltsnmp.Service
	logger          *logrus.Entry
	pollInterval    time.Duration
	stateMu         sync.RWMutex
	syncState       map[uint]model.OLTSyncStatus
	lockMu          sync.Mutex
	oltLocks        map[uint]*sync.Mutex
}

func NewOLTService(repo *repository.OLTRepository, troubleshootRepo *repository.TroubleshootRepository, snmpSvc *oltsnmp.Service, logger *logrus.Logger, pollInterval time.Duration) *OLTService {
	if pollInterval <= 0 {
		pollInterval = 60 * time.Second
	}
	svc := &OLTService{
		repo:             repo,
		troubleshootRepo: troubleshootRepo,
		snmp:             snmpSvc,
		logger:           logger.WithField("module", "olt"),
		pollInterval:     pollInterval,
		syncState:        make(map[uint]model.OLTSyncStatus),
		oltLocks:         make(map[uint]*sync.Mutex),
	}
	snmpSvc.SetTroubleshootLogger(svc.writeTroubleshootLog)
	return svc
}

func (s *OLTService) CreateOLT(olt *model.OLT) error {
	normalizeOLT(olt)
	if err := validateOLT(*olt); err != nil {
		return err
	}
	return s.repo.Create(olt)
}

func (s *OLTService) ListOLTs() ([]model.OLT, error) {
	return s.repo.List()
}

func (s *OLTService) GetOLT(id uint) (*model.OLT, error) {
	return s.repo.GetByID(id)
}

func (s *OLTService) UpdateOLT(id uint, olt *model.OLT) error {
	normalizeOLT(olt)
	if err := validateOLT(*olt); err != nil {
		return err
	}
	if strings.TrimSpace(olt.TelnetPassword) == "" {
		if current, err := s.repo.GetByID(id); err == nil {
			olt.TelnetPassword = current.TelnetPassword
		}
	}
	olt.ID = id
	return s.repo.Update(olt)
}

func (s *OLTService) DeleteOLT(id uint) error {
	return s.repo.Delete(id)
}

func (s *OLTService) TestConnection(req model.OLTTestConnectionRequest) model.OLTTestConnectionResult {
	olt := model.OLT{
		IPAddress:      strings.TrimSpace(req.IPAddress),
		SNMPRO:         strings.TrimSpace(req.SNMPRO),
		SNMPPort:       req.SNMPPort,
		TelnetHost:     strings.TrimSpace(req.TelnetHost),
		TelnetPort:     req.TelnetPort,
		TelnetUsername: strings.TrimSpace(req.TelnetUsername),
		TelnetPassword: req.TelnetPassword,
	}
	normalizeOLT(&olt)
	result := model.OLTTestConnectionResult{}
	if err := s.snmp.TestConnection(olt); err != nil {
		result.Error = "SNMP: " + err.Error()
	} else {
		result.SNMP = true
	}
	telnetHost := olt.TelnetHost
	if telnetHost == "" {
		telnetHost = olt.IPAddress
	}
	if err := oltsnmp.TestTelnet(telnetHost, olt.TelnetPort, 4*time.Second); err != nil {
		if result.Error != "" {
			result.Error += "; "
		}
		result.Error += "Telnet: " + err.Error()
	} else {
		result.Telnet = true
	}
	return result
}

func (s *OLTService) SyncONUs(oltID uint) ([]model.ONUDevice, error) {
	lock := s.syncLock(oltID)
	lock.Lock()
	defer lock.Unlock()

	olt, err := s.repo.GetByID(oltID)
	if err != nil {
		return nil, err
	}
	existing, _ := s.repo.ListONUs(olt.ID)
	onus, err := s.snmp.GetAllONUSNMP(*olt)
	if err != nil {
		s.writeTroubleshootLog("error", "olt_sync", "Gagal mengambil data ONU via SNMP", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        err.Error(),
		})
		return nil, err
	}
	if len(existing) > 0 {
		onus = mergePersistentONUConfig(existing, onus)
	}
	if needsONUConfigRefresh(onus) {
		onus = s.snmp.EnrichONUConfig(*olt, onus)
	}
	s.logIncompleteONUs(*olt, onus)
	if err := s.repo.UpsertONUs(olt.ID, onus); err != nil {
		s.writeTroubleshootLog("error", "olt_sync", "Gagal menyimpan hasil sinkron ONU ke database", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        err.Error(),
		})
		return nil, err
	}
	s.writeTroubleshootLog("info", "olt_sync", fmt.Sprintf("Sinkron ONU selesai: %d data", len(onus)), map[string]interface{}{
		"olt_id":         int(olt.ID),
		"olt_name":       olt.Name,
		"olt_ip_address": olt.IPAddress,
		"details":        fmt.Sprintf("PPPoE/VLAN/password/lastonline/lastoffline divalidasi untuk %d ONU", len(onus)),
	})
	return s.repo.ListONUs(olt.ID)
}

func (s *OLTService) StartONUSync(oltID uint) (model.OLTSyncStatus, error) {
	if _, err := s.repo.GetByID(oltID); err != nil {
		return model.OLTSyncStatus{}, err
	}

	now := time.Now()
	s.stateMu.Lock()
	current := s.syncState[oltID]
	if current.Running {
		s.stateMu.Unlock()
		return current, nil
	}
	current = model.OLTSyncStatus{
		OLTID:         oltID,
		Running:       true,
		LastStartedAt: &now,
		LastCount:     current.LastCount,
		Message:       "Polling SNMP sedang berjalan di background",
	}
	s.syncState[oltID] = current
	s.stateMu.Unlock()

	go func() {
		onus, err := s.SyncONUs(oltID)
		finished := time.Now()
		status := model.OLTSyncStatus{
			OLTID:          oltID,
			Running:        false,
			LastStartedAt:  current.LastStartedAt,
			LastFinishedAt: &finished,
			LastCount:      len(onus),
		}
		if err != nil {
			status.LastError = err.Error()
			status.Message = "Sync SNMP gagal: " + err.Error()
			s.logger.WithError(err).WithField("olt_id", oltID).Warn("async ONU sync failed")
		} else {
			status.Message = fmt.Sprintf("Sync SNMP selesai: %d ONU", len(onus))
		}
		s.stateMu.Lock()
		s.syncState[oltID] = status
		s.stateMu.Unlock()
	}()

	return current, nil
}

func (s *OLTService) GetONUSyncStatus(oltID uint) model.OLTSyncStatus {
	s.stateMu.RLock()
	status, ok := s.syncState[oltID]
	s.stateMu.RUnlock()
	if ok {
		return status
	}
	cached, err := s.repo.ListONUs(oltID)
	if err != nil {
		return model.OLTSyncStatus{OLTID: oltID, Message: "Belum ada status sync"}
	}
	return model.OLTSyncStatus{
		OLTID:     oltID,
		LastCount: len(cached),
		Message:   "Idle",
	}
}

func (s *OLTService) ListONUs(oltID uint, refresh bool) ([]model.ONUDevice, error) {
	if refresh {
		if onus, err := s.SyncONUs(oltID); err == nil {
			return onus, nil
		} else {
			s.logger.WithError(err).WithField("olt_id", oltID).Warn("SNMP refresh failed, returning cached ONU data")
			cached, cacheErr := s.repo.ListONUs(oltID)
			if cacheErr != nil {
				return nil, cacheErr
			}
			if len(cached) > 0 {
				return cached, nil
			}
			return nil, err
		}
	}
	return s.repo.ListONUs(oltID)
}

func (s *OLTService) GetONUDetail(sn string) (*model.ONUDevice, error) {
	sn = strings.ToUpper(strings.TrimSpace(sn))
	if sn == "" {
		return nil, fmt.Errorf("serial number required")
	}
	onu, err := s.repo.GetONUBySerial(sn)
	if err == nil {
		return onu, nil
	}
	if cached, cacheErr := s.snmp.GetONUDetail(sn); cacheErr == nil {
		return &cached, nil
	}
	return nil, err
}

func (s *OLTService) GetRawTelnetDump(oltID uint, mode string) (*model.OLTTelnetDump, error) {
	olt, err := s.repo.GetByID(oltID)
	if err != nil {
		return nil, err
	}
	dump, err := s.snmp.CaptureRawTelnetDump(*olt, mode)
	if err != nil {
		s.writeTroubleshootLog("error", "olt_raw_telnet", "Gagal mengambil raw Telnet OLT", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        err.Error(),
		})
		return nil, err
	}
	s.writeTroubleshootLog("info", "olt_raw_telnet", "Raw Telnet OLT berhasil diambil", map[string]interface{}{
		"olt_id":         int(olt.ID),
		"olt_name":       olt.Name,
		"olt_ip_address": olt.IPAddress,
		"details":        fmt.Sprintf("%d section command berhasil diambil untuk troubleshoot (mode=%s)", len(dump.Sections), firstFilledString(mode, "quick")),
	})
	return dump, nil
}

func (s *OLTService) RunTelnetCommand(oltID uint, preset, target string) (*model.OLTTelnetDump, error) {
	olt, err := s.repo.GetByID(oltID)
	if err != nil {
		return nil, err
	}
	dump, err := s.snmp.CaptureRawTelnetCommand(*olt, preset, target)
	if err != nil {
		s.writeTroubleshootLog("error", "olt_raw_telnet", "Gagal menjalankan command Telnet OLT", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"preset":         preset,
			"target":         target,
			"details":        err.Error(),
		})
		return nil, err
	}
	s.writeTroubleshootLog("info", "olt_raw_telnet", "Command Telnet OLT berhasil dijalankan", map[string]interface{}{
		"olt_id":         int(olt.ID),
		"olt_name":       olt.Name,
		"olt_ip_address": olt.IPAddress,
		"preset":         preset,
		"target":         target,
		"details":        fmt.Sprintf("%d section command berhasil diambil untuk preset %s", len(dump.Sections), preset),
	})
	return dump, nil
}

func (s *OLTService) StartWorker(ctx context.Context) {
	ticker := time.NewTicker(s.pollInterval)
	go func() {
		defer ticker.Stop()
		s.pollAll()
		for {
			select {
			case <-ctx.Done():
				s.logger.Info("OLT polling worker stopped")
				return
			case <-ticker.C:
				s.pollAll()
			}
		}
	}()
}

func (s *OLTService) pollAll() {
	olts, err := s.repo.List()
	if err != nil {
		s.logger.WithError(err).Warn("failed to list OLTs for polling")
		return
	}
	for _, olt := range olts {
		if _, err := s.SyncONUs(olt.ID); err != nil {
			s.logger.WithError(err).WithField("olt_id", olt.ID).Warn("failed to poll OLT")
		}
	}
}

func (s *OLTService) logIncompleteONUs(olt model.OLT, onus []model.ONUDevice) {
	logged := 0
	missingCount := 0
	for _, onu := range onus {
		missing := make([]string, 0, 5)
		if strings.TrimSpace(onu.PPPoEUsername) == "" {
			missing = append(missing, "pppoe_username")
		}
		if strings.TrimSpace(onu.PPPoEPassword) == "" {
			missing = append(missing, "pppoe_password")
		}
		if strings.TrimSpace(onu.VLAN) == "" {
			missing = append(missing, "vlan")
		}
		if onu.LastOnline == nil {
			missing = append(missing, "last_online")
		}
		if onu.LastOffline == nil {
			missing = append(missing, "last_offline")
		}
		if len(missing) == 0 {
			continue
		}
		missingCount++
		if logged >= 20 {
			continue
		}
		logged++
		s.writeTroubleshootLog("warn", "olt_data_quality", "ONU masih memiliki field yang belum lengkap setelah sync", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"onu_interface":  firstFilledString(onu.ONUInterface, onu.BoardPort),
			"serial_number":  onu.SerialNumber,
			"details":        "missing fields: " + strings.Join(missing, ", "),
		})
	}
	if missingCount > 20 {
		s.writeTroubleshootLog("warn", "olt_data_quality", "Masih ada banyak field ONU yang kosong setelah sync", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        fmt.Sprintf("%d ONU memiliki field yang belum lengkap. Hanya 20 entri pertama yang ditulis detail.", missingCount),
		})
	}
}

func (s *OLTService) writeTroubleshootLog(level, source, message string, fields map[string]interface{}) {
	if s.troubleshootRepo == nil {
		return
	}
	item := &models.TroubleshootLog{
		Level:   strings.ToLower(strings.TrimSpace(level)),
		Source:  strings.TrimSpace(source),
		Scope:   "olt",
		Message: strings.TrimSpace(message),
	}
	if fields != nil {
		if value, ok := fields["details"].(string); ok {
			item.Details = redactTroubleshootText(value)
		}
		if value, ok := fields["olt_name"].(string); ok {
			item.OLTName = strings.TrimSpace(value)
		}
		if value, ok := fields["olt_ip_address"].(string); ok {
			item.OLTIPAddress = strings.TrimSpace(value)
		}
		if value, ok := fields["onu_interface"].(string); ok {
			item.ONUInterface = strings.TrimSpace(value)
		}
		if value, ok := fields["serial_number"].(string); ok {
			item.SerialNumber = strings.TrimSpace(value)
		}
		switch value := fields["olt_id"].(type) {
		case int:
			item.OLTID = &value
		case uint:
			tmp := int(value)
			item.OLTID = &tmp
		case uint64:
			tmp := int(value)
			item.OLTID = &tmp
		}
	}
	if item.Details == "" {
		item.Details = item.Message
	}
	if err := s.troubleshootRepo.InsertLog(item); err != nil {
		s.logger.WithError(err).Warn("failed to persist troubleshoot log")
	}
}

func redactTroubleshootText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"\r", "\n",
		"\x00", "",
	)
	value = replacer.Replace(value)
	value = strings.ReplaceAll(value, "\n\n\n", "\n\n")
	value = regexp.MustCompile(`(?i)(password\s+)(\S+)`).ReplaceAllString(value, `${1}[redacted]`)
	value = regexp.MustCompile(`(?i)(password:\s*)(\S+)`).ReplaceAllString(value, `${1}[redacted]`)
	if len(value) > 4000 {
		value = value[:4000] + "\n...[truncated]"
	}
	return value
}

func firstFilledString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *OLTService) syncLock(oltID uint) *sync.Mutex {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	if s.oltLocks[oltID] == nil {
		s.oltLocks[oltID] = &sync.Mutex{}
	}
	return s.oltLocks[oltID]
}

func normalizeOLT(olt *model.OLT) {
	olt.Name = strings.TrimSpace(olt.Name)
	olt.IPAddress = strings.TrimSpace(olt.IPAddress)
	olt.SNMPRO = strings.TrimSpace(olt.SNMPRO)
	olt.SNMPRW = strings.TrimSpace(olt.SNMPRW)
	olt.TelnetHost = strings.TrimSpace(olt.TelnetHost)
	olt.TelnetUsername = strings.TrimSpace(olt.TelnetUsername)
	if olt.SNMPPort <= 0 {
		olt.SNMPPort = 161
	}
	if olt.TelnetPort <= 0 {
		olt.TelnetPort = 23
	}
	if olt.TelnetHost == "" {
		olt.TelnetHost = olt.IPAddress
	}
}

func validateOLT(olt model.OLT) error {
	if olt.Name == "" {
		return fmt.Errorf("name required")
	}
	if olt.IPAddress == "" {
		return fmt.Errorf("ip_address required")
	}
	if olt.SNMPRO == "" {
		return fmt.Errorf("snmp_ro required")
	}
	return nil
}

func mergePersistentONUConfig(existing []model.ONUDevice, incoming []model.ONUDevice) []model.ONUDevice {
	bySerial := make(map[string]model.ONUDevice, len(existing))
	byInterface := make(map[string]model.ONUDevice, len(existing))
	byBoardPort := make(map[string]model.ONUDevice, len(existing))
	for _, onu := range existing {
		if key := strings.ToUpper(strings.TrimSpace(onu.SerialNumber)); key != "" {
			bySerial[key] = onu
		}
		if key := strings.ToLower(strings.TrimSpace(onu.ONUInterface)); key != "" {
			byInterface[key] = onu
		}
		if key := strings.ToLower(strings.TrimSpace(onu.BoardPort)); key != "" {
			byBoardPort[key] = onu
		}
	}
	for i := range incoming {
		var prev model.ONUDevice
		var ok bool
		if key := strings.ToUpper(strings.TrimSpace(incoming[i].SerialNumber)); key != "" {
			prev, ok = bySerial[key]
		}
		if !ok {
			if key := strings.ToLower(strings.TrimSpace(incoming[i].ONUInterface)); key != "" {
				prev, ok = byInterface[key]
			}
		}
		if !ok {
			if key := strings.ToLower(strings.TrimSpace(incoming[i].BoardPort)); key != "" {
				prev, ok = byBoardPort[key]
			}
		}
		if !ok {
			continue
		}
		if strings.TrimSpace(incoming[i].PPPoEUsername) == "" {
			incoming[i].PPPoEUsername = prev.PPPoEUsername
		}
		if strings.TrimSpace(incoming[i].PPPoEPassword) == "" {
			incoming[i].PPPoEPassword = prev.PPPoEPassword
		}
		if strings.TrimSpace(incoming[i].VLAN) == "" {
			incoming[i].VLAN = prev.VLAN
		}
		if strings.TrimSpace(incoming[i].ONUInterface) == "" {
			incoming[i].ONUInterface = prev.ONUInterface
		}
		if strings.TrimSpace(incoming[i].ONUType) == "" {
			incoming[i].ONUType = prev.ONUType
		}
		if strings.TrimSpace(incoming[i].Description) == "" {
			incoming[i].Description = prev.Description
		}
		if incoming[i].LastOnline == nil && prev.LastOnline != nil {
			lastOnline := *prev.LastOnline
			incoming[i].LastOnline = &lastOnline
		}
		if incoming[i].LastOffline == nil && prev.LastOffline != nil {
			lastOffline := *prev.LastOffline
			incoming[i].LastOffline = &lastOffline
		}
		if strings.TrimSpace(incoming[i].OfflineReason) == "" {
			incoming[i].OfflineReason = prev.OfflineReason
		}
	}
	return incoming
}

func needsONUConfigRefresh(onus []model.ONUDevice) bool {
	for _, onu := range onus {
		if strings.TrimSpace(onu.PPPoEUsername) == "" ||
			strings.TrimSpace(onu.PPPoEPassword) == "" ||
			strings.TrimSpace(onu.VLAN) == "" {
			return true
		}
	}
	return false
}
