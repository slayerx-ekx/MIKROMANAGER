package snmp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mikrotik-ppp-management/internal/model"

	"github.com/gosnmp/gosnmp"
)

const (
	StatusOnline    = "ONLINE"
	StatusOffline   = "OFFLINE"
	StatusLOS       = "LOS"
	StatusDyingGasp = "DYING_GASP"
)

type oidProfile struct {
	Label         string
	Name          []string
	Description   []string
	Serial        []string
	Status        []string
	RXPower       []string
	TXPower       []string
	LastOnline    []string
	LastOffline   []string
	OfflineReason []string
	LocationName  []string
}

type c320Profile struct {
	Key                 string
	Label               string
	BaseOID             string
	NamePrefix          string
	SerialPrefix        string
	DescriptionPrefix   string
	StatusPrefix        string
	OnuRxPrefix         string
	IPPrefix            string
	DistancePrefix      string
	LastOnlinePrefix    string
	LastOfflinePrefix   string
	OfflineReasonPrefix string
	Board1Base          int
	Board2Base          int
	Increment           int
}

type c320ONUSeed struct {
	board  int
	port   int
	onuID  int
	name   string
	suffix int
}

type c320PortSeed struct {
	ifIndex int
	board   int
	port    int
	label   string
}

type Service struct {
	timeout            time.Duration
	retries            int
	cacheMu            sync.RWMutex
	cache              map[string]model.ONUDevice
	troubleshootLogger func(level, source, message string, fields map[string]interface{})
}

const (
	c320LegacyBaseOID      = ".1.3.6.1.4.1.3902.1012"
	c320LegacyOnuRxPrefix  = ".3.50.12.1.1.10"
	c320V1082BaseOID       = ".1.3.6.1.4.1.3902.1082"
	c320V1082OnuRxPrefix   = ".500.20.2.2.2.1.10"
	c320OltRxBaseOID       = ".1.3.6.1.4.1.3902.1015"
	c320OltRxPrefix        = ".1010.11.2.1.2"
	c320Board1TypeBase     = 268500992
	c320Board2TypeBase     = 268566528
	c320BoardTypeStep      = 65536
	c320TypeSuffixStep     = 256
)

var (
	c320PortNameRe      = regexp.MustCompile(`(?i)gpon[^0-9]*(\d+)\/(\d+)\/(\d+)`)
	c320BoardPortNameRe = regexp.MustCompile(`(?i)gpon[_-]?\d+\/(\d+)\/(\d+):(\d+)`)
	c320Profiles        = []c320Profile{
		{
			Key:                 "v2.2",
			Label:               "ZTE C320 V2.2+ / 1082",
			BaseOID:             ".1.3.6.1.4.1.3902.1082",
			NamePrefix:          ".500.10.2.3.3.1.2",
			SerialPrefix:        ".500.10.2.3.3.1.18",
			DescriptionPrefix:   ".500.10.2.3.3.1.3",
			StatusPrefix:        ".500.10.2.3.8.1.4",
			OnuRxPrefix:         ".500.20.2.2.2.1.10",
			IPPrefix:            ".3.50.16.1.1.10",
			DistancePrefix:      ".500.10.2.3.10.1.2",
			LastOnlinePrefix:    ".500.10.2.3.8.1.5",
			LastOfflinePrefix:   ".500.10.2.3.8.1.6",
			OfflineReasonPrefix: ".500.10.2.3.8.1.7",
			Board1Base:          285278464,
			Board2Base:          285278720,
			Increment:           1,
		},
		{
			Key:                 "v2.1",
			Label:               "ZTE C320 V2.1 / 1012",
			BaseOID:             ".1.3.6.1.4.1.3902.1012",
			NamePrefix:          ".3.13.3.1.5",
			SerialPrefix:        ".3.13.3.1.2",
			DescriptionPrefix:   ".3.28.1.1.3",
			StatusPrefix:        ".3.28.2.1.4",
			OnuRxPrefix:         ".3.50.12.1.1.10",
			IPPrefix:            ".3.13.3.1.3",
			DistancePrefix:      ".3.13.1.1.20",
			LastOnlinePrefix:    ".3.28.2.1.5",
			LastOfflinePrefix:   ".3.28.2.1.6",
			OfflineReasonPrefix: ".3.28.2.1.7",
			Board1Base:          268500992,
			Board2Base:          268509184,
			Increment:           256,
		},
	}
)

func NewService() *Service {
	return &Service{
		timeout: 8 * time.Second,
		retries: 2,
		cache:   make(map[string]model.ONUDevice),
	}
}

func (s *Service) SetTroubleshootLogger(fn func(level, source, message string, fields map[string]interface{})) {
	s.troubleshootLogger = fn
}

func (s *Service) logTroubleshoot(level, source, message string, fields map[string]interface{}) {
	if s == nil || s.troubleshootLogger == nil {
		return
	}
	s.troubleshootLogger(level, source, message, fields)
}

func oidProfiles() []oidProfile {
	if customBase := strings.TrimSpace(os.Getenv("OLT_ZTE_BASE_OID")); customBase != "" {
		return []oidProfile{oidProfileForBase("custom", customBase)}
	}
	return []oidProfile{
		oidProfileForBase("zte-c3xx-checkmk-1082", ".1.3.6.1.4.1.3902.1082"),
		{
			Label:        "zte-c320-v2.1.0-gpon",
			LocationName: oidList("OLT_ZTE_ONU_LOCATION_OIDS", ".1.3.6.1.4.1.3902.1012.3.28.1.1.3"),
			Name:         oidList("OLT_ZTE_ONU_NAME_OIDS", ".1.3.6.1.4.1.3902.1012.3.13.3.1.5"),
			Description:  oidList("OLT_ZTE_ONU_DESCRIPTION_OIDS", ".1.3.6.1.4.1.3902.1012.3.28.1.1.3", ".1.3.6.1.4.1.3902.1012.3.13.3.1.11"),
			Serial:       oidList("OLT_ZTE_ONU_SERIAL_OIDS", ".1.3.6.1.4.1.3902.1012.3.13.3.1.2"),
			Status:       oidList("OLT_ZTE_ONU_STATUS_OIDS", ".1.3.6.1.4.1.3902.1012.3.28.2.1.4"),
			RXPower:      oidList("OLT_ZTE_ONU_RX_POWER_OIDS", ".1.3.6.1.4.1.3902.1012.3.50.12.1.1.10", ".1.3.6.1.4.1.3902.1082.500.20.2.2.2.1.10"),
			TXPower:      oidList("OLT_ZTE_OLT_RX_POWER_OIDS", ".1.3.6.1.4.1.3902.1015.1010.11.2.1.2"),
			LastOnline:   oidList("OLT_ZTE_ONU_LAST_ONLINE_OIDS", ".1.3.6.1.4.1.3902.1012.3.28.2.1.5"),
			LastOffline:  oidList("OLT_ZTE_ONU_LAST_OFFLINE_OIDS", ".1.3.6.1.4.1.3902.1012.3.28.2.1.6"),
			OfflineReason: oidList("OLT_ZTE_ONU_OFFLINE_REASON_OIDS", ".1.3.6.1.4.1.3902.1012.3.28.2.1.7"),
		},
	}
}

func oidProfileForBase(label, base string) oidProfile {
	return oidProfile{
		Label:       label,
		Name:        oidList("OLT_ZTE_ONU_NAME_OIDS", base+".500.10.2.3.3.1.2"),
		Description: oidList("OLT_ZTE_ONU_DESCRIPTION_OIDS", base+".500.10.2.3.3.1.3"),
		Serial:      oidList("OLT_ZTE_ONU_SERIAL_OIDS", base+".500.10.2.3.3.1.18"),
		Status:      oidList("OLT_ZTE_ONU_STATUS_OIDS", base+".500.10.2.3.8.1.4"),
		RXPower:     oidList("OLT_ZTE_ONU_RX_POWER_OIDS", base+".500.20.2.2.2.1.10"),
		TXPower:     oidList("OLT_ZTE_OLT_RX_POWER_OIDS", ".1.3.6.1.4.1.3902.1015.1010.11.2.1.2"),
		LastOnline:  oidList("OLT_ZTE_ONU_LAST_ONLINE_OIDS", base+".500.10.2.3.8.1.5"),
		LastOffline: oidList("OLT_ZTE_ONU_LAST_OFFLINE_OIDS", base+".500.10.2.3.8.1.6"),
		OfflineReason: oidList("OLT_ZTE_ONU_OFFLINE_REASON_OIDS", base+".500.10.2.3.8.1.7"),
	}
}

func oidList(key string, fallback ...string) []string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if oid := strings.TrimSpace(part); oid != "" {
				result = append(result, oid)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	if strings.HasSuffix(key, "S") {
		if value := strings.TrimSpace(os.Getenv(strings.TrimSuffix(key, "S"))); value != "" {
			return []string{value}
		}
	}
	return fallback
}

func (s *Service) GetAllONU(olt model.OLT) ([]model.ONUDevice, error) {
	onus, err := s.GetAllONUSNMP(olt)
	if err != nil {
		return nil, err
	}
	return s.EnrichONUConfig(olt, onus), nil
}

func (s *Service) GetAllONUSNMP(olt model.OLT) ([]model.ONUDevice, error) {
	client := s.client(olt)
	if err := client.Connect(); err != nil {
		s.logTroubleshoot("error", "snmp_connect", "Koneksi SNMP ke OLT gagal", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        err.Error(),
		})
		return nil, fmt.Errorf("snmp connect failed: %w", err)
	}
	defer client.Conn.Close()

	var discoveryErr error
	if result, err := s.getAllONUByPortDiscovery(client); err == nil && len(result) > 0 {
		result = s.mergeSupplementalProfileData(client, result)
		result = s.finalizeONUs(result)
		s.cacheONUs(result)
		s.logTroubleshoot("info", "snmp_discovery", "Discovery ONU via SNMP port discovery berhasil", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        fmt.Sprintf("%d ONU ditemukan melalui SNMP port discovery", len(result)),
		})
		return result, nil
	} else if err != nil {
		discoveryErr = err
	}

	if result, err := s.getAllONUByDirectProfileWalk(client); err == nil && len(result) > 0 {
		result = s.mergeSupplementalProfileData(client, result)
		result = s.finalizeONUs(result)
		s.cacheONUs(result)
		s.logTroubleshoot("info", "snmp_discovery", "Discovery ONU via direct profile walk berhasil", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        fmt.Sprintf("%d ONU ditemukan melalui SNMP direct profile walk", len(result)),
		})
		return result, nil
	} else if err != nil && discoveryErr == nil {
		discoveryErr = err
	}

	var lastErr error
	for _, profile := range oidProfiles() {
		result, err := s.getAllONUWithProfile(client, profile)
		if err != nil {
			lastErr = fmt.Errorf("%s profile failed: %w", profile.Label, err)
			continue
		}
		if len(result) == 0 {
			lastErr = fmt.Errorf("%s profile returned no ONU rows", profile.Label)
			continue
		}
		result = s.mergeSupplementalProfileData(client, result)
		result = s.finalizeONUs(result)
		s.cacheONUs(result)
		s.logTroubleshoot("info", "snmp_profile", "Discovery ONU via fallback profile berhasil", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        fmt.Sprintf("%s menghasilkan %d ONU", profile.Label, len(result)),
		})
		return result, nil
	}

	if lastErr != nil {
		s.logTroubleshoot("error", "snmp_discovery", "Semua metode SNMP gagal mengambil data ONU", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        fmt.Sprintf("discoveryErr=%v; lastErr=%v", discoveryErr, lastErr),
		})
		if discoveryErr != nil {
			return nil, fmt.Errorf("C320 port discovery failed: %v; fallback OID walk failed: %w", discoveryErr, lastErr)
		}
		return nil, lastErr
	}
	if discoveryErr != nil {
		s.logTroubleshoot("error", "snmp_discovery", "SNMP discovery ONU gagal", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": olt.IPAddress,
			"details":        discoveryErr.Error(),
		})
		return nil, discoveryErr
	}
	return nil, fmt.Errorf("no onu data found via ZTE C320 SNMP OID profiles")
}

func (s *Service) EnrichONUConfig(olt model.OLT, onus []model.ONUDevice) []model.ONUDevice {
	onus = s.finalizeONUs(onus)
	onus = s.enrichONUsFromTelnet(olt, onus)
	s.cacheONUs(onus)
	return onus
}

func (s *Service) finalizeONUs(onus []model.ONUDevice) []model.ONUDevice {
	for i := range onus {
		if strings.TrimSpace(onus[i].ONUInterface) == "" {
			onus[i].ONUInterface = normalizeONUInterface(onus[i].BoardPort)
		}
		if strings.TrimSpace(onus[i].PhaseState) == "" {
			onus[i].PhaseState = strings.ToLower(strings.ReplaceAll(onus[i].Status, "_", "-"))
		}
	}
	return onus
}

func (s *Service) mergeSupplementalProfileData(client *gosnmp.GoSNMP, onus []model.ONUDevice) []model.ONUDevice {
	if len(onus) == 0 || client == nil {
		return onus
	}
	merged := onus
	for _, profile := range oidProfiles() {
		supplemental, err := s.getAllONUWithProfile(client, profile)
		if err != nil || len(supplemental) == 0 {
			continue
		}
		merged = mergeONUByIdentity(merged, supplemental)
	}
	return merged
}

func mergeONUByIdentity(base []model.ONUDevice, extra []model.ONUDevice) []model.ONUDevice {
	if len(base) == 0 || len(extra) == 0 {
		return base
	}
	bySerial := make(map[string]int, len(base))
	byInterface := make(map[string]int, len(base))
	byBoardPort := make(map[string]int, len(base))
	for i := range base {
		if key := strings.ToUpper(strings.TrimSpace(base[i].SerialNumber)); key != "" {
			bySerial[key] = i
		}
		if key := strings.ToLower(strings.TrimSpace(base[i].ONUInterface)); key != "" {
			byInterface[key] = i
		}
		if key := strings.ToLower(strings.TrimSpace(base[i].BoardPort)); key != "" {
			byBoardPort[key] = i
		}
	}
	for _, item := range extra {
		index, ok := -1, false
		if key := strings.ToUpper(strings.TrimSpace(item.SerialNumber)); key != "" {
			index, ok = bySerial[key]
		}
		if !ok {
			if key := strings.ToLower(strings.TrimSpace(item.ONUInterface)); key != "" {
				index, ok = byInterface[key]
			}
		}
		if !ok {
			if key := strings.ToLower(strings.TrimSpace(item.BoardPort)); key != "" {
				index, ok = byBoardPort[key]
			}
		}
		if !ok || index < 0 {
			continue
		}
		if base[index].LastOnline == nil && item.LastOnline != nil {
			base[index].LastOnline = item.LastOnline
		}
		if base[index].LastOffline == nil && item.LastOffline != nil {
			base[index].LastOffline = item.LastOffline
		}
		if strings.TrimSpace(base[index].OfflineReason) == "" && strings.TrimSpace(item.OfflineReason) != "" {
			base[index].OfflineReason = item.OfflineReason
		}
		if strings.TrimSpace(base[index].Description) == "" && strings.TrimSpace(item.Description) != "" {
			base[index].Description = item.Description
		}
		if strings.TrimSpace(base[index].Name) == "" && strings.TrimSpace(item.Name) != "" {
			base[index].Name = item.Name
		}
	}
	return base
}

func (s *Service) cacheONUs(onus []model.ONUDevice) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for _, onu := range onus {
		s.cache[strings.ToUpper(onu.SerialNumber)] = onu
	}
}

func (s *Service) getAllONUByPortDiscovery(client *gosnmp.GoSNMP) ([]model.ONUDevice, error) {
	ports, err := s.discoverC320GPONPorts(client)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("GPON ports not found via ifName/ifDescr")
	}

	var lastErr error
	for _, profile := range c320Profiles {
		result := make([]model.ONUDevice, 0, 256)
		for _, port := range ports {
			rows, err := s.fetchC320PortONUs(client, profile, port)
			if err != nil {
				lastErr = err
				continue
			}
			result = append(result, rows...)
		}
		if len(result) > 0 {
			sort.Slice(result, func(i, j int) bool {
				if result[i].BoardPort != result[j].BoardPort {
					return result[i].BoardPort < result[j].BoardPort
				}
				return result[i].SerialNumber < result[j].SerialNumber
			})
			return result, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("ONU rows not found from %d discovered GPON ports", len(ports))
}

func (s *Service) getAllONUByDirectProfileWalk(client *gosnmp.GoSNMP) ([]model.ONUDevice, error) {
	var lastErr error
	for _, profile := range c320Profiles {
		seedsByPort := map[int][]c320ONUSeed{}
		root := profile.BaseOID + profile.NamePrefix
		err := s.walkWithFallback(client, root, func(pdu gosnmp.SnmpPDU) error {
			ifIndex, onuID := c320LastTwoOIDInts(pdu.Name)
			if ifIndex <= 0 || onuID <= 0 {
				return nil
			}
			name := cleanText(pduToString(pdu.Value))
			if name == "" || name == "0" {
				return nil
			}
			seed, ok := c320SeedFromIfIndex(ifIndex, onuID, name)
			if !ok {
				return nil
			}
			seedsByPort[ifIndex] = append(seedsByPort[ifIndex], seed)
			return nil
		})
		if err != nil {
			lastErr = err
			continue
		}
		if len(seedsByPort) == 0 {
			lastErr = fmt.Errorf("%s direct ONU name walk returned no rows from %s", profile.Label, root)
			continue
		}

		result := make([]model.ONUDevice, 0, 256)
		for ifIndex, seeds := range seedsByPort {
			if len(seeds) == 0 {
				continue
			}
			rows, err := s.fetchC320ONUsFromSeeds(client, profile, seeds)
			if err != nil {
				lastErr = fmt.Errorf("ifIndex %d: %w", ifIndex, err)
				continue
			}
			result = append(result, rows...)
		}
		if len(result) > 0 {
			sort.Slice(result, func(i, j int) bool {
				if result[i].BoardPort != result[j].BoardPort {
					return result[i].BoardPort < result[j].BoardPort
				}
				return result[i].SerialNumber < result[j].SerialNumber
			})
			return result, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("direct C320 ONU name walk returned no rows")
}

func (s *Service) discoverC320GPONPorts(client *gosnmp.GoSNMP) ([]c320PortSeed, error) {
	roots := []string{".1.3.6.1.2.1.31.1.1.1.1", ".1.3.6.1.2.1.2.2.1.2"}
	seen := map[int]bool{}
	items := make([]c320PortSeed, 0, 32)
	var lastErr error

	for _, root := range roots {
		err := s.walkWithFallback(client, root, func(pdu gosnmp.SnmpPDU) error {
			ifIndex := oidLastInt(pdu.Name)
			if ifIndex <= 0 || seen[ifIndex] {
				return nil
			}
			seed, ok := parseC320PortSeed(pduToString(pdu.Value), ifIndex)
			if !ok {
				return nil
			}
			seen[ifIndex] = true
			items = append(items, seed)
			return nil
		})
		if err != nil {
			lastErr = err
			continue
		}
		if len(items) > 0 {
			break
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].board != items[j].board {
			return items[i].board < items[j].board
		}
		return items[i].port < items[j].port
	})
	if len(items) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return items, nil
}

func parseC320PortSeed(name string, ifIndex int) (c320PortSeed, bool) {
	m := c320PortNameRe.FindStringSubmatch(strings.TrimSpace(name))
	if len(m) != 4 {
		return c320PortSeed{}, false
	}
	board, _ := strconv.Atoi(m[2])
	port, _ := strconv.Atoi(m[3])
	if board <= 0 || port <= 0 || ifIndex <= 0 {
		return c320PortSeed{}, false
	}
	return c320PortSeed{ifIndex: ifIndex, board: board, port: port, label: strings.TrimSpace(name)}, true
}

func (s *Service) fetchC320PortONUs(client *gosnmp.GoSNMP, profile c320Profile, port c320PortSeed) ([]model.ONUDevice, error) {
	root := profile.BaseOID + profile.NamePrefix + "." + strconv.Itoa(port.ifIndex)
	seeds := make([]c320ONUSeed, 0, 128)
	if err := s.walkWithFallback(client, root, func(pdu gosnmp.SnmpPDU) error {
		onuID := oidLastInt(pdu.Name)
		if onuID <= 0 {
			return nil
		}
		name := strings.TrimSpace(pduToString(pdu.Value))
		if name == "" || name == "0" || strings.EqualFold(name, "NULL") {
			return nil
		}
		seeds = append(seeds, c320ONUSeed{
			board:  port.board,
			port:   port.port,
			onuID:  onuID,
			name:   name,
			suffix: port.ifIndex,
		})
		return nil
	}); err != nil {
		return nil, err
	}
	if len(seeds) == 0 {
		return nil, nil
	}
	return s.fetchC320ONUsFromSeeds(client, profile, seeds)
}

func (s *Service) fetchC320ONUsFromSeeds(client *gosnmp.GoSNMP, profile c320Profile, seeds []c320ONUSeed) ([]model.ONUDevice, error) {
	oids := make([]string, 0, len(seeds)*20)
	seen := map[string]bool{}
	lookup := map[string]struct {
		field string
		seed  c320ONUSeed
	}{}
	appendOID := func(baseOID, prefix, field string, seed c320ONUSeed, indexes ...int) {
		oid := c320CandidateOID(baseOID, prefix, indexes...)
		if oid == "" || seen[oid] {
			return
		}
		seen[oid] = true
		oids = append(oids, oid)
		lookup[oid] = struct {
			field string
			seed  c320ONUSeed
		}{field: field, seed: seed}
	}

	for _, seed := range seeds {
		typeSuffix := c320TypeSuffix(seed.board, seed.port)
		appendOID(profile.BaseOID, profile.SerialPrefix, "serial", seed, seed.suffix, seed.onuID)
		appendOID(profile.BaseOID, profile.SerialPrefix, "serial", seed, seed.suffix, seed.onuID, 1)
		appendOID(profile.BaseOID, profile.DescriptionPrefix, "description", seed, seed.suffix, seed.onuID)
		appendOID(profile.BaseOID, profile.DescriptionPrefix, "description", seed, seed.suffix, seed.onuID, 1)
		appendOID(profile.BaseOID, profile.StatusPrefix, "status", seed, seed.suffix, seed.onuID)
		appendOID(profile.BaseOID, profile.StatusPrefix, "status", seed, seed.suffix, seed.onuID, 1)
		appendOID(profile.BaseOID, profile.LastOnlinePrefix, "last_online", seed, seed.suffix, seed.onuID)
		appendOID(profile.BaseOID, profile.LastOnlinePrefix, "last_online", seed, seed.suffix, seed.onuID, 1)
		appendOID(profile.BaseOID, profile.LastOfflinePrefix, "last_offline", seed, seed.suffix, seed.onuID)
		appendOID(profile.BaseOID, profile.LastOfflinePrefix, "last_offline", seed, seed.suffix, seed.onuID, 1)
		appendOID(profile.BaseOID, profile.OfflineReasonPrefix, "reason", seed, seed.suffix, seed.onuID)
		appendOID(profile.BaseOID, profile.OfflineReasonPrefix, "reason", seed, seed.suffix, seed.onuID, 1)
		appendOID(profile.BaseOID, profile.OnuRxPrefix, "rx", seed, seed.suffix, seed.onuID)
		appendOID(profile.BaseOID, profile.OnuRxPrefix, "rx", seed, seed.suffix, seed.onuID, 1)
		appendOID(c320OltRxBaseOID, c320OltRxPrefix, "olt_rx", seed, seed.suffix, seed.onuID)
		appendOID(c320OltRxBaseOID, c320OltRxPrefix, "olt_rx", seed, seed.suffix, seed.onuID, 1)
		appendOID(c320LegacyBaseOID, c320LegacyOnuRxPrefix, "rx", seed, seed.suffix, seed.onuID, 1)
		appendOID(c320V1082BaseOID, c320V1082OnuRxPrefix, "rx", seed, seed.suffix, seed.onuID)
		appendOID(c320V1082BaseOID, c320V1082OnuRxPrefix, "rx", seed, seed.suffix, seed.onuID, 1)
		if typeSuffix > 0 {
			appendOID(c320LegacyBaseOID, c320LegacyOnuRxPrefix, "rx", seed, typeSuffix, seed.onuID, 1)
			appendOID(c320OltRxBaseOID, c320OltRxPrefix, "olt_rx", seed, typeSuffix, seed.onuID)
			appendOID(c320OltRxBaseOID, c320OltRxPrefix, "olt_rx", seed, typeSuffix, seed.onuID, 1)
		}
	}

	pdus, err := s.getSNMPInChunks(client, oids, 24)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	rows := make(map[string]*model.ONUDevice, len(seeds))
	rawStatus := map[string]int{}
	rawReason := map[string]string{}
	for _, seed := range seeds {
		key := c320SeedKey(seed)
		rows[key] = &model.ONUDevice{
			SerialNumber: fallbackSerialFromBoardPort(key),
			ONUInterface: c320BoardPort(seed),
			Name:         cleanText(seed.name),
			BoardPort:    c320BoardPort(seed),
			Status:       StatusOffline,
			LastSeen:     &now,
		}
	}

	for _, pdu := range pdus {
		entry, ok := lookup[pdu.Name]
		if !ok {
			continue
		}
		key := c320SeedKey(entry.seed)
		row := rows[key]
		if row == nil {
			continue
		}
		switch entry.field {
		case "serial":
			if sn := normalizeSerial(pduToString(pdu.Value)); sn != "" {
				row.SerialNumber = sn
			}
		case "description":
			if desc := cleanText(pduToString(pdu.Value)); desc != "" {
				row.Description = desc
			}
		case "status":
			if status, ok := pduToInt(pdu.Value); ok {
				rawStatus[key] = status
				row.Status = mapStatus(status)
			}
			if profile.StatusPrefix == profile.OnuRxPrefix && row.RXPower == nil {
				if value, ok := pduToOpticalPower(pdu.Value); ok {
					row.RXPower = &value
				}
			}
		case "last_online":
			row.LastOnline = parseZTETimeValue(pduToString(pdu.Value))
		case "last_offline":
			row.LastOffline = parseZTETimeValue(pduToString(pdu.Value))
		case "reason":
			reason := strings.ToLower(strings.TrimSpace(pduToString(pdu.Value)))
			rawReason[key] = reason
			row.OfflineReason = normalizeOfflineReason(reason)
		case "rx":
			if value, ok := pduToOpticalPower(pdu.Value); ok {
				row.RXPower = &value
			}
		case "tx":
			if value, ok := pduToOpticalPower(pdu.Value); ok {
				row.TXPower = &value
			}
		case "olt_rx":
			if value, ok := pduToOpticalPower(pdu.Value); ok {
				row.TXPower = &value
			}
		}
	}

	out := make([]model.ONUDevice, 0, len(rows))
	for key, row := range rows {
		row.Status = normalizeC320Status(rawStatus[key], rawReason[key], row.RXPower)
		if strings.TrimSpace(row.Description) == "" {
			row.Description = row.Name
		}
		out = append(out, *row)
	}
	return out, nil
}

func c320LastTwoOIDInts(oid string) (int, int) {
	parts := strings.Split(strings.Trim(oid, "."), ".")
	values := make([]int, 0, 2)
	for i := len(parts) - 1; i >= 0 && len(values) < 2; i-- {
		if n, err := strconv.Atoi(parts[i]); err == nil {
			values = append(values, n)
		}
	}
	if len(values) < 2 {
		return 0, 0
	}
	return values[1], values[0]
}

func c320SeedFromIfIndex(ifIndex, onuID int, name string) (c320ONUSeed, bool) {
	for _, decoded := range []string{
		decodeZTEBoardPort(ifIndex, onuID),
		decodeZTEIfIndex(ifIndex, onuID),
	} {
		if decoded == "" {
			continue
		}
		m := c320BoardPortNameRe.FindStringSubmatch(decoded)
		if len(m) != 4 {
			continue
		}
		board, _ := strconv.Atoi(m[1])
		port, _ := strconv.Atoi(m[2])
		if board > 0 && port > 0 {
			return c320ONUSeed{board: board, port: port, onuID: onuID, name: name, suffix: ifIndex}, true
		}
	}
	return c320ONUSeed{}, false
}

func c320CandidateOID(baseOID, prefix string, indexes ...int) string {
	baseOID = strings.TrimRight(strings.TrimSpace(baseOID), ".")
	prefix = strings.Trim(strings.TrimSpace(prefix), ".")
	if baseOID == "" || prefix == "" {
		return ""
	}
	parts := make([]string, 0, 2+len(indexes))
	parts = append(parts, baseOID, prefix)
	for _, index := range indexes {
		if index <= 0 {
			return ""
		}
		parts = append(parts, strconv.Itoa(index))
	}
	return strings.Join(parts, ".")
}

func c320TypeSuffix(board, port int) int {
	if board <= 0 || port <= 0 {
		return 0
	}
	base := c320Board1TypeBase
	if board > 1 {
		base = c320Board2TypeBase + ((board - 2) * c320BoardTypeStep)
	}
	return base + (port * c320TypeSuffixStep)
}

func c320SeedKey(seed c320ONUSeed) string {
	return fmt.Sprintf("%d/%d/%d", seed.board, seed.port, seed.onuID)
}

func c320BoardPort(seed c320ONUSeed) string {
	return fmt.Sprintf("gpon_1/%d/%d:%d", seed.board, seed.port, seed.onuID)
}

func cleanText(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "\x00"))
	if value == "" || strings.EqualFold(value, "null") {
		return ""
	}
	return strings.Join(strings.Fields(value), " ")
}

func parseZTETimeValue(value string) *time.Time {
	raw := cleanText(strings.ReplaceAll(strings.TrimSpace(value), "T", " "))
	raw = strings.ReplaceAll(raw, "/", "-")
	raw = strings.ReplaceAll(raw, "0000-00-0000:00:00", "0000-00-00 00:00:00")
	if raw == "" || strings.HasPrefix(raw, "0000-00-00") {
		return nil
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		"2006-01-02-15:04:05",
		"2006-01-02 15:04",
	} {
		if parsed, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return &parsed
		}
	}
	return nil
}

func normalizeOfflineReason(value string) string {
	raw := strings.ToLower(cleanText(value))
	if raw == "" {
		return ""
	}
	switch raw {
	case "1":
		return "LOS_RECOVERY"
	case "2":
		return "LOS"
	case "3":
		return "LOF"
	case "4":
		return "DYING_GASP"
	case "5":
		return "POWER_FAIL"
	case "6":
		return "REBOOT"
	case "7":
		return "AUTH_FAIL"
	case "8":
		return "OFFLINE"
	}
	switch {
	case strings.Contains(raw, "dying") || strings.Contains(raw, "gasp"):
		return "DYING_GASP"
	case strings.Contains(raw, "auth"):
		return "AUTH_FAIL"
	case strings.Contains(raw, "reboot") || strings.Contains(raw, "reset"):
		return "REBOOT"
	case strings.Contains(raw, "power"):
		return "POWER_FAIL"
	case strings.Contains(raw, "los") || strings.Contains(raw, "lof") || strings.Contains(raw, "loss"):
		return "LOS"
	case strings.Contains(raw, "offline"):
		return "OFFLINE"
	default:
		return strings.ToUpper(strings.ReplaceAll(raw, " ", "_"))
	}
}

func normalizeC320Status(statusCode int, reason string, rx *float64) string {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "2" || reason == "los" || reason == "lof" || reason == "loss" {
		return StatusLOS
	}
	if reason == "5" || reason == "dying_gasp" || reason == "dying gasp" {
		return StatusDyingGasp
	}
	if strings.Contains(reason, "dying") || strings.Contains(reason, "gasp") || strings.Contains(reason, "power") {
		return StatusDyingGasp
	}
	if strings.Contains(reason, "los") || strings.Contains(reason, "lof") || strings.Contains(reason, "loss") {
		return StatusLOS
	}

	switch statusCode {
	case 4:
		return StatusOnline
	case 2:
		return StatusLOS
	case 5:
		return StatusDyingGasp
	case 1, 3:
		if rx != nil && *rx > -39 {
			return StatusOnline
		}
		return StatusOffline
	case 6, 7:
		return StatusOffline
	default:
		if rx != nil && *rx > -39 {
			return StatusOnline
		}
		if statusCode > 7 && statusCode < 65535 {
			return StatusOnline
		}
		return StatusOffline
	}
}

func (s *Service) getAllONUWithProfile(client *gosnmp.GoSNMP, profile oidProfile) ([]model.ONUDevice, error) {
	items := map[string]*model.ONUDevice{}
	walked := 0
	var walkErrors []string

	for _, root := range profile.LocationName {
		if err := s.walkString(client, root, func(idx, value string) {
			onu := ensureONU(items, normalizeIndexKey(idx))
			if strings.TrimSpace(onu.Name) == "" {
				onu.Name = strings.TrimSpace(value)
			}
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("location %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.Serial {
		if err := s.walkString(client, root, func(idx, value string) {
			sn := normalizeSerial(value)
			if sn != "" {
				ensureONU(items, normalizeIndexKey(idx)).SerialNumber = sn
			}
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("serial %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.Name {
		if err := s.walkString(client, root, func(idx, value string) {
			ensureONU(items, normalizeIndexKey(idx)).Name = strings.TrimSpace(value)
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("name %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.Description {
		if err := s.walkString(client, root, func(idx, value string) {
			ensureONU(items, normalizeIndexKey(idx)).Description = strings.TrimSpace(value)
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("description %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.Status {
		if err := s.walkInt(client, root, func(idx string, value int) {
			ensureONU(items, normalizeIndexKey(idx)).Status = mapStatus(value)
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("status %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.RXPower {
		if err := s.walkPower(client, root, func(idx string, value float64) {
			ensureONU(items, normalizeIndexKey(idx)).RXPower = &value
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("rx %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.TXPower {
		if err := s.walkPower(client, root, func(idx string, value float64) {
			ensureONU(items, normalizeIndexKey(idx)).TXPower = &value
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("tx %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.LastOnline {
		if err := s.walkString(client, root, func(idx, value string) {
			ensureONU(items, normalizeIndexKey(idx)).LastOnline = parseZTETimeValue(value)
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("last_online %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.LastOffline {
		if err := s.walkString(client, root, func(idx, value string) {
			ensureONU(items, normalizeIndexKey(idx)).LastOffline = parseZTETimeValue(value)
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("last_offline %s: %v", root, err))
		} else {
			walked++
		}
	}
	for _, root := range profile.OfflineReason {
		if err := s.walkString(client, root, func(idx, value string) {
			ensureONU(items, normalizeIndexKey(idx)).OfflineReason = normalizeOfflineReason(value)
		}); err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("offline_reason %s: %v", root, err))
		} else {
			walked++
		}
	}

	if walked == 0 && len(walkErrors) > 0 {
		return nil, errors.New(strings.Join(walkErrors, "; "))
	}

	now := time.Now()
	result := make([]model.ONUDevice, 0, len(items))
	for key, onu := range items {
		if strings.TrimSpace(onu.SerialNumber) == "" {
			onu.SerialNumber = fallbackSerialFromBoardPort(key)
		}
		if onu.Status == "" {
			onu.Status = StatusOffline
		}
		if onu.BoardPort == "" {
			onu.BoardPort = "-"
		}
		onu.LastSeen = &now
		result = append(result, *onu)
	}

	return result, nil
}

func (s *Service) GetONUDetail(sn string) (model.ONUDevice, error) {
	key := strings.ToUpper(strings.TrimSpace(sn))
	if key == "" {
		return model.ONUDevice{}, fmt.Errorf("serial number required")
	}
	s.cacheMu.RLock()
	onu, ok := s.cache[key]
	s.cacheMu.RUnlock()
	if !ok {
		return model.ONUDevice{}, fmt.Errorf("onu %s not found in snmp cache", sn)
	}
	return onu, nil
}

func (s *Service) TestConnection(olt model.OLT) error {
	client := s.client(olt)
	if err := client.Connect(); err != nil {
		return err
	}
	defer client.Conn.Close()
	_, err := client.Get([]string{".1.3.6.1.2.1.1.1.0"})
	return err
}

func TestTelnet(host string, port int, timeout time.Duration) error {
	if strings.TrimSpace(host) == "" {
		return nil
	}
	if port <= 0 {
		port = 23
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (s *Service) client(olt model.OLT) *gosnmp.GoSNMP {
	port := uint16(olt.SNMPPort)
	if port == 0 {
		port = 161
	}
	return &gosnmp.GoSNMP{
		Target:         olt.IPAddress,
		Port:           port,
		Community:      olt.SNMPRO,
		Version:        gosnmp.Version2c,
		Timeout:        s.timeout,
		Retries:        s.retries,
		MaxOids:        gosnmp.MaxOids,
		MaxRepetitions: 10,
	}
}

func (s *Service) walkString(client *gosnmp.GoSNMP, root string, fn func(index string, value string)) error {
	return s.walkWithFallback(client, root, func(pdu gosnmp.SnmpPDU) error {
		fn(indexSuffix(root, pdu.Name), pduToString(pdu.Value))
		return nil
	})
}

func (s *Service) walkInt(client *gosnmp.GoSNMP, root string, fn func(index string, value int)) error {
	return s.walkWithFallback(client, root, func(pdu gosnmp.SnmpPDU) error {
		if value, ok := pduToInt(pdu.Value); ok {
			fn(indexSuffix(root, pdu.Name), value)
		}
		return nil
	})
}

func (s *Service) walkFloat(client *gosnmp.GoSNMP, root string, fn func(index string, value float64)) error {
	return s.walkWithFallback(client, root, func(pdu gosnmp.SnmpPDU) error {
		if value, ok := pduToFloat(pdu.Value); ok {
			fn(indexSuffix(root, pdu.Name), value)
		}
		return nil
	})
}

func (s *Service) walkPower(client *gosnmp.GoSNMP, root string, fn func(index string, value float64)) error {
	return s.walkWithFallback(client, root, func(pdu gosnmp.SnmpPDU) error {
		if value, ok := pduToOpticalPower(pdu.Value); ok {
			fn(indexSuffix(root, pdu.Name), value)
		}
		return nil
	})
}

func (s *Service) walkWithFallback(client *gosnmp.GoSNMP, root string, handler gosnmp.WalkFunc) error {
	count := 0
	bulkErr := client.BulkWalk(root, func(pdu gosnmp.SnmpPDU) error {
		count++
		return handler(pdu)
	})
	if bulkErr == nil && count > 0 {
		return nil
	}

	walkCount := 0
	walkErr := client.Walk(root, func(pdu gosnmp.SnmpPDU) error {
		walkCount++
		return handler(pdu)
	})
	if walkErr != nil {
		if bulkErr != nil {
			return fmt.Errorf("bulkwalk: %w; walk: %v", bulkErr, walkErr)
		}
		return walkErr
	}
	if walkCount == 0 && bulkErr != nil {
		return bulkErr
	}
	return nil
}

func (s *Service) getSNMPInChunks(client *gosnmp.GoSNMP, oids []string, chunkSize int) ([]gosnmp.SnmpPDU, error) {
	if chunkSize <= 0 {
		chunkSize = 24
	}
	var out []gosnmp.SnmpPDU
	var lastErr error

	for start := 0; start < len(oids); start += chunkSize {
		end := start + chunkSize
		if end > len(oids) {
			end = len(oids)
		}
		chunk := oids[start:end]
		packet, err := client.Get(chunk)
		if err == nil && packet != nil {
			for _, pdu := range packet.Variables {
				if validSNMPPDU(pdu) {
					out = append(out, pdu)
				}
			}
			continue
		}

		lastErr = err
		// Some C320 builds reject larger GET packets when one OID is invalid.
		// Retrying one-by-one preserves partial data instead of failing the whole port.
		for _, oid := range chunk {
			packet, singleErr := client.Get([]string{oid})
			if singleErr != nil {
				lastErr = singleErr
				continue
			}
			if packet == nil {
				continue
			}
			for _, pdu := range packet.Variables {
				if validSNMPPDU(pdu) {
					out = append(out, pdu)
				}
			}
		}
	}

	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

func validSNMPPDU(pdu gosnmp.SnmpPDU) bool {
	if strings.TrimSpace(pdu.Name) == "" || pdu.Value == nil {
		return false
	}
	switch pdu.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return false
	default:
		return true
	}
}

func ensureONU(items map[string]*model.ONUDevice, idx string) *model.ONUDevice {
	if items[idx] == nil {
		items[idx] = &model.ONUDevice{BoardPort: idx}
	}
	return items[idx]
}

func normalizeIndexKey(idx string) string {
	parts := strings.Split(strings.Trim(idx, "."), ".")
	nums := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err == nil {
			nums = append(nums, n)
		}
	}
	if len(nums) >= 2 {
		if decoded := decodeZTEBoardPort(nums[0], nums[1]); decoded != "" {
			return decoded
		}
		if decoded := decodeZTEIfIndex(nums[0], nums[1]); decoded != "" {
			return decoded
		}
	}
	if decoded := boardPortFromIndex(idx); decoded != "" && decoded != "-" {
		return decoded
	}
	return strings.Trim(idx, ".")
}

func indexSuffix(root, oid string) string {
	return strings.TrimPrefix(strings.TrimPrefix(oid, root), ".")
}

func oidLastInt(oid string) int {
	parts := strings.Split(strings.Trim(oid, "."), ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if n, err := strconv.Atoi(parts[i]); err == nil {
			return n
		}
	}
	return 0
}

func normalizeSerial(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "\x00"))
	if value == "" {
		return ""
	}
	if parts := strings.SplitN(value, ",", 2); len(parts) == 2 {
		if _, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
			value = strings.TrimSpace(parts[1])
		}
	}
	return strings.ToUpper(value)
}

func pduToString(value interface{}) string {
	switch v := value.(type) {
	case []byte:
		trimmed := trimNullBytes(v)
		if len(trimmed) >= 8 && printableASCII(trimmed[:4]) && !printableASCII(trimmed[4:]) {
			return string(trimmed[:4]) + strings.ToUpper(hex.EncodeToString(trimmed[4:]))
		}
		if printableASCII(trimmed) {
			return string(trimmed)
		}
		return strings.ToUpper(hex.EncodeToString(trimmed))
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func trimNullBytes(value []byte) []byte {
	start := 0
	end := len(value)
	for start < end && value[start] == 0 {
		start++
	}
	for end > start && value[end-1] == 0 {
		end--
	}
	return value[start:end]
}

func printableASCII(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, b := range value {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

func pduToInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case uint:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	case int64:
		return int(v), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(v))
		return i, err == nil
	default:
		i, err := strconv.Atoi(fmt.Sprint(v))
		return i, err == nil
	}
}

func pduToFloat(value interface{}) (float64, bool) {
	raw := strings.TrimSpace(pduToString(value))
	if raw == "" {
		return 0, false
	}
	if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
		if parsed < -1000 || parsed > 1000 {
			parsed = parsed / 1000
		} else if parsed > 100 || parsed < -100 {
			parsed = parsed / 100
		}
		return parsed, true
	}
	if i, ok := pduToInt(value); ok {
		parsed := float64(i)
		if parsed < -1000 || parsed > 1000 {
			parsed = parsed / 1000
		} else if parsed > 100 || parsed < -100 {
			parsed = parsed / 100
		}
		return parsed, true
	}
	return 0, false
}

func pduToOpticalPower(value interface{}) (float64, bool) {
	if i, ok := pduToInt(value); ok {
		parsed := float64(i)
		if i >= 0 && i < 32768 {
			return (parsed * 0.002) - 30.0, true
		}
		if i > 32767 && i < 65535 {
			return -30.0 - (float64(65535-i) * 0.002), true
		}
		if i == 65535 {
			return -40.0, true
		}
	}
	return pduToFloat(value)
}

func mapStatus(value int) string {
	switch value {
	case 4:
		return StatusOnline
	case 2:
		return StatusLOS
	case 5:
		return StatusDyingGasp
	case 0, 1, 3, 6, 7:
		return StatusOffline
	default:
		return StatusOffline
	}
}

func boardPortFromIndex(idx string) string {
	parts := strings.Split(strings.Trim(idx, "."), ".")
	nums := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err == nil {
			nums = append(nums, n)
		}
	}
	if len(nums) >= 2 {
		if decoded := decodeZTEBoardPort(nums[0], nums[1]); decoded != "" {
			return decoded
		}
		if decoded := decodeZTEIfIndex(nums[0], nums[1]); decoded != "" {
			return decoded
		}
	}
	if len(nums) >= 3 && nums[len(nums)-3] <= 32 {
		return fmt.Sprintf("%d/%d:%d", nums[len(nums)-3], nums[len(nums)-2], nums[len(nums)-1])
	}
	if len(nums) >= 2 {
		if decoded := decodeZTEBoardPort(nums[len(nums)-2], nums[len(nums)-1]); decoded != "" {
			return decoded
		}
	}
	if len(nums) >= 1 {
		return strings.Trim(idx, ".")
	}
	return "-"
}

func decodeZTEIfIndex(ifIndex, onuID int) string {
	if ifIndex <= 0 || onuID <= 0 {
		return ""
	}
	if ifIndex >= 268000000 {
		return ""
	}
	rack := (ifIndex >> 16) & 0xff
	slot := (ifIndex >> 8) & 0xff
	port := ifIndex & 0xff
	if rack <= 0 || slot <= 0 || port <= 0 || port > 128 {
		return ""
	}
	return fmt.Sprintf("gpon_%d/%d/%d:%d", rack, slot, port, onuID)
}

func decodeZTEBoardPort(entity, onuID int) string {
	type base struct {
		board int
		value int
		step  int
	}
	bases := []base{
		{board: 1, value: 285278464, step: 1},
		{board: 2, value: 285278720, step: 1},
		{board: 1, value: 268500992, step: 256},
		{board: 2, value: 268566528, step: 256},
		{board: 2, value: 268509184, step: 256},
		{board: 1, value: 268500736, step: 256},
		{board: 2, value: 268508928, step: 256},
	}
	for _, b := range bases {
		diff := entity - b.value
		if diff > 0 && diff <= 16*b.step && diff%b.step == 0 {
			pon := diff / b.step
			return fmt.Sprintf("gpon_1/%d/%d:%d", b.board, pon, onuID)
		}
	}
	return ""
}

func fallbackSerialFromBoardPort(boardPort string) string {
	key := strings.NewReplacer("/", "-", ":", "-", ".", "-").Replace(strings.TrimSpace(boardPort))
	if key == "" || key == "-" {
		key = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return "SNMP-" + strings.ToUpper(key)
}
