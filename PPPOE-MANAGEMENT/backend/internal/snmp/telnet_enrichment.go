package snmp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mikrotik-ppp-management/internal/model"
)

type onuCLIServiceInfo struct {
	Interface     string
	Name          string
	Type          string
	State         string
	AdminState    string
	PhaseState    string
	SerialNumber  string
	Description   string
	PPPoEUser     string
	PPPoEPass     string
	VLAN          string
	LastOnline    string // dari Authpass Time di show gpon onu detail-info
	LastOffline   string // dari OfflineTime di show gpon onu detail-info
	OfflineReason string // dari Cause di show gpon onu detail-info
	Raw           string
}

var (
	cliPromptRe        = regexp.MustCompile(`(?m)(?:^|[\r\n])[A-Za-z0-9_.:/() -]+[#>]\s*$`)
	cliInterfaceRe     = regexp.MustCompile(`(?i)^\s*(?:ONU interface|pon-onu-mng|interface)\s*:?\s*((?:gpon[-_]onu[_-]?\d+[\/_]\d+[\/_]\d+:\d+))`)
	cliKeyValueRe      = regexp.MustCompile(`(?i)^\s*(Name|Type|State|Admin state|Phase state|Serial number|Description)\s*:\s*(.*)\s*$`)
	cliFlowVLANRe      = regexp.MustCompile(`(?i)^\s*flow\s+\d+\s+.*\bvlan\s+(\d+)\b`)
	cliVlanFilterRe    = regexp.MustCompile(`(?i)^\s*vlan-filter\s+\S+\s+.*\bvlan\s+(\d+)\b`)
	cliServiceVLANRe   = regexp.MustCompile(`(?i)^\s*service\s+\S+\s+gemport\s+\d+\s+vlan\s+(\d+)\b`)

	// FIX: regex sebelumnya pakai \S+ setelah index, gagal untuk "pppoe 1 user X password Y"
	// Format ZTE C320: "pppoe 1 nat enable user X password Y" ATAU "pppoe 1 user X password Y"
	cliPPPoERe    = regexp.MustCompile(`(?i)^\s*pppoe\s+\d+(?:\s+\S+)*\s+user\s+(\S+)\s+password\s+(\S+)`)
	cliWANPPPoERe = regexp.MustCompile(`(?i)^\s*wan-ip\s+\d+.*\bmode\s+pppoe\b.*?\busername\s+(\S+)(?:\s+password\s+(\S+))?`)
	cliUserKVRe   = regexp.MustCompile(`(?i)^\s*(?:pppoe\s+username|pppoe\s+user|username|user(?:name)?)\s*:\s*(\S+)`)
	cliPassKVRe   = regexp.MustCompile(`(?i)^\s*(?:pppoe\s+password|password)\s*:\s*(\S+)`)
	cliVLANKVRe   = regexp.MustCompile(`(?i)^\s*(?:vlan|cvlan|user-vlan)\s*:\s*(\d+)`)
	cliVLANProfileRe = regexp.MustCompile(`(?i)\bvlan-profile\s+(\S+)`)
	cliRemoteUsernameRe = regexp.MustCompile(`(?i)^\s*(?:user\s*name|username)\s*:\s*(\S+)`)
	cliRemotePasswordRe = regexp.MustCompile(`(?i)^\s*(?:password)\s*:\s*(\S+)`)
	cliRemoteVLANRe = regexp.MustCompile(`(?i)^\s*(?:vlan id|vlan|cvlan|user-vlan)\s*:\s*(\d+)`)
	cliAuthpassKVRe = regexp.MustCompile(`(?i)^\s*authpass\s*time\s*:\s*((?:20\d\d|0000)[-\/]\d\d[-\/]\d\d\s+\d\d:\d\d:\d\d)`)
	cliOfflineTimeKVRe = regexp.MustCompile(`(?i)^\s*offline\s*time\s*:\s*((?:20\d\d|0000)[-\/]\d\d[-\/]\d\d\s+\d\d:\d\d:\d\d)`)
	cliCauseKVRe = regexp.MustCompile(`(?i)^\s*cause\s*:\s*(.+?)\s*$`)
	cliPPPoEBlockRe = regexp.MustCompile(`(?is)\bpppoe\s+\d+(?:\s+\S+)*\s+user\s+(\S+)(?:\s+password\s+(\S+))?`)
	cliWANPPPoEBlockRe = regexp.MustCompile(`(?is)\bwan-ip\s+\d+(?:\s+\S+)*\s+username\s+(\S+)(?:\s+password\s+(\S+))?`)
	cliFlowVLANBlockRe = regexp.MustCompile(`(?is)\bflow\s+\d+(?:\s+\S+)*\s+vlan\s+(\d+)\b`)
	cliVlanFilterBlockRe = regexp.MustCompile(`(?is)\bvlan-filter\s+\S+(?:\s+\S+)*\s+vlan\s+(\d+)\b`)
	cliServicePortBlockRe = regexp.MustCompile(`(?is)\bservice-port\s+\d+(?:\s+\S+)*\b(?:user-vlan|vlan)\s+(\d+)\b`)
	cliONUBlockHeaderRe = regexp.MustCompile(`(?im)^pon-onu-mng\s+(gpon-onu_[0-9/_:]+)\s*$`)

	// Regex untuk baris "show gpon onu detail-info": tabel Authpass Time / OfflineTime / Cause
	// Contoh: "1  2024-01-15 08:30:00  2024-01-14 22:00:00  DyingGasp"
	cliAuthpassRe = regexp.MustCompile(`(?i)^\s*\d+\s+((?:20\d\d|0000)-\d\d-\d\d\s+\d\d:\d\d:\d\d)\s+((?:20\d\d|0000)-\d\d-\d\d\s+\d\d:\d\d:\d\d)(?:\s+(\S+))?`)

	cliBoardPortRe      = regexp.MustCompile(`(?i)^gpon(?:[-_]?onu)?[_-]?(\d+)[/_](\d+)[/_](\d+):(\d+)$`)
	cliMorePromptRe     = regexp.MustCompile(`(?i)--more--|more\.\.\.`)
	cliPasswordPromptRe = regexp.MustCompile(`(?i)password\s*:?`)
	cliTerminalNoiseRe  = regexp.MustCompile(`(?m)^\s*(?:show|terminal|end|exit)\b.*$`)

	cliNullTime = "0000-00-00 00:00:00"
)

func (s *Service) enrichONUsFromTelnet(olt model.OLT, onus []model.ONUDevice) []model.ONUDevice {
	if len(onus) == 0 || strings.EqualFold(strings.TrimSpace(os.Getenv("OLT_TELNET_ENRICH")), "false") {
		return onus
	}
	host := strings.TrimSpace(olt.TelnetHost)
	if host == "" {
		host = strings.TrimSpace(olt.IPAddress)
	}
	if host == "" || strings.TrimSpace(olt.TelnetUsername) == "" || strings.TrimSpace(olt.TelnetPassword) == "" {
		s.logTroubleshoot("warn", "telnet_enrichment", "Telnet enrichment dilewati karena credential OLT belum lengkap", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": firstNonEmptyString(host, olt.IPAddress),
			"details":        "pastikan telnet host, username, dan password OLT sudah diisi",
		})
		return onus
	}

	infoByInterface, err := fetchZTEONUServiceInfo(host, olt.TelnetPort, olt.TelnetUsername, olt.TelnetPassword, onus)
	if err != nil || len(infoByInterface) == 0 {
		details := "tidak ada hasil parser dari Telnet"
		if err != nil {
			details = err.Error()
		}
		s.logTroubleshoot("error", "telnet_enrichment", "Pengambilan Telnet untuk enrichment ONU gagal", map[string]interface{}{
			"olt_id":         int(olt.ID),
			"olt_name":       olt.Name,
			"olt_ip_address": firstNonEmptyString(host, olt.IPAddress),
			"details":        details,
		})
		return onus
	}
	s.logTroubleshoot("info", "telnet_enrichment", "Telnet enrichment berhasil dijalankan", map[string]interface{}{
		"olt_id":         int(olt.ID),
		"olt_name":       olt.Name,
		"olt_ip_address": firstNonEmptyString(host, olt.IPAddress),
		"details":        fmt.Sprintf("%d interface ONU berhasil dipetakan dari output Telnet", len(infoByInterface)),
	})

	debug := strings.EqualFold(strings.TrimSpace(os.Getenv("OLT_TELNET_DEBUG")), "true")
	rawLogBudget := 10
	completeConfigCount := 0
	if debug {
		keys := make([]string, 0, 5)
		for k := range infoByInterface {
			keys = append(keys, k)
			if len(keys) >= 5 {
				break
			}
		}
		fmt.Fprintf(os.Stderr, "[TELNET DEBUG] infoByInterface has %d keys, sample: %v\n", len(infoByInterface), keys)
	}

	for i := range onus {
		if onus[i].ONUInterface == "" {
			onus[i].ONUInterface = normalizeONUInterface(onus[i].BoardPort)
		}
		lookupKey := normalizeONUInterface(firstNonEmptyString(onus[i].ONUInterface, onus[i].BoardPort))
		info, ok := infoByInterface[lookupKey]
		if !ok {
			if debug {
				fmt.Fprintf(os.Stderr, "[TELNET DEBUG] ONU %s lookup key=%q NOT FOUND\n", onus[i].SerialNumber, lookupKey)
			}
			continue
		}
		if debug {
			fmt.Fprintf(os.Stderr, "[TELNET DEBUG] ONU %s lookup key=%q FOUND pppoe=%q vlan=%q lastOnline=%q\n",
				onus[i].SerialNumber, lookupKey, info.PPPoEUser, info.VLAN, info.LastOnline)
		}
		if rawLogBudget > 0 && !hasCompleteCLIConfig(info) {
			rawLogBudget--
			s.logTroubleshoot("warn", "telnet_enrichment", "Output Telnet ONU ditemukan tetapi field penting belum berhasil diparse", map[string]interface{}{
				"olt_id":         int(olt.ID),
				"olt_name":       olt.Name,
				"olt_ip_address": firstNonEmptyString(host, olt.IPAddress),
				"onu_interface":  lookupKey,
				"serial_number":  onus[i].SerialNumber,
				"details":        compactTelnetSection(info.Raw),
			})
		}
		applyCLIServiceInfo(&onus[i], info)
		if strings.TrimSpace(onus[i].PPPoEUsername) != "" &&
			strings.TrimSpace(onus[i].PPPoEPassword) != "" &&
			strings.TrimSpace(onus[i].VLAN) != "" {
			completeConfigCount++
		}
	}
	s.logTroubleshoot("info", "telnet_enrichment", "Ringkasan hasil parsing konfigurasi ONU dari Telnet", map[string]interface{}{
		"olt_id":          int(olt.ID),
		"olt_name":        olt.Name,
		"olt_ip_address":  firstNonEmptyString(host, olt.IPAddress),
		"details":         fmt.Sprintf("%d dari %d ONU memiliki PPPoE/password/VLAN lengkap setelah enrichment", completeConfigCount, len(onus)),
		"complete_onu":    completeConfigCount,
		"total_onu":       len(onus),
	})
	return onus
}

func fetchZTEONUServiceInfo(host string, port int, username, password string, onus []model.ONUDevice) (map[string]onuCLIServiceInfo, error) {
	if port <= 0 {
		port = 23
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 6*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := loginZTETelnet(conn, username, password); err != nil {
		return nil, err
	}

	_, _ = runZTECommand(conn, "terminal length 0", 2*time.Second)
	_, _ = runZTECommand(conn, "terminal width 512", 2*time.Second)

	combinedSections := make([]string, 0, 4)
	master := map[string]onuCLIServiceInfo{}
	for _, bulkCommand := range []string{
		"show running-config",
		"show running-config | begin pon-onu-mng",
		"show running-config | include pon-onu-mng|pppoe|flow|vlan-filter|service-port|wan-ip",
		"show onu running config",
	} {
		timeout := 45 * time.Second
		if bulkCommand == "show running-config" {
			timeout = 75 * time.Second
		}
		if strings.Contains(bulkCommand, "| include ") {
			timeout = 25 * time.Second
		}
		bulkOut, _ := runZTECommand(conn, bulkCommand, timeout)
		if strings.TrimSpace(bulkOut) == "" {
			continue
		}
		filtered := extractONUManagementSections(bulkOut)
		if strings.TrimSpace(filtered) == "" {
			filtered = bulkOut
		}
		combinedSections = append(combinedSections, filtered)
		mergeCLIServiceMaps(master, parseONUServiceInfo(filtered))
		mergeCLIServiceMaps(master, parseONUManagementBlocks(filtered))
		if coversKnownONUs(master, onus) {
			break
		}
	}
	if !coversKnownONUs(master, onus) {
		for _, altCommand := range []string{
			"show running-config interface",
			"show run interface",
		} {
			altBulk, _ := runZTECommand(conn, altCommand, 60*time.Second)
			if strings.TrimSpace(altBulk) == "" {
				continue
			}
			filtered := extractONUManagementSections(altBulk)
			if strings.TrimSpace(filtered) == "" {
				filtered = altBulk
			}
			combinedSections = append(combinedSections, filtered)
			mergeCLIServiceMaps(master, parseONUServiceInfo(strings.Join(combinedSections, "\n")))
			mergeCLIServiceMaps(master, parseONUManagementBlocks(strings.Join(combinedSections, "\n")))
			if coversKnownONUs(master, onus) {
				break
			}
		}
	}

	unresolved := collectUnresolvedONUInterfaces(master, onus)
	limit := getEnvInt("OLT_TELNET_DETAIL_LIMIT", 25)
	for i, iface := range unresolved {
		if limit > 0 && i >= limit {
			break
		}
		sectionParts := []string{"pon-onu-mng " + iface}
		if commandOut, _ := runZTECommand(conn, "show onu running config "+iface, 10*time.Second); strings.TrimSpace(commandOut) != "" {
			sectionParts = append(sectionParts, commandOut)
		}
		section := strings.Join(sectionParts, "\n")
		ifaceInfo := parseONUServiceInfo(section)[iface]
		if blockInfo, ok := parseONUManagementBlocks(section)[iface]; ok {
			ifaceInfo = mergeCLIServiceInfo(ifaceInfo, blockInfo)
		}
		if !hasCompleteCLIConfig(ifaceInfo) {
			for _, command := range []string{
				"show gpon remote-onu wan-ip " + iface,
				"show gpon remote-onu pppoe " + iface,
				"show gpon remote-onu ip-host " + iface,
				"show interface " + iface,
				"show run interface " + iface,
				"show running-config interface " + iface,
			} {
				alt, _ := runZTECommand(conn, command, 8*time.Second)
				if strings.TrimSpace(alt) != "" {
					sectionParts = append(sectionParts, "["+command+"]", alt)
					section = strings.Join(sectionParts, "\n")
				}
				ifaceInfo = parseONUServiceInfo(section)[iface]
				if blockInfo, ok := parseONUManagementBlocks(section)[iface]; ok {
					ifaceInfo = mergeCLIServiceInfo(ifaceInfo, blockInfo)
				}
				if hasCompleteCLIConfig(ifaceInfo) {
					break
				}
			}
		}

		parsedOne := parseONUServiceInfo(section)
		mergeCLIServiceMaps(parsedOne, parseONUManagementBlocks(section))
		if info, ok := parsedOne[iface]; ok {
			prev := master[iface]
			master[iface] = mergeCLIServiceInfo(prev, info)
			if !hasCompleteCLIConfig(info) {
				master[iface] = mergeCLIServiceInfo(master[iface], onuCLIServiceInfo{
					Interface: iface,
					Raw:       compactTelnetSection(section),
				})
			}
		} else {
			mergeCLIServiceMaps(master, parsedOne)
		}
	}
	if len(master) == 0 {
		return parseONUServiceInfo(strings.Join(combinedSections, "\n")), nil
	}
	return master, nil
}

func loginZTETelnet(conn net.Conn, username, password string) error {
	banner, err := readTelnetUntilMatch(conn, 8*time.Second, "username", "login", "password", ">", "#")
	if err != nil && strings.TrimSpace(banner) == "" {
		return err
	}
	lowerBanner := strings.ToLower(banner)
	if strings.Contains(lowerBanner, "username") || strings.Contains(lowerBanner, "login") {
		if _, err := conn.Write([]byte(username + "\r\n")); err != nil {
			return err
		}
		banner, err = readTelnetUntilMatch(conn, 6*time.Second, "password", ">", "#", "bad password", "authentication failed")
		if err != nil && strings.TrimSpace(banner) == "" {
			return err
		}
		lowerBanner = strings.ToLower(banner)
	}
	if strings.Contains(lowerBanner, "password") && !cliPromptRe.MatchString(banner) {
		if _, err := conn.Write([]byte(password + "\r\n")); err != nil {
			return err
		}
		afterPass, readErr := readTelnetUntilMatch(conn, 8*time.Second, ">", "#", "bad password", "authentication failed", "no username or bad password")
		banner += afterPass
		if readErr != nil && strings.TrimSpace(afterPass) == "" {
			return readErr
		}
	}
	if hasExplicitAuthFailure(banner) {
		return fmt.Errorf("login telnet gagal: username atau password tidak diterima")
	}
	if err := promoteZTETelnetPrivilege(conn, banner, password); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

func runZTECommand(conn net.Conn, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(command + "\r\n")); err != nil {
		return "", err
	}
	_ = conn.SetWriteDeadline(time.Time{})
	deadline := time.Now().Add(timeout)
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
			text := b.String()
			if cliMorePromptRe.MatchString(text) {
				_, _ = conn.Write([]byte(" "))
				continue
			}
			if cliPromptRe.MatchString(text) {
				return cleanCLIOutput(command, text), nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				text := b.String()
				if cliMorePromptRe.MatchString(text) {
					_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_, _ = conn.Write([]byte(" "))
					_ = conn.SetWriteDeadline(time.Time{})
					continue
				}
				if cliPromptRe.MatchString(text) {
					_ = conn.SetReadDeadline(time.Time{})
					return cleanCLIOutput(command, text), nil
				}
				if time.Now().After(deadline) {
					if b.Len() > 0 {
						_ = conn.SetReadDeadline(time.Time{})
						return cleanCLIOutput(command, text), nil
					}
					return "", err
				}
				continue
			}
			if b.Len() > 0 {
				_ = conn.SetReadDeadline(time.Time{})
				return cleanCLIOutput(command, b.String()), nil
			}
			return "", err
		}
		if time.Now().After(deadline) {
			_ = conn.SetReadDeadline(time.Time{})
			return cleanCLIOutput(command, b.String()), nil
		}
	}
}

func cleanCLIOutput(command, raw string) string {
	raw = strings.ReplaceAll(raw, "\r", "\n")
	raw = strings.ReplaceAll(raw, "\x00", "")
	raw = strings.ReplaceAll(raw, "\b", "")
	raw = cliMorePromptRe.ReplaceAllString(raw, "")
	raw = strings.ReplaceAll(raw, command, "")
	raw = cliTerminalNoiseRe.ReplaceAllString(raw, "")
	return strings.TrimSpace(raw)
}

func parseONUServiceInfo(raw string) map[string]onuCLIServiceInfo {
	result := map[string]onuCLIServiceInfo{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	current := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if m := cliInterfaceRe.FindStringSubmatch(line); len(m) == 2 {
			current = normalizeONUInterface(m[1])
			info := result[current]
			info.Interface = current
			info.Raw = appendRawLine(info.Raw, line)
			result[current] = info
			continue
		}
		if current == "" {
			continue
		}
		info := result[current]
		info.Raw = appendRawLine(info.Raw, line)

		if m := cliKeyValueRe.FindStringSubmatch(line); len(m) == 3 {
			setCLIKeyValue(&info, m[1], m[2])
		}

		// VLAN: coba semua format
		if info.VLAN == "" {
			if m := cliFlowVLANRe.FindStringSubmatch(line); len(m) == 2 {
				info.VLAN = strings.TrimSpace(m[1])
			}
		}
		if info.VLAN == "" {
			if m := cliVlanFilterRe.FindStringSubmatch(line); len(m) == 2 {
				info.VLAN = strings.TrimSpace(m[1])
			}
		}
		if info.VLAN == "" {
			if m := cliServiceVLANRe.FindStringSubmatch(line); len(m) == 2 {
				info.VLAN = strings.TrimSpace(m[1])
			}
		}
		if info.VLAN == "" {
			if m := cliVLANKVRe.FindStringSubmatch(line); len(m) == 2 {
				info.VLAN = strings.TrimSpace(m[1])
			}
		}
		if info.VLAN == "" {
			if m := cliVLANProfileRe.FindStringSubmatch(line); len(m) == 2 {
				info.VLAN = extractTrailingDigits(m[1])
			}
		}
		if info.VLAN == "" {
			if m := cliRemoteVLANRe.FindStringSubmatch(line); len(m) == 2 {
				info.VLAN = strings.TrimSpace(m[1])
			}
		}

		// PPPoE: coba semua format
		if m := cliPPPoERe.FindStringSubmatch(line); len(m) >= 3 {
			info.PPPoEUser = strings.TrimSpace(m[1])
			info.PPPoEPass = strings.TrimSpace(m[2])
		}
		if info.PPPoEUser == "" {
			if m := cliWANPPPoERe.FindStringSubmatch(line); len(m) >= 2 {
				info.PPPoEUser = strings.TrimSpace(m[1])
				if len(m) >= 3 && strings.TrimSpace(m[2]) != "" {
					info.PPPoEPass = strings.TrimSpace(m[2])
				}
			}
		}
		if info.PPPoEUser == "" {
			if m := cliUserKVRe.FindStringSubmatch(line); len(m) == 2 {
				info.PPPoEUser = strings.TrimSpace(m[1])
			}
		}
		if info.PPPoEUser == "" {
			if m := cliRemoteUsernameRe.FindStringSubmatch(line); len(m) == 2 {
				info.PPPoEUser = strings.TrimSpace(m[1])
			}
		}
		if info.PPPoEPass == "" {
			if m := cliPassKVRe.FindStringSubmatch(line); len(m) == 2 {
				info.PPPoEPass = strings.TrimSpace(m[1])
			}
		}
		if info.PPPoEPass == "" {
			if m := cliRemotePasswordRe.FindStringSubmatch(line); len(m) == 2 {
				info.PPPoEPass = strings.TrimSpace(m[1])
			}
		}

		// Last Online / Last Offline dari tabel "show gpon onu detail-info"
		// Format: "1  2024-01-15 08:30:00  2024-01-14 22:00:00  DyingGasp"
		// Ambil hanya row pertama (paling recent) untuk LastOnline dan LastOffline
		if m := cliAuthpassRe.FindStringSubmatch(line); len(m) >= 3 {
			authpass := strings.TrimSpace(m[1])
			offline := strings.TrimSpace(m[2])
			cause := ""
			if len(m) >= 4 {
				cause = strings.TrimSpace(m[3])
			}
			if authpass != cliNullTime && info.LastOnline == "" {
				info.LastOnline = authpass
			}
			if offline != cliNullTime && info.LastOffline == "" {
				info.LastOffline = offline
				info.OfflineReason = cause
			}
		}
		if info.LastOnline == "" {
			if m := cliAuthpassKVRe.FindStringSubmatch(line); len(m) == 2 {
				info.LastOnline = normalizeTelnetTimeString(m[1])
			}
		}
		if info.LastOffline == "" {
			if m := cliOfflineTimeKVRe.FindStringSubmatch(line); len(m) == 2 {
				info.LastOffline = normalizeTelnetTimeString(m[1])
			}
		}
		if info.OfflineReason == "" {
			if m := cliCauseKVRe.FindStringSubmatch(line); len(m) == 2 {
				info.OfflineReason = strings.TrimSpace(m[1])
			}
		}

		result[current] = info
	}
	for key, info := range result {
		hydrateCLIConfigFromRaw(&info)
		result[key] = info
	}
	return result
}

func promoteZTETelnetPrivilege(conn net.Conn, banner, loginPassword string) error {
	if strings.Contains(banner, "#") || !strings.Contains(banner, ">") {
		return nil
	}
	enablePassword := strings.TrimSpace(os.Getenv("OLT_TELNET_ENABLE_PASSWORD"))
	if enablePassword == "" {
		enablePassword = loginPassword
	}
	if _, err := conn.Write([]byte("enable\r\n")); err != nil {
		return err
	}
	time.Sleep(250 * time.Millisecond)
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	text := string(buf[:maxInt(n, 0)])
	if err == nil && cliPasswordPromptRe.MatchString(text) && enablePassword != "" {
		if _, writeErr := conn.Write([]byte(enablePassword + "\r\n")); writeErr != nil {
			return writeErr
		}
		time.Sleep(250 * time.Millisecond)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ = conn.Read(buf)
		text += string(buf[:maxInt(n, 0)])
	}
	_ = conn.SetReadDeadline(time.Time{})
	if looksLikeAuthFailure(text) {
		return fmt.Errorf("enable telnet gagal: password enable tidak sesuai atau privilege belum diberikan")
	}
	return nil
}

func looksLikeAuthFailure(raw string) bool {
	text := strings.ToLower(strings.TrimSpace(raw))
	if text == "" {
		return false
	}
	return hasExplicitAuthFailure(text) ||
		(strings.Contains(text, "username:") && !cliPromptRe.MatchString(raw)) ||
		(strings.Contains(text, "password:") && !strings.Contains(text, "#") && !strings.Contains(text, ">"))
}

func hasExplicitAuthFailure(raw string) bool {
	text := strings.ToLower(strings.TrimSpace(raw))
	if text == "" {
		return false
	}
	return strings.Contains(text, "no username or bad password") ||
		strings.Contains(text, "bad password") ||
		strings.Contains(text, "authentication failed")
}

func readTelnetUntilMatch(conn net.Conn, timeout time.Duration, markers ...string) (string, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		step := 900 * time.Millisecond
		if remaining < step {
			step = remaining
		}
		_ = conn.SetReadDeadline(time.Now().Add(step))
		n, err := conn.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
			text := strings.ToLower(b.String())
			if cliPromptRe.MatchString(b.String()) {
				_ = conn.SetReadDeadline(time.Time{})
				return b.String(), nil
			}
			for _, marker := range markers {
				if marker != "" && strings.Contains(text, strings.ToLower(marker)) {
					_ = conn.SetReadDeadline(time.Time{})
					return b.String(), nil
				}
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			_ = conn.SetReadDeadline(time.Time{})
			if b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return b.String(), nil
}

func setCLIKeyValue(info *onuCLIServiceInfo, key, value string) {
	key = strings.ToLower(strings.TrimSpace(key))
	value = cleanText(value)
	switch key {
	case "name":
		info.Name = value
	case "type":
		info.Type = value
	case "state":
		info.State = value
	case "admin state":
		info.AdminState = value
	case "phase state":
		info.PhaseState = value
	case "serial number":
		info.SerialNumber = normalizeSerial(value)
	case "description":
		info.Description = value
	}
}

func hydrateCLIConfigFromRaw(info *onuCLIServiceInfo) {
	if info == nil {
		return
	}
	raw := strings.TrimSpace(info.Raw)
	if raw == "" {
		return
	}
	if info.PPPoEUser == "" || info.PPPoEPass == "" {
		if m := cliPPPoEBlockRe.FindStringSubmatch(raw); len(m) >= 2 {
			if info.PPPoEUser == "" {
				info.PPPoEUser = strings.TrimSpace(m[1])
			}
			if len(m) >= 3 && info.PPPoEPass == "" {
				info.PPPoEPass = strings.TrimSpace(m[2])
			}
		}
	}
	if info.PPPoEUser == "" || info.PPPoEPass == "" {
		if m := cliWANPPPoEBlockRe.FindStringSubmatch(raw); len(m) >= 2 {
			if info.PPPoEUser == "" {
				info.PPPoEUser = strings.TrimSpace(m[1])
			}
			if len(m) >= 3 && info.PPPoEPass == "" {
				info.PPPoEPass = strings.TrimSpace(m[2])
			}
		}
	}
	if info.VLAN == "" {
		if m := cliFlowVLANBlockRe.FindStringSubmatch(raw); len(m) == 2 {
			info.VLAN = strings.TrimSpace(m[1])
		}
	}
	if info.VLAN == "" {
		if m := cliVlanFilterBlockRe.FindStringSubmatch(raw); len(m) == 2 {
			info.VLAN = strings.TrimSpace(m[1])
		}
	}
	if info.VLAN == "" {
		if m := cliServicePortBlockRe.FindStringSubmatch(raw); len(m) == 2 {
			info.VLAN = strings.TrimSpace(m[1])
		}
	}
}

func applyCLIServiceInfo(onu *model.ONUDevice, info onuCLIServiceInfo) {
	if info.Interface != "" {
		onu.ONUInterface = info.Interface
	}
	if info.Name != "" {
		onu.Name = info.Name
	}
	if info.Type != "" {
		onu.ONUType = info.Type
	}
	if info.Description != "" {
		onu.Description = info.Description
	}
	if info.SerialNumber != "" {
		onu.SerialNumber = info.SerialNumber
	}
	if info.AdminState != "" {
		onu.AdminState = info.AdminState
	}
	if info.PhaseState != "" {
		onu.PhaseState = info.PhaseState
	}
	if info.PPPoEUser != "" {
		onu.PPPoEUsername = info.PPPoEUser
	}
	if info.PPPoEPass != "" {
		onu.PPPoEPassword = info.PPPoEPass
	}
	if info.VLAN != "" {
		onu.VLAN = info.VLAN
	}
	// Terapkan Last Online / Last Offline dari Telnet jika SNMP belum mengisi
	if info.LastOnline != "" && onu.LastOnline == nil {
		if t := parseZTETimeStringLocal(info.LastOnline); t != nil {
			onu.LastOnline = t
		}
	}
	if info.LastOffline != "" && onu.LastOffline == nil {
		if t := parseZTETimeStringLocal(info.LastOffline); t != nil {
			onu.LastOffline = t
		}
	}
	if info.OfflineReason != "" && onu.OfflineReason == "" {
		onu.OfflineReason = info.OfflineReason
	}
}

func mergeCLIServiceInfo(base, incoming onuCLIServiceInfo) onuCLIServiceInfo {
	if incoming.Interface != "" {
		base.Interface = incoming.Interface
	}
	if incoming.Name != "" {
		base.Name = incoming.Name
	}
	if incoming.Type != "" {
		base.Type = incoming.Type
	}
	if incoming.State != "" {
		base.State = incoming.State
	}
	if incoming.AdminState != "" {
		base.AdminState = incoming.AdminState
	}
	if incoming.PhaseState != "" {
		base.PhaseState = incoming.PhaseState
	}
	if incoming.SerialNumber != "" {
		base.SerialNumber = incoming.SerialNumber
	}
	if incoming.Description != "" {
		base.Description = incoming.Description
	}
	if incoming.PPPoEUser != "" {
		base.PPPoEUser = incoming.PPPoEUser
	}
	if incoming.PPPoEPass != "" {
		base.PPPoEPass = incoming.PPPoEPass
	}
	if incoming.VLAN != "" {
		base.VLAN = incoming.VLAN
	}
	if incoming.LastOnline != "" {
		base.LastOnline = incoming.LastOnline
	}
	if incoming.LastOffline != "" {
		base.LastOffline = incoming.LastOffline
	}
	if incoming.OfflineReason != "" {
		base.OfflineReason = incoming.OfflineReason
	}
	if incoming.Raw != "" {
		base.Raw = appendRawLine(base.Raw, incoming.Raw)
	}
	return base
}

func mergeCLIServiceMaps(dst map[string]onuCLIServiceInfo, src map[string]onuCLIServiceInfo) {
	for key, value := range src {
		dst[key] = mergeCLIServiceInfo(dst[key], value)
	}
}

// parseZTETimeStringLocal parse string "2006-01-02 15:04:05" ke *time.Time (local timezone)
func parseZTETimeStringLocal(s string) *time.Time {
	s = normalizeTelnetTimeString(s)
	if s == "" || strings.HasPrefix(s, "0000-00-00") {
		return nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return &t
		}
	}
	return nil
}

func hasPPPoEOrVLAN(items map[string]onuCLIServiceInfo) bool {
	for _, item := range items {
		if item.PPPoEUser != "" || item.VLAN != "" {
			return true
		}
	}
	return false
}

func hasCompleteCLIConfig(info onuCLIServiceInfo) bool {
	return strings.TrimSpace(info.PPPoEUser) != "" &&
		strings.TrimSpace(info.PPPoEPass) != "" &&
		strings.TrimSpace(info.VLAN) != ""
}

func collectUnresolvedONUInterfaces(items map[string]onuCLIServiceInfo, onus []model.ONUDevice) []string {
	unresolved := make([]string, 0, 64)
	seen := make(map[string]bool, len(onus))
	for _, onu := range onus {
		iface := normalizeONUInterface(firstNonEmptyString(onu.ONUInterface, onu.BoardPort))
		if iface == "" || seen[iface] {
			continue
		}
		seen[iface] = true
		if !hasCompleteCLIConfig(items[iface]) {
			unresolved = append(unresolved, iface)
		}
	}
	return unresolved
}

func coversKnownONUs(items map[string]onuCLIServiceInfo, onus []model.ONUDevice) bool {
	if len(items) == 0 || !hasPPPoEOrVLAN(items) {
		return false
	}
	known := 0
	enriched := 0
	for _, onu := range onus {
		iface := normalizeONUInterface(firstNonEmptyString(onu.ONUInterface, onu.BoardPort))
		if iface == "" {
			continue
		}
		known++
		if info, ok := items[iface]; ok && hasCompleteCLIConfig(info) {
			enriched++
		}
	}
	if known == 0 {
		return true
	}
	return enriched >= known || (known > 20 && enriched >= (known*8/10))
}

func normalizeONUInterface(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || value == "-" {
		return ""
	}
	if m := cliBoardPortRe.FindStringSubmatch(value); len(m) == 5 {
		return fmt.Sprintf("gpon-onu_%s/%s/%s:%s", m[1], m[2], m[3], m[4])
	}
	return value
}

func appendRawLine(raw, line string) string {
	if strings.TrimSpace(line) == "" {
		return raw
	}
	if raw == "" {
		return line
	}
	return raw + "\n" + line
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func extractTrailingDigits(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	matches := regexp.MustCompile(`(\d{1,4})`).FindAllString(value, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func normalizeTelnetTimeString(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "/", "-"))
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func extractONUManagementSections(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	sections := make([]string, 0, 128)
	lines := make([]string, 0, 16)
	collecting := false

	flush := func() {
		if len(lines) == 0 {
			return
		}
		sections = append(sections, strings.Join(lines, "\n"))
		lines = lines[:0]
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "pon-onu-mng gpon-onu_") {
			flush()
			collecting = true
			lines = append(lines, trimmed)
			continue
		}
		if !collecting {
			continue
		}
		if trimmed == "!" {
			lines = append(lines, trimmed)
			flush()
			collecting = false
			continue
		}
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
	}
	flush()
	if len(sections) == 0 {
		return raw
	}
	return strings.Join(sections, "\n")
}

func parseONUManagementBlocks(raw string) map[string]onuCLIServiceInfo {
	result := make(map[string]onuCLIServiceInfo)
	raw = strings.ReplaceAll(raw, "\r", "\n")
	locs := cliONUBlockHeaderRe.FindAllStringSubmatchIndex(raw, -1)
	if len(locs) == 0 {
		return result
	}
	for i, loc := range locs {
		if len(loc) < 4 {
			continue
		}
		iface := normalizeONUInterface(raw[loc[2]:loc[3]])
		if iface == "" {
			continue
		}
		start := loc[0]
		end := len(raw)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := strings.TrimSpace(raw[start:end])
		if bang := strings.Index(block, "\n!"); bang >= 0 {
			block = strings.TrimSpace(block[:bang])
		}
		info := result[iface]
		info.Interface = iface
		info.Raw = appendRawLine(info.Raw, block)
		hydrateCLIConfigFromRaw(&info)
		result[iface] = info
	}
	return result
}

func compactTelnetSection(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lines := strings.Split(value, "\n")
	if len(lines) > 40 {
		lines = append(lines[:40], "...[truncated]")
	}
	return strings.Join(lines, "\n")
}

func truncateTelnetOutput(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if value == "" || maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	return strings.TrimSpace(value[:maxBytes]) + "\n...[truncated]"
}

type telnetCommandSpec struct {
	Label   string
	Command string
	Timeout time.Duration
}

func openZTETelnetSession(olt model.OLT) (net.Conn, string, error) {
	host := strings.TrimSpace(olt.TelnetHost)
	if host == "" {
		host = strings.TrimSpace(olt.IPAddress)
	}
	if host == "" {
		return nil, "", fmt.Errorf("telnet host belum diisi")
	}
	if strings.TrimSpace(olt.TelnetUsername) == "" || strings.TrimSpace(olt.TelnetPassword) == "" {
		return nil, "", fmt.Errorf("credential telnet olt belum lengkap")
	}
	port := olt.TelnetPort
	if port <= 0 {
		port = 23
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 6*time.Second)
	if err != nil {
		return nil, "", err
	}
	if err := loginZTETelnet(conn, olt.TelnetUsername, olt.TelnetPassword); err != nil {
		conn.Close()
		return nil, "", err
	}
	_, _ = runZTECommand(conn, "terminal length 0", 2*time.Second)
	_, _ = runZTECommand(conn, "terminal width 512", 2*time.Second)
	return conn, host, nil
}

func normalizeTroubleshootONUInterface(raw string) string {
	normalized := normalizeONUInterface(raw)
	if normalized != "" {
		return normalized
	}
	return "gpon-onu_1/1/1:1"
}

func buildTelnetPresetCommands(preset, target string) ([]telnetCommandSpec, string, error) {
	preset = strings.ToLower(strings.TrimSpace(preset))
	if preset == "" {
		preset = "session"
	}
	iface := normalizeTroubleshootONUInterface(target)
	switch preset {
	case "session":
		return []telnetCommandSpec{
			{Label: "Session Check", Command: "show version", Timeout: 8 * time.Second},
		}, "", nil
	case "show-running-config", "all":
		return []telnetCommandSpec{
			{Label: "Running Config Penuh", Command: "show running-config", Timeout: 45 * time.Second},
		}, "", nil
	case "show-running-config-interface":
		return []telnetCommandSpec{
			{Label: "Running Config Interface", Command: "show running-config interface " + iface, Timeout: 15 * time.Second},
		}, iface, nil
	case "show-onu-running-config":
		return []telnetCommandSpec{
			{Label: "ONU Running Config", Command: "show onu running config " + iface, Timeout: 15 * time.Second},
		}, iface, nil
	case "show-attenuation":
		return []telnetCommandSpec{
			{Label: "Power Attenuation", Command: "show pon power attenuation " + iface, Timeout: 15 * time.Second},
		}, iface, nil
	default:
		return nil, "", fmt.Errorf("preset command tidak dikenal: %s", preset)
	}
}

func executeTelnetCommandSpecs(olt model.OLT, mode, preset, target string, commands []telnetCommandSpec) (*model.OLTTelnetDump, error) {
	conn, host, err := openZTETelnetSession(olt)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sections := make([]model.OLTTelnetDumpSection, 0, len(commands))
	for _, item := range commands {
		out, cmdErr := runZTECommand(conn, item.Command, item.Timeout)
		if cmdErr != nil && strings.TrimSpace(out) == "" {
			out = "ERROR: " + cmdErr.Error()
		}
		sections = append(sections, model.OLTTelnetDumpSection{
			Label:   item.Label,
			Command: item.Command,
			Output:  truncateTelnetOutput(out, 200000),
		})
	}

	return &model.OLTTelnetDump{
		OLTID:        olt.ID,
		OLTName:      olt.Name,
		OLTIPAddress: olt.IPAddress,
		TelnetHost:   host,
		RetrievedAt:  time.Now(),
		Mode:         mode,
		Preset:       preset,
		Target:       target,
		Sections:     sections,
	}, nil
}

func (s *Service) CaptureRawTelnetDump(olt model.OLT, mode string) (*model.OLTTelnetDump, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	commands := []telnetCommandSpec{}
	switch mode {
	case "full":
		commands = []telnetCommandSpec{
			{Label: "Running Config from pon-onu-mng", Command: "show running-config | begin pon-onu-mng", Timeout: 45 * time.Second},
			{Label: "Running Config Filtered", Command: "show running-config | include pon-onu-mng|pppoe|flow|vlan-filter|service-port|wan-ip", Timeout: 25 * time.Second},
			{Label: "ONU Running Config Semua", Command: "show onu running config", Timeout: 45 * time.Second},
		}
	default:
		mode = "quick"
		commands = []telnetCommandSpec{
			{Label: "Running Config Filtered", Command: "show running-config | include pon-onu-mng|pppoe|flow|vlan-filter|service-port|wan-ip", Timeout: 20 * time.Second},
			{Label: "Running Config from pon-onu-mng", Command: "show running-config | begin pon-onu-mng", Timeout: 30 * time.Second},
		}
	}
	return executeTelnetCommandSpecs(olt, mode, "", "", commands)
}

func (s *Service) CaptureRawTelnetCommand(olt model.OLT, preset, target string) (*model.OLTTelnetDump, error) {
	commands, resolvedTarget, err := buildTelnetPresetCommands(preset, target)
	if err != nil {
		return nil, err
	}
	return executeTelnetCommandSpecs(olt, "single", strings.ToLower(strings.TrimSpace(preset)), resolvedTarget, commands)
}
