package api

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mikrotik-ppp-management/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/gosnmp/gosnmp"
)

type snmpIfaceInfo struct {
	IfIndex     int    `json:"if_index"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Alias       string `json:"alias"`
	DisplayName string `json:"display_name"`
	OperStatus  int    `json:"oper_status"`
}

type snmpCounterState struct {
	InOctets  uint64
	OutOctets uint64
	Timestamp time.Time
	RxBps     int64
	TxBps     int64
}

type snmpIfaceCacheItem struct {
	Items     []snmpIfaceInfo
	ExpiresAt time.Time
}

type snmpPreferredItem struct {
	Community string
	Version   gosnmp.SnmpVersion
	ExpiresAt time.Time
}

var (
	snmpPrevMu       sync.Mutex
	snmpPrev         = map[string]snmpCounterState{}
	snmpIfaceCacheMu sync.Mutex
	snmpIfaceCache   = map[int]snmpIfaceCacheItem{}
	snmpPrefMu       sync.Mutex
	snmpPreferred    = map[string]snmpPreferredItem{}
)

func (h *Handler) GetSNMPInterfaces(c *gin.Context) {
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
		respond(c, 500, false, "SNMP connect failed: "+err.Error(), nil)
		return
	}
	defer client.Conn.Close()

	ifaces, err := getCachedInterfaces(routerID, client, false)
	if err != nil {
		respond(c, 500, false, "SNMP read failed: "+err.Error(), nil)
		return
	}
	respond(c, 200, true, "OK", gin.H{
		"community":  usedCommunity,
		"interfaces": ifaces,
	})
}

func (h *Handler) GetSNMPLiveTraffic(c *gin.Context) {
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
		respond(c, 500, false, "SNMP connect failed: "+err.Error(), nil)
		return
	}
	defer client.Conn.Close()
	// Realtime polling should fail fast so the widget can refresh again quickly
	// instead of appearing to hang while waiting for a long SNMP timeout.
	client.Timeout = 1500 * time.Millisecond
	client.Retries = 0

	filterIndexes := parseIndexFilter(c.Query("if_index"))
	search := strings.ToLower(strings.TrimSpace(c.Query("search")))
	var selected []int
	ifaceMap := make(map[int]snmpIfaceInfo)

	if len(filterIndexes) > 0 {
		// Fast path for realtime widget with specific ifIndex:
		// use cached metadata if available, do not force SNMP interface walk.
		cached := getInterfaceCacheSnapshot(routerID)
		for _, inf := range cached {
			ifaceMap[inf.IfIndex] = inf
		}
		for _, idx := range filterIndexes {
			selected = append(selected, idx)
			if _, ok := ifaceMap[idx]; !ok {
				fallbackName := "if" + strconv.Itoa(idx)
				ifaceMap[idx] = snmpIfaceInfo{
					IfIndex:     idx,
					Name:        fallbackName,
					Description: "",
					DisplayName: buildSNMPInterfaceLabel(fallbackName, "", "", idx),
					OperStatus:  0,
				}
			}
		}
	} else {
		ifaces, err := getCachedInterfaces(routerID, client, false)
		if err != nil {
			respond(c, 500, false, "SNMP read interfaces failed: "+err.Error(), nil)
			return
		}
		for _, inf := range ifaces {
			ifaceMap[inf.IfIndex] = inf
		}
		for idx, inf := range ifaceMap {
			if search != "" {
				candidate := strings.ToLower(inf.Name + " " + inf.Description + " " + inf.Alias + " " + inf.DisplayName)
				if !strings.Contains(candidate, search) {
					continue
				}
			}
			selected = append(selected, idx)
		}
	}
	sort.Ints(selected)
	if len(selected) > 20 {
		selected = selected[:20]
	}
	if len(selected) == 0 {
		respond(c, 200, true, "OK", gin.H{
			"community": usedCommunity,
			"rows":      []map[string]interface{}{},
		})
		return
	}

	oids := make([]string, 0, len(selected)*5)
	for _, idx := range selected {
		oids = append(oids,
			".1.3.6.1.2.1.31.1.1.1.6."+strconv.Itoa(idx),  // ifHCInOctets
			".1.3.6.1.2.1.31.1.1.1.10."+strconv.Itoa(idx), // ifHCOutOctets
			".1.3.6.1.2.1.2.2.1.10."+strconv.Itoa(idx),    // ifInOctets fallback
			".1.3.6.1.2.1.2.2.1.16."+strconv.Itoa(idx),    // ifOutOctets fallback
			".1.3.6.1.2.1.2.2.1.8."+strconv.Itoa(idx),     // ifOperStatus
		)
	}

	var packet *gosnmp.SnmpPacket
	if len(oids) > 40 {
		packet, err = getSNMPInChunks(client, oids, 40)
	} else {
		packet, err = client.Get(oids)
		if err != nil {
			// Retry with safe chunking when device/library max OIDs is lower than our request.
			packet, err = getSNMPInChunks(client, oids, 40)
		}
	}
	if err != nil {
		// If preferred SNMP credential becomes stale, clear cache and retry one full fallback.
		clearPreferredSNMP(router.IPAddress, router.SNMPPort)
		if client.Conn != nil {
			_ = client.Conn.Close()
		}
		retryClient, retryCommunity, retryErr := connectSNMPWithFallback(router.IPAddress, router.SNMPPort, router.SNMPUser)
		if retryErr == nil {
			client = retryClient
			usedCommunity = retryCommunity
			defer client.Conn.Close()
			if len(oids) > 40 {
				packet, err = getSNMPInChunks(client, oids, 40)
			} else {
				packet, err = client.Get(oids)
				if err != nil {
					packet, err = getSNMPInChunks(client, oids, 40)
				}
			}
		}
	}
	if err != nil {
		respond(c, 500, false, "SNMP get failed: "+err.Error(), nil)
		return
	}

	type currVal struct {
		in   uint64
		out  uint64
		in32 uint64
		out32 uint64
		oper int
	}
	curr := make(map[int]*currVal, len(selected))
	for _, idx := range selected {
		curr[idx] = &currVal{}
	}

	for _, v := range packet.Variables {
		idx := oidLastInt(v.Name)
		if idx <= 0 {
			continue
		}
		row, ok := curr[idx]
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.31.1.1.1.6."):
			row.in = pduToUint64(v)
		case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.31.1.1.1.10."):
			row.out = pduToUint64(v)
		case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.2.2.1.10."):
			row.in32 = pduToUint64(v)
		case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.2.2.1.16."):
			row.out32 = pduToUint64(v)
		case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.2.2.1.8."):
			row.oper = int(pduToUint64(v))
		}
	}

	now := time.Now()
	rows := make([]map[string]interface{}, 0, len(selected))

	snmpPrevMu.Lock()
	for _, idx := range selected {
		info := ifaceMap[idx]
		val := curr[idx]
		if val.in == 0 && val.in32 > 0 {
			val.in = val.in32
		}
		if val.out == 0 && val.out32 > 0 {
			val.out = val.out32
		}
		key := fmt.Sprintf("%d:%d", routerID, idx)
		prev, hasPrev := snmpPrev[key]

		rxBpsRaw := int64(0)
		txBpsRaw := int64(0)
		rxBps := prev.RxBps
		txBps := prev.TxBps
		if hasPrev {
			sec := now.Sub(prev.Timestamp).Seconds()
			if sec >= 0.5 && sec <= 20 {
				if val.in >= prev.InOctets {
					rxBpsRaw = int64(float64((val.in-prev.InOctets)*8) / sec)
				}
				if val.out >= prev.OutOctets {
					txBpsRaw = int64(float64((val.out-prev.OutOctets)*8) / sec)
				}
				// EMA smoothing to reduce jitter spikes and make graph stable.
				rxBps = emaBps(prev.RxBps, rxBpsRaw, 0.35)
				txBps = emaBps(prev.TxBps, txBpsRaw, 0.35)
			}
		} else {
			rxBps = 0
			txBps = 0
		}
		snmpPrev[key] = snmpCounterState{
			InOctets:  val.in,
			OutOctets: val.out,
			Timestamp: now,
			RxBps:     rxBps,
			TxBps:     txBps,
		}

		statusTxt := "unknown"
		switch val.oper {
		case 1:
			statusTxt = "up"
		case 2:
			statusTxt = "down"
		case 3:
			statusTxt = "testing"
		}

		rows = append(rows, map[string]interface{}{
			"router_id":      routerID,
			"router_name":    router.Name,
			"if_index":       idx,
			"display_name":   firstNonEmpty(info.DisplayName, info.Name, info.Description, "if"+strconv.Itoa(idx)),
			"interface_name": firstNonEmpty(info.Name, info.DisplayName, info.Description, "if"+strconv.Itoa(idx)),
			"description":    info.Description,
			"alias":          info.Alias,
			"oper_status":    statusTxt,
			"rx_bps":         rxBps,
			"tx_bps":         txBps,
			"rx_bps_raw":     rxBpsRaw,
			"tx_bps_raw":     txBpsRaw,
			"rx_human":       formatBps(rxBps),
			"tx_human":       formatBps(txBps),
			"poll_time":      now,
		})
	}
	snmpPrevMu.Unlock()

	sort.Slice(rows, func(i, j int) bool {
		ri, _ := rows[i]["rx_bps"].(int64)
		ti, _ := rows[i]["tx_bps"].(int64)
		rj, _ := rows[j]["rx_bps"].(int64)
		tj, _ := rows[j]["tx_bps"].(int64)
		return (ri + ti) > (rj + tj)
	})

	if len(rows) > 0 {
		samples := make([]models.NMSSample, 0, len(rows))
		for _, row := range rows {
			ifIndex, _ := row["if_index"].(int)
			if ifIndex <= 0 {
				ifIndex64, _ := row["if_index"].(int64)
				if ifIndex64 > 0 {
					ifIndex = int(ifIndex64)
				}
			}
			rxBps, _ := row["rx_bps"].(int64)
			txBps, _ := row["tx_bps"].(int64)
			samples = append(samples, models.NMSSample{
				RouterID:       routerID,
				IfIndex:        ifIndex,
				InterfaceName:  firstNonEmpty(stringValue(row["interface_name"]), stringValue(row["display_name"])),
				InterfaceLabel: firstNonEmpty(stringValue(row["display_name"]), stringValue(row["interface_name"])),
				OperStatus:     stringValue(row["oper_status"]),
				RxBps:          rxBps,
				TxBps:          txBps,
				SampledAt:      now,
			})
		}
		_ = h.userRepo.SaveNMSSamples(samples)
	}

	respond(c, 200, true, "OK", gin.H{
		"community": usedCommunity,
		"rows":      rows,
	})
}

func (h *Handler) GetSNMPHistory(c *gin.Context) {
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

	from, to, bucket, err := parseNMSHistoryWindow(c)
	if err != nil {
		respond(c, 400, false, err.Error(), nil)
		return
	}
	rows, err := h.userRepo.GetNMSSamples(models.NMSHistoryFilter{
		RouterID:      routerID,
		IfIndexes:     parseIndexFilter(c.Query("if_index")),
		From:          from,
		To:            to,
		BucketSeconds: bucket,
	})
	if err != nil {
		respond(c, 500, false, "Gagal ambil history NMS: "+err.Error(), nil)
		return
	}

	type seriesPoint struct {
		At    string `json:"at"`
		RxBps int64  `json:"rx_bps"`
		TxBps int64  `json:"tx_bps"`
	}
	type seriesPayload struct {
		RouterID       int           `json:"router_id"`
		RouterName     string        `json:"router_name"`
		IfIndex        int           `json:"if_index"`
		InterfaceName  string        `json:"interface_name"`
		InterfaceLabel string        `json:"interface_label"`
		OperStatus     string        `json:"oper_status"`
		LastUpdate     string        `json:"last_update"`
		Points         []seriesPoint `json:"points"`
	}

	seriesMap := map[int]*seriesPayload{}
	totalPoints := 0
	for _, row := range rows {
		item := seriesMap[row.IfIndex]
		if item == nil {
			item = &seriesPayload{
				RouterID:       routerID,
				RouterName:     router.Name,
				IfIndex:        row.IfIndex,
				InterfaceName:  row.InterfaceName,
				InterfaceLabel: firstNonEmpty(row.InterfaceLabel, row.InterfaceName, "if"+strconv.Itoa(row.IfIndex)),
				OperStatus:     firstNonEmpty(row.OperStatus, "unknown"),
				Points:         make([]seriesPoint, 0, 128),
			}
			seriesMap[row.IfIndex] = item
		}
		at := formatJakarta(row.SampledAt)
		item.LastUpdate = at
		item.OperStatus = firstNonEmpty(row.OperStatus, item.OperStatus)
		item.Points = append(item.Points, seriesPoint{
			At:    at,
			RxBps: row.RxBps,
			TxBps: row.TxBps,
		})
		totalPoints++
	}

	series := make([]seriesPayload, 0, len(seriesMap))
	indexes := make([]int, 0, len(seriesMap))
	for idx := range seriesMap {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	for _, idx := range indexes {
		series = append(series, *seriesMap[idx])
	}

	respond(c, 200, true, "OK", gin.H{
		"router_id":       routerID,
		"router_name":     router.Name,
		"from":            formatJakarta(from),
		"to":              formatJakarta(to),
		"bucket_seconds":  bucket,
		"interval_label":  describeNMSBucket(bucket),
		"total_points":    totalPoints,
		"series":          series,
	})
}

func connectSNMP(ip string, port int, community string, version gosnmp.SnmpVersion) (*gosnmp.GoSNMP, error) {
	community = strings.TrimSpace(community)
	if community == "" {
		community = "public"
	}
	if port <= 0 {
		port = 161
	}
	client := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      uint16(port),
		Community: community,
		Version:   version,
		Timeout:   2500 * time.Millisecond,
		Retries:   1,
		MaxOids:   gosnmp.MaxOids,
	}
	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

func connectSNMPWithFallback(ip string, port int, configuredCommunity string) (*gosnmp.GoSNMP, string, error) {
	if port <= 0 {
		port = 161
	}
	cands := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		cands = append(cands, v)
	}
	add(configuredCommunity)
	add("public")
	add("private")
	if len(cands) == 0 {
		cands = []string{"public"}
	}

	targetKey := fmt.Sprintf("%s:%d", ip, port)
	if prefClient, prefLabel, ok := tryPreferredSNMP(targetKey, ip, port); ok {
		return prefClient, prefLabel, nil
	}

	errs := make([]string, 0, len(cands))
	versions := []gosnmp.SnmpVersion{gosnmp.Version2c, gosnmp.Version1}

	for _, comm := range cands {
		for _, ver := range versions {
			client, err := connectSNMP(ip, port, comm, ver)
			if err != nil {
				errs = append(errs, maskCommunity(comm)+" "+snmpVersionLabel(ver)+": "+err.Error())
				continue
			}
			pkt, getErr := client.Get([]string{".1.3.6.1.2.1.1.1.0"})
			if getErr != nil || pkt == nil || len(pkt.Variables) == 0 {
				if client.Conn != nil {
					client.Conn.Close()
				}
				msg := "unknown error"
				if getErr != nil {
					msg = getErr.Error()
				}
				errs = append(errs, maskCommunity(comm)+" "+snmpVersionLabel(ver)+": "+msg)
				continue
			}
			rememberPreferredSNMP(targetKey, comm, ver)
			return client, maskCommunity(comm)+" "+snmpVersionLabel(ver), nil
		}
	}
	srcIP := detectSourceIP(ip, port)
	hint := "Cek SNMP enable, community, allowed-address, dan firewall UDP/161"
	if srcIP != "" {
		hint += " (tambahkan " + srcIP + " ke allowed-address SNMP MikroTik)"
	}
	return nil, "", fmt.Errorf("semua community gagal (%s). %s", strings.Join(errs, " | "), hint)
}

func maskCommunity(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "(empty)"
	}
	if len(v) <= 2 {
		return "**"
	}
	return v[:1] + strings.Repeat("*", len(v)-2) + v[len(v)-1:]
}

func snmpVersionLabel(v gosnmp.SnmpVersion) string {
	if v == gosnmp.Version1 {
		return "(v1)"
	}
	return "(v2c)"
}

func detectSourceIP(target string, port int) string {
	if port <= 0 {
		port = 161
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(target, strconv.Itoa(port)), 1200*time.Millisecond)
	if err != nil || conn == nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr != nil && addr.IP != nil {
		return addr.IP.String()
	}
	return ""
}

func getCachedInterfaces(routerID int, client *gosnmp.GoSNMP, force bool) ([]snmpIfaceInfo, error) {
	now := time.Now()
	if !force {
		snmpIfaceCacheMu.Lock()
		item, ok := snmpIfaceCache[routerID]
		snmpIfaceCacheMu.Unlock()
		if ok && item.ExpiresAt.After(now) && len(item.Items) > 0 {
			return item.Items, nil
		}
	}

	items, err := collectSNMPInterfaces(client)
	if err != nil {
		return nil, err
	}
	snmpIfaceCacheMu.Lock()
	snmpIfaceCache[routerID] = snmpIfaceCacheItem{
		Items:     items,
		ExpiresAt: now.Add(2 * time.Minute),
	}
	snmpIfaceCacheMu.Unlock()
	return items, nil
}

func getInterfaceCacheSnapshot(routerID int) []snmpIfaceInfo {
	snmpIfaceCacheMu.Lock()
	item, ok := snmpIfaceCache[routerID]
	snmpIfaceCacheMu.Unlock()
	if !ok || len(item.Items) == 0 {
		return nil
	}
	out := make([]snmpIfaceInfo, len(item.Items))
	copy(out, item.Items)
	return out
}

func tryPreferredSNMP(targetKey, ip string, port int) (*gosnmp.GoSNMP, string, bool) {
	now := time.Now()
	snmpPrefMu.Lock()
	pref, ok := snmpPreferred[targetKey]
	snmpPrefMu.Unlock()
	if !ok || pref.ExpiresAt.Before(now) {
		return nil, "", false
	}
	client, err := connectSNMP(ip, port, pref.Community, pref.Version)
	if err != nil {
		return nil, "", false
	}
	return client, maskCommunity(pref.Community) + " " + snmpVersionLabel(pref.Version), true
}

func rememberPreferredSNMP(targetKey, community string, version gosnmp.SnmpVersion) {
	snmpPrefMu.Lock()
	snmpPreferred[targetKey] = snmpPreferredItem{
		Community: strings.TrimSpace(community),
		Version:   version,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	snmpPrefMu.Unlock()
}

func clearPreferredSNMP(ip string, port int) {
	if port <= 0 {
		port = 161
	}
	key := fmt.Sprintf("%s:%d", ip, port)
	snmpPrefMu.Lock()
	delete(snmpPreferred, key)
	snmpPrefMu.Unlock()
}

func collectSNMPInterfaces(client *gosnmp.GoSNMP) ([]snmpIfaceInfo, error) {
	byIdx := map[int]*snmpIfaceInfo{}

	_ = client.Walk(".1.3.6.1.2.1.31.1.1.1.1", func(pdu gosnmp.SnmpPDU) error {
		idx := oidLastInt(pdu.Name)
		if idx <= 0 {
			return nil
		}
		if _, ok := byIdx[idx]; !ok {
			byIdx[idx] = &snmpIfaceInfo{IfIndex: idx}
		}
		byIdx[idx].Name = strings.TrimSpace(pduToString(pdu))
		return nil
	})

	if err := client.Walk(".1.3.6.1.2.1.2.2.1.2", func(pdu gosnmp.SnmpPDU) error {
		idx := oidLastInt(pdu.Name)
		if idx <= 0 {
			return nil
		}
		if _, ok := byIdx[idx]; !ok {
			byIdx[idx] = &snmpIfaceInfo{IfIndex: idx}
		}
		byIdx[idx].Description = strings.TrimSpace(pduToString(pdu))
		return nil
	}); err != nil {
		return nil, err
	}

	_ = client.Walk(".1.3.6.1.2.1.31.1.1.1.18", func(pdu gosnmp.SnmpPDU) error {
		idx := oidLastInt(pdu.Name)
		if idx <= 0 {
			return nil
		}
		if _, ok := byIdx[idx]; !ok {
			byIdx[idx] = &snmpIfaceInfo{IfIndex: idx}
		}
		byIdx[idx].Alias = strings.TrimSpace(pduToString(pdu))
		return nil
	})

	if err := client.Walk(".1.3.6.1.2.1.2.2.1.8", func(pdu gosnmp.SnmpPDU) error {
		idx := oidLastInt(pdu.Name)
		if idx <= 0 {
			return nil
		}
		if _, ok := byIdx[idx]; !ok {
			byIdx[idx] = &snmpIfaceInfo{IfIndex: idx}
		}
		byIdx[idx].OperStatus = int(pduToUint64(pdu))
		return nil
	}); err != nil {
		return nil, err
	}

	out := make([]snmpIfaceInfo, 0, len(byIdx))
	for idx, inf := range byIdx {
		if inf.Name == "" {
			inf.Name = "if" + strconv.Itoa(idx)
		}
		inf.DisplayName = buildSNMPInterfaceLabel(inf.Name, inf.Description, inf.Alias, idx)
		out = append(out, *inf)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IfIndex < out[j].IfIndex
	})
	return out, nil
}

func buildSNMPInterfaceLabel(name, description, alias string, idx int) string {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	alias = strings.TrimSpace(alias)
	parts := make([]string, 0, 3)
	push := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		lv := strings.ToLower(v)
		for _, existing := range parts {
			if strings.ToLower(existing) == lv {
				return
			}
		}
		parts = append(parts, v)
	}
	if idx > 0 {
		push("[" + strconv.Itoa(idx) + "]")
	}
	push(name)
	if description != "" && strings.ToLower(description) != strings.ToLower(name) {
		push(description)
	}
	if alias != "" && strings.ToLower(alias) != strings.ToLower(name) && strings.ToLower(alias) != strings.ToLower(description) {
		push(alias)
	}
	if len(parts) == 0 {
		if idx > 0 {
			push("if" + strconv.Itoa(idx))
		} else {
			push("Interface")
		}
	}
	return strings.Join(parts, " - ")
}

func oidLastInt(oid string) int {
	parts := strings.Split(strings.TrimSpace(oid), ".")
	if len(parts) == 0 {
		return 0
	}
	last := parts[len(parts)-1]
	v, _ := strconv.Atoi(last)
	return v
}

func pduToString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

func pduToUint64(pdu gosnmp.SnmpPDU) uint64 {
	switch v := pdu.Value.(type) {
	case uint:
		return uint64(v)
	case uint8:
		return uint64(v)
	case uint16:
		return uint64(v)
	case uint32:
		return uint64(v)
	case uint64:
		return v
	case int:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int8:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int16:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int32:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case string:
		n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		return n
	default:
		return 0
	}
}

func emaBps(prev, curr int64, alpha float64) int64 {
	if curr < 0 {
		curr = 0
	}
	if prev <= 0 {
		return curr
	}
	if alpha <= 0 || alpha >= 1 {
		alpha = 0.35
	}
	return int64((alpha * float64(curr)) + ((1.0 - alpha) * float64(prev)))
}

func getSNMPInChunks(client *gosnmp.GoSNMP, oids []string, chunkSize int) (*gosnmp.SnmpPacket, error) {
	if chunkSize <= 0 {
		chunkSize = 40
	}
	var all []gosnmp.SnmpPDU
	for i := 0; i < len(oids); i += chunkSize {
		end := i + chunkSize
		if end > len(oids) {
			end = len(oids)
		}
		pkt, err := client.Get(oids[i:end])
		if err != nil {
			time.Sleep(150 * time.Millisecond)
			pkt, err = client.Get(oids[i:end])
			if err != nil {
				return nil, err
			}
		}
		if pkt != nil && len(pkt.Variables) > 0 {
			all = append(all, pkt.Variables...)
		}
	}
	return &gosnmp.SnmpPacket{Variables: all}, nil
}

func parseIndexFilter(raw string) []int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	seen := map[int]bool{}
	for _, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func parseNMSHistoryWindow(c *gin.Context) (time.Time, time.Time, int, error) {
	now := time.Now()
	loc := jakartaLocation()
	rangeKey := strings.ToLower(strings.TrimSpace(c.Query("range")))
	from := parseNMSFlexibleTime(c.Query("from"), loc)
	to := parseNMSFlexibleTime(c.Query("to"), loc)
	if to.IsZero() {
		to = now
	}
	if from.IsZero() {
		switch rangeKey {
		case "1h":
			from = to.Add(-1 * time.Hour)
		case "6h":
			from = to.Add(-6 * time.Hour)
		case "24h":
			from = to.Add(-24 * time.Hour)
		case "7d":
			from = to.Add(-7 * 24 * time.Hour)
		case "live":
			from = to.Add(-15 * time.Minute)
		default:
			from = to.Add(-1 * time.Hour)
		}
	}
	if to.Before(from) {
		from, to = to, from
	}
	bucket := 0
	if v, err := strconv.Atoi(strings.TrimSpace(c.Query("bucket"))); err == nil && v > 0 {
		bucket = v
	}
	if bucket <= 0 {
		span := to.Sub(from)
		switch {
		case span <= 2*time.Hour:
			bucket = 30
		case span <= 8*time.Hour:
			bucket = 120
		case span <= 24*time.Hour:
			bucket = 300
		case span <= 72*time.Hour:
			bucket = 900
		default:
			bucket = 1800
		}
	}
	if bucket < 5 {
		bucket = 5
	}
	return from, to, bucket, nil
}

func parseNMSFlexibleTime(raw string, loc *time.Location) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, raw, loc); err == nil {
			return t
		}
	}
	if unixMs, err := strconv.ParseInt(raw, 10, 64); err == nil && unixMs > 0 {
		if unixMs > 1_000_000_000_000 {
			return time.UnixMilli(unixMs).In(loc)
		}
		return time.Unix(unixMs, 0).In(loc)
	}
	return time.Time{}
}

func describeNMSBucket(bucket int) string {
	switch {
	case bucket < 60:
		return strconv.Itoa(bucket) + " detik"
	case bucket < 3600:
		return strconv.Itoa(bucket/60) + " menit"
	default:
		return strconv.Itoa(bucket/3600) + " jam"
	}
}

func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case fmt.Stringer:
		return strings.TrimSpace(x.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
