package snmp

import (
	"testing"
)

// Test 1: Format asli dari OLT ZTE C320 V2.1.0 kamu
func TestParseZTEC320RealOutput(t *testing.T) {
	raw := `
pon-onu-mng gpon-onu_1/1/1:1
  flow mode 1 tag-filter vlan-filter untag-filter discard
  flow 1 pri 0 vlan 1009
  gemport 1 flow 1
  switchport-bind switch_0/1 iphost 1
  switchport-bind switch_0/1 veip 1
  pppoe 1 nat enable user samsulhuda@isp.net password 1234
  vlan-filter-mode iphost 1 tag-filter vlan-filter untag-filter discard
  vlan-filter iphost 1 pri 0 vlan 1009
  dhcp-ip ethuni eth_0/1 from-onu
`
	result := parseONUServiceInfo(raw)
	entry, ok := result["gpon-onu_1/1/1:1"]
	if !ok {
		t.Fatalf("key gpon-onu_1/1/1:1 tidak ditemukan, keys: %v", keysOf(result))
	}
	if entry.PPPoEUser != "samsulhuda@isp.net" {
		t.Errorf("PPPoEUser: got %q want %q", entry.PPPoEUser, "samsulhuda@isp.net")
	}
	if entry.PPPoEPass != "1234" {
		t.Errorf("PPPoEPass: got %q want %q", entry.PPPoEPass, "1234")
	}
	if entry.VLAN != "1009" {
		t.Errorf("VLAN: got %q want %q", entry.VLAN, "1009")
	}
}

// Test 2: Format "pppoe 1 user X password Y" (tanpa "nat enable")
func TestParsePPPoESimpleFormat(t *testing.T) {
	raw := `
pon-onu-mng gpon-onu_1/1/2:3
  flow 1 pri 0 vlan 200
  pppoe 1 user abc@isp.net password secret99
`
	result := parseONUServiceInfo(raw)
	entry, ok := result["gpon-onu_1/1/2:3"]
	if !ok {
		t.Fatal("key tidak ditemukan")
	}
	if entry.PPPoEUser != "abc@isp.net" {
		t.Errorf("PPPoEUser: got %q", entry.PPPoEUser)
	}
	if entry.PPPoEPass != "secret99" {
		t.Errorf("PPPoEPass: got %q", entry.PPPoEPass)
	}
}

// Test 3: Last Online / Last Offline dari "show gpon onu detail-info"
func TestParseDetailInfoLastOnlineOffline(t *testing.T) {
	raw := `
pon-onu-mng gpon-onu_1/1/1:1
  flow 1 pri 0 vlan 1009
  pppoe 1 nat enable user samsul@isp.net password 1234

ONU interface: gpon-onu_1/1/1:1
Name: PERUM_JAPANAN_SAMSUL
Phase state: working
------------------------------------------
Authpass Time         OfflineTime          Cause
1  2024-01-15 08:30:00  2024-01-14 22:00:00  DyingGasp
2  2024-01-14 07:00:00  0000-00-00 00:00:00  LOS
3  0000-00-00 00:00:00  0000-00-00 00:00:00
`
	result := parseONUServiceInfo(raw)
	entry, ok := result["gpon-onu_1/1/1:1"]
	if !ok {
		t.Fatal("key tidak ditemukan")
	}
	if entry.LastOnline != "2024-01-15 08:30:00" {
		t.Errorf("LastOnline: got %q want %q", entry.LastOnline, "2024-01-15 08:30:00")
	}
	if entry.LastOffline != "2024-01-14 22:00:00" {
		t.Errorf("LastOffline: got %q want %q", entry.LastOffline, "2024-01-14 22:00:00")
	}
	if entry.OfflineReason != "DyingGasp" {
		t.Errorf("OfflineReason: got %q want %q", entry.OfflineReason, "DyingGasp")
	}
}

// Test 4: Normalisasi interface - semua format harus menghasilkan canonical key yang sama
func TestNormalizeONUInterface(t *testing.T) {
	cases := []struct{ input, want string }{
		{"gpon-onu_1/1/1:1", "gpon-onu_1/1/1:1"},
		{"gpon_1/1/1:1", "gpon-onu_1/1/1:1"},
		{"GPON_1/1/1:1", "gpon-onu_1/1/1:1"},
		{"gpon-onu_1_1_1:1", "gpon-onu_1/1/1:1"},
		{"gpon1/1/1:1", "gpon-onu_1/1/1:1"},
	}
	for _, c := range cases {
		got := normalizeONUInterface(c.input)
		if got != c.want {
			t.Errorf("normalizeONUInterface(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// Test 5: Simulasi lookup SNMP BoardPort "gpon_1/1/1:1" ke Telnet key "gpon-onu_1/1/1:1"
func TestSNMPBoardPortLookup(t *testing.T) {
	raw := `
pon-onu-mng gpon-onu_1/1/1:1
  flow 1 pri 0 vlan 1009
  pppoe 1 nat enable user samsul@isp.net password 1234
`
	parsed := parseONUServiceInfo(raw)
	// SNMP menghasilkan BoardPort = "gpon_1/1/1:1"
	lookupKey := normalizeONUInterface("gpon_1/1/1:1")
	if _, ok := parsed[lookupKey]; !ok {
		t.Errorf("Lookup GAGAL: key %q tidak ada di map. Keys: %v", lookupKey, keysOf(parsed))
	}
}

// Test 6: Format service gemport vlan (format lain di ZTE C320)
func TestParseServiceGemportVLAN(t *testing.T) {
	raw := `
pon-onu-mng gpon-onu_1/2/11:8
  service Internet-Customer1 gemport 1 vlan 671
  pppoe 1 user customer@isp password mypass
`
	result := parseONUServiceInfo(raw)
	entry, ok := result["gpon-onu_1/2/11:8"]
	if !ok {
		t.Fatal("key tidak ditemukan")
	}
	if entry.VLAN != "671" {
		t.Errorf("VLAN: got %q want %q", entry.VLAN, "671")
	}
}

func TestParseRunningConfigBulkSections(t *testing.T) {
	raw := `
pon-onu-mng gpon-onu_1/1/2:22
  flow mode 1 tag-filter vlan-filter untag-filter discard
  flow 1 pri 0 vlan 663
  gemport 1 flow 1
  switchport-bind switch_0/1 iphost 1
  switchport-bind switch_0/1 veip 1
  pppoe 1 nat enable user didikkurniawancendoro@salak.net password 1234
  vlan-filter-mode iphost 1 tag-filter vlan-filter untag-filter discard
  vlan-filter iphost 1 pri 0 vlan 663
!
pon-onu-mng gpon-onu_1/1/2:23
  flow mode 1 tag-filter vlan-filter untag-filter discard
  flow 1 pri 0 vlan 663
  gemport 1 flow 1
  switchport-bind switch_0/1 iphost 1
  switchport-bind switch_0/1 veip 1
  pppoe 1 nat enable user sumardicndro@salak.net password 1234
  vlan-filter-mode iphost 1 tag-filter vlan-filter untag-filter discard
  vlan-filter iphost 1 pri 0 vlan 663
  dhcp-ip ethuni eth_0/1 from-onu
`
	result := parseONUServiceInfo(raw)
	entry := result["gpon-onu_1/1/2:22"]
	if entry.PPPoEUser != "didikkurniawancendoro@salak.net" {
		t.Errorf("PPPoEUser section 22: got %q", entry.PPPoEUser)
	}
	if entry.PPPoEPass != "1234" {
		t.Errorf("PPPoEPass section 22: got %q", entry.PPPoEPass)
	}
	if entry.VLAN != "663" {
		t.Errorf("VLAN section 22: got %q", entry.VLAN)
	}
	entry2 := result["gpon-onu_1/1/2:23"]
	if entry2.PPPoEUser != "sumardicndro@salak.net" {
		t.Errorf("PPPoEUser section 23: got %q", entry2.PPPoEUser)
	}
	if entry2.PPPoEPass != "1234" {
		t.Errorf("PPPoEPass section 23: got %q", entry2.PPPoEPass)
	}
	if entry2.VLAN != "663" {
		t.Errorf("VLAN section 23: got %q", entry2.VLAN)
	}
}

func TestParseRunningConfigWanIPSection(t *testing.T) {
	raw := `
pon-onu-mng gpon-onu_1/2/7:1
  service 1 gemport 1 cos 0 vlan 100
  wan-ip 1 mode pppoe username 01bumdes password 01BUMDES vlan-profile PPPOE host 1
!
interface gpon-onu_1/2/7:1
  service-port 1 vport 1 user-vlan 100 vlan 100
`
	result := parseONUManagementBlocks(raw)
	entry, ok := result["gpon-onu_1/2/7:1"]
	if !ok {
		t.Fatalf("key gpon-onu_1/2/7:1 tidak ditemukan, keys: %v", keysOf(result))
	}
	if entry.PPPoEUser != "01bumdes" {
		t.Errorf("PPPoEUser: got %q want %q", entry.PPPoEUser, "01bumdes")
	}
	if entry.PPPoEPass != "01BUMDES" {
		t.Errorf("PPPoEPass: got %q want %q", entry.PPPoEPass, "01BUMDES")
	}
	if entry.VLAN != "100" {
		t.Errorf("VLAN: got %q want %q", entry.VLAN, "100")
	}
}

func keysOf(m map[string]onuCLIServiceInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
