package model

import "time"

type OLT struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Name           string    `gorm:"type:varchar(160);not null" json:"name"`
	IPAddress      string    `gorm:"type:varchar(45);not null;index" json:"ip_address"`
	SNMPRO         string    `gorm:"type:varchar(160);not null;column:snmp_ro" json:"snmp_ro"`
	SNMPRW         string    `gorm:"type:varchar(160);column:snmp_rw" json:"snmp_rw"`
	SNMPPort       int       `gorm:"default:161;column:snmp_port" json:"snmp_port"`
	TelnetHost     string    `gorm:"type:varchar(120);column:telnet_host" json:"telnet_host"`
	TelnetPort     int       `gorm:"default:23;column:telnet_port" json:"telnet_port"`
	TelnetUsername string    `gorm:"type:varchar(120);column:telnet_username" json:"telnet_username"`
	TelnetPassword string    `gorm:"type:varchar(255);column:telnet_password" json:"telnet_password,omitempty"`
	CreatedAt      time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (OLT) TableName() string { return "olts" }

type ONUDevice struct {
	ID            uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	OLTID         uint       `gorm:"not null;index;uniqueIndex:uniq_olt_serial" json:"olt_id"`
	OLT           OLT        `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
	SerialNumber  string     `gorm:"type:varchar(120);not null;index;uniqueIndex:uniq_olt_serial" json:"serial_number"`
	ONUInterface  string     `gorm:"type:varchar(120);column:onu_interface;index" json:"onu_interface"`
	Name          string     `gorm:"type:varchar(180)" json:"name"`
	ONUType       string     `gorm:"type:varchar(80);column:onu_type" json:"onu_type"`
	Description   string     `gorm:"type:text" json:"description"`
	BoardPort     string     `gorm:"type:varchar(80)" json:"board_port"`
	Status        string     `gorm:"type:varchar(32);index" json:"status"`
	AdminState    string     `gorm:"type:varchar(40);column:admin_state" json:"admin_state"`
	PhaseState    string     `gorm:"type:varchar(40);column:phase_state" json:"phase_state"`
	PPPoEUsername string     `gorm:"type:varchar(180);column:pppoe_username;index" json:"pppoe_username"`
	PPPoEPassword string     `gorm:"type:varchar(255);column:pppoe_password" json:"pppoe_password,omitempty"`
	VLAN          string     `gorm:"type:varchar(32);column:vlan;index" json:"vlan"`
	RXPower       *float64   `gorm:"column:rx_power" json:"rx_power"`
	TXPower       *float64   `gorm:"column:tx_power" json:"tx_power"`
	LastOnline    *time.Time `gorm:"column:last_online;index" json:"last_online"`
	LastOffline   *time.Time `gorm:"column:last_offline;index" json:"last_offline"`
	OfflineReason string     `gorm:"type:varchar(120);column:offline_reason" json:"offline_reason"`
	LastSeen      *time.Time `gorm:"column:last_seen;index" json:"last_seen"`
}

func (ONUDevice) TableName() string { return "onu_devices" }

type OLTTestConnectionRequest struct {
	IPAddress      string `json:"ip_address" binding:"required"`
	SNMPRO         string `json:"snmp_ro" binding:"required"`
	SNMPPort       int    `json:"snmp_port"`
	TelnetHost     string `json:"telnet_host"`
	TelnetPort     int    `json:"telnet_port"`
	TelnetUsername string `json:"telnet_username"`
	TelnetPassword string `json:"telnet_password"`
}

type OLTTestConnectionResult struct {
	SNMP   bool   `json:"snmp"`
	Telnet bool   `json:"telnet"`
	Error  string `json:"error,omitempty"`
}

type OLTSyncStatus struct {
	OLTID          uint       `json:"olt_id"`
	Running        bool       `json:"running"`
	LastStartedAt  *time.Time `json:"last_started_at,omitempty"`
	LastFinishedAt *time.Time `json:"last_finished_at,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	LastCount      int        `json:"last_count"`
	Message        string     `json:"message"`
}

type OLTTelnetDumpSection struct {
	Label   string `json:"label,omitempty"`
	Command string `json:"command"`
	Output  string `json:"output"`
}

type OLTTelnetDump struct {
	OLTID        uint                   `json:"olt_id"`
	OLTName      string                 `json:"olt_name"`
	OLTIPAddress string                 `json:"olt_ip_address"`
	TelnetHost   string                 `json:"telnet_host"`
	RetrievedAt  time.Time              `json:"retrieved_at"`
	Mode         string                 `json:"mode,omitempty"`
	Preset       string                 `json:"preset,omitempty"`
	Target       string                 `json:"target,omitempty"`
	Sections     []OLTTelnetDumpSection `json:"sections"`
}
