package models

import "time"

type User struct {
	ID        int        `db:"id" json:"id"`
	Username  string     `db:"username" json:"username"`
	Password  string     `db:"password" json:"-"`
	FullName  string     `db:"full_name" json:"full_name"`
	Role      string     `db:"role" json:"role"`
	IsActive  bool       `db:"is_active" json:"is_active"`
	LastLogin *time.Time `db:"last_login" json:"last_login"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

type Router struct {
	ID          int       `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	IPAddress   string    `db:"ip_address" json:"ip_address"`
	APIPort     int       `db:"api_port" json:"api_port"`
	SNMPUser    string    `db:"snmp_user" json:"snmp_user"`
	SNMPPort    int       `db:"snmp_port" json:"snmp_port"`
	Username    string    `db:"username" json:"username"`
	Password    string    `db:"password" json:"password,omitempty"`
	Email       string    `db:"email" json:"email"`
	Description string    `db:"description" json:"description"`
	IsActive    bool      `db:"is_active" json:"is_active"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

type RouterListFilter struct {
	Search  string
	Page    int
	Limit   int
	Summary bool
}

type PPPSecret struct {
	ID            int64      `db:"id" json:"id"`
	RouterID      int        `db:"router_id" json:"router_id"`
	Username      string     `db:"username" json:"username"`
	SessionID     string     `json:"session_id,omitempty"`
	IPAddress     string     `db:"ip_address" json:"ip_address"`
	InterfaceName string     `db:"interface_name" json:"interface_name"`
	Profile       string     `db:"profile" json:"profile"`
	Service       string     `db:"service" json:"service"`
	LocalAddress  string     `db:"local_address" json:"local_address"`
	RemoteAddress string     `db:"remote_address" json:"remote_address"`
	Uptime        string     `db:"uptime" json:"uptime"`
	LastLinkDown  string     `db:"last_link_down" json:"last_link_down"`
	LastLinkUp    string     `db:"last_link_up" json:"last_link_up"`
	Status        string     `db:"status" json:"status"`
	CallerID      string     `db:"caller_id" json:"caller_id"`
	BytesIn       int64      `db:"bytes_in" json:"bytes_in"`
	BytesOut      int64      `db:"bytes_out" json:"bytes_out"`
	LastSeen      *time.Time `db:"last_seen" json:"last_seen"`
	SyncedAt      time.Time  `db:"synced_at" json:"synced_at"`
	RouterName    string     `db:"router_name" json:"router_name,omitempty"`
	RouterIP      string     `db:"router_ip" json:"router_ip,omitempty"`
	Disabled      bool       `json:"disabled,omitempty"`
	MonitoringEnabled bool   `json:"monitoring_enabled,omitempty"`
}

type TrafficHistory struct {
	ID            int64     `db:"id" json:"id"`
	RouterID      int       `db:"router_id" json:"router_id"`
	InterfaceName string    `db:"interface_name" json:"interface_name"`
	RxBps         int64     `db:"rx_bps" json:"rx_bps"`
	TxBps         int64     `db:"tx_bps" json:"tx_bps"`
	RecordedAt    time.Time `db:"recorded_at" json:"recorded_at"`
}

type NMSSample struct {
	RouterID       int       `db:"router_id" json:"router_id"`
	IfIndex        int       `db:"if_index" json:"if_index"`
	InterfaceName  string    `db:"interface_name" json:"interface_name"`
	InterfaceLabel string    `db:"interface_label" json:"interface_label"`
	OperStatus     string    `db:"oper_status" json:"oper_status"`
	RxBps          int64     `db:"rx_bps" json:"rx_bps"`
	TxBps          int64     `db:"tx_bps" json:"tx_bps"`
	SampledAt      time.Time `db:"sampled_at" json:"sampled_at"`
}

type NMSHistoryFilter struct {
	RouterID      int
	IfIndexes     []int
	From          time.Time
	To            time.Time
	BucketSeconds int
}

type TrafficData struct {
	InterfaceName string `json:"interface_name"`
	RxBps         int64  `json:"rx_bps"`
	TxBps         int64  `json:"tx_bps"`
	RxHuman       string `json:"rx_human"`
	TxHuman       string `json:"tx_human"`
	RouterName    string `json:"router_name"`
	RouterID      int    `json:"router_id"`
}

type SyncSettings struct {
	ID                  int        `db:"id" json:"id"`
	AutoSyncEnabled     bool       `db:"auto_sync_enabled" json:"auto_sync_enabled"`
	SyncIntervalSeconds int        `db:"sync_interval_seconds" json:"sync_interval_seconds"`
	LastSyncAt          *time.Time `db:"last_sync_at" json:"last_sync_at"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `db:"updated_at" json:"updated_at"`
}

type SyncLog struct {
	ID            int64     `db:"id" json:"id"`
	RouterID      *int      `db:"router_id" json:"router_id"`
	RouterName    string    `db:"router_name" json:"router_name"`
	Status        string    `db:"status" json:"status"`
	Message       string    `db:"message" json:"message"`
	DurationMs    int       `db:"duration_ms" json:"duration_ms"`
	RecordsSynced int       `db:"records_synced" json:"records_synced"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}

type TroubleshootLog struct {
	ID           int64      `db:"id" json:"id"`
	Level        string     `db:"level" json:"level"`
	Source       string     `db:"source" json:"source"`
	Scope        string     `db:"scope" json:"scope"`
	Message      string     `db:"message" json:"message"`
	Details      string     `db:"details" json:"details"`
	RouterID     *int       `db:"router_id" json:"router_id"`
	RouterName   string     `db:"router_name" json:"router_name"`
	RouterIP     string     `db:"router_ip" json:"router_ip"`
	OLTID        *int       `db:"olt_id" json:"olt_id"`
	OLTName      string     `db:"olt_name" json:"olt_name"`
	OLTIPAddress string     `db:"olt_ip_address" json:"olt_ip_address"`
	ONUInterface string     `db:"onu_interface" json:"onu_interface"`
	SerialNumber string     `db:"serial_number" json:"serial_number"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
}

type MonitoringStats struct {
	TotalPelanggan int `json:"total_pelanggan"`
	TotalAktif     int `json:"total_aktif"`
	TotalOffline   int `json:"total_offline"`
	ProfileIsolir  int `json:"profile_isolir"`
	TotalRouters   int `json:"total_routers"`
	ActiveRouters  int `json:"active_routers"`
}

type RouterStatus struct {
	RouterID   int    `json:"router_id"`
	RouterName string `json:"router_name"`
	RouterIP   string `json:"router_ip"`
	IsOnline   bool   `json:"is_online"`
	TotalUsers int    `json:"total_users"`
	Online     int    `json:"online"`
	Offline    int    `json:"offline"`
	Isolir     int    `json:"isolir"`
}

type PPPFilter struct {
	RouterID string
	Status   string
	Profile  string
	InterfaceName string
	Search   string
	Page     int
	Limit    int
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	Limit      int         `json:"limit"`
	TotalPages int         `json:"total_pages"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

type ServerInfo struct {
	Hostname      string  `json:"hostname"`
	OS            string  `json:"os"`
	Kernel        string  `json:"kernel"`
	UptimeSeconds int64   `json:"uptime_seconds"`
	UptimeHuman   string  `json:"uptime_human"`
	CPUCores      int     `json:"cpu_cores"`
	MemoryTotalMB float64 `json:"memory_total_mb"`
	MemoryUsedMB  float64 `json:"memory_used_mb"`
	MemoryFreeMB  float64 `json:"memory_free_mb"`
	StorageTotal  string  `json:"storage_total"`
	StorageUsed   string  `json:"storage_used"`
	StorageFree   string  `json:"storage_free"`
}

type UserMonitoringPPPInterface struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Service      string `json:"service"`
	Flag         string `json:"flag,omitempty"`
	Status       string `json:"status"`
	Running      bool   `json:"running"`
	Disabled     bool   `json:"disabled,omitempty"`
	LastLinkDown string `json:"last_link_down"`
	LastLinkUp   string `json:"last_link_up"`
	LastChange   string `json:"last_change,omitempty"`
	Note         string `json:"note,omitempty"`
	Source       string `json:"source,omitempty"`
}
