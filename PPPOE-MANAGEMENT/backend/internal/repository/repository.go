package repository

import (
	"database/sql"
	"fmt"
	"mikrotik-ppp-management/internal/models"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// ===== User Repository =====
type UserRepository struct{ db *sqlx.DB }

func NewUserRepository(db *sqlx.DB) *UserRepository { return &UserRepository{db: db} }

func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	var u models.User
	err := r.db.Get(&u, "SELECT * FROM users WHERE username=? AND is_active=true", username)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) UpdateLastLogin(id int) {
	r.db.Exec("UPDATE users SET last_login=NOW() WHERE id=?", id)
}

func (r *UserRepository) SaveNMSSamples(samples []models.NMSSample) error {
	if len(samples) == 0 {
		return nil
	}
	var b strings.Builder
	args := make([]interface{}, 0, len(samples)*8)
	b.WriteString("INSERT INTO nms_history_samples (router_id, if_index, interface_name, interface_label, oper_status, rx_bps, tx_bps, sampled_at) VALUES ")
	for i, sample := range samples {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("(?,?,?,?,?,?,?,?)")
		args = append(args,
			sample.RouterID,
			sample.IfIndex,
			sample.InterfaceName,
			sample.InterfaceLabel,
			sample.OperStatus,
			sample.RxBps,
			sample.TxBps,
			sample.SampledAt,
		)
	}
	_, err := r.db.Exec(b.String(), args...)
	return err
}

func (r *UserRepository) GetNMSSamples(filter models.NMSHistoryFilter) ([]models.NMSSample, error) {
	if filter.RouterID <= 0 {
		return nil, fmt.Errorf("router id required")
	}
	if filter.From.IsZero() || filter.To.IsZero() {
		return nil, fmt.Errorf("time range required")
	}
	if filter.To.Before(filter.From) {
		filter.From, filter.To = filter.To, filter.From
	}
	bucket := filter.BucketSeconds
	if bucket <= 0 {
		bucket = 60
	}
	query := `
		SELECT
			router_id,
			if_index,
			MAX(interface_name) AS interface_name,
			MAX(interface_label) AS interface_label,
			MAX(oper_status) AS oper_status,
			CAST(ROUND(AVG(rx_bps)) AS SIGNED) AS rx_bps,
			CAST(ROUND(AVG(tx_bps)) AS SIGNED) AS tx_bps,
			FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(sampled_at) / ?) * ?) AS sampled_at
		FROM nms_history_samples
		WHERE router_id = ? AND sampled_at BETWEEN ? AND ?`
	args := []interface{}{bucket, bucket, filter.RouterID, filter.From, filter.To}
	if len(filter.IfIndexes) > 0 {
		query += " AND if_index IN (?)"
		args = append(args, filter.IfIndexes)
	}
	query += `
		GROUP BY router_id, if_index, FLOOR(UNIX_TIMESTAMP(sampled_at) / ?)
		ORDER BY sampled_at ASC, if_index ASC`
	args = append(args, bucket)

	query, args, err := sqlx.In(query, args...)
	if err != nil {
		return nil, err
	}

	var rows []models.NMSSample
	if err := r.db.Select(&rows, query, args...); err != nil {
		return nil, err
	}
	return rows, nil
}

// ===== Router Repository =====
type RouterRepository struct{ db *sqlx.DB }

func NewRouterRepository(db *sqlx.DB) *RouterRepository { return &RouterRepository{db: db} }

func (r *RouterRepository) GetAll() ([]models.Router, error) {
	var routers []models.Router
	err := r.db.Select(&routers, "SELECT * FROM routers ORDER BY id ASC")
	return routers, err
}

func (r *RouterRepository) List(filter models.RouterListFilter) ([]models.Router, int, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 5000 {
		limit = 5000
	}
	page := filter.Page
	if page <= 0 {
		page = 1
	}

	conditions := []string{}
	args := []interface{}{}
	search := strings.TrimSpace(filter.Search)
	if search != "" {
		like := "%" + search + "%"
		conditions = append(conditions, "(name LIKE ? OR ip_address LIKE ? OR username LIKE ? OR email LIKE ? OR description LIKE ?)")
		args = append(args, like, like, like, like, like)
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM routers" + where
	var total int
	if err := r.db.Get(&total, countQuery, args...); err != nil {
		return nil, 0, err
	}

	selectCols := "id, name, ip_address, api_port, snmp_user, snmp_port, username, email, description, is_active, created_at, updated_at"
	if !filter.Summary {
		selectCols = "*"
	}

	query := "SELECT " + selectCols + " FROM routers" + where + " ORDER BY id DESC"
	if !filter.Summary || total > limit {
		offset := (page - 1) * limit
		query += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}

	var routers []models.Router
	if err := r.db.Select(&routers, query, args...); err != nil {
		return nil, 0, err
	}
	return routers, total, nil
}

func (r *RouterRepository) GetByID(id int) (*models.Router, error) {
	var router models.Router
	err := r.db.Get(&router, "SELECT * FROM routers WHERE id=?", id)
	if err != nil {
		return nil, err
	}
	return &router, nil
}

func (r *RouterRepository) Create(router *models.Router) error {
	query := `INSERT INTO routers (name,ip_address,api_port,snmp_user,snmp_port,username,password,email,description,is_active)
	          VALUES (:name,:ip_address,:api_port,:snmp_user,:snmp_port,:username,:password,:email,:description,:is_active)`
	result, err := r.db.NamedExec(query, router)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	router.ID = int(id)
	return nil
}

func (r *RouterRepository) Update(router *models.Router) error {
	query := `UPDATE routers SET name=:name, ip_address=:ip_address, api_port=:api_port,
	          snmp_user=:snmp_user, snmp_port=:snmp_port,
	          username=:username, email=:email, description=:description, is_active=:is_active`
	if router.Password != "" {
		query += ", password=:password"
	}
	query += " WHERE id=:id"
	_, err := r.db.NamedExec(query, router)
	return err
}

func (r *RouterRepository) Delete(id int) error {
	_, err := r.db.Exec("DELETE FROM routers WHERE id=?", id)
	return err
}

// ===== PPP Repository =====
type PPPRepository struct{ db *sqlx.DB }

func NewPPPRepository(db *sqlx.DB) *PPPRepository { return &PPPRepository{db: db} }

func (r *PPPRepository) UpsertSecrets(routerID int, secrets []models.PPPSecret) error {
	if len(secrets) == 0 {
		return nil
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Mark all existing as offline first (Diubah: Hapus semua data lama untuk router ini agar terganti bersih)
	if _, err := tx.Exec("DELETE FROM ppp_secrets WHERE router_id=?", routerID); err != nil {
		return err
	}

	for _, s := range secrets {
		_, err = tx.Exec(`
			INSERT INTO ppp_secrets (router_id, username, interface_name, profile, service, local_address, remote_address, status, uptime, ip_address, last_link_down, last_link_up, caller_id, bytes_in, bytes_out, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				interface_name=VALUES(interface_name),
				profile=VALUES(profile), service=VALUES(service),
				local_address=VALUES(local_address), remote_address=VALUES(remote_address),
				status=VALUES(status), uptime=VALUES(uptime), ip_address=VALUES(ip_address),
				last_link_down=VALUES(last_link_down), last_link_up=VALUES(last_link_up),
				caller_id=VALUES(caller_id), bytes_in=VALUES(bytes_in), bytes_out=VALUES(bytes_out),
				last_seen=VALUES(last_seen), synced_at=NOW()`,
			routerID, s.Username, s.InterfaceName, s.Profile, s.Service, s.LocalAddress, s.RemoteAddress,
			s.Status, s.Uptime, s.IPAddress, s.LastLinkDown, s.LastLinkUp, s.CallerID, s.BytesIn, s.BytesOut, s.LastSeen)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *PPPRepository) GetAllSecrets(filter models.PPPFilter) ([]models.PPPSecret, int, error) {
	conditions := []string{}
	args := []interface{}{}

	if filter.RouterID != "" {
		conditions = append(conditions, "ps.router_id=?")
		args = append(args, filter.RouterID)
	}
	if filter.Status != "" {
		conditions = append(conditions, "ps.status=?")
		args = append(args, filter.Status)
	}
	if filter.Profile != "" {
		if strings.ToUpper(filter.Profile) == "ISOLIR" {
			conditions = append(conditions, "UPPER(ps.profile) LIKE ?")
			args = append(args, "%ISOLIR%")
		} else {
			conditions = append(conditions, "ps.profile LIKE ?")
			args = append(args, "%"+filter.Profile+"%")
		}
	}
	if filter.Search != "" {
		conditions = append(conditions, "(ps.username LIKE ? OR ps.ip_address LIKE ?)")
		args = append(args, "%"+filter.Search+"%", "%"+filter.Search+"%")
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	if err := r.db.Get(&total, fmt.Sprintf("SELECT COUNT(*) FROM ppp_secrets ps %s", where), args...); err != nil {
		return nil, 0, err
	}

	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Limit < 1 {
		filter.Limit = 20
	}
	offset := (filter.Page - 1) * filter.Limit
	args = append(args, filter.Limit, offset)

	query := fmt.Sprintf(`
		SELECT ps.*, r.name as router_name, r.ip_address as router_ip
		FROM ppp_secrets ps
		LEFT JOIN routers r ON r.id=ps.router_id
		%s ORDER BY ps.status ASC, ps.username ASC LIMIT ? OFFSET ?`, where)

	var results []models.PPPSecret
	err := r.db.Select(&results, query, args...)
	return results, total, err
}

func (r *PPPRepository) GetPPPoEAddressMap() (map[string]string, error) {
	rows, err := r.db.Queryx(`
		SELECT username, ip_address, remote_address
		FROM ppp_secrets
		WHERE username <> ''
		ORDER BY synced_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var username, ipAddress, remoteAddress string
		if err := rows.Scan(&username, &ipAddress, &remoteAddress); err != nil {
			continue
		}
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}
		if ip := strings.TrimSpace(ipAddress); ip != "" {
			if _, ok := out[ip]; !ok {
				out[ip] = username
			}
		}
		if ip := strings.TrimSpace(remoteAddress); ip != "" {
			if _, ok := out[ip]; !ok {
				out[ip] = username
			}
		}
	}
	return out, nil
}

func (r *PPPRepository) GetStats() (*models.MonitoringStats, error) {
	stats := &models.MonitoringStats{}
	r.db.Get(&stats.TotalPelanggan, "SELECT COUNT(*) FROM ppp_secrets")
	r.db.Get(&stats.TotalAktif, "SELECT COUNT(*) FROM ppp_secrets WHERE status='online'")
	r.db.Get(&stats.TotalOffline, "SELECT COUNT(*) FROM ppp_secrets WHERE status='offline'")
	r.db.Get(&stats.ProfileIsolir, "SELECT COUNT(*) FROM ppp_secrets WHERE UPPER(profile) LIKE '%ISOLIR%'")
	r.db.Get(&stats.TotalRouters, "SELECT COUNT(*) FROM routers")
	r.db.Get(&stats.ActiveRouters, "SELECT COUNT(*) FROM routers WHERE is_active=true")
	return stats, nil
}

func (r *PPPRepository) GetRouterStatuses() ([]models.RouterStatus, error) {
	rows, err := r.db.Queryx(`
		SELECT r.id, r.name, r.ip_address,
		       COUNT(ps.id) as total_users,
		       SUM(CASE WHEN ps.status='online' THEN 1 ELSE 0 END) as online_count,
		       SUM(CASE WHEN ps.status='offline' THEN 1 ELSE 0 END) as offline_count,
		       SUM(CASE WHEN UPPER(ps.profile) LIKE '%ISOLIR%' THEN 1 ELSE 0 END) as isolir_count
		FROM routers r
		LEFT JOIN ppp_secrets ps ON ps.router_id=r.id
		WHERE r.is_active=true
		GROUP BY r.id, r.name, r.ip_address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []models.RouterStatus
	for rows.Next() {
		var s models.RouterStatus
		if err := rows.Scan(&s.RouterID, &s.RouterName, &s.RouterIP, &s.TotalUsers, &s.Online, &s.Offline, &s.Isolir); err != nil {
			continue
		}
		s.IsOnline = s.Online > 0
		statuses = append(statuses, s)
	}
	return statuses, nil
}

func (r *PPPRepository) GetOnlineChartData() ([]map[string]interface{}, error) {
	rows, err := r.db.Queryx(`
		SELECT r.name as router_name,
		       SUM(CASE WHEN ps.status='online' THEN 1 ELSE 0 END) as online_count,
		       SUM(CASE WHEN ps.status='offline' THEN 1 ELSE 0 END) as offline_count,
		       SUM(CASE WHEN UPPER(ps.profile) LIKE '%ISOLIR%' THEN 1 ELSE 0 END) as isolir_count
		FROM routers r
		LEFT JOIN ppp_secrets ps ON ps.router_id=r.id
		GROUP BY r.id, r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var name string
		var online, offline, isolir int
		if err := rows.Scan(&name, &online, &offline, &isolir); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"router": name, "online": online, "offline": offline, "isolir": isolir,
		})
	}
	return result, nil
}

// ===== Traffic Repository =====
type TrafficRepository struct{ db *sqlx.DB }

func NewTrafficRepository(db *sqlx.DB) *TrafficRepository { return &TrafficRepository{db: db} }

func (r *TrafficRepository) InsertTraffic(routerID int, iface string, rx, tx int64) error {
	_, err := r.db.Exec(
		"INSERT INTO traffic_history (router_id, interface_name, rx_bps, tx_bps) VALUES (?,?,?,?)",
		routerID, iface, rx, tx)
	return err
}

func (r *TrafficRepository) GetRecentTraffic(routerID int, iface string, limit int) ([]models.TrafficHistory, error) {
	var result []models.TrafficHistory
	err := r.db.Select(&result, `
		SELECT * FROM traffic_history
		WHERE router_id=? AND interface_name=?
		ORDER BY recorded_at DESC LIMIT ?`, routerID, iface, limit)
	return result, err
}

func (r *TrafficRepository) CleanOld() {
	r.db.Exec("DELETE FROM traffic_history WHERE recorded_at < DATE_SUB(NOW(), INTERVAL 2 HOUR)")
}

// ===== Sync Repository =====
type SyncRepository struct{ db *sqlx.DB }

func NewSyncRepository(db *sqlx.DB) *SyncRepository { return &SyncRepository{db: db} }

func currentJakartaTime() time.Time {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		loc = time.FixedZone("WIB", 7*3600)
	}
	return time.Now().In(loc)
}

func (r *SyncRepository) GetSettings() (*models.SyncSettings, error) {
	var s models.SyncSettings
	err := r.db.Get(&s, "SELECT * FROM sync_settings LIMIT 1")
	return &s, err
}

func (r *SyncRepository) UpdateSettings(s *models.SyncSettings) error {
	_, err := r.db.Exec("UPDATE sync_settings SET auto_sync_enabled=?, sync_interval_seconds=?",
		s.AutoSyncEnabled, s.SyncIntervalSeconds)
	return err
}

func (r *SyncRepository) UpdateLastSync() error {
	_, err := r.db.Exec("UPDATE sync_settings SET last_sync_at=?", currentJakartaTime())
	return err
}

func (r *SyncRepository) InsertLog(log *models.SyncLog) error {
	_, err := r.db.Exec(`INSERT INTO sync_logs (router_id,router_name,status,message,duration_ms,records_synced,created_at)
		VALUES (?,?,?,?,?,?,?)`,
		log.RouterID, log.RouterName, log.Status, log.Message, log.DurationMs, log.RecordsSynced, currentJakartaTime())
	return err
}

func (r *SyncRepository) GetRecentLogs(limit int) ([]models.SyncLog, error) {
	var logs []models.SyncLog
	err := r.db.Select(&logs, "SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT ?", limit)
	return logs, err
}

// ===== Troubleshoot Repository =====
type TroubleshootRepository struct{ db *sqlx.DB }

func NewTroubleshootRepository(db *sqlx.DB) *TroubleshootRepository {
	return &TroubleshootRepository{db: db}
}

func (r *TroubleshootRepository) InsertLog(logItem *models.TroubleshootLog) error {
	if logItem == nil {
		return nil
	}
	if strings.TrimSpace(logItem.Level) == "" {
		logItem.Level = "info"
	}
	if strings.TrimSpace(logItem.Source) == "" {
		logItem.Source = "system"
	}
	if strings.TrimSpace(logItem.Scope) == "" {
		logItem.Scope = "general"
	}
	logItem.Level = strings.ToLower(strings.TrimSpace(logItem.Level))
	logItem.Source = strings.TrimSpace(logItem.Source)
	logItem.Scope = strings.TrimSpace(logItem.Scope)
	logItem.Message = strings.TrimSpace(logItem.Message)
	logItem.Details = strings.TrimSpace(logItem.Details)
	if logItem.Level == "" {
		logItem.Level = "info"
	}
	if logItem.Message == "" {
		logItem.Message = "Operational event"
	}

	var existingID int64
	_ = r.db.Get(&existingID, `
		SELECT id FROM troubleshoot_logs
		WHERE level=? AND source=? AND scope=? AND message=? AND details=?
			AND COALESCE(router_id, 0)=COALESCE(?, 0)
			AND COALESCE(olt_id, 0)=COALESCE(?, 0)
			AND created_at >= DATE_SUB(NOW(), INTERVAL 60 SECOND)
		ORDER BY created_at DESC LIMIT 1`,
		logItem.Level,
		logItem.Source,
		logItem.Scope,
		logItem.Message,
		logItem.Details,
		logItem.RouterID,
		logItem.OLTID,
	)
	if existingID > 0 {
		_, err := r.db.Exec(`UPDATE troubleshoot_logs
			SET created_at=?, router_name=?, router_ip=?, olt_name=?, olt_ip_address=?, onu_interface=?, serial_number=?
			WHERE id=?`,
			currentJakartaTime(),
			logItem.RouterName,
			logItem.RouterIP,
			logItem.OLTName,
			logItem.OLTIPAddress,
			logItem.ONUInterface,
			logItem.SerialNumber,
			existingID,
		)
		return err
	}
	_, err := r.db.Exec(`INSERT INTO troubleshoot_logs
		(level, source, scope, message, details, router_id, router_name, router_ip, olt_id, olt_name, olt_ip_address, onu_interface, serial_number, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		logItem.Level,
		logItem.Source,
		logItem.Scope,
		logItem.Message,
		logItem.Details,
		logItem.RouterID,
		logItem.RouterName,
		logItem.RouterIP,
		logItem.OLTID,
		logItem.OLTName,
		logItem.OLTIPAddress,
		logItem.ONUInterface,
		logItem.SerialNumber,
		currentJakartaTime(),
	)
	return err
}

func (r *TroubleshootRepository) GetRecentLogs(limit int, source, level, search string) ([]models.TroubleshootLog, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	conditions := []string{}
	args := []interface{}{}
	if source = strings.TrimSpace(source); source != "" {
		conditions = append(conditions, "source = ?")
		args = append(args, source)
	}
	if level = strings.TrimSpace(level); level != "" {
		switch strings.ToLower(level) {
		case "issue", "alert", "problem":
			conditions = append(conditions, "level IN ('warn','warning','error','critical')")
		default:
			conditions = append(conditions, "level = ?")
			args = append(args, strings.ToLower(level))
		}
	}
	if search = strings.TrimSpace(search); search != "" {
		like := "%" + search + "%"
		conditions = append(conditions, "(message LIKE ? OR details LIKE ? OR router_name LIKE ? OR router_ip LIKE ? OR olt_name LIKE ? OR olt_ip_address LIKE ? OR onu_interface LIKE ? OR serial_number LIKE ?)")
		args = append(args, like, like, like, like, like, like, like, like)
	}
	query := "SELECT * FROM troubleshoot_logs"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	var logs []models.TroubleshootLog
	err := r.db.Select(&logs, query, args...)
	return logs, err
}

func (r *TroubleshootRepository) DeleteLogs(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	clean := make([]int64, 0, len(ids))
	seen := map[int64]bool{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		clean = append(clean, id)
	}
	if len(clean) == 0 {
		return 0, nil
	}
	query, args, err := sqlx.In("DELETE FROM troubleshoot_logs WHERE id IN (?)", clean)
	if err != nil {
		return 0, err
	}
	result, err := r.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}

// ===== Extended User Repository =====
func (r *UserRepository) GetAll() ([]models.User, error) {
	var users []models.User
	err := r.db.Select(&users, "SELECT id, username, full_name, role, is_active, last_login, created_at FROM users ORDER BY id ASC")
	return users, err
}

func (r *UserRepository) GetByID(id int) (*models.User, error) {
	var u models.User
	err := r.db.Get(&u, "SELECT * FROM users WHERE id=?", id)
	if err != nil { return nil, err }
	return &u, nil
}

func (r *UserRepository) Create(u *models.User) error {
	result, err := r.db.Exec(
		"INSERT INTO users (username, password, full_name, role, is_active) VALUES (?,?,?,?,?)",
		u.Username, u.Password, u.FullName, u.Role, u.IsActive)
	if err != nil { return err }
	id, _ := result.LastInsertId()
	u.ID = int(id)
	return nil
}

func (r *UserRepository) Update(u *models.User) error {
	_, err := r.db.Exec(
		"UPDATE users SET username=?, full_name=?, role=?, is_active=? WHERE id=?",
		u.Username, u.FullName, u.Role, u.IsActive, u.ID)
	return err
}

func (r *UserRepository) UpdatePassword(id int, hashedPassword string) error {
	_, err := r.db.Exec("UPDATE users SET password=? WHERE id=?", hashedPassword, id)
	return err
}

func (r *UserRepository) Delete(id int) error {
	_, err := r.db.Exec("DELETE FROM users WHERE id=?", id)
	return err
}

func (r *UserRepository) GetNMSLayout(userID int) (string, error) {
	var layout string
	err := r.db.Get(&layout, "SELECT layout_json FROM user_nms_layouts WHERE user_id=?", userID)
	if err == sql.ErrNoRows {
		return "[]", nil
	}
	if err != nil {
		return "", err
	}
	layout = strings.TrimSpace(layout)
	if layout == "" {
		layout = "[]"
	}
	return layout, nil
}

func (r *UserRepository) UpsertNMSLayout(userID int, layout string) error {
	layout = strings.TrimSpace(layout)
	if layout == "" || layout == "null" {
		layout = "[]"
	}
	_, err := r.db.Exec(
		`INSERT INTO user_nms_layouts (user_id, layout_json)
		 VALUES (?, ?)
		 ON DUPLICATE KEY UPDATE layout_json=VALUES(layout_json), updated_at=CURRENT_TIMESTAMP`,
		userID, layout,
	)
	return err
}

func (r *UserRepository) GetUserMonitoringLayout(userID int) (string, error) {
	var layout string
	err := r.db.Get(&layout, "SELECT layout_json FROM user_monitoring_layouts WHERE user_id=?", userID)
	if err == sql.ErrNoRows {
		return `{"widgets":[],"layout_mode":"auto","wall_mode":false}`, nil
	}
	if err != nil {
		return "", err
	}
	layout = strings.TrimSpace(layout)
	if layout == "" {
		layout = `{"widgets":[],"layout_mode":"auto","wall_mode":false}`
	}
	return layout, nil
}

func (r *UserRepository) UpsertUserMonitoringLayout(userID int, layout string) error {
	layout = strings.TrimSpace(layout)
	if layout == "" || layout == "null" {
		layout = `{"widgets":[],"layout_mode":"auto","wall_mode":false}`
	}
	_, err := r.db.Exec(
		`INSERT INTO user_monitoring_layouts (user_id, layout_json)
		 VALUES (?, ?)
		 ON DUPLICATE KEY UPDATE layout_json=VALUES(layout_json), updated_at=CURRENT_TIMESTAMP`,
		userID, layout,
	)
	return err
}

func (r *UserRepository) GetGlobalNMSLayout() (string, error) {
	var layout string
	err := r.db.Get(&layout, "SELECT layout_json FROM nms_layout_global WHERE id=1")
	if err == sql.ErrNoRows {
		return "[]", nil
	}
	if err != nil {
		return "", err
	}
	layout = strings.TrimSpace(layout)
	if layout == "" {
		layout = "[]"
	}
	return layout, nil
}

func (r *UserRepository) UpsertGlobalNMSLayout(layout string) error {
	layout = strings.TrimSpace(layout)
	if layout == "" || layout == "null" {
		layout = "[]"
	}
	_, err := r.db.Exec(
		`INSERT INTO nms_layout_global (id, layout_json)
		 VALUES (1, ?)
		 ON DUPLICATE KEY UPDATE layout_json=VALUES(layout_json), updated_at=CURRENT_TIMESTAMP`,
		layout,
	)
	return err
}

func (r *UserRepository) GetLatestUserNMSLayout() (string, error) {
	var layout string
	err := r.db.Get(&layout, "SELECT layout_json FROM user_nms_layouts ORDER BY updated_at DESC LIMIT 1")
	if err == sql.ErrNoRows {
		return "[]", nil
	}
	if err != nil {
		return "", err
	}
	layout = strings.TrimSpace(layout)
	if layout == "" {
		layout = "[]"
	}
	return layout, nil
}
