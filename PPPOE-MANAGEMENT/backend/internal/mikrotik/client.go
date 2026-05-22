// Pure Go Mikrotik API - no external dependencies
package mikrotik

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	host     string
	port     int
	username string
	password string
	conn     net.Conn
}

type Reply struct {
	Re   []map[string]string
	Done map[string]string
	Trap string
}

type PPPActiveEntry struct {
	Name          string
	Address       string
	Uptime        string
	Profile       string
	Service       string
	CallerID      string
	LocalAddress  string
	RemoteAddress string
	BytesIn       int64
	BytesOut      int64
	PacketsIn     int64
	PacketsOut    int64
	SessionID     string
}

type PPPSecretEntry struct {
	Name          string
	Password      string
	Profile       string
	Service       string
	LocalAddress  string
	RemoteAddress string
	Comment       string
	Disabled      bool
}

func NewClient(host string, port int, username, password string) *Client {
	return &Client{host: host, port: port, username: username, password: password}
}

func encodeLength(l int) []byte {
	switch {
	case l < 0x80:
		return []byte{byte(l)}
	case l < 0x4000:
		l |= 0x8000
		return []byte{byte(l >> 8), byte(l)}
	case l < 0x200000:
		l |= 0xC00000
		return []byte{byte(l >> 16), byte(l >> 8), byte(l)}
	default:
		l |= 0xE0000000
		return []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	}
}

func writeWord(conn net.Conn, word string) error {
	b := []byte(word)
	if _, err := conn.Write(encodeLength(len(b))); err != nil {
		return err
	}
	if len(b) > 0 {
		_, err := conn.Write(b)
		return err
	}
	return nil
}

func writeSentence(conn net.Conn, words []string) error {
	for _, w := range words {
		if err := writeWord(conn, w); err != nil {
			return err
		}
	}
	return writeWord(conn, "")
}

func readLength(conn net.Conn) (int, error) {
	b1 := make([]byte, 1)
	if _, err := io.ReadFull(conn, b1); err != nil {
		return 0, err
	}
	b := b1[0]
	switch {
	case b&0x80 == 0:
		return int(b), nil
	case b&0xC0 == 0x80:
		rest := make([]byte, 1)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return 0, err
		}
		return int(b&^0xC0)<<8 | int(rest[0]), nil
	case b&0xE0 == 0xC0:
		rest := make([]byte, 2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return 0, err
		}
		return int(b&^0xE0)<<16 | int(rest[0])<<8 | int(rest[1]), nil
	default:
		rest := make([]byte, 3)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return 0, err
		}
		return int(b&^0xF0)<<24 | int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2]), nil
	}
}

func readWord(conn net.Conn) (string, error) {
	length, err := readLength(conn)
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func parseReply(conn net.Conn) (*Reply, error) {
	reply := &Reply{}
	for {
		var words []string
		for {
			word, err := readWord(conn)
			if err != nil {
				return nil, err
			}
			if word == "" {
				break
			}
			words = append(words, word)
		}
		if len(words) == 0 {
			continue
		}
		tag := words[0]
		attrs := make(map[string]string)
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "=") {
				parts := strings.SplitN(w[1:], "=", 2)
				if len(parts) == 2 {
					attrs[parts[0]] = parts[1]
				}
			}
		}
		switch tag {
		case "!re":
			reply.Re = append(reply.Re, attrs)
		case "!done":
			reply.Done = attrs
			return reply, nil
		case "!trap":
			reply.Trap = attrs["message"]
			return reply, fmt.Errorf("API trap: %s", reply.Trap)
		case "!fatal":
			return nil, fmt.Errorf("API fatal: %v", attrs)
		}
	}
}

func (c *Client) dial() error {
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c.conn = conn
	return nil
}

func (c *Client) Connect() error {
	if err := c.dial(); err != nil {
		return err
	}
	return c.login()
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) login() error {
	// Try new-style login (RouterOS 6.43+): send name+password directly
	if err := writeSentence(c.conn, []string{
		"/login",
		"=name=" + c.username,
		"=password=" + c.password,
	}); err != nil {
		return err
	}
	reply, err := parseReply(c.conn)
	if err == nil {
		if reply.Done != nil {
			if _, hasRet := reply.Done["ret"]; !hasRet {
				return nil // new-style success
			}
			// old-style: challenge in ret
			return c.loginChallenge(reply.Done["ret"])
		}
		return nil
	}
	// Retry with challenge-response (RouterOS < 6.43)
	c.Close()
	if err2 := c.dial(); err2 != nil {
		return err
	}
	if err2 := writeSentence(c.conn, []string{"/login"}); err2 != nil {
		return err
	}
	reply2, err2 := parseReply(c.conn)
	if err2 != nil || reply2.Done == nil {
		return err
	}
	challenge := reply2.Done["ret"]
	if challenge == "" {
		return err
	}
	return c.loginChallenge(challenge)
}

func (c *Client) loginChallenge(challenge string) error {
	h := md5.New()
	h.Write([]byte{0})
	h.Write([]byte(c.password))
	b, _ := hex.DecodeString(challenge)
	h.Write(b)
	response := "00" + hex.EncodeToString(h.Sum(nil))
	if err := writeSentence(c.conn, []string{
		"/login",
		"=name=" + c.username,
		"=response=" + response,
	}); err != nil {
		return err
	}
	_, err := parseReply(c.conn)
	return err
}

func (c *Client) run(words []string) (*Reply, error) {
	c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeSentence(c.conn, words); err != nil {
		return nil, err
	}
	return parseReply(c.conn)
}

func (c *Client) TestConnection() error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()
	_, err := c.run([]string{"/system/identity/print"})
	return err
}

func (c *Client) GetActivePPP() ([]PPPActiveEntry, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.run([]string{"/ppp/active/print"})
	if err != nil {
		return nil, fmt.Errorf("failed to get active PPP: %w", err)
	}
	var entries []PPPActiveEntry
	for _, re := range reply.Re {
		e := PPPActiveEntry{
			Name:          re["name"],
			Address:       re["address"],
			Uptime:        re["uptime"],
			Profile:       re["profile"],
			Service:       re["service"],
			CallerID:      re["caller-id"],
			LocalAddress:  re["local-address"],
			RemoteAddress: re["remote-address"],
			SessionID:     re[".id"],
		}
		if v, err2 := strconv.ParseInt(strings.TrimSpace(re["bytes-in"]), 10, 64); err2 == nil {
			e.BytesIn = v
		}
		if v, err2 := strconv.ParseInt(strings.TrimSpace(re["bytes-out"]), 10, 64); err2 == nil {
			e.BytesOut = v
		}
		if v, err2 := strconv.ParseInt(strings.TrimSpace(re["packets-in"]), 10, 64); err2 == nil {
			e.PacketsIn = v
		}
		if v, err2 := strconv.ParseInt(strings.TrimSpace(re["packets-out"]), 10, 64); err2 == nil {
			e.PacketsOut = v
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (c *Client) GetPPPSecrets() ([]PPPSecretEntry, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.run([]string{"/ppp/secret/print"})
	if err != nil {
		return nil, fmt.Errorf("failed to get PPP secrets: %w", err)
	}
	var entries []PPPSecretEntry
	for _, re := range reply.Re {
		entries = append(entries, PPPSecretEntry{
			Name:          re["name"],
			Password:      re["password"],
			Profile:       re["profile"],
			Service:       re["service"],
			LocalAddress:  re["local-address"],
			RemoteAddress: re["remote-address"],
			Comment:       re["comment"],
			Disabled:      strings.EqualFold(strings.TrimSpace(re["disabled"]), "true") || strings.EqualFold(strings.TrimSpace(re["disabled"]), "yes"),
		})
	}
	return entries, nil
}

func (c *Client) GetSystemIdentity() (string, error) {
	if err := c.Connect(); err != nil {
		return "", err
	}
	defer c.Close()
	reply, err := c.run([]string{"/system/identity/print"})
	if err != nil {
		return "", err
	}
	if len(reply.Re) > 0 {
		return reply.Re[0]["name"], nil
	}
	return "", nil
}

func (c *Client) DisconnectPPPUser(sessionID string) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()
	_, err := c.run([]string{"/ppp/active/remove", "=.id=" + sessionID})
	return err
}

func (c *Client) DisconnectPPPUsersByNames(names ...string) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	reply, err := c.run([]string{"/ppp/active/print"})
	if err != nil {
		return err
	}

	targets := map[string]bool{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name != "" {
			targets[strings.ToLower(name)] = true
		}
	}

	var firstErr error
	for _, row := range reply.Re {
		name := strings.TrimSpace(row["name"])
		if !targets[strings.ToLower(name)] {
			continue
		}
		sessionID := strings.TrimSpace(row[".id"])
		if sessionID == "" {
			continue
		}
		if _, remErr := c.run([]string{"/ppp/active/remove", "=.id=" + sessionID}); remErr != nil && firstErr == nil {
			firstErr = remErr
		}
	}
	return firstErr
}

func (c *Client) GetPPPProfiles() ([]string, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.run([]string{"/ppp/profile/print"})
	if err != nil {
		return nil, err
	}
	var profiles []string
	for _, re := range reply.Re {
		if name := re["name"]; name != "" {
			profiles = append(profiles, name)
		}
	}
	return profiles, nil
}

func (c *Client) AddPPPSecret(name, password, profile, service string, disabled bool) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	if strings.TrimSpace(service) == "" {
		service = "pppoe"
	}
	disabledWord := "no"
	if disabled {
		disabledWord = "yes"
	}
	args := []string{
		"/ppp/secret/add",
		"=name=" + strings.TrimSpace(name),
		"=password=" + password,
		"=service=" + strings.TrimSpace(service),
		"=disabled=" + disabledWord,
	}
	if strings.TrimSpace(profile) != "" {
		args = append(args, "=profile="+strings.TrimSpace(profile))
	}
	_, err := c.run(args)
	return err
}

func (c *Client) AddPPPoEServerBinding(name, user string) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()
	_, err := c.run([]string{
		"/interface/pppoe-server/add",
		"=name=" + strings.TrimSpace(name),
		"=user=" + strings.TrimSpace(user),
	})
	return err
}

func (c *Client) UpdatePPPSecret(oldName, newName, password, profile, service string, disabled bool) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	reply, err := c.run([]string{
		"/ppp/secret/print",
		"?name=" + strings.TrimSpace(oldName),
	})
	if err != nil {
		return err
	}
	if len(reply.Re) == 0 {
		return fmt.Errorf("PPP secret %s tidak ditemukan", oldName)
	}
	id := strings.TrimSpace(reply.Re[0][".id"])
	if id == "" {
		return fmt.Errorf("PPP secret %s tidak memiliki id", oldName)
	}
	currentProfile := strings.TrimSpace(reply.Re[0]["profile"])
	if strings.TrimSpace(newName) == "" {
		newName = oldName
	}
	if strings.TrimSpace(service) == "" {
		service = "pppoe"
	}
	disabledWord := "no"
	if disabled {
		disabledWord = "yes"
	}
	args := []string{
		"/ppp/secret/set",
		"=.id=" + id,
		"=name=" + strings.TrimSpace(newName),
		"=service=" + strings.TrimSpace(service),
		"=profile=" + strings.TrimSpace(profile),
		"=disabled=" + disabledWord,
	}
	if password != "" {
		args = append(args, "=password="+password)
	}
	_, err = c.run(args)
	if err != nil {
		return err
	}

	if !strings.EqualFold(strings.TrimSpace(currentProfile), strings.TrimSpace(profile)) {
		if discErr := c.DisconnectPPPUsersByNames(oldName, newName); discErr != nil {
			return fmt.Errorf("secret updated but failed to disconnect active PPP sessions: %w", discErr)
		}
	}
	return err
}

func (c *Client) RemovePPPSecretByName(name string) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	reply, err := c.run([]string{
		"/ppp/secret/print",
		"?name=" + strings.TrimSpace(name),
	})
	if err != nil {
		return err
	}
	if len(reply.Re) == 0 {
		return nil
	}
	id := strings.TrimSpace(reply.Re[0][".id"])
	if id == "" {
		return nil
	}
	_, err = c.run([]string{"/ppp/secret/remove", "=.id=" + id})
	return err
}

func (c *Client) SyncPPPoEServerBinding(oldRef, newName, newUser string, enabled bool) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	reply, err := c.run([]string{"/interface/pppoe-server/print"})
	if err != nil {
		return err
	}

	refSet := map[string]bool{}
	for _, ref := range []string{oldRef, newName, newUser} {
		ref = strings.TrimSpace(ref)
		if ref != "" {
			refSet[ref] = true
		}
	}

	matches := filterPPPoEServerBindingRows(reply.Re, refSet)

	if !enabled {
		for _, row := range matches {
			if id := strings.TrimSpace(row[".id"]); id != "" {
				if _, remErr := c.run([]string{"/interface/pppoe-server/remove", "=.id=" + id}); remErr != nil {
					return remErr
				}
			}
		}
		return nil
	}

	serviceName := c.resolvePPPoEServerBindingServiceName(matches)

	if len(matches) == 0 {
		if err := c.runPPPoEServerBindingCommand("/interface/pppoe-server/add", "", strings.TrimSpace(newName), strings.TrimSpace(newUser), serviceName); err != nil {
			return err
		}
		return c.verifyPPPoEServerBindingVisible(strings.TrimSpace(newName), strings.TrimSpace(newUser))
	}

	firstID := strings.TrimSpace(matches[0][".id"])
	if firstID == "" {
		return fmt.Errorf("binding PPPoE tidak memiliki id")
	}
	if err := c.runPPPoEServerBindingCommand("/interface/pppoe-server/set", firstID, strings.TrimSpace(newName), strings.TrimSpace(newUser), serviceName); err != nil {
		return err
	}
	for i := 1; i < len(matches); i++ {
		if id := strings.TrimSpace(matches[i][".id"]); id != "" {
			if _, remErr := c.run([]string{"/interface/pppoe-server/remove", "=.id=" + id}); remErr != nil {
				return remErr
			}
		}
	}
	return c.verifyPPPoEServerBindingVisible(strings.TrimSpace(newName), strings.TrimSpace(newUser))
}

func filterPPPoEServerBindingRows(rows []map[string]string, refSet map[string]bool) []map[string]string {
	matches := make([]map[string]string, 0)
	for _, row := range rows {
		name := strings.TrimSpace(row["name"])
		user := strings.TrimSpace(row["user"])
		if refSet[name] || refSet[user] {
			matches = append(matches, row)
		}
	}
	return matches
}

func (c *Client) resolvePPPoEServerBindingServiceName(matches []map[string]string) string {
	for _, row := range matches {
		service := strings.TrimSpace(row["service"])
		if service == "" {
			service = strings.TrimSpace(row["service-name"])
		}
		if service != "" {
			return service
		}
	}

	reply, err := c.run([]string{"/interface/pppoe-server/server/print"})
	if err != nil {
		return ""
	}

	firstEnabled := ""
	firstAny := ""
	for _, row := range reply.Re {
		service := strings.TrimSpace(row["service-name"])
		if service == "" {
			service = strings.TrimSpace(row["service"])
		}
		if service == "" {
			continue
		}
		if firstAny == "" {
			firstAny = service
		}
		disabled := strings.EqualFold(strings.TrimSpace(row["disabled"]), "yes") || strings.EqualFold(strings.TrimSpace(row["disabled"]), "true")
		if disabled {
			continue
		}
		if firstEnabled == "" {
			firstEnabled = service
		}
	}

	if firstEnabled != "" {
		return firstEnabled
	}
	if firstAny != "" {
		return firstAny
	}
	return ""
}

func (c *Client) runPPPoEServerBindingCommand(command, id, name, user, service string) error {
	base := []string{command}
	if strings.TrimSpace(id) != "" {
		base = append(base, "=.id="+strings.TrimSpace(id))
	}
	base = append(base,
		"=name="+strings.TrimSpace(name),
		"=user="+strings.TrimSpace(user),
	)

	service = strings.TrimSpace(service)
	commands := [][]string{
		append(append([]string{}, base...), "=service="+service),
	}
	if service != "" {
		commands = append(commands, append(append([]string{}, base...), "=service-name="+service))
	}

	var lastErr error
	for _, words := range commands {
		if _, err := c.run(words); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("gagal menjalankan sinkronisasi binding PPPoE")
}

func (c *Client) verifyPPPoEServerBindingVisible(name, user string) error {
	name = strings.TrimSpace(name)
	user = strings.TrimSpace(user)
	for attempt := 0; attempt < 3; attempt++ {
		reply, err := c.run([]string{"/interface/pppoe-server/print"})
		if err != nil {
			return err
		}
		for _, row := range reply.Re {
			rowName := strings.TrimSpace(row["name"])
			rowUser := strings.TrimSpace(row["user"])
			if rowName == name && rowUser == user {
				return nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("binding PPPoE belum muncul di router untuk name=%s user=%s", name, user)
}

// GetInterfaces returns all interfaces
func (c *Client) GetInterfaces() ([]map[string]string, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.run([]string{"/interface/print"})
	if err != nil {
		return nil, err
	}
	return reply.Re, nil
}

// GetInterfaceTraffic returns real-time traffic for interfaces
func (c *Client) GetInterfaceTraffic(ifaces []string) ([]map[string]string, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()

	args := []string{"/interface/monitor-traffic", "=once="}
	ifaceStr := ""
	for i, iface := range ifaces {
		if i > 0 {
			ifaceStr += ","
		}
		ifaceStr += iface
	}
	args = append(args, "=interface="+ifaceStr)

	reply, err := c.run(args)
	if err != nil {
		return nil, err
	}
	return reply.Re, nil
}

// Ping performs ping from router to target
func (c *Client) Ping(target string, count int) ([]map[string]string, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()
	if count <= 0 {
		count = 4
	}
	reply, err := c.run([]string{
		"/ping",
		"=address=" + target,
		"=count=" + strconv.Itoa(count),
	})
	if err != nil {
		return nil, err
	}
	return reply.Re, nil
}

// GetPPPActiveByUser returns active session for specific user
func (c *Client) GetPPPActiveByUser(username string) (*PPPActiveEntry, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.run([]string{
		"/ppp/active/print",
		"?name=" + username,
	})
	if err != nil {
		return nil, err
	}
	if len(reply.Re) == 0 {
		return nil, nil
	}
	re := reply.Re[0]
	e := &PPPActiveEntry{
		Name:      re["name"],
		Address:   re["address"],
		Uptime:    re["uptime"],
		Profile:   re["profile"],
		Service:   re["service"],
		CallerID:  re["caller-id"],
		SessionID: re[".id"],
	}
	return e, nil
}

// GetPPPoEInterfaces returns detail entries from /interface/pppoe-server
func (c *Client) GetPPPoEInterfaces() ([]map[string]string, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.run([]string{"/interface/pppoe-server/print"})
	if err != nil {
		return nil, err
	}
	return reply.Re, nil
}

// GetPPPInterfaces returns PPP interface-like entries.
// Some RouterOS builds do not expose /ppp/interface/print over API,
// so we fall back to /interface/print and filter PPP/PPPoE interfaces there.
func (c *Client) GetPPPInterfaces() ([]map[string]string, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	defer c.Close()

	reply, err := c.run([]string{"/ppp/interface/print"})
	if err == nil {
		return reply.Re, nil
	}

	reply, fallbackErr := c.run([]string{"/interface/print"})
	if fallbackErr != nil {
		return nil, err
	}
	filtered := make([]map[string]string, 0, len(reply.Re))
	for _, row := range reply.Re {
		typeVal := strings.ToLower(strings.TrimSpace(row["type"]))
		nameVal := strings.ToLower(strings.TrimSpace(row["name"]))
		defaultNameVal := strings.ToLower(strings.TrimSpace(row["default-name"]))
		if strings.Contains(typeVal, "pppoe") ||
			strings.Contains(typeVal, "ppp") ||
			strings.HasPrefix(nameVal, "pppoe") ||
			strings.Contains(nameVal, "pppoe") ||
			strings.HasPrefix(defaultNameVal, "pppoe") {
			filtered = append(filtered, row)
		}
	}
	return filtered, nil
}
