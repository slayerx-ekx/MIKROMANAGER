package api

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type ONTSession struct {
	IP        string
	Jar       http.CookieJar
	CreatedAt time.Time
}

var (
	ontSessions   = make(map[string]*ONTSession)
	ontSessionsMu sync.RWMutex
)

func getOrCreateSession(ip string) *ONTSession {
	ontSessionsMu.Lock()
	defer ontSessionsMu.Unlock()
	if s, ok := ontSessions[ip]; ok {
		return s
	}
	jar, _ := cookiejar.New(nil)
	s := &ONTSession{IP: ip, Jar: jar, CreatedAt: time.Now()}
	ontSessions[ip] = s
	return s
}

func (h *Handler) ClearONTSession(c *gin.Context) {
	target := c.Query("target")
	ontSessionsMu.Lock()
	delete(ontSessions, target)
	ontSessionsMu.Unlock()
	respond(c, 200, true, "Session cleared", nil)
}

func (h *Handler) GetONTSessionInfo(c *gin.Context) {
	target := c.Query("target")
	ontSessionsMu.RLock()
	s, ok := ontSessions[target]
	ontSessionsMu.RUnlock()
	if !ok {
		respond(c, 200, true, "No session", gin.H{"has_session": false})
		return
	}
	u, _ := url.Parse("http://" + target + "/")
	cookies := s.Jar.Cookies(u)
	names := make([]string, len(cookies))
	for i, ck := range cookies {
		v := ck.Value
		if len(v) > 8 {
			v = v[:8] + "..."
		}
		names[i] = ck.Name + "=" + v
	}
	respond(c, 200, true, "OK", gin.H{"has_session": true, "cookies": names})
}

// ProxyONTSmart - smart proxy with persistent cookie jar session
func (h *Handler) ProxyONTSmart(c *gin.Context) {
	target := c.Query("target")
	path := c.Query("path")
	if target == "" {
		respond(c, 400, false, "Target required", nil)
		return
	}
	if path == "" || path == "null" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	sess := getOrCreateSession(target)
	method := c.Request.Method
	var postBody []byte
	if method == "POST" {
		postBody, _ = io.ReadAll(c.Request.Body)
	}

	htmlContent, err := fetchWithSession(target, path, method, postBody, sess.Jar)
	if err != nil {
		respond(c, 502, false, "Cannot reach ONT: "+err.Error(), nil)
		return
	}

	finalHTML := rewriteONTHTML(htmlContent, target)
	c.Data(200, "text/html; charset=utf-8", []byte(finalHTML))
}

func fetchWithSession(target, path, method string, body []byte, jar http.CookieJar) (string, error) {
	ontURL := "http://" + target + path

	client := &http.Client{
		Timeout: 20 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			req.Host = target
			return nil
		},
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, ontURL, bodyReader)
	if err != nil {
		return "", err
	}

	req.Host = target
	req.Header = make(http.Header)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "id-ID,id;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")

	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", "http://"+target+"/")
		req.Header.Set("Origin", "http://"+target)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Handle redirect manually if needed
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			if !strings.HasPrefix(loc, "http") {
				loc = "http://" + target + loc
			}
			u, err := url.Parse(loc)
			if err == nil {
				return fetchWithSession(target, u.RequestURI(), "GET", nil, jar)
			}
		}
	}

	return string(respBody), nil
}

// ProxyONTAsset - serve static assets for ONT
func (h *Handler) ProxyONTAsset(c *gin.Context) {
	target := c.Query("target")
	path := c.Query("path")
	if target == "" || path == "" {
		c.Status(404)
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	sess := getOrCreateSession(target)
	client := &http.Client{Timeout: 10 * time.Second, Jar: sess.Jar}
	req, err := http.NewRequest("GET", "http://"+target+path, nil)
	if err != nil {
		c.Status(502)
		return
	}
	req.Host = target
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Referer", "http://"+target+"/")

	resp, err := client.Do(req)
	if err != nil {
		c.Status(502)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = guessContentType(path)
	}
	if strings.Contains(ct, "text/css") {
		body = []byte(rewriteONTCSS(string(body), target))
	}
	c.Data(200, ct, body)
}
