package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const cdpHost = "ont-browser:9222"

type cdpTarget struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

func getCDPTargets() ([]cdpTarget, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + cdpHost + "/json/list")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var targets []cdpTarget
	json.Unmarshal(body, &targets)
	return targets, nil
}

// navigateCDP opens a new tab pointing to the given URL
func navigateCDP(targetURL string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	// /json/new?<url> opens a new tab and navigates to URL
	resp, err := client.Get(fmt.Sprintf("http://%s/json/new?%s", cdpHost, targetURL))
	if err != nil {
		return fmt.Errorf("CDP not available: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// NavigateONTBrowser navigates server's Chromium to an ONT URL
func (h *Handler) NavigateONTBrowser(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		respond(c, 400, false, "Target IP required", nil)
		return
	}
	ontURL := "http://" + target + "/"
	novncURL := "/novnc/vnc.html?autoconnect=true&reconnect=true&resize=scale&path=websockify"

	if err := navigateCDP(ontURL); err != nil {
		respond(c, 200, false, "Browser container belum siap: "+err.Error(), gin.H{
			"novnc_url":   novncURL,
			"ont_url":     ontURL,
			"auto_opened": false,
		})
		return
	}

	respond(c, 200, true, "Browser navigating to ONT", gin.H{
		"novnc_url":   novncURL,
		"ont_url":     ontURL,
		"auto_opened": true,
	})
}

// GetBrowserStatus checks if ont-browser container is running
func (h *Handler) GetBrowserStatus(c *gin.Context) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + cdpHost + "/json/version")
	if err != nil {
		respond(c, 200, false, "Browser container not running", gin.H{"running": false})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info map[string]interface{}
	json.Unmarshal(body, &info)

	targets, _ := getCDPTargets()
	respond(c, 200, true, "Browser running", gin.H{
		"running":      true,
		"browser_info": info,
		"tab_count":    len(targets),
		"novnc_url":    "/novnc/vnc.html?autoconnect=true&reconnect=true&resize=scale&path=websockify",
	})
}
