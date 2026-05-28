package api

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"mikrotik-ppp-management/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetServerInfo(c *gin.Context) {
	hostname, _ := os.Hostname()
	kernel := readSingleLine("/proc/sys/kernel/osrelease")
	if kernel == "" {
		kernel = runtime.GOARCH
	}

	uptime := readUptimeSeconds()
	memTotalMB, memFreeMB := readMemoryInfoMB()
	memUsedMB := memTotalMB - memFreeMB
	if memUsedMB < 0 {
		memUsedMB = 0
	}

	totalBytes, freeBytes := readDiskUsage("/")
	usedBytes := totalBytes - freeBytes
	if usedBytes < 0 {
		usedBytes = 0
	}

	respond(c, 200, true, "OK", models.ServerInfo{
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Kernel:        kernel,
		UptimeSeconds: uptime,
		UptimeHuman:   humanizeUptime(uptime),
		CPUCores:      runtime.NumCPU(),
		MemoryTotalMB: round2(memTotalMB),
		MemoryUsedMB:  round2(memUsedMB),
		MemoryFreeMB:  round2(memFreeMB),
		StorageTotal:  humanizeBytes(totalBytes),
		StorageUsed:   humanizeBytes(usedBytes),
		StorageFree:   humanizeBytes(freeBytes),
	})
}

func readSingleLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readUptimeSeconds() int64 {
	line := readSingleLine("/proc/uptime")
	if line == "" {
		return 0
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

func readMemoryInfoMB() (totalMB float64, freeMB float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var totalKB float64
	var availKB float64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			totalKB = parseMemKB(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			availKB = parseMemKB(line)
		}
	}
	return totalKB / 1024, availKB / 1024
}

func parseMemKB(line string) float64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[1], 64)
	return v
}

func readDiskUsage(path string) (total int64, free int64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	total = int64(stat.Blocks) * int64(stat.Bsize)
	free = int64(stat.Bavail) * int64(stat.Bsize)
	return total, free
}

func humanizeUptime(seconds int64) string {
	if seconds <= 0 {
		return "0m"
	}
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func humanizeBytes(b int64) string {
	const kb = 1024
	const mb = 1024 * kb
	const gb = 1024 * mb
	const tb = 1024 * gb

	switch {
	case b >= tb:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(tb))
	case b >= gb:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
