package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ServiceStatus struct {
	Name   string
	Label  string
	Active bool
}

type Account struct {
	Username string
	Expired  string
	Protocol string
}

type Bandwidth struct {
	MonthName   string
	MonthTotal  string
	MonthRX     string
	MonthTX     string
	DayName     string
	DayTotal    string
	DayRX       string
	DayTX       string
	TrafficRate string
}

type Snapshot struct {
	Domain      string
	IP          string
	ISP         string
	City        string
	OSName      string
	CPUCores    int
	Uptime      string
	LoadAvg     string
	MemUsedMB   uint64
	MemTotalMB  uint64
	MemPercent  int
	SwapTotalMB uint64
	SlowDNSNS   string
	SlowDNSPub  string
	BW          Bandwidth
	Services    []ServiceStatus
	SSHAccounts []Account
	VMessAccs   []Account
	VLESSAccs   []Account
	TrojanAccs  []Account
}

func Collect() Snapshot {
	s := Snapshot{
		Domain:     readTrimmed("/etc/xray/domain", "-"),
		IP:         readTrimmed("/root/.myip", "-"),
		ISP:        readTrimmed("/root/.isp", "-"),
		City:       readTrimmed("/root/.city", "-"),
		OSName:     readOSName("/etc/os-release"),
		CPUCores:   runtime.NumCPU(),
		Uptime:     readUptime("/proc/uptime"),
		LoadAvg:    readLoadAvg("/proc/loadavg"),
		SlowDNSNS:  readTrimmed("/etc/xray/dns", "Belum diset"),
		SlowDNSPub: readFirstNonEmpty([]string{"/etc/slowdns/server.pub", "/root/slowdns/server.pub"}, "Belum diset"),
		BW:         readBandwidth(),
	}

	s.MemUsedMB, s.MemTotalMB, s.MemPercent, s.SwapTotalMB = readMemInfo("/proc/meminfo")

	svcDefs := []struct{ name, label string }{
		{"xray", "XRAY"},
		{"ws", "SSH-WS"},
		{"haproxy", "LOADBLC"},
		{"nginx", "NGINX"},
		{"dropbear", "DROPBEAR"},
		{"slowdns", "SLOWDNS"},
		{"zevpn-limit", "QUOTA"},
		{"ssh", "SSH"},
	}
	s.Services = make([]ServiceStatus, 0, len(svcDefs))
	for _, d := range svcDefs {
		s.Services = append(s.Services, ServiceStatus{
			Name:   d.name,
			Label:  d.label,
			Active: isServiceActive(d.name),
		})
	}

	s.SSHAccounts = ParseSSHAccounts("/etc/ssh/.ssh.db")
	s.VMessAccs, s.VLESSAccs, s.TrojanAccs = ParseXrayAccounts("/etc/xray/config.json")
	return s
}

func readBandwidth() Bandwidth {
	now := time.Now()
	bw := Bandwidth{
		MonthName:   now.Month().String(),
		MonthTotal:  "-",
		MonthRX:     "-",
		MonthTX:     "-",
		DayName:     now.Weekday().String(),
		DayTotal:    "-",
		DayRX:       "-",
		DayTX:       "-",
		TrafficRate: "-",
	}
	out, err := exec.Command("vnstat", "--oneline").Output()
	if err != nil {
		return bw
	}
	// Format: 1;iface;date;rx_day;tx_day;total_day;avg_day;month;rx_mon;tx_mon;total_mon;avg_mon;...
	parts := strings.Split(strings.TrimSpace(string(out)), ";")
	if len(parts) >= 11 {
		if v := strings.TrimSpace(parts[3]); v != "" {
			bw.DayRX = v
		}
		if v := strings.TrimSpace(parts[4]); v != "" {
			bw.DayTX = v
		}
		if v := strings.TrimSpace(parts[5]); v != "" {
			bw.DayTotal = v
		}
		if v := strings.TrimSpace(parts[6]); v != "" {
			bw.TrafficRate = v
		}
		if v := strings.TrimSpace(parts[8]); v != "" {
			bw.MonthRX = v
		}
		if v := strings.TrimSpace(parts[9]); v != "" {
			bw.MonthTX = v
		}
		if v := strings.TrimSpace(parts[10]); v != "" {
			bw.MonthTotal = v
		}
	}
	return bw
}

func readTrimmed(path, fallback string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return fallback
	}
	return v
}

func readFirstNonEmpty(paths []string, fallback string) string {
	for _, p := range paths {
		if v := readTrimmed(p, ""); v != "" {
			return v
		}
	}
	return fallback
}

func readOSName(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "Linux"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(v, `"'`)
		}
	}
	return "Linux"
}

func readUptime(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "-"
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return "-"
	}
	secsFloat, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secsFloat < 0 {
		return "-"
	}
	total := uint64(secsFloat)
	days := total / 86400
	hours := (total % 86400) / 3600
	mins := (total % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%d days, %d hours, %d mins", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%d hours, %d minutes", hours, mins)
	}
	return fmt.Sprintf("%d minutes", mins)
}

func readLoadAvg(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "-"
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return "-"
	}
	return fmt.Sprintf("%s %s %s", fields[0], fields[1], fields[2])
}

func readMemInfo(path string) (usedMB, totalMB uint64, pct int, swapMB uint64) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, 0
	}
	defer f.Close()

	var totalKB, availKB, swapKB uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalKB = val
		case "MemAvailable:":
			availKB = val
		case "SwapTotal:":
			swapKB = val
		}
	}
	swapMB = swapKB / 1024
	if totalKB == 0 {
		return 0, 0, 0, swapMB
	}
	usedKB := totalKB
	if availKB <= totalKB {
		usedKB = totalKB - availKB
	}
	usedMB = usedKB / 1024
	totalMB = totalKB / 1024
	pct = int((usedKB * 100) / totalKB)
	return usedMB, totalMB, pct, swapMB
}

func isServiceActive(name string) bool {
	if err := exec.Command("systemctl", "is-active", "--quiet", name).Run(); err == nil {
		return true
	}
	if name == "ssh" {
		return exec.Command("systemctl", "is-active", "--quiet", "sshd").Run() == nil
	}
	return false
}

// ParseSSHAccounts reads deduplicated SSH accounts from `/etc/ssh/.ssh.db`.
func ParseSSHAccounts(path string) []Account {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var out []Account
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "#ssh# ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		user := fields[1]
		if _, dup := seen[user]; dup {
			continue
		}
		seen[user] = struct{}{}
		exp := "-"
		if len(fields) >= 6 {
			exp = strings.Join(fields[5:], " ")
		}
		out = append(out, Account{
			Username: user,
			Expired:  exp,
			Protocol: "SSH",
		})
	}
	return out
}

// ParseXrayAccounts parses deduplicated VMess, VLESS, and Trojan accounts from `/etc/xray/config.json`.
func ParseXrayAccounts(path string) (vmess, vless, trojan []Account) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil
	}
	defer f.Close()

	seenVM := make(map[string]struct{})
	seenVL := make(map[string]struct{})
	seenTR := make(map[string]struct{})

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "### "):
			if acc, ok := parseMarkerLine(line, "VMess"); ok {
				if _, dup := seenVM[acc.Username]; !dup {
					seenVM[acc.Username] = struct{}{}
					vmess = append(vmess, acc)
				}
			}
		case strings.HasPrefix(line, "#& "):
			if acc, ok := parseMarkerLine(line, "VLESS"); ok {
				if _, dup := seenVL[acc.Username]; !dup {
					seenVL[acc.Username] = struct{}{}
					vless = append(vless, acc)
				}
			}
		case strings.HasPrefix(line, "#! "):
			if acc, ok := parseMarkerLine(line, "Trojan"); ok {
				if _, dup := seenTR[acc.Username]; !dup {
					seenTR[acc.Username] = struct{}{}
					trojan = append(trojan, acc)
				}
			}
		}
	}
	return vmess, vless, trojan
}

func parseMarkerLine(line, proto string) (Account, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Account{}, false
	}
	exp := "-"
	if len(fields) >= 3 {
		exp = fields[2]
	}
	return Account{
		Username: fields[1],
		Expired:  exp,
		Protocol: proto,
	}, true
}
