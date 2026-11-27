package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

type Snapshot struct {
	Domain       string
	IP           string
	ISP          string
	City         string
	OSName       string
	Uptime       string
	LoadAvg      string
	MemUsedMB    uint64
	MemTotalMB   uint64
	MemPercent   int
	SlowDNSNS    string
	SlowDNSPub   string
	Services     []ServiceStatus
	SSHAccounts  []Account
	VMessAccs    []Account
	VLESSAccs    []Account
	TrojanAccs   []Account
}

func Collect() Snapshot {
	s := Snapshot{
		Domain:     readTrimmed("/etc/xray/domain", "-"),
		IP:         readTrimmed("/root/.myip", "-"),
		ISP:        readTrimmed("/root/.isp", "-"),
		City:       readTrimmed("/root/.city", "-"),
		OSName:     readOSName("/etc/os-release"),
		Uptime:     readUptime("/proc/uptime"),
		LoadAvg:    readLoadAvg("/proc/loadavg"),
		SlowDNSNS:  readTrimmed("/etc/xray/dns", "Belum diset"),
		SlowDNSPub: readFirstNonEmpty([]string{"/etc/slowdns/server.pub", "/root/slowdns/server.pub"}, "Belum diset"),
	}

	s.MemUsedMB, s.MemTotalMB, s.MemPercent = readMemInfo("/proc/meminfo")

	svcDefs := []struct{ name, label string }{
		{"xray", "Xray"},
		{"nginx", "Nginx"},
		{"haproxy", "HAProxy"},
		{"ws", "WS-Proxy"},
		{"dropbear", "Dropbear"},
		{"slowdns", "SlowDNS"},
		{"zevpn-limit", "Quota"},
		{"udp-mini-1", "UDPGW"},
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
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
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

func readMemInfo(path string) (usedMB, totalMB uint64, pct int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, 0
	}
	defer f.Close()

	var totalKB, availKB uint64
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
		}
	}
	if totalKB == 0 {
		return 0, 0, 0
	}
	usedKB := totalKB
	if availKB <= totalKB {
		usedKB = totalKB - availKB
	}
	usedMB = usedKB / 1024
	totalMB = totalKB / 1024
	pct = int((usedKB * 100) / totalKB)
	return usedMB, totalMB, pct
}

func isServiceActive(name string) bool {
	err := exec.Command("systemctl", "is-active", "--quiet", name).Run()
	return err == nil
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
