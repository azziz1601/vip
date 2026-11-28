package sysops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azziz1601/vip/vip-menu/internal/accounts"
)

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

func BandwidthReport() string {
	var b strings.Builder
	b.WriteString("DAILY TRAFFIC\n")
	b.WriteString("────────────────────────────────────────────────────\n")
	if out, err := exec.Command("vnstat", "-d").Output(); err == nil {
		b.WriteString(strings.TrimSpace(string(out)) + "\n")
	} else {
		b.WriteString("vnstat is not available.\n")
	}
	b.WriteString("\nMONTHLY TRAFFIC\n")
	b.WriteString("────────────────────────────────────────────────────\n")
	if out, err := exec.Command("vnstat", "-m").Output(); err == nil {
		b.WriteString(strings.TrimSpace(string(out)) + "\n")
	}
	return b.String()
}

func PortInfo() string {
	var b strings.Builder
	b.WriteString("SERVICE PORTS\n")
	b.WriteString("────────────────────────────────────────────────────\n")
	rows := [][2]string{
		{"TLS Multi-Transport", "443"},
		{"Non-TLS Multi-Transport", "80, 8080, 8880, 2080, 2082"},
		{"OpenSSH", "22"},
		{"Dropbear", "109, 143"},
		{"SlowDNS UDP", "53"},
		{"OpenVPN TCP / UDP", "1194 / 2200"},
		{"BadVPN UDPGW", "7100, 7200, 7300"},
		{"Web Config Download", "81"},
	}
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-24s : %s\n", r[0], r[1])
	}
	return b.String()
}

func MultiLoginSSH() string {
	report := accounts.CheckSSHLogins()
	// Also summarize per-user session count vs IP limit
	liveDB, liveSSH := accounts.LivePIDsByComm()
	var logBuf strings.Builder
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if b, err := os.ReadFile(p); err == nil {
			logBuf.Write(b)
			logBuf.WriteByte('\n')
		}
	}
	if jOut, err := exec.Command("journalctl", "-u", "dropbear", "-u", "ssh", "-u", "sshd", "--no-pager", "-n", "4000").Output(); err == nil {
		logBuf.Write(jOut)
		logBuf.WriteByte('\n')
	}
	dbSess, sshSess := accounts.ParseSSHLoginsFromText(logBuf.String(), liveDB, liveSSH)
	counts := make(map[string]int)
	for _, s := range append(dbSess, sshSess...) {
		counts[s.Username]++
	}

	var b strings.Builder
	b.WriteString("SSH MULTI LOGIN CHECK\n")
	b.WriteString("────────────────────────────────────────────────────\n")
	var over []string
	users := make([]string, 0, len(counts))
	for u := range counts {
		users = append(users, u)
	}
	sort.Strings(users)
	for _, u := range users {
		limStr := readTrimmed(filepath.Join("/etc/kyt/limit/ssh/ip", u), "0")
		lim, _ := strconv.Atoi(limStr)
		if lim > 0 && counts[u] > lim {
			over = append(over, fmt.Sprintf("  %-16s  %d / %d sessions", u, counts[u], lim))
		}
	}
	if len(over) == 0 {
		b.WriteString("  No SSH users exceeding IP limit.\n\n")
	} else {
		b.WriteString(strings.Join(over, "\n") + "\n\n")
	}
	b.WriteString(report)
	return b.String()
}

func SetAutoReboot(schedule string) string {
	cronFile := "/etc/cron.d/daily_reboot"
	if schedule == "off" {
		_ = os.Remove(cronFile)
		_ = exec.Command("systemctl", "restart", "cron").Run()
		return "Auto reboot disabled."
	}
	content := fmt.Sprintf("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n%s root /sbin/reboot\n", schedule)
	if err := os.WriteFile(cronFile, []byte(content), 0644); err != nil {
		return "Failed to write cron: " + err.Error()
	}
	_ = exec.Command("systemctl", "restart", "cron").Run()
	return fmt.Sprintf("Auto reboot scheduled: %s", schedule)
}

func SetAutokill(minutes int) string {
	cronFile := "/etc/cron.d/tendang"
	if minutes <= 0 {
		_ = os.Remove(cronFile)
		_ = exec.Command("systemctl", "restart", "cron").Run()
		return "SSH autokill disabled."
	}
	content := fmt.Sprintf("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n*/%d * * * * root /usr/local/sbin/tendang\n", minutes)
	if err := os.WriteFile(cronFile, []byte(content), 0644); err != nil {
		return "Failed to configure autokill: " + err.Error()
	}
	_ = exec.Command("systemctl", "restart", "cron").Run()
	return fmt.Sprintf("SSH autokill enabled every %d minutes.", minutes)
}

func ChangeDomain(newDomain string) error {
	newDomain = strings.TrimSpace(newDomain)
	if newDomain == "" || strings.ContainsAny(newDomain, " \t\n\r/") {
		return fmt.Errorf("invalid domain")
	}
	oldDomain := readTrimmed("/etc/xray/domain", "")
	if err := os.WriteFile("/etc/xray/domain", []byte(newDomain+"\n"), 0644); err != nil {
		return err
	}
	if oldDomain != "" {
		if raw, err := os.ReadFile("/etc/nginx/conf.d/xray.conf"); err == nil {
			updated := strings.ReplaceAll(string(raw), oldDomain, newDomain)
			_ = os.WriteFile("/etc/nginx/conf.d/xray.conf", []byte(updated), 0644)
			if exec.Command("nginx", "-t").Run() == nil {
				_ = exec.Command("systemctl", "reload", "nginx").Run()
			}
		}
	}
	return nil
}

func RenewSSL() string {
	domain := readTrimmed("/etc/xray/domain", "")
	if domain == "" {
		return "Domain is not configured in /etc/xray/domain."
	}
	script := fmt.Sprintf(`set -e
systemctl stop nginx haproxy 2>/dev/null || true
if [ -x /root/.acme.sh/acme.sh ]; then
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  /root/.acme.sh/acme.sh --issue -d %q --standalone -k ec-256 --force
  /root/.acme.sh/acme.sh --installcert -d %q --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
  cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
  chown www-data:www-data /etc/xray/xray.crt /etc/xray/xray.key 2>/dev/null || true
else
  echo "acme.sh not found in /root/.acme.sh/acme.sh"
  exit 1
fi
systemctl start nginx haproxy 2>/dev/null || true
systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null || true
echo "SSL certificate renewed for %s"
`, domain, domain, domain)
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		_ = exec.Command("systemctl", "start", "nginx", "haproxy").Run()
		return "SSL renewal failed:\n" + strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(out))
}

func ConfigureBotNotif(token, chatID string) error {
	token = strings.TrimSpace(token)
	chatID = strings.TrimSpace(chatID)
	if token == "" || chatID == "" {
		return fmt.Errorf("bot token and chat ID are required")
	}
	if err := os.MkdirAll("/etc/bot", 0755); err != nil {
		return err
	}
	line := fmt.Sprintf("#bot# %s %s\n", token, chatID)
	return os.WriteFile("/etc/bot/.bot.db", []byte(line), 0600)
}

func SetLimitSpeed(downMbps, upMbps int) string {
	ifaceOut, err := exec.Command("bash", "-c", "ip -o -4 route show to default | awk '{print $5}' | head -n1").Output()
	iface := strings.TrimSpace(string(ifaceOut))
	if err != nil || iface == "" {
		return "Unable to detect default network interface."
	}
	if downMbps <= 0 && upMbps <= 0 {
		_ = exec.Command("wondershaper", "-c", "-a", iface).Run()
		return fmt.Sprintf("Speed limit cleared on %s.", iface)
	}
	downKbps := strconv.Itoa(downMbps * 1024)
	upKbps := strconv.Itoa(upMbps * 1024)
	if out, err := exec.Command("wondershaper", "-a", iface, "-d", downKbps, "-u", upKbps).CombinedOutput(); err != nil {
		return "Failed to apply speed limit: " + strings.TrimSpace(string(out))
	}
	return fmt.Sprintf("Speed limit set on %s: %d Mbps down / %d Mbps up.", iface, downMbps, upMbps)
}

func ReadBotConfig() (string, string) {
	b, err := os.ReadFile("/etc/bot/.bot.db")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#bot# ") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				return f[1], f[2]
			}
		}
	}
	return "", ""
}

func AutoBackupStatus() string {
	b, err := os.ReadFile("/etc/cron.d/vip_autobackup")
	if err != nil {
		return "Inactive"
	}
	if strings.Contains(string(b), "--backup-now") {
		return "Active"
	}
	return "Inactive"
}

func removeLegacyBackupCrons() {
	_ = os.Remove("/etc/cron.d/bckp_otm")
	_ = os.Remove("/etc/cron.d/backup")
}

func BackupToTelegram() (string, error) {
	token, chatID := ReadBotConfig()
	if token == "" || chatID == "" {
		return "", fmt.Errorf("Telegram bot token and chat ID are not configured")
	}

	domain := readTrimmed("/etc/xray/domain", "vps")
	ip := readTrimmed("/etc/xray/ipvps", "-")
	ts := time.Now().Format("2006-01-02-1504")
	safeDom := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, domain)
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("vip-backup-%s-%s.tar.gz", safeDom, ts))
	defer os.Remove(tmpFile)

	targets := []string{
		"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
		"/etc/xray/config.json", "/etc/xray/domain", "/etc/xray/dns",
		"/etc/vmess", "/etc/vless", "/etc/trojan", "/etc/ssh",
		"/etc/kyt/limit", "/etc/bot", "/root/slowdns",
	}
	var existing []string
	for _, t := range targets {
		if _, err := os.Stat(t); err == nil {
			existing = append(existing, t)
		}
	}
	if len(existing) == 0 {
		return "", fmt.Errorf("no backup targets found")
	}

	args := append([]string{"-czf", tmpFile}, existing...)
	if out, err := exec.Command("tar", args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("tar failed: %s", strings.TrimSpace(string(out)))
	}

	info, err := os.Stat(tmpFile)
	if err != nil {
		return "", err
	}
	sizeKB := info.Size() / 1024
	if sizeKB == 0 && info.Size() > 0 {
		sizeKB = 1
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("chat_id", chatID)
	_ = w.WriteField("parse_mode", "HTML")
	caption := fmt.Sprintf("<b>VIP Backup</b>\n<code>Host : %s\nIP   : %s\nDate : %s\nSize : %d KB</code>", domain, ip, time.Now().Format("2006-01-02 15:04"), sizeKB)
	_ = w.WriteField("caption", caption)
	part, err := w.CreateFormFile("document", filepath.Base(tmpFile))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	endpoint := "https://api.telegram.org/bot" + token + "/sendDocument"
	req, err := http.NewRequest(http.MethodPost, endpoint, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload failed: %v", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	var tgResp struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(respBytes, &tgResp)
	if resp.StatusCode >= 300 || !tgResp.OK {
		if tgResp.Description != "" {
			return "", fmt.Errorf("Telegram API: %s", tgResp.Description)
		}
		return "", fmt.Errorf("Telegram HTTP %d", resp.StatusCode)
	}

	return fmt.Sprintf("Backup sent to Telegram.\nFile    : %s\nSize    : %d KB\nChat ID : %s\nLocal   : Cleaned", filepath.Base(tmpFile), sizeKB, chatID), nil
}

func BackupData() string {
	res, err := BackupToTelegram()
	if err != nil {
		return "Backup failed: " + err.Error()
	}
	return res
}

func RestoreData(archivePath string) string {
	archivePath = strings.TrimSpace(archivePath)
	if archivePath == "" {
		return "Archive path is required."
	}
	if _, err := os.Stat(archivePath); err != nil {
		return "Backup file not found: " + archivePath
	}
	if out, err := exec.Command("tar", "-xzf", archivePath, "-C", "/").CombinedOutput(); err != nil {
		return "Restore failed: " + strings.TrimSpace(string(out))
	}
	_ = exec.Command("systemctl", "reload", "xray").Run()
	_ = exec.Command("systemctl", "reload", "nginx").Run()
	_ = exec.Command("systemctl", "reload", "haproxy").Run()
	return fmt.Sprintf("Restored successfully from %s.", archivePath)
}

func SetupTelegramAutoBackup(token, chatID string, hour int) string {
	if err := ConfigureBotNotif(token, chatID); err != nil {
		return "Failed to save bot config: " + err.Error()
	}
	if hour < 0 || hour > 23 {
		hour = 2
	}
	removeLegacyBackupCrons()
	cronFile := "/etc/cron.d/vip_autobackup"
	cmd := fmt.Sprintf("0 %d * * * root /usr/local/bin/vip-menu --backup-now >/dev/null 2>&1", hour)
	content := "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n" + cmd + "\n"
	if err := os.WriteFile(cronFile, []byte(content), 0644); err != nil {
		return "Failed to schedule auto backup: " + err.Error()
	}
	_ = exec.Command("systemctl", "restart", "cron").Run()

	var b strings.Builder
	fmt.Fprintf(&b, "Telegram auto backup enabled daily at %02d:00.\n", hour)
	b.WriteString("────────────────────────────────────────────────────\n")
	res, err := BackupToTelegram()
	if err != nil {
		b.WriteString("Initial backup failed: " + err.Error())
	} else {
		b.WriteString(res)
	}
	return b.String()
}

func ToggleAutoBackup(enable bool) string {
	removeLegacyBackupCrons()
	cronFile := "/etc/cron.d/vip_autobackup"
	if !enable {
		_ = os.Remove(cronFile)
		_ = exec.Command("systemctl", "restart", "cron").Run()
		return "Auto backup disabled."
	}
	token, chatID := ReadBotConfig()
	if token == "" || chatID == "" {
		return "Telegram bot token and chat ID are not configured. Run Auto Backup Setup first."
	}
	cmd := "0 2 * * * root /usr/local/bin/vip-menu --backup-now >/dev/null 2>&1"
	content := "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n" + cmd + "\n"
	if err := os.WriteFile(cronFile, []byte(content), 0644); err != nil {
		return "Failed to schedule auto backup: " + err.Error()
	}
	_ = exec.Command("systemctl", "restart", "cron").Run()
	return "Daily Telegram auto backup enabled at 02:00."
}

func RunSpeedtest() string {
	if p, err := exec.LookPath("speedtest-cli"); err == nil {
		out, err := exec.Command(p, "--simple").CombinedOutput()
		if err != nil {
			return "Speedtest failed:\n" + strings.TrimSpace(string(out))
		}
		return strings.TrimSpace(string(out))
	}
	if p, err := exec.LookPath("speedtest"); err == nil {
		out, err := exec.Command(p, "--accept-license", "--accept-gdpr").CombinedOutput()
		if err != nil {
			return "Speedtest failed:\n" + strings.TrimSpace(string(out))
		}
		return strings.TrimSpace(string(out))
	}
	return "speedtest-cli is not installed."
}
