package accounts

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	XrayConfigPath = "/etc/xray/config.json"
	XrayAccessLog  = "/var/log/xray/access.log"
	SSHDBPath      = "/etc/ssh/.ssh.db"
	BotDBPath      = "/etc/bot/.bot.db"
)

type Protocol string

const (
	ProtoSSH    Protocol = "ssh"
	ProtoVMess  Protocol = "vmess"
	ProtoVLESS  Protocol = "vless"
	ProtoTrojan Protocol = "trojan"
)

var validUserRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func ValidateUsername(u string) error {
	if !validUserRe.MatchString(u) {
		return fmt.Errorf("username hanya boleh huruf, angka, '-', '_' (maks 32 karakter)")
	}
	return nil
}

// NewUUIDv4 generates a standard RFC 4122 UUIDv4 using crypto/rand (0 external deps).
func NewUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func RandomTrialUser(prefix string) string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	num := (int(b[0])<<8 | int(b[1])) % 9000 + 1000
	return fmt.Sprintf("%s%d", prefix, num)
}

func protoMarker(p Protocol) string {
	switch p {
	case ProtoVMess:
		return "###"
	case ProtoVLESS:
		return "#&"
	case ProtoTrojan:
		return "#!"
	default:
		return ""
	}
}

func protoInboundMarkers(p Protocol) []string {
	switch p {
	case ProtoVMess:
		return []string{"#vmess", "#vmessgrpc", "#vmesshu", "#vmessxhttp"}
	case ProtoVLESS:
		return []string{"#vless", "#vlessgrpc", "#vlesshu", "#vlessxhttp"}
	case ProtoTrojan:
		return []string{"#trojanws", "#trojangrpc", "#trojanhu", "#trojanxhttp"}
	default:
		return nil
	}
}

func protoDBPath(p Protocol) string {
	switch p {
	case ProtoVMess:
		return "/etc/vmess/.vmess.db"
	case ProtoVLESS:
		return "/etc/vless/.vless.db"
	case ProtoTrojan:
		return "/etc/trojan/.trojan.db"
	default:
		return SSHDBPath
	}
}

func protoQuotaDir(p Protocol) string {
	return "/etc/" + string(p)
}

func protoIPLimitDir(p Protocol) string {
	return "/etc/kyt/limit/" + string(p) + "/ip"
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

func writeAtomic(path string, content []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, content, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func reloadXray() {
	if err := exec.Command("systemctl", "reload", "xray").Run(); err != nil {
		_ = exec.Command("systemctl", "restart", "xray").Run()
	}
}

func sendTelegram(htmlText string) {
	b, err := os.ReadFile(BotDBPath)
	if err != nil {
		return
	}
	var chatID, key string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#bot# ") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				key = f[1]
				chatID = f[2]
				break
			}
		}
	}
	if chatID == "" || key == "" {
		return
	}
	client := &http.Client{Timeout: 8 * time.Second}
	form := url.Values{}
	form.Set("chat_id", chatID)
	form.Set("disable_web_page_preview", "1")
	form.Set("parse_mode", "html")
	form.Set("text", htmlText)
	resp, err := client.PostForm("https://api.telegram.org/bot"+key+"/sendMessage", form)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// ---------- Xray (VMess / VLESS / Trojan) CRUD ----------

type XrayCreateParams struct {
	Proto    Protocol
	Username string
	Days     int
	QuotaGB  int
	IPLimit  int
}

type XrayLinks struct {
	WSTLS     string
	WSNTLS    string
	GRPC      string
	HUTLS     string
	HUNTLS    string
	XHTTPTLS  string
	XHTTPNTLS string
	TxtURL    string
}

func BuildXrayLinks(p Protocol, domain, user, uuid string) XrayLinks {
	switch p {
	case ProtoVLESS:
		return XrayLinks{
			WSTLS:     fmt.Sprintf("vless://%s@%s:443?path=%%2Fvless&security=tls&encryption=none&host=%s&type=ws&sni=%s#%s", uuid, domain, domain, domain, user),
			WSNTLS:    fmt.Sprintf("vless://%s@%s:80?path=%%2Fvless&security=none&encryption=none&host=%s&type=ws#%s", uuid, domain, domain, user),
			GRPC:      fmt.Sprintf("vless://%s@%s:443?mode=gun&security=tls&encryption=none&host=%s&type=grpc&serviceName=vless-grpc&sni=%s#%s", uuid, domain, domain, domain, user),
			HUTLS:     fmt.Sprintf("vless://%s@%s:443?path=%%2Fupvless&security=tls&encryption=none&host=%s&type=httpupgrade&sni=%s#%s-HU-TLS", uuid, domain, domain, domain, user),
			HUNTLS:    fmt.Sprintf("vless://%s@%s:80?path=%%2Fupvless&security=none&encryption=none&host=%s&type=httpupgrade#%s-HU-NTLS", uuid, domain, domain, user),
			XHTTPTLS:  fmt.Sprintf("vless://%s@%s:443?path=%%2Fvless-xhttp&mode=auto&security=tls&encryption=none&host=%s&type=xhttp&sni=%s#%s-XHTTP-TLS", uuid, domain, domain, domain, user),
			XHTTPNTLS: fmt.Sprintf("vless://%s@%s:80?path=%%2Fvless-xhttp&mode=auto&security=none&encryption=none&host=%s&type=xhttp#%s-XHTTP-NTLS", uuid, domain, domain, user),
			TxtURL:    fmt.Sprintf("https://%s:81/vless-%s.txt", domain, user),
		}
	case ProtoTrojan:
		return XrayLinks{
			WSTLS:     fmt.Sprintf("trojan://%s@%s:443?path=%%2Ftrojan-ws&security=tls&host=%s&type=ws&sni=%s#%s", uuid, domain, domain, domain, user),
			WSNTLS:    fmt.Sprintf("trojan://%s@%s:80?path=%%2Ftrojan-ws&security=none&host=%s&type=ws#%s", uuid, domain, domain, user),
			GRPC:      fmt.Sprintf("trojan://%s@%s:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=%s#%s", uuid, domain, domain, user),
			HUTLS:     fmt.Sprintf("trojan://%s@%s:443?path=%%2Fuptrojan&security=tls&host=%s&type=httpupgrade&sni=%s#%s-HU-TLS", uuid, domain, domain, domain, user),
			HUNTLS:    fmt.Sprintf("trojan://%s@%s:80?path=%%2Fuptrojan&security=none&host=%s&type=httpupgrade#%s-HU-NTLS", uuid, domain, domain, user),
			XHTTPTLS:  fmt.Sprintf("trojan://%s@%s:443?path=%%2Ftrojan-xhttp&mode=auto&security=tls&host=%s&type=xhttp&sni=%s#%s-XHTTP-TLS", uuid, domain, domain, domain, user),
			XHTTPNTLS: fmt.Sprintf("trojan://%s@%s:80?path=%%2Ftrojan-xhttp&mode=auto&security=none&host=%s&type=xhttp#%s-XHTTP-NTLS", uuid, domain, domain, user),
			TxtURL:    fmt.Sprintf("https://%s:81/trojan-%s.txt", domain, user),
		}
	default: // VMess
		mk := func(ps, port, net, typ, path, tls string) string {
			obj := map[string]string{
				"v":    "2",
				"ps":   ps,
				"add":  domain,
				"port": port,
				"id":   uuid,
				"aid":  "0",
				"net":  net,
				"path": path,
				"type": typ,
				"host": domain,
				"tls":  tls,
				"sni":  domain,
			}
			if tls == "none" {
				obj["sni"] = ""
			}
			raw, _ := json.Marshal(obj)
			return "vmess://" + base64.StdEncoding.EncodeToString(raw)
		}
		return XrayLinks{
			WSTLS:     mk(user, "443", "ws", "none", "/vmess", "tls"),
			WSNTLS:    mk(user, "80", "ws", "none", "/vmess", "none"),
			GRPC:      mk(user, "443", "grpc", "gun", "vmess-grpc", "tls"),
			HUTLS:     mk(user+"-HU-TLS", "443", "httpupgrade", "none", "/upvmess", "tls"),
			HUNTLS:    mk(user+"-HU-NTLS", "80", "httpupgrade", "none", "/upvmess", "none"),
			XHTTPTLS:  mk(user+"-XHTTP-TLS", "443", "xhttp", "auto", "/vmess-xhttp", "tls"),
			XHTTPNTLS: mk(user+"-XHTTP-NTLS", "80", "xhttp", "auto", "/vmess-xhttp", "none"),
			TxtURL:    fmt.Sprintf("https://%s:81/vmess-%s.txt", domain, user),
		}
	}
}

func AddXrayAccountToFile(configPath string, params XrayCreateParams) (uuid, exp string, err error) {
	if err := ValidateUsername(params.Username); err != nil {
		return "", "", err
	}
	if params.Days <= 0 {
		params.Days = 1
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return "", "", fmt.Errorf("gagal membaca %s: %w", configPath, err)
	}
	content := string(raw)
	marker := protoMarker(params.Proto)

	// Check duplicate username
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, marker+" ") {
			f := strings.Fields(trimmed)
			if len(f) >= 2 && f[1] == params.Username {
				return "", "", fmt.Errorf("username '%s' sudah ada di %s", params.Username, params.Proto)
			}
		}
	}

	uuid, err = NewUUIDv4()
	if err != nil {
		return "", "", err
	}
	exp = time.Now().AddDate(0, 0, params.Days).Format("2006-01-02")

	var clientLine string
	switch params.Proto {
	case ProtoVMess:
		clientLine = fmt.Sprintf(`},{"id": "%s","alterId": 0,"email": "%s"`, uuid, params.Username)
	case ProtoVLESS:
		clientLine = fmt.Sprintf(`},{"id": "%s","email": "%s"`, uuid, params.Username)
	case ProtoTrojan:
		clientLine = fmt.Sprintf(`},{"password": "%s","email": "%s"`, uuid, params.Username)
	default:
		return "", "", fmt.Errorf("protokol tidak didukung: %s", params.Proto)
	}

	block := fmt.Sprintf("%s %s %s\n%s", marker, params.Username, exp, clientLine)
	inserted := 0
	for _, mk := range protoInboundMarkers(params.Proto) {
		target := mk + "\n"
		if strings.Contains(content, target) {
			content = strings.Replace(content, target, mk+"\n"+block+"\n", 1)
			inserted++
		}
	}
	if inserted == 0 {
		return "", "", fmt.Errorf("marker inbound %s tidak ditemukan di %s", params.Proto, configPath)
	}

	// Validate config using xray -t if /usr/local/bin/xray exists and editing real config
	if configPath == XrayConfigPath {
		tmpCheck := fmt.Sprintf("/tmp/xray-check-%d.json", time.Now().UnixNano())
		if err := os.WriteFile(tmpCheck, []byte(content), 0644); err != nil {
			return "", "", err
		}
		defer os.Remove(tmpCheck)
		if _, statErr := os.Stat("/usr/local/bin/xray"); statErr == nil {
			if out, verr := exec.Command("/usr/local/bin/xray", "-t", "-config", tmpCheck).CombinedOutput(); verr != nil {
				return "", "", fmt.Errorf("validasi xray -t gagal: %s", strings.TrimSpace(string(out)))
			}
		}
	}

	if err := writeAtomic(configPath, []byte(content), 0644); err != nil {
		return "", "", err
	}
	return uuid, exp, nil
}

func CreateXrayAccount(params XrayCreateParams) (string, error) {
	uuid, exp, err := AddXrayAccountToFile(XrayConfigPath, params)
	if err != nil {
		return "", err
	}

	// Save IP limit, quota, and .db
	if params.IPLimit > 0 {
		_ = writeAtomic(filepath.Join(protoIPLimitDir(params.Proto), params.Username), []byte(fmt.Sprintf("%d\n", params.IPLimit)), 0644)
	}
	if params.QuotaGB > 0 {
		bytesVal := int64(params.QuotaGB) * 1024 * 1024 * 1024
		_ = writeAtomic(filepath.Join(protoQuotaDir(params.Proto), params.Username), []byte(fmt.Sprintf("%d\n", bytesVal)), 0644)
	}
	_ = upsertDBLine(protoDBPath(params.Proto), params.Username, fmt.Sprintf("### %s %s %s %d %d", params.Username, exp, uuid, params.QuotaGB, params.IPLimit))

	reloadXray()

	domain := readTrimmed("/etc/xray/domain", "localhost")
	links := BuildXrayLinks(params.Proto, domain, params.Username, uuid)
	detail := FormatXrayDetail(params.Proto, domain, params.Username, uuid, exp, params.QuotaGB, params.IPLimit, links)
	_ = writeAtomic(fmt.Sprintf("/var/www/html/%s-%s.txt", params.Proto, params.Username), []byte(detail), 0644)
	sendTelegram(fmt.Sprintf("<b>Create %s Success</b>\n<code>User : %s\nExp  : %s\nHost : %s</code>\n\n<code>%s</code>", strings.ToUpper(string(params.Proto)), params.Username, exp, domain, links.WSTLS))
	return detail, nil
}

func FormatXrayDetail(p Protocol, domain, user, uuid, exp string, quotaGB, ipLimit int, l XrayLinks) string {
	var b strings.Builder
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "  AKUN %s BERHASIL\n", strings.ToUpper(string(p)))
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "Remarks     : %s\n", user)
	fmt.Fprintf(&b, "Domain      : %s\n", domain)
	fmt.Fprintf(&b, "User ID     : %s\n", uuid)
	fmt.Fprintf(&b, "Expired     : %s\n", exp)
	fmt.Fprintf(&b, "Limit IP    : %d IP | Quota: %d GB\n", ipLimit, quotaGB)
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "WS TLS      :\n%s\n\n", l.WSTLS)
	fmt.Fprintf(&b, "WS NTLS     :\n%s\n\n", l.WSNTLS)
	fmt.Fprintf(&b, "gRPC TLS    :\n%s\n\n", l.GRPC)
	fmt.Fprintf(&b, "HTTPUp TLS  :\n%s\n\n", l.HUTLS)
	fmt.Fprintf(&b, "XHTTP TLS   :\n%s\n", l.XHTTPTLS)
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "Link Txt    : %s\n", l.TxtURL)
	return b.String()
}

func GetXrayAccountDetail(p Protocol, user string) (string, error) {
	domain := readTrimmed("/etc/xray/domain", "localhost")
	uuid, exp, quotaGB, ipLimit := lookupXrayDB(p, user)
	if uuid == "" {
		uuid, exp = lookupXrayFromConfig(XrayConfigPath, p, user)
	}
	if uuid == "" {
		return "", fmt.Errorf("detail akun '%s' tidak ditemukan", user)
	}
	links := BuildXrayLinks(p, domain, user, uuid)
	return FormatXrayDetail(p, domain, user, uuid, exp, quotaGB, ipLimit, links), nil
}

func lookupXrayDB(p Protocol, user string) (uuid, exp string, quotaGB, ipLimit int) {
	b, err := os.ReadFile(protoDBPath(p))
	if err != nil {
		return "", "", 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "###" && f[1] == user {
			exp = f[2]
			uuid = f[3]
			if len(f) >= 5 {
				quotaGB, _ = strconv.Atoi(f[4])
			}
			if len(f) >= 6 {
				ipLimit, _ = strconv.Atoi(f[5])
			}
			return
		}
	}
	return "", "", 0, 0
}

func lookupXrayFromConfig(configPath string, p Protocol, user string) (uuid, exp string) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return "", ""
	}
	marker := protoMarker(p)
	lines := strings.Split(string(b), "\n")
	for i := 0; i+1 < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, marker+" ") {
			f := strings.Fields(trimmed)
			if len(f) >= 2 && f[1] == user {
				if len(f) >= 3 {
					exp = f[2]
				}
				re := regexp.MustCompile(`"(?:id|password)"\s*:\s*"([^"]+)"`)
				if m := re.FindStringSubmatch(lines[i+1]); len(m) == 2 {
					return m[1], exp
				}
			}
		}
	}
	return "", ""
}

func DeleteXrayAccountFromFile(configPath string, p Protocol, user string) (bool, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}
	marker := protoMarker(p)
	var out []string
	skipping := false
	removed := false

	for _, line := range strings.Split(string(raw), "\n") {
		if !skipping {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, marker+" ") {
				f := strings.Fields(trimmed)
				if len(f) >= 2 && f[1] == user {
					skipping = true
					removed = true
					continue
				}
			}
			out = append(out, line)
		} else if strings.HasPrefix(strings.TrimSpace(line), "},{") {
			skipping = false
		}
	}
	if !removed {
		return false, nil
	}
	if err := writeAtomic(configPath, []byte(strings.Join(out, "\n")), 0644); err != nil {
		return false, err
	}
	return true, nil
}

func DeleteXrayAccount(p Protocol, user string) error {
	removed, err := DeleteXrayAccountFromFile(XrayConfigPath, p, user)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("akun '%s' tidak ditemukan di config.json", user)
	}
	_ = removeDBLine(protoDBPath(p), user)
	_ = os.Remove(filepath.Join(protoQuotaDir(p), user))
	_ = os.Remove(filepath.Join(protoIPLimitDir(p), user))
	_ = os.Remove(fmt.Sprintf("/var/www/html/%s-%s.txt", p, user))
	reloadXray()
	return nil
}

func RenewXrayAccountInFile(configPath string, p Protocol, user string, addDays int) (string, error) {
	if addDays <= 0 {
		return "", fmt.Errorf("jumlah hari harus > 0")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	marker := protoMarker(p)
	lines := strings.Split(string(raw), "\n")
	newExp := ""
	updated := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, marker+" ") {
			f := strings.Fields(trimmed)
			if len(f) >= 3 && f[1] == user {
				if newExp == "" {
					baseTime := time.Now()
					if parsed, perr := time.Parse("2006-01-02", f[2]); perr == nil && parsed.After(baseTime) {
						baseTime = parsed
					}
					newExp = baseTime.AddDate(0, 0, addDays).Format("2006-01-02")
				}
				lines[i] = fmt.Sprintf("%s %s %s", marker, user, newExp)
				updated = true
			}
		}
	}
	if !updated {
		return "", fmt.Errorf("akun '%s' tidak ditemukan", user)
	}
	if err := writeAtomic(configPath, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return "", err
	}
	return newExp, nil
}

func RenewXrayAccount(p Protocol, user string, addDays int) (string, error) {
	newExp, err := RenewXrayAccountInFile(XrayConfigPath, p, user, addDays)
	if err != nil {
		return "", err
	}
	uuid, _, quotaGB, ipLimit := lookupXrayDB(p, user)
	if uuid != "" {
		_ = upsertDBLine(protoDBPath(p), user, fmt.Sprintf("### %s %s %s %d %d", user, newExp, uuid, quotaGB, ipLimit))
	}
	reloadXray()
	return newExp, nil
}

// ---------- SSH CRUD ----------

type SSHCreateParams struct {
	Username string
	Password string
	Days     int
	IPLimit  int
}

func CreateSSHAccount(params SSHCreateParams) (string, error) {
	if err := ValidateUsername(params.Username); err != nil {
		return "", err
	}
	if params.Password == "" {
		return "", fmt.Errorf("password tidak boleh kosong")
	}
	if params.Days <= 0 {
		params.Days = 1
	}

	expDate := time.Now().AddDate(0, 0, params.Days)
	expISO := expDate.Format("2006-01-02")
	expHuman := expDate.Format("02 Jan, 2006")

	if out, err := exec.Command("useradd", "-e", expISO, "-s", "/bin/false", "-M", params.Username).CombinedOutput(); err != nil {
		return "", fmt.Errorf("useradd gagal: %s", strings.TrimSpace(string(out)))
	}
	chp := exec.Command("chpasswd")
	chp.Stdin = strings.NewReader(params.Username + ":" + params.Password + "\n")
	if out, err := chp.CombinedOutput(); err != nil {
		return "", fmt.Errorf("chpasswd gagal: %s", strings.TrimSpace(string(out)))
	}

	if params.IPLimit > 0 {
		_ = writeAtomic(filepath.Join(protoIPLimitDir(ProtoSSH), params.Username), []byte(fmt.Sprintf("%d\n", params.IPLimit)), 0644)
	}
	_ = upsertDBLine(SSHDBPath, params.Username, fmt.Sprintf("#ssh# %s %s 0 %d %s", params.Username, params.Password, params.IPLimit, expHuman))

	detail := FormatSSHDetail(params.Username, params.Password, params.IPLimit, expHuman)
	_ = writeAtomic(fmt.Sprintf("/var/www/html/ssh-%s.txt", params.Username), []byte(detail), 0644)
	domain := readTrimmed("/etc/xray/domain", "-")
	ns := readTrimmed("/etc/xray/dns", "Belum diset")
	pub := readFirstNonEmpty([]string{"/etc/slowdns/server.pub", "/root/slowdns/server.pub"}, "Belum diset")
	sendTelegram(fmt.Sprintf("<b>Create SSH Success</b>\n<code>Host : %s\nUser : %s\nPass : %s\nExp  : %s\nNS   : %s\nPub  : %s</code>", domain, params.Username, params.Password, expHuman, ns, pub))
	return detail, nil
}

func FormatSSHDetail(user, pass string, ipLimit int, expHuman string) string {
	domain := readTrimmed("/etc/xray/domain", "-")
	ip := readTrimmed("/root/.myip", "-")
	ns := readTrimmed("/etc/xray/dns", "Belum diset")
	pub := readFirstNonEmpty([]string{"/etc/slowdns/server.pub", "/root/slowdns/server.pub"}, "Belum diset")

	var b strings.Builder
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "  AKUN SSH & SLOWDNS\n")
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "Host          : %s\n", domain)
	fmt.Fprintf(&b, "IP VPS        : %s\n", ip)
	fmt.Fprintf(&b, "Username      : %s\n", user)
	fmt.Fprintf(&b, "Password      : %s\n", pass)
	fmt.Fprintf(&b, "Limit IP      : %d device\n", ipLimit)
	fmt.Fprintf(&b, "Expired       : %s\n", expHuman)
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "SSH CUSTOM    : %s:80@%s:%s\n", domain, user, pass)
	fmt.Fprintf(&b, "SSH SSL/TLS   : %s:443@%s:%s\n", domain, user, pass)
	fmt.Fprintf(&b, "UDP CUSTOM    : %s:1-65535@%s:%s\n", domain, user, pass)
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "SLOWDNS (HTTP Custom) :\n")
	fmt.Fprintf(&b, "Name Server   : %s\n", ns)
	fmt.Fprintf(&b, "Pub Key       : %s\n", pub)
	fmt.Fprintf(&b, "Port DNS      : 53\n")
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━◇\n")
	return b.String()
}

func GetSSHAccountDetail(user string) (string, error) {
	b, err := os.ReadFile(SSHDBPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "#ssh#" && f[1] == user {
			pass := f[2]
			ipLimit := 0
			exp := "-"
			if len(f) >= 5 {
				ipLimit, _ = strconv.Atoi(f[4])
			}
			if len(f) >= 6 {
				exp = strings.Join(f[5:], " ")
			}
			return FormatSSHDetail(user, pass, ipLimit, exp), nil
		}
	}
	return "", fmt.Errorf("detail akun SSH '%s' tidak ditemukan di .ssh.db", user)
}

func DeleteSSHAccount(user string) error {
	_ = exec.Command("userdel", "-f", user).Run()
	_ = removeDBLine(SSHDBPath, user)
	_ = os.Remove(filepath.Join(protoIPLimitDir(ProtoSSH), user))
	_ = os.Remove(fmt.Sprintf("/var/www/html/ssh-%s.txt", user))
	return nil
}

func RenewSSHAccount(user string, addDays int) (string, error) {
	if addDays <= 0 {
		return "", fmt.Errorf("jumlah hari harus > 0")
	}
	expDate := time.Now().AddDate(0, 0, addDays)
	expISO := expDate.Format("2006-01-02")
	expHuman := expDate.Format("02 Jan, 2006")
	if out, err := exec.Command("chage", "-E", expISO, user).CombinedOutput(); err != nil {
		return "", fmt.Errorf("chage gagal: %s", strings.TrimSpace(string(out)))
	}
	// Update .ssh.db if present
	b, err := os.ReadFile(SSHDBPath)
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 && f[0] == "#ssh#" && f[1] == user {
				_ = upsertDBLine(SSHDBPath, user, fmt.Sprintf("#ssh# %s %s %s %s %s", user, f[2], f[3], f[4], expHuman))
				break
			}
		}
	}
	return expHuman, nil
}

// ---------- Login Checks & Maintenance ----------

func CheckXrayLoginsFromLog(logPath string, users []string, p Protocol) string {
	userSet := make(map[string]struct{}, len(users))
	for _, u := range users {
		userSet[u] = struct{}{}
	}
	activeIPs := make(map[string]map[string]struct{})

	if f, err := os.Open(logPath); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			idx := strings.LastIndex(line, "email: ")
			if idx < 0 {
				continue
			}
			email := strings.TrimSpace(line[idx+len("email: "):])
			if _, ok := userSet[email]; !ok {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			ip := strings.TrimPrefix(fields[2], "tcp:")
			if colon := strings.IndexByte(ip, ':'); colon >= 0 {
				ip = ip[:colon]
			}
			if ip == "" || ip == "127.0.0.1" {
				continue
			}
			if activeIPs[email] == nil {
				activeIPs[email] = make(map[string]struct{})
			}
			activeIPs[email][ip] = struct{}{}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇\n")
	fmt.Fprintf(&b, "  USER LOGIN %s\n", strings.ToUpper(string(p)))
	fmt.Fprintf(&b, "◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇\n")
	if len(activeIPs) == 0 {
		b.WriteString("  Tidak ada user aktif di access.log.\n")
		return b.String()
	}
	names := make([]string, 0, len(activeIPs))
	for u := range activeIPs {
		names = append(names, u)
	}
	sort.Strings(names)
	for _, u := range names {
		ips := make([]string, 0, len(activeIPs[u]))
		for ip := range activeIPs[u] {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		lim := readTrimmed(filepath.Join(protoIPLimitDir(p), u), "-")
		fmt.Fprintf(&b, "  %-16s [%d/%s IP]  %s\n", u, len(ips), lim, strings.Join(ips, ", "))
	}
	return b.String()
}

func CheckSSHLogins() string {
	out, _ := exec.Command("bash", "-c", "who 2>/dev/null || true").Output()
	var b strings.Builder
	b.WriteString("◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇\n")
	b.WriteString("  USER LOGIN SSH\n")
	b.WriteString("◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇\n")
	txt := strings.TrimSpace(string(out))
	if txt == "" {
		b.WriteString("  Tidak ada sesi SSH aktif (who).\n")
	} else {
		b.WriteString(txt + "\n")
	}
	return b.String()
}

func CleanExpiredXray() string {
	today := time.Now().Format("2006-01-02")
	var removed []string
	for _, p := range []Protocol{ProtoVMess, ProtoVLESS, ProtoTrojan} {
		raw, err := os.ReadFile(XrayConfigPath)
		if err != nil {
			continue
		}
		marker := protoMarker(p)
		seen := make(map[string]string)
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, marker+" ") {
				f := strings.Fields(trimmed)
				if len(f) >= 3 {
					seen[f[1]] = f[2]
				}
			}
		}
		for u, exp := range seen {
			if len(exp) == 10 && exp < today {
				if err := DeleteXrayAccount(p, u); err == nil {
					removed = append(removed, fmt.Sprintf("%s:%s (exp %s)", p, u, exp))
				}
			}
		}
	}
	if len(removed) == 0 {
		return "Tidak ada akun Xray yang expired hari ini."
	}
	return "Akun expired dihapus:\n- " + strings.Join(removed, "\n- ")
}

func ClearCacheAndLogs() string {
	_ = exec.Command("sync").Run()
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0644)
	for _, logFile := range []string{"/var/log/xray/access.log", "/var/log/xray/error.log", "/var/log/nginx/access.log"} {
		if _, err := os.Stat(logFile); err == nil {
			_ = os.Truncate(logFile, 0)
		}
	}
	return "RAM cache & log akses berhasil dibersihkan (izin file tetap utuh)."
}

func upsertDBLine(path, user, newLine string) error {
	var lines []string
	if raw, err := os.ReadFile(path); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			f := strings.Fields(l)
			if len(f) >= 2 && f[1] == user {
				continue
			}
			lines = append(lines, l)
		}
	}
	lines = append(lines, newLine)
	return writeAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func removeDBLine(path, user string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == user {
			continue
		}
		lines = append(lines, l)
	}
	return writeAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func readFirstNonEmpty(paths []string, fallback string) string {
	for _, p := range paths {
		if v := readTrimmed(p, ""); v != "" {
			return v
		}
	}
	return fallback
}
