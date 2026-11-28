package tui

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/azziz1601/vip/vip-menu/internal/accounts"
	"github.com/azziz1601/vip/vip-menu/internal/rollback"
	"github.com/azziz1601/vip/vip-menu/internal/sysinfo"
)

type viewID int

const (
	viewDashboard viewID = iota
	viewProtoMenu
	viewSystem
	viewServices
	viewSlowDNS
	viewBackup
	viewRollbackConfirm
	viewForm
	viewPickUser
	viewTextResult
)

type pickAction int

const (
	pickDetail pickAction = iota
	pickRenew
	pickDelete
	pickChangeIP
	pickChangeQuota
	pickLock
	pickUnlock
)

type formMode int

const (
	formCreateSSH formMode = iota
	formCreateXray
	formRenewAccount
	formChangeIPLimit
	formChangeQuotaGB
)

type formField struct {
	Label   string
	Value   string
	Numeric bool
}

type menuItem struct {
	Key   string
	Label string
	Run   func(m *Model) tea.Cmd
}

type execFinishedMsg struct{ err error }
type serviceActionMsg struct {
	service string
	action  string
	err     error
}
type rollbackDoneMsg struct{ err error }

type Model struct {
	version string
	view    viewID
	proto   accounts.Protocol
	cursor  int
	width   int
	height  int
	snap    sysinfo.Snapshot
	notice  string

	fMode      formMode
	fTitle     string
	fFields    []formField
	fFocus     int
	fTargetUsr string

	pAction pickAction
	pUsers  []sysinfo.Account

	rTitle string
	rBody  string
	rBack  viewID
}

var (
	colorBlueLine = lipgloss.Color("#2563EB")
	colorRedLine  = lipgloss.Color("#991B1B")
	colorRedBar   = lipgloss.Color("#EF4444")
	colorGreen    = lipgloss.Color("#22C55E")
	colorSky      = lipgloss.Color("#38BDF8")
	colorAmber    = lipgloss.Color("#F59E0B")
	colorRed      = lipgloss.Color("#F87171")
	colorMuted    = lipgloss.Color("#94A3B8")
	colorText     = lipgloss.Color("#E2E8F0")

	panelWidth = 52

	barBannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGreen).
			Background(colorRedBar).
			Width(panelWidth).
			Align(lipgloss.Center)

	blueRuleStyle = lipgloss.NewStyle().Foreground(colorBlueLine)
	redRuleStyle  = lipgloss.NewStyle().Foreground(colorRedLine)

	greenStyle = lipgloss.NewStyle().Foreground(colorGreen)
	skyStyle   = lipgloss.NewStyle().Foreground(colorSky).Bold(true)
	amberStyle = lipgloss.NewStyle().Foreground(colorAmber).Bold(true)
	errStyle   = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	mutedStyle = lipgloss.NewStyle().Foreground(colorMuted)
	valStyle   = lipgloss.NewStyle().Foreground(colorText).Bold(true)

	selRowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0F172A")).
			Background(colorGreen)
)

func blueLine() string {
	return blueRuleStyle.Render(strings.Repeat("─", panelWidth))
}

func redLine() string {
	return redRuleStyle.Render(strings.Repeat("─", panelWidth))
}

func NewModel(version string) Model {
	return Model{
		version: version,
		view:    viewDashboard,
		snap:    sysinfo.Collect(),
	}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) currentAccounts() []sysinfo.Account {
	switch m.proto {
	case accounts.ProtoSSH:
		return m.snap.SSHAccounts
	case accounts.ProtoVMess:
		return m.snap.VMessAccs
	case accounts.ProtoVLESS:
		return m.snap.VLESSAccs
	case accounts.ProtoTrojan:
		return m.snap.TrojanAccs
	default:
		return nil
	}
}

func (m Model) itemsForCurrentView() []menuItem {
	switch m.view {
	case viewDashboard:
		return []menuItem{
			{Key: "1", Label: "MENU SSH", Run: openProto(accounts.ProtoSSH)},
			{Key: "2", Label: "MENU VMESS", Run: openProto(accounts.ProtoVMess)},
			{Key: "3", Label: "MENU VLESS", Run: openProto(accounts.ProtoVLESS)},
			{Key: "4", Label: "MENU TROJAN", Run: openProto(accounts.ProtoTrojan)},
			{Key: "5", Label: "MENU SYSTEM", Run: goView(viewSystem)},
			{Key: "6", Label: "SERVICE CTRL", Run: goView(viewServices)},
			{Key: "7", Label: "INFO SLOWDNS", Run: goView(viewSlowDNS)},
			{Key: "8", Label: "UPDATE SCRIPT", Run: runUpdateScript()},
			{Key: "9", Label: "BACKUP/RESTORE", Run: goView(viewBackup)},
			{Key: "0", Label: "ROLLBACK KLASIK", Run: goView(viewRollbackConfirm)},
		}
	case viewProtoMenu:
		if m.proto == accounts.ProtoSSH {
			return []menuItem{
				{Key: "1", Label: "Buat Akun SSH & SlowDNS", Run: startCreateForm()},
				{Key: "2", Label: "Trial SSH (1 Hari)", Run: runQuickTrial()},
				{Key: "3", Label: "Perpanjang SSH", Run: openPicker(pickRenew)},
				{Key: "4", Label: "Cek User Login SSH", Run: runCheckLogins()},
				{Key: "5", Label: "Daftar Member SSH", Run: runListMembers()},
				{Key: "6", Label: "Hapus Akun SSH", Run: openPicker(pickDelete)},
				{Key: "7", Label: "Hapus User Expired SSH", Run: runMaintenance("HAPUS EXPIRED SSH", accounts.CleanExpiredSSH, viewProtoMenu)},
				{Key: "8", Label: "Ubah Limit IP SSH", Run: openPicker(pickChangeIP)},
				{Key: "9", Label: "Lock Akun SSH", Run: openPicker(pickLock)},
				{Key: "a", Label: "Unlock Akun SSH", Run: openPicker(pickUnlock)},
				{Key: "b", Label: "Detail Config SSH (+ SlowDNS)", Run: openPicker(pickDetail)},
				{Key: "c", Label: "Autokill SSH", Run: runExternal("autokill")},
				{Key: "d", Label: "Cek Multi Login SSH", Run: runExternal("ceklim")},
				{Key: "0", Label: "Kembali ke Menu Utama", Run: goView(viewDashboard)},
			}
		}
		pName := strings.ToUpper(string(m.proto))
		return []menuItem{
			{Key: "1", Label: "Buat Akun " + pName, Run: startCreateForm()},
			{Key: "2", Label: "Trial " + pName + " (1 Hari)", Run: runQuickTrial()},
			{Key: "3", Label: "Hapus Akun " + pName, Run: openPicker(pickDelete)},
			{Key: "4", Label: "Perpanjang " + pName, Run: openPicker(pickRenew)},
			{Key: "5", Label: "Cek User Login " + pName, Run: runCheckLogins()},
			{Key: "6", Label: "Lihat Detail / 7 Link " + pName, Run: openPicker(pickDetail)},
			{Key: "7", Label: "Ubah Limit IP " + pName, Run: openPicker(pickChangeIP)},
			{Key: "8", Label: "Ubah Limit Quota (GB) " + pName, Run: openPicker(pickChangeQuota)},
			{Key: "9", Label: "Daftar Member " + pName, Run: runListMembers()},
			{Key: "a", Label: "Lock Akun " + pName, Run: openPicker(pickLock)},
			{Key: "b", Label: "Unlock Akun " + pName, Run: openPicker(pickUnlock)},
			{Key: "0", Label: "Kembali ke Menu Utama", Run: goView(viewDashboard)},
		}
	case viewSystem:
		return []menuItem{
			{Key: "1", Label: "Hapus Semua Akun Expired", Run: runMaintenance("CLEAN EXPIRED", accounts.CleanAllExpired, viewSystem)},
			{Key: "2", Label: "Clear Cache & Log", Run: runMaintenance("CLEAR CACHE & LOG", accounts.ClearCacheAndLogs, viewSystem)},
			{Key: "3", Label: "Monitor Bandwidth (vnstat)", Run: runExternal("bw")},
			{Key: "4", Label: "Speedtest VPS", Run: runExternal("speedtest")},
			{Key: "5", Label: "Limit Speed", Run: runExternal("limitspeed")},
			{Key: "6", Label: "Ganti Domain (addhost)", Run: runExternal("addhost")},
			{Key: "7", Label: "Perbarui Cert SSL (fixcert)", Run: runExternal("fixcert")},
			{Key: "8", Label: "Atur Auto Reboot", Run: runExternal("autoreboot")},
			{Key: "9", Label: "Kelola Bot Telegram", Run: runExternal("mbot")},
			{Key: "a", Label: "Add Bot Notifikasi", Run: runExternal("add-bot-notif")},
			{Key: "b", Label: "Info Port VPS", Run: runExternal("prot")},
			{Key: "c", Label: "Menu Utility Lengkap", Run: runExternal("utility")},
			{Key: "0", Label: "Kembali ke Menu Utama", Run: goView(viewDashboard)},
		}
	case viewBackup:
		return []menuItem{
			{Key: "1", Label: "Backup VPS Data", Run: runExternal("backup")},
			{Key: "2", Label: "Restore VPS Data", Run: runExternal("restore")},
			{Key: "3", Label: "AutoBackup VPS Data", Run: runExternal("autobackup")},
			{Key: "0", Label: "Kembali ke Menu Utama", Run: goView(viewDashboard)},
		}
	case viewServices:
		return []menuItem{
			{Key: "1", Label: "Hot-Reload Xray (SIGHUP)", Run: runServiceAction("xray", "reload")},
			{Key: "2", Label: "Restart Xray", Run: runServiceAction("xray", "restart")},
			{Key: "3", Label: "Reload Nginx", Run: runServiceAction("nginx", "reload")},
			{Key: "4", Label: "Reload HAProxy", Run: runServiceAction("haproxy", "reload")},
			{Key: "5", Label: "Restart WS Proxy (ws-rs)", Run: runServiceAction("ws", "restart")},
			{Key: "6", Label: "Restart Dropbear", Run: runServiceAction("dropbear", "restart")},
			{Key: "7", Label: "Restart SlowDNS", Run: runServiceAction("slowdns", "restart")},
			{Key: "8", Label: "Restart Quota (zevpn-limit)", Run: runServiceAction("zevpn-limit", "restart")},
			{Key: "0", Label: "Kembali ke Menu Utama", Run: goView(viewDashboard)},
		}
	case viewSlowDNS:
		return []menuItem{
			{Key: "1", Label: "Restart SlowDNS", Run: runServiceAction("slowdns", "restart")},
			{Key: "0", Label: "Kembali ke Menu Utama", Run: goView(viewDashboard)},
		}
	case viewRollbackConfirm:
		return []menuItem{
			{Key: "y", Label: "Ya, Kembalikan ke Menu Klasik (Bash)", Run: runRollback()},
			{Key: "n", Label: "Batal & Kembali ke Dashboard", Run: goView(viewDashboard)},
		}
	}
	return nil
}

func goView(v viewID) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.view = v
		m.cursor = 0
		m.notice = ""
		m.snap = sysinfo.Collect()
		return nil
	}
}

func openProto(p accounts.Protocol) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.proto = p
		m.view = viewProtoMenu
		m.cursor = 0
		m.notice = ""
		m.snap = sysinfo.Collect()
		return nil
	}
}

func startCreateForm() func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.view = viewForm
		m.fFocus = 0
		m.notice = ""
		if m.proto == accounts.ProtoSSH {
			m.fMode = formCreateSSH
			m.fTitle = "BUAT AKUN SSH & SLOWDNS"
			m.fFields = []formField{
				{Label: "Username      ", Value: ""},
				{Label: "Password      ", Value: ""},
				{Label: "Limit IP      ", Value: "2", Numeric: true},
				{Label: "Expired (Hari)", Value: "30", Numeric: true},
			}
		} else {
			m.fMode = formCreateXray
			m.fTitle = "BUAT AKUN " + strings.ToUpper(string(m.proto))
			m.fFields = []formField{
				{Label: "Username      ", Value: ""},
				{Label: "Limit IP      ", Value: "2", Numeric: true},
				{Label: "Quota (GB)    ", Value: "100", Numeric: true},
				{Label: "Expired (Hari)", Value: "30", Numeric: true},
			}
		}
		return nil
	}
}

func runQuickTrial() func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		user := accounts.RandomTrialUser("trial")
		var detail string
		var err error
		if m.proto == accounts.ProtoSSH {
			detail, err = accounts.CreateSSHAccount(accounts.SSHCreateParams{
				Username: user, Password: "1", Days: 1, IPLimit: 2,
			})
		} else {
			detail, err = accounts.CreateXrayAccount(accounts.XrayCreateParams{
				Proto: m.proto, Username: user, Days: 1, QuotaGB: 1, IPLimit: 2,
			})
		}
		if err != nil {
			m.notice = errStyle.Render("Gagal buat trial: " + err.Error())
			return nil
		}
		m.snap = sysinfo.Collect()
		m.view = viewProtoMenu
		return showInTerminal("TRIAL "+strings.ToUpper(string(m.proto))+" BERHASIL", detail)
	}
}

func openPicker(act pickAction) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.snap = sysinfo.Collect()
		var list []sysinfo.Account
		if act == pickUnlock && m.proto != accounts.ProtoSSH {
			locked := accounts.ListLockedXrayUsers(m.proto)
			for _, u := range locked {
				list = append(list, sysinfo.Account{Username: u, Expired: "LOCKED", Protocol: string(m.proto)})
			}
		} else {
			list = m.currentAccounts()
		}
		if len(list) == 0 {
			if act == pickUnlock && m.proto != accounts.ProtoSSH {
				m.notice = amberStyle.Render("Tidak ada akun terkunci di " + strings.ToUpper(string(m.proto)))
			} else {
				m.notice = amberStyle.Render("Belum ada akun " + strings.ToUpper(string(m.proto)))
			}
			return nil
		}
		m.pAction = act
		m.pUsers = list
		m.cursor = 0
		m.notice = ""
		m.view = viewPickUser
		return nil
	}
}

func runListMembers() func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.snap = sysinfo.Collect()
		accs := m.currentAccounts()
		names := make([]string, 0, len(accs))
		exps := make(map[string]string, len(accs))
		for _, a := range accs {
			names = append(names, a.Username)
			exps[a.Username] = a.Expired
		}
		body := accounts.ListMembers(m.proto, names, exps)
		return showInTerminal("DAFTAR MEMBER "+strings.ToUpper(string(m.proto)), body)
	}
}

func runCheckLogins() func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.snap = sysinfo.Collect()
		var body string
		if m.proto == accounts.ProtoSSH {
			body = accounts.CheckSSHLogins()
		} else {
			accs := m.currentAccounts()
			names := make([]string, 0, len(accs))
			for _, a := range accs {
				names = append(names, a.Username)
			}
			body = accounts.CheckXrayLoginsFromLog(accounts.XrayAccessLog, names, m.proto)
		}
		return showInTerminal("CEK LOGIN "+strings.ToUpper(string(m.proto)), body)
	}
}

func runMaintenance(title string, fn func() string, back viewID) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		body := fn()
		m.snap = sysinfo.Collect()
		m.view = back
		return showInTerminal(title, body)
	}
}

func runExternal(name string) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		path := "/usr/local/sbin/" + name
		if _, err := os.Stat(path); err != nil {
			if found, lerr := exec.LookPath(name); lerr == nil {
				path = found
			}
		}
		cmd := exec.Command(path)
		cmd.Env = append(os.Environ(), "VIP_MENU_NESTED=1")
		return tea.ExecProcess(cmd, func(err error) tea.Msg { return execFinishedMsg{err: err} })
	}
}

func runUpdateScript() func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		script := `SHA=$(curl -fsSL -H "Accept: application/vnd.github.sha" "https://api.github.com/repos/azziz1601/vip/commits/main" 2>/dev/null | tr -dc 'a-fA-F0-9'); REF="${SHA:-main}"; curl -fsSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/azziz1601/vip/${REF}/update.sh?t=$(date +%s)" -o /tmp/update.sh && chmod +x /tmp/update.sh && bash /tmp/update.sh`
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "VIP_MENU_NESTED=1")
		return tea.ExecProcess(cmd, func(err error) tea.Msg { return execFinishedMsg{err: err} })
	}
}

func runServiceAction(service, action string) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		return func() tea.Msg {
			err := exec.Command("systemctl", action, service).Run()
			return serviceActionMsg{service: service, action: action, err: err}
		}
	}
}

func runRollback() func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		return func() tea.Msg { return rollbackDoneMsg{err: rollback.RollbackToLegacy()} }
	}
}

func showInTerminal(title, body string) tea.Cmd {
	f, err := os.CreateTemp("", "vip-out-*.txt")
	if err != nil {
		return nil
	}
	tmpPath := f.Name()
	_, _ = fmt.Fprintf(f, "\033[1;33m%s\033[0m\n%s\n%s\n", title, strings.Repeat("─", 48), body)
	_ = f.Close()

	script := `clear; cat "$1"; rm -f "$1"; printf "\n\033[90mTekan Enter untuk kembali ke menu...\033[0m"; read -r _ || true`
	cmd := exec.Command("bash", "-c", script, "_", tmpPath)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return execFinishedMsg{err: nil}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case execFinishedMsg:
		m.snap = sysinfo.Collect()
		if msg.err != nil {
			m.notice = errStyle.Render("Error: " + msg.err.Error())
		} else {
			m.notice = ""
		}
		return m, nil

	case serviceActionMsg:
		m.snap = sysinfo.Collect()
		if msg.err != nil {
			m.notice = errStyle.Render(fmt.Sprintf("Gagal %s %s: %v", msg.action, msg.service, msg.err))
		} else {
			m.notice = greenStyle.Render(fmt.Sprintf("Berhasil %s %s", msg.action, msg.service))
		}
		return m, nil

	case rollbackDoneMsg:
		if msg.err != nil {
			m.notice = errStyle.Render("Rollback gagal: " + msg.err.Error())
			m.view = viewDashboard
			m.cursor = 0
			return m, nil
		}
		return m, tea.Quit

	case tea.KeyMsg:
		if m.view == viewForm {
			return m.updateForm(msg)
		}
		if m.view == viewPickUser {
			return m.updatePicker(msg)
		}
		if m.view == viewTextResult {
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "enter", "esc", "backspace", "q", " ":
				m.view = m.rBack
				m.cursor = 0
				m.notice = ""
			}
			return m, nil
		}

		items := m.itemsForCurrentView()
		switch msg.String() {
		case "ctrl+c", "q":
			if m.view == viewDashboard {
				return m, tea.Quit
			}
			m.view = viewDashboard
			m.cursor = 0
			m.notice = ""
			return m, nil
		case "esc", "backspace":
			if m.view != viewDashboard {
				m.view = viewDashboard
				m.cursor = 0
				m.notice = ""
			}
			return m, nil
		case "r":
			m.snap = sysinfo.Collect()
			m.notice = greenStyle.Render("Status diperbarui")
			return m, nil
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			} else if len(items) > 0 {
				m.cursor = len(items) - 1
			}
			return m, nil
		case "down", "j":
			if len(items) > 0 {
				m.cursor = (m.cursor + 1) % len(items)
			}
			return m, nil
		case "enter":
			if m.cursor >= 0 && m.cursor < len(items) && items[m.cursor].Run != nil {
				return m, items[m.cursor].Run(&m)
			}
			return m, nil
		default:
			key := strings.ToLower(msg.String())
			for idx, it := range items {
				if strings.ToLower(it.Key) == key && it.Run != nil {
					m.cursor = idx
					return m, it.Run(&m)
				}
			}
		}
	}
	return m, nil
}

func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.view = viewProtoMenu
		m.cursor = 0
		m.notice = ""
		return m, nil
	case "up", "shift+tab":
		if m.fFocus > 0 {
			m.fFocus--
		}
		return m, nil
	case "down", "tab":
		if m.fFocus < len(m.fFields)-1 {
			m.fFocus++
		}
		return m, nil
	case "enter":
		if m.fFocus < len(m.fFields)-1 {
			m.fFocus++
			return m, nil
		}
		return m.submitForm()
	case "backspace":
		v := m.fFields[m.fFocus].Value
		if len(v) > 0 {
			m.fFields[m.fFocus].Value = v[:len(v)-1]
		}
		return m, nil
	default:
		if len(msg.Runes) > 0 {
			for _, r := range msg.Runes {
				if m.fFields[m.fFocus].Numeric && (r < '0' || r > '9') {
					continue
				}
				if r >= 32 && r <= 126 {
					m.fFields[m.fFocus].Value += string(r)
				}
			}
		}
	}
	return m, nil
}

func (m Model) submitForm() (tea.Model, tea.Cmd) {
	switch m.fMode {
	case formCreateSSH:
		user := strings.TrimSpace(m.fFields[0].Value)
		pass := strings.TrimSpace(m.fFields[1].Value)
		ipLim, _ := strconv.Atoi(m.fFields[2].Value)
		days, _ := strconv.Atoi(m.fFields[3].Value)
		detail, err := accounts.CreateSSHAccount(accounts.SSHCreateParams{
			Username: user, Password: pass, Days: days, IPLimit: ipLim,
		})
		if err != nil {
			m.notice = errStyle.Render(err.Error())
			return m, nil
		}
		m.snap = sysinfo.Collect()
		m.view = viewProtoMenu
		m.cursor = 0
		return m, showInTerminal("AKUN SSH BERHASIL DIBUAT", detail)

	case formCreateXray:
		user := strings.TrimSpace(m.fFields[0].Value)
		ipLim, _ := strconv.Atoi(m.fFields[1].Value)
		quotaGB, _ := strconv.Atoi(m.fFields[2].Value)
		days, _ := strconv.Atoi(m.fFields[3].Value)
		detail, err := accounts.CreateXrayAccount(accounts.XrayCreateParams{
			Proto: m.proto, Username: user, Days: days, QuotaGB: quotaGB, IPLimit: ipLim,
		})
		if err != nil {
			m.notice = errStyle.Render(err.Error())
			return m, nil
		}
		m.snap = sysinfo.Collect()
		m.view = viewProtoMenu
		m.cursor = 0
		return m, showInTerminal("AKUN "+strings.ToUpper(string(m.proto))+" BERHASIL DIBUAT", detail)

	case formRenewAccount:
		days, _ := strconv.Atoi(m.fFields[0].Value)
		var newExp string
		var err error
		if m.proto == accounts.ProtoSSH {
			newExp, err = accounts.RenewSSHAccount(m.fTargetUsr, days)
		} else {
			newExp, err = accounts.RenewXrayAccount(m.proto, m.fTargetUsr, days)
		}
		if err != nil {
			m.notice = errStyle.Render(err.Error())
			return m, nil
		}
		m.snap = sysinfo.Collect()
		m.notice = greenStyle.Render(fmt.Sprintf("Akun '%s' diperpanjang s/d %s", m.fTargetUsr, newExp))
		m.view = viewProtoMenu
		m.cursor = 0
		return m, nil

	case formChangeIPLimit:
		newLim, _ := strconv.Atoi(m.fFields[0].Value)
		if err := accounts.ChangeIPLimit(m.proto, m.fTargetUsr, newLim); err != nil {
			m.notice = errStyle.Render(err.Error())
			return m, nil
		}
		m.snap = sysinfo.Collect()
		m.notice = greenStyle.Render(fmt.Sprintf("Limit IP '%s' diubah ke %d IP", m.fTargetUsr, newLim))
		m.view = viewProtoMenu
		m.cursor = 0
		return m, nil

	case formChangeQuotaGB:
		newQ, _ := strconv.Atoi(m.fFields[0].Value)
		if err := accounts.ChangeQuotaGB(m.proto, m.fTargetUsr, newQ); err != nil {
			m.notice = errStyle.Render(err.Error())
			return m, nil
		}
		m.snap = sysinfo.Collect()
		m.notice = greenStyle.Render(fmt.Sprintf("Quota '%s' diubah ke %d GB", m.fTargetUsr, newQ))
		m.view = viewProtoMenu
		m.cursor = 0
		return m, nil
	}
	return m, nil
}

func (m Model) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "backspace", "q":
		m.view = viewProtoMenu
		m.cursor = 0
		m.notice = ""
		return m, nil
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		} else if len(m.pUsers) > 0 {
			m.cursor = len(m.pUsers) - 1
		}
		return m, nil
	case "down", "j":
		if len(m.pUsers) > 0 {
			m.cursor = (m.cursor + 1) % len(m.pUsers)
		}
		return m, nil
	case "enter":
		if m.cursor < 0 || m.cursor >= len(m.pUsers) {
			return m, nil
		}
		target := m.pUsers[m.cursor].Username
		switch m.pAction {
		case pickDetail:
			var detail string
			var err error
			if m.proto == accounts.ProtoSSH {
				detail, err = accounts.GetSSHAccountDetail(target)
			} else {
				detail, err = accounts.GetXrayAccountDetail(m.proto, target)
			}
			if err != nil {
				m.notice = errStyle.Render(err.Error())
				m.view = viewProtoMenu
				return m, nil
			}
			m.view = viewProtoMenu
			m.cursor = 0
			return m, showInTerminal("DETAIL AKUN "+strings.ToUpper(string(m.proto))+" — "+target, detail)

		case pickRenew:
			m.fMode = formRenewAccount
			m.fTargetUsr = target
			m.fTitle = fmt.Sprintf("PERPANJANG %s — %s", strings.ToUpper(string(m.proto)), target)
			m.fFields = []formField{{Label: "Tambah (Hari) ", Value: "30", Numeric: true}}
			m.fFocus = 0
			m.notice = ""
			m.view = viewForm
			return m, nil

		case pickChangeIP:
			m.fMode = formChangeIPLimit
			m.fTargetUsr = target
			m.fTitle = fmt.Sprintf("UBAH LIMIT IP %s — %s", strings.ToUpper(string(m.proto)), target)
			m.fFields = []formField{{Label: "Limit IP Baru ", Value: "2", Numeric: true}}
			m.fFocus = 0
			m.notice = ""
			m.view = viewForm
			return m, nil

		case pickChangeQuota:
			m.fMode = formChangeQuotaGB
			m.fTargetUsr = target
			m.fTitle = fmt.Sprintf("UBAH QUOTA %s — %s", strings.ToUpper(string(m.proto)), target)
			m.fFields = []formField{{Label: "Quota Baru (GB)", Value: "100", Numeric: true}}
			m.fFocus = 0
			m.notice = ""
			m.view = viewForm
			return m, nil

		case pickLock:
			var err error
			if m.proto == accounts.ProtoSSH {
				err = accounts.LockSSHAccount(target)
			} else {
				err = accounts.LockXrayAccount(m.proto, target)
			}
			if err != nil {
				m.notice = errStyle.Render("Gagal lock: " + err.Error())
			} else {
				m.notice = greenStyle.Render(fmt.Sprintf("Akun '%s' berhasil dikunci", target))
			}
			m.snap = sysinfo.Collect()
			m.view = viewProtoMenu
			m.cursor = 0
			return m, nil

		case pickUnlock:
			var err error
			if m.proto == accounts.ProtoSSH {
				err = accounts.UnlockSSHAccount(target)
			} else {
				err = accounts.UnlockXrayAccount(m.proto, target)
			}
			if err != nil {
				m.notice = errStyle.Render("Gagal unlock: " + err.Error())
			} else {
				m.notice = greenStyle.Render(fmt.Sprintf("Akun '%s' berhasil dibuka kembali", target))
			}
			m.snap = sysinfo.Collect()
			m.view = viewProtoMenu
			m.cursor = 0
			return m, nil

		case pickDelete:
			var err error
			if m.proto == accounts.ProtoSSH {
				err = accounts.DeleteSSHAccount(target)
			} else {
				err = accounts.DeleteXrayAccount(m.proto, target)
			}
			if err != nil {
				m.notice = errStyle.Render("Gagal hapus: " + err.Error())
			} else {
				m.notice = greenStyle.Render(fmt.Sprintf("Akun '%s' berhasil dihapus", target))
			}
			m.snap = sysinfo.Collect()
			m.view = viewProtoMenu
			m.cursor = 0
			return m, nil
		}
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder

	b.WriteString(blueLine() + "\n")
	b.WriteString(barBannerStyle.Render(fmt.Sprintf("ZE-VPN TUNNELING  •  v%s", m.version)) + "\n")
	b.WriteString(blueLine() + "\n")

	if m.view == viewDashboard {
		b.WriteString(m.renderDashboard())
		return b.String()
	}

	if m.view == viewForm {
		b.WriteString("\n" + greenStyle.Bold(true).Render("  "+m.fTitle) + "\n")
		b.WriteString(redLine() + "\n")
		for i, f := range m.fFields {
			cursorMark := "  "
			valDisplay := valStyle.Render(f.Value)
			if i == m.fFocus {
				cursorMark = amberStyle.Render("▸ ")
				valDisplay = skyStyle.Render(f.Value + "█")
			}
			b.WriteString(fmt.Sprintf("%s%s : %s\n", cursorMark, greenStyle.Render(f.Label), valDisplay))
		}
		if m.notice != "" {
			b.WriteString("\n  " + m.notice + "\n")
		}
		b.WriteString(blueLine() + "\n")
		b.WriteString(mutedStyle.Render("  Tab/↓ Lanjut • Enter Simpan • Esc Batal") + "\n")
		return b.String()
	}

	if m.view == viewPickUser {
		actLabel := "PILIH AKUN"
		switch m.pAction {
		case pickDetail:
			actLabel = "LIHAT DETAIL — " + strings.ToUpper(string(m.proto))
		case pickRenew:
			actLabel = "PERPANJANG — " + strings.ToUpper(string(m.proto))
		case pickDelete:
			actLabel = "HAPUS AKUN — " + strings.ToUpper(string(m.proto))
		case pickChangeIP:
			actLabel = "UBAH LIMIT IP — " + strings.ToUpper(string(m.proto))
		case pickChangeQuota:
			actLabel = "UBAH QUOTA GB — " + strings.ToUpper(string(m.proto))
		case pickLock:
			actLabel = "LOCK AKUN — " + strings.ToUpper(string(m.proto))
		case pickUnlock:
			actLabel = "UNLOCK AKUN — " + strings.ToUpper(string(m.proto))
		}
		b.WriteString("\n" + greenStyle.Bold(true).Render("  "+actLabel) + "\n")
		b.WriteString(redLine() + "\n")
		for i, a := range m.pUsers {
			row := fmt.Sprintf(" %2d) %-18s  exp: %s", i+1, a.Username, a.Expired)
			if i == m.cursor {
				b.WriteString(selRowStyle.Width(panelWidth).Render("▸"+row) + "\n")
			} else {
				b.WriteString(greenStyle.Render(" "+row) + "\n")
			}
		}
		b.WriteString(blueLine() + "\n")
		b.WriteString(mutedStyle.Render("  ↑/↓ Pilih • Enter Lanjut • Esc Kembali") + "\n")
		return b.String()
	}

	if m.view == viewSlowDNS {
		b.WriteString("\n" + greenStyle.Bold(true).Render("  KONFIGURASI SLOWDNS (HTTP CUSTOM)") + "\n")
		b.WriteString(redLine() + "\n")
		b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("DOMAIN     "), skyStyle.Render(m.snap.Domain)))
		b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("NAME SERVER"), skyStyle.Render(m.snap.SlowDNSNS)))
		b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("PUB KEY    "), amberStyle.Render(m.snap.SlowDNSPub)))
		b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("PORT UDP   "), greenStyle.Render("53")))
		b.WriteString(blueLine() + "\n")
	} else if m.view == viewRollbackConfirm {
		b.WriteString("\n" + amberStyle.Render("  KONFIRMASI ROLLBACK KE MENU KLASIK") + "\n")
		b.WriteString(redLine() + "\n")
		b.WriteString("  Perintah 'menu' akan dikembalikan ke menu-legacy.\n")
		b.WriteString("  Untuk balik ke TUI Go kapan saja, ketik: menu-tui\n")
		b.WriteString(blueLine() + "\n")
	} else if m.view == viewProtoMenu {
		pTitle := strings.ToUpper(string(m.proto))
		b.WriteString(fmt.Sprintf("\n  %s  (%s akun)\n", greenStyle.Bold(true).Render("MENU "+pTitle), amberStyle.Render(fmt.Sprintf("%d", len(m.currentAccounts())))))
		b.WriteString(redLine() + "\n")
	} else if m.view == viewBackup {
		b.WriteString("\n" + greenStyle.Bold(true).Render("  BACKUP & RESTORE VPS") + "\n")
		b.WriteString(redLine() + "\n")
	} else if m.view == viewSystem {
		b.WriteString("\n" + greenStyle.Bold(true).Render("  MENU SYSTEM & UTILITY") + "\n")
		b.WriteString(redLine() + "\n")
	} else if m.view == viewServices {
		b.WriteString("\n" + greenStyle.Bold(true).Render("  SERVICE CONTROL") + "\n")
		b.WriteString(redLine() + "\n")
	}

	if m.notice != "" {
		b.WriteString("  " + m.notice + "\n")
	}

	items := m.itemsForCurrentView()
	for i, it := range items {
		if i == m.cursor {
			b.WriteString(selRowStyle.Width(panelWidth).Render(fmt.Sprintf(" ▸ [%s] %s", it.Key, it.Label)) + "\n")
		} else {
			b.WriteString(fmt.Sprintf("   [%s] %s\n", amberStyle.Render(it.Key), greenStyle.Render(it.Label)))
		}
	}
	b.WriteString(blueLine() + "\n")
	b.WriteString(mutedStyle.Render("  ↑/↓ Navigasi • Enter Pilih • Esc/0 Kembali") + "\n")
	return b.String()
}

func (m Model) renderDashboard() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("OS     "), greenStyle.Render(m.snap.OSName)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("RAM    "), greenStyle.Render(fmt.Sprintf("%dM / %dM (%d%%)", m.snap.MemUsedMB, m.snap.MemTotalMB, m.snap.MemPercent))))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("SWAP   "), greenStyle.Render(fmt.Sprintf("%dM", m.snap.SwapTotalMB))))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("CITY   "), greenStyle.Render(m.snap.City)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("ISP    "), greenStyle.Render(m.snap.ISP)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("IP     "), skyStyle.Render(m.snap.IP)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("DOMAIN "), skyStyle.Render(m.snap.Domain)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("UPTIME "), greenStyle.Render(m.snap.Uptime)))
	b.WriteString(redLine() + "\n")
	b.WriteString(fmt.Sprintf("  %s : %-13s %s\n", greenStyle.Render("MONTH  "), greenStyle.Render(m.snap.BW.MonthTotal), greenStyle.Render("["+m.snap.BW.MonthName+"]")))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("RX     "), greenStyle.Render(m.snap.BW.MonthRX)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("TX     "), greenStyle.Render(m.snap.BW.MonthTX)))
	b.WriteString(redLine() + "\n")
	b.WriteString(fmt.Sprintf("  %s : %-13s %s\n", greenStyle.Render("DAY    "), greenStyle.Render(m.snap.BW.DayTotal), greenStyle.Render("["+m.snap.BW.DayName+"]")))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("RX     "), greenStyle.Render(m.snap.BW.DayRX)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("TX     "), greenStyle.Render(m.snap.BW.DayTX)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", greenStyle.Render("TRAFFIC"), greenStyle.Render(m.snap.BW.TrafficRate)))
	b.WriteString(blueLine() + "\n")

	svcBadge := func(name string) string {
		for _, s := range m.snap.Services {
			if s.Name == name {
				if s.Active {
					return amberStyle.Render("ON")
				}
				return errStyle.Render("OFF")
			}
		}
		return errStyle.Render("OFF")
	}
	b.WriteString(fmt.Sprintf("  %s: %s  %s: %s  %s: %s  %s: %s\n",
		greenStyle.Render("XRAY"), svcBadge("xray"),
		greenStyle.Render("SSH-WS"), svcBadge("ws"),
		greenStyle.Render("LOADBLC"), svcBadge("haproxy"),
		greenStyle.Render("DNS"), svcBadge("slowdns"),
	))
	b.WriteString(blueLine() + "\n")

	b.WriteString(lipgloss.NewStyle().Width(panelWidth).Align(lipgloss.Center).Foreground(colorGreen).Render("LIST ACCOUNTS") + "\n")
	b.WriteString(redLine() + "\n")
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", greenStyle.Render("SSH/OPENVPN"), amberStyle.Render(fmt.Sprintf("%d", len(m.snap.SSHAccounts))), greenStyle.Render("ACCOUNT")))
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", greenStyle.Render("VMESS      "), amberStyle.Render(fmt.Sprintf("%d", len(m.snap.VMessAccs))), greenStyle.Render("ACCOUNT")))
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", greenStyle.Render("VLESS      "), amberStyle.Render(fmt.Sprintf("%d", len(m.snap.VLESSAccs))), greenStyle.Render("ACCOUNT")))
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", greenStyle.Render("TROJAN     "), amberStyle.Render(fmt.Sprintf("%d", len(m.snap.TrojanAccs))), greenStyle.Render("ACCOUNT")))
	b.WriteString(blueLine() + "\n")

	if m.notice != "" {
		b.WriteString("  " + m.notice + "\n")
	}

	items := m.itemsForCurrentView()
	half := (len(items) + 1) / 2
	for i := 0; i < half; i++ {
		left := renderMenuCell(items[i], i == m.cursor, 25)
		right := ""
		if i+half < len(items) {
			right = renderMenuCell(items[i+half], i+half == m.cursor, 25)
		}
		b.WriteString(" " + left + " " + right + "\n")
	}
	b.WriteString(blueLine() + "\n")
	b.WriteString(mutedStyle.Render("  ↑/↓ Pilih • Enter Buka • 0-9 Pintasan • r Refresh • q") + "\n")
	return b.String()
}

func renderMenuCell(it menuItem, selected bool, width int) string {
	if selected {
		return selRowStyle.Width(width).Render(fmt.Sprintf("▸[%s] %s", it.Key, it.Label))
	}
	plain := fmt.Sprintf(" [%s] %s", it.Key, it.Label)
	pad := width - len(plain)
	if pad < 0 {
		pad = 0
	}
	return fmt.Sprintf(" [%s] %s%s", amberStyle.Render(it.Key), greenStyle.Render(it.Label), strings.Repeat(" ", pad))
}
