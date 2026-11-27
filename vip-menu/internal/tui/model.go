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
	viewProtoMenu        // Native submenu for SSH / VMess / VLESS / Trojan
	viewSystem
	viewServices
	viewSlowDNS
	viewRollbackConfirm
	viewForm       // Native Go input form (Create / Renew)
	viewPickUser   // Native Go user picker (Renew / Delete / Detail)
	viewTextResult // Native Go copyable result viewer (Created config / Login table / Maintenance output)
)

type pickAction int

const (
	pickDetail pickAction = iota
	pickRenew
	pickDelete
)

type formMode int

const (
	formCreateSSH formMode = iota
	formCreateXray
	formRenewAccount
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

	// Native form state
	fMode      formMode
	fTitle     string
	fFields    []formField
	fFocus     int
	fTargetUsr string

	// Native user picker state
	pAction pickAction
	pUsers  []sysinfo.Account

	// Native result screen state
	rTitle string
	rBody  string
	rBack  viewID
}

var (
	colorCyan   = lipgloss.Color("#22D3EE")
	colorBlue   = lipgloss.Color("#38BDF8")
	colorGreen  = lipgloss.Color("#4ADE80")
	colorRed    = lipgloss.Color("#F87171")
	colorYellow = lipgloss.Color("#FACC15")
	colorMuted  = lipgloss.Color("#94A3B8")
	colorText   = lipgloss.Color("#F8FAFC")

	// Classic-inspired fixed-width (62 chars) bordered boxes with modern rounded corners
	boxWidth = 62

	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#DC2626")).
			Width(boxWidth - 4).
			Align(lipgloss.Center)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorCyan).
			Width(boxWidth).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(colorCyan)
	labelStyle = lipgloss.NewStyle().Foreground(colorCyan)
	mutedStyle = lipgloss.NewStyle().Foreground(colorMuted)
	valStyle   = lipgloss.NewStyle().Foreground(colorText).Bold(true)
	okStyle    = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	errStyle   = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	warnStyle  = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)

	selRowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0F172A")).
			Background(colorCyan)

	numStyle = lipgloss.NewStyle().Bold(true).Foreground(colorGreen)
)

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
			{Key: "9", Label: "BACKUP/RESTORE", Run: runExternal("menu-backup")},
			{Key: "0", Label: "ROLLBACK KLASIK", Run: goView(viewRollbackConfirm)},
		}
	case viewProtoMenu:
		pName := strings.ToUpper(string(m.proto))
		return []menuItem{
			{Key: "1", Label: "Buat Akun " + pName, Run: startCreateForm()},
			{Key: "2", Label: "Trial " + pName + " (1 Hari)", Run: runQuickTrial()},
			{Key: "3", Label: "Perpanjang " + pName, Run: openPicker(pickRenew)},
			{Key: "4", Label: "Hapus " + pName, Run: openPicker(pickDelete)},
			{Key: "5", Label: "Cek User Login " + pName, Run: runCheckLogins()},
			{Key: "6", Label: "Lihat Detail / Link " + pName, Run: openPicker(pickDetail)},
			{Key: "0", Label: "Kembali ke Menu Utama", Run: goView(viewDashboard)},
		}
	case viewSystem:
		return []menuItem{
			{Key: "1", Label: "Hapus Akun Expired (XP)", Run: runMaintenance("CLEAN EXPIRED", accounts.CleanExpiredXray)},
			{Key: "2", Label: "Clear Cache & Log", Run: runMaintenance("CLEAR CACHE & LOG", accounts.ClearCacheAndLogs)},
			{Key: "3", Label: "Monitor Bandwidth (vnstat)", Run: runExternal("bw")},
			{Key: "4", Label: "Speedtest VPS", Run: runExternal("speedtest")},
			{Key: "5", Label: "Limit Speed", Run: runExternal("limitspeed")},
			{Key: "6", Label: "Utility & Pengaturan Lainnya", Run: runExternal("utility")},
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
				Username: user,
				Password: "1",
				Days:     1,
				IPLimit:  2,
			})
		} else {
			detail, err = accounts.CreateXrayAccount(accounts.XrayCreateParams{
				Proto:    m.proto,
				Username: user,
				Days:     1,
				QuotaGB:  1,
				IPLimit:  2,
			})
		}
		if err != nil {
			m.notice = errStyle.Render("Gagal buat trial: " + err.Error())
			return nil
		}
		m.snap = sysinfo.Collect()
		m.rTitle = "TRIAL " + strings.ToUpper(string(m.proto)) + " BERHASIL"
		m.rBody = detail
		m.rBack = viewProtoMenu
		m.view = viewTextResult
		return nil
	}
}

func openPicker(act pickAction) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.snap = sysinfo.Collect()
		accs := m.currentAccounts()
		if len(accs) == 0 {
			m.notice = warnStyle.Render("Belum ada akun " + strings.ToUpper(string(m.proto)))
			return nil
		}
		m.pAction = act
		m.pUsers = accs
		m.cursor = 0
		m.notice = ""
		m.view = viewPickUser
		return nil
	}
}

func runCheckLogins() func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.snap = sysinfo.Collect()
		if m.proto == accounts.ProtoSSH {
			m.rBody = accounts.CheckSSHLogins()
		} else {
			accs := m.currentAccounts()
			names := make([]string, 0, len(accs))
			for _, a := range accs {
				names = append(names, a.Username)
			}
			m.rBody = accounts.CheckXrayLoginsFromLog(accounts.XrayAccessLog, names, m.proto)
		}
		m.rTitle = "CEK LOGIN " + strings.ToUpper(string(m.proto))
		m.rBack = viewProtoMenu
		m.view = viewTextResult
		return nil
	}
}

func runMaintenance(title string, fn func() string) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		m.rTitle = title
		m.rBody = fn()
		m.rBack = viewSystem
		m.snap = sysinfo.Collect()
		m.view = viewTextResult
		return nil
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
			m.notice = okStyle.Render("Selesai")
		}
		return m, nil

	case serviceActionMsg:
		m.snap = sysinfo.Collect()
		if msg.err != nil {
			m.notice = errStyle.Render(fmt.Sprintf("Gagal %s %s: %v", msg.action, msg.service, msg.err))
		} else {
			m.notice = okStyle.Render(fmt.Sprintf("Berhasil %s %s", msg.action, msg.service))
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
			m.notice = okStyle.Render("Status diperbarui")
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
		m.rTitle = "AKUN SSH BERHASIL DIBUAT"
		m.rBody = detail
		m.rBack = viewProtoMenu
		m.view = viewTextResult
		return m, nil

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
		m.rTitle = "AKUN " + strings.ToUpper(string(m.proto)) + " BERHASIL DIBUAT"
		m.rBody = detail
		m.rBack = viewProtoMenu
		m.view = viewTextResult
		return m, nil

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
		m.notice = okStyle.Render(fmt.Sprintf("Akun '%s' diperpanjang s/d %s", m.fTargetUsr, newExp))
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
			m.rTitle = "DETAIL AKUN " + strings.ToUpper(string(m.proto)) + " — " + target
			m.rBody = detail
			m.rBack = viewProtoMenu
			m.view = viewTextResult
			return m, nil

		case pickRenew:
			m.fMode = formRenewAccount
			m.fTargetUsr = target
			m.fTitle = fmt.Sprintf("PERPANJANG %s — %s", strings.ToUpper(string(m.proto)), target)
			m.fFields = []formField{{Label: "Tambah (Hari) ", Value: "30", Numeric: true}}
			m.fFocus = 0
			m.notice = ""
			m.view = viewForm
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
				m.notice = okStyle.Render(fmt.Sprintf("Akun '%s' berhasil dihapus", target))
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

	// Top classic-style centered banner
	topBox := boxStyle.Render(bannerStyle.Render(fmt.Sprintf(".::. ZE-VPN STORE TUNNEL  v%s .::.", m.version)))
	b.WriteString(topBox + "\n")

	if m.view == viewDashboard {
		b.WriteString(m.renderClassicDashboard())
		return b.String()
	}

	if m.view == viewTextResult {
		body := titleStyle.Render(m.rTitle) + "\n\n" + m.rBody
		b.WriteString(boxStyle.Width(boxWidth + 14).Render(body) + "\n")
		b.WriteString(mutedStyle.Render("  Tekan Enter / Esc untuk kembali...") + "\n")
		return b.String()
	}

	if m.view == viewForm {
		var lines []string
		lines = append(lines, titleStyle.Render(m.fTitle), "")
		for i, f := range m.fFields {
			cursorMark := "  "
			valDisplay := f.Value
			if i == m.fFocus {
				cursorMark = okStyle.Render("▸ ")
				valDisplay = valStyle.Render(f.Value + "█")
			} else {
				valDisplay = valStyle.Render(f.Value)
			}
			lines = append(lines, fmt.Sprintf("%s%s : %s", cursorMark, labelStyle.Render(f.Label), valDisplay))
		}
		if m.notice != "" {
			lines = append(lines, "", m.notice)
		}
		b.WriteString(boxStyle.Render(strings.Join(lines, "\n")) + "\n")
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
		}
		var lines []string
		lines = append(lines, titleStyle.Render(actLabel), "")
		for i, a := range m.pUsers {
			row := fmt.Sprintf(" %2d) %-20s  exp: %s", i+1, a.Username, a.Expired)
			if i == m.cursor {
				lines = append(lines, selRowStyle.Width(boxWidth-4).Render("▸"+row))
			} else {
				lines = append(lines, " "+row)
			}
		}
		b.WriteString(boxStyle.Render(strings.Join(lines, "\n")) + "\n")
		b.WriteString(mutedStyle.Render("  ↑/↓ Pilih • Enter Lanjut • Esc Kembali") + "\n")
		return b.String()
	}

	// Sub-menus (Proto / System / Services / SlowDNS / Rollback)
	if m.view == viewSlowDNS {
		info := strings.Join([]string{
			titleStyle.Render("KONFIGURASI SLOWDNS (HTTP CUSTOM)"),
			fmt.Sprintf(" %s = %s", labelStyle.Render("Domain      "), valStyle.Render(m.snap.Domain)),
			fmt.Sprintf(" %s = %s", labelStyle.Render("Name Server "), valStyle.Render(m.snap.SlowDNSNS)),
			fmt.Sprintf(" %s = %s", labelStyle.Render("Pub Key     "), okStyle.Render(m.snap.SlowDNSPub)),
			fmt.Sprintf(" %s = %s", labelStyle.Render("Port UDP    "), valStyle.Render("53")),
		}, "\n")
		b.WriteString(boxStyle.Render(info) + "\n")
	} else if m.view == viewRollbackConfirm {
		info := strings.Join([]string{
			warnStyle.Render("KONFIRMASI ROLLBACK KE MENU KLASIK"),
			"Perintah 'menu' akan dikembalikan ke /usr/local/sbin/menu-legacy.",
			"Untuk balik ke TUI Go kapan saja, ketik: menu-tui",
		}, "\n")
		b.WriteString(boxStyle.Render(info) + "\n")
	} else if m.view == viewProtoMenu {
		pTitle := strings.ToUpper(string(m.proto))
		b.WriteString(boxStyle.Render(fmt.Sprintf("%s  (%d akun aktif)", titleStyle.Render("MENU "+pTitle), len(m.currentAccounts()))) + "\n")
	}

	if m.notice != "" {
		b.WriteString("  " + m.notice + "\n")
	}

	items := m.itemsForCurrentView()
	var listLines []string
	for i, it := range items {
		if i == m.cursor {
			listLines = append(listLines, selRowStyle.Width(boxWidth-4).Render(fmt.Sprintf(" ▸ [%s] %s", it.Key, it.Label)))
		} else {
			listLines = append(listLines, fmt.Sprintf("   [%s] %s", numStyle.Render(it.Key), it.Label))
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(listLines, "\n")) + "\n")
	b.WriteString(mutedStyle.Render("  ↑/↓ Navigasi • Enter Pilih • Angka Pintasan • Esc/0 Kembali") + "\n")
	return b.String()
}

func (m Model) renderClassicDashboard() string {
	var b strings.Builder

	// 1. System Info Box (mirrors classic menu/menu lines 209-223)
	sysLines := []string{
		fmt.Sprintf(" %s %-14s = %s", errStyle.Render("•"), labelStyle.Render("System OS"), m.snap.OSName),
		fmt.Sprintf(" %s %-14s = %d Core  (Load: %s)", errStyle.Render("•"), labelStyle.Render("Core System"), m.snap.CPUCores, m.snap.LoadAvg),
		fmt.Sprintf(" %s %-14s = %d/%d MB (%d%%)", errStyle.Render("•"), labelStyle.Render("Server RAM"), m.snap.MemUsedMB, m.snap.MemTotalMB, m.snap.MemPercent),
		fmt.Sprintf(" %s %-14s = %s", errStyle.Render("•"), labelStyle.Render("Uptime Server"), m.snap.Uptime),
		fmt.Sprintf(" %s %-14s = %s", errStyle.Render("•"), labelStyle.Render("Domain"), valStyle.Render(m.snap.Domain)),
		fmt.Sprintf(" %s %-14s = %s", errStyle.Render("•"), labelStyle.Render("IP VPS"), valStyle.Render(m.snap.IP)),
		fmt.Sprintf(" %s %-14s = %s (%s)", errStyle.Render("•"), labelStyle.Render("ISP / City"), m.snap.ISP, m.snap.City),
	}
	b.WriteString(boxStyle.Render(strings.Join(sysLines, "\n")) + "\n")

	// 2. Account Summary Box (mirrors classic lines 224-229)
	accLines := []string{
		fmt.Sprintf("   %-16s %s %s ACCOUNT", labelStyle.Render("SSH/OPENVPN"), warnStyle.Render("➤"), valStyle.Render(fmt.Sprintf("%-3d", len(m.snap.SSHAccounts)))),
		fmt.Sprintf("   %-16s %s %s ACCOUNT", labelStyle.Render("VMESS/MULTI"), warnStyle.Render("➤"), valStyle.Render(fmt.Sprintf("%-3d", len(m.snap.VMessAccs)))),
		fmt.Sprintf("   %-16s %s %s ACCOUNT", labelStyle.Render("VLESS/MULTI"), warnStyle.Render("➤"), valStyle.Render(fmt.Sprintf("%-3d", len(m.snap.VLESSAccs)))),
		fmt.Sprintf("   %-16s %s %s ACCOUNT", labelStyle.Render("TROJAN/MULTI"), warnStyle.Render("➤"), valStyle.Render(fmt.Sprintf("%-3d", len(m.snap.TrojanAccs)))),
	}
	b.WriteString(boxStyle.Render(strings.Join(accLines, "\n")) + "\n")

	// 3. Service Status Grid (2 rows x 4 services, compact like classic lines 231-234)
	var svcRows []string
	for r := 0; r < len(m.snap.Services); r += 4 {
		var cols []string
		for c := r; c < r+4 && c < len(m.snap.Services); c++ {
			s := m.snap.Services[c]
			dot := errStyle.Render("●")
			if s.Active {
				dot = okStyle.Render("●")
			}
			cols = append(cols, fmt.Sprintf("%s %-10s", dot, s.Label))
		}
		svcRows = append(svcRows, " "+strings.Join(cols, " "))
	}
	b.WriteString(boxStyle.Render(strings.Join(svcRows, "\n")) + "\n")

	if m.notice != "" {
		b.WriteString("  " + m.notice + "\n")
	}

	// 4. Classic 2-Column Menu Grid (mirrors classic lines 235-241)
	items := m.itemsForCurrentView()
	half := (len(items) + 1) / 2
	var gridLines []string
	for i := 0; i < half; i++ {
		leftCell := renderGridCell(items[i], i == m.cursor, 27)
		rightCell := strings.Repeat(" ", 27)
		if i+half < len(items) {
			rightCell = renderGridCell(items[i+half], i+half == m.cursor, 27)
		}
		gridLines = append(gridLines, leftCell+" │ "+rightCell)
	}
	b.WriteString(boxStyle.Render(strings.Join(gridLines, "\n")) + "\n")

	// 5. Bandwidth Box (mirrors classic lines 242-245)
	bwLine := fmt.Sprintf("  %s  Daily: %s   │   Monthly: %s",
		titleStyle.Render("Bandwidth"), valStyle.Render(m.snap.BW.Daily), valStyle.Render(m.snap.BW.Monthly))
	b.WriteString(boxStyle.Render(bwLine) + "\n")

	b.WriteString(mutedStyle.Render("  ↑/↓ Navigasi • Enter Pilih • 0-9 Pintasan • r Refresh • q Keluar") + "\n")
	return b.String()
}

func renderGridCell(it menuItem, selected bool, width int) string {
	if selected {
		text := fmt.Sprintf("▸[%s] %s", it.Key, it.Label)
		return selRowStyle.Width(width).Render(text)
	}
	plain := fmt.Sprintf(" [%s] %s", it.Key, it.Label)
	pad := width - len(plain)
	if pad < 0 {
		pad = 0
	}
	return fmt.Sprintf(" [%s] %s%s", numStyle.Render(it.Key), it.Label, strings.Repeat(" ", pad))
}
