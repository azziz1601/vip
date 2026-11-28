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
	pOffset int
	pQuery  string
}

var (
	// Calm slate palette (no neon/glow)
	colorLine    = lipgloss.Color("#475569")
	colorSubLine = lipgloss.Color("#334155")
	colorHeader  = lipgloss.Color("#1E293B")
	colorText    = lipgloss.Color("#CBD5E1")
	colorBright  = lipgloss.Color("#F1F5F9")
	colorLabel   = lipgloss.Color("#94A3B8")
	colorAccent  = lipgloss.Color("#93C5FD")
	colorOk      = lipgloss.Color("#86EFAC")
	colorWarn    = lipgloss.Color("#FDE68A")
	colorErr     = lipgloss.Color("#FCA5A5")
	colorMuted   = lipgloss.Color("#64748B")

	panelWidth = 52

	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBright).
			Background(colorHeader).
			Width(panelWidth).
			Align(lipgloss.Center)

	ruleStyle    = lipgloss.NewStyle().Foreground(colorLine)
	subRuleStyle = lipgloss.NewStyle().Foreground(colorSubLine)

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(colorBright)
	labelStyle = lipgloss.NewStyle().Foreground(colorLabel)
	textStyle  = lipgloss.NewStyle().Foreground(colorText)
	valStyle   = lipgloss.NewStyle().Foreground(colorBright)
	accStyle   = lipgloss.NewStyle().Foreground(colorAccent)
	okStyle    = lipgloss.NewStyle().Foreground(colorOk)
	warnStyle  = lipgloss.NewStyle().Foreground(colorWarn)
	errStyle   = lipgloss.NewStyle().Foreground(colorErr)
	mutedStyle = lipgloss.NewStyle().Foreground(colorMuted)

	selRowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBright).
			Background(colorSubLine)
)

func mainLine() string { return ruleStyle.Render(strings.Repeat("─", panelWidth)) }
func thinLine() string { return subRuleStyle.Render(strings.Repeat("─", panelWidth)) }

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
			{Key: "1", Label: "SSH", Run: openProto(accounts.ProtoSSH)},
			{Key: "2", Label: "VMess", Run: openProto(accounts.ProtoVMess)},
			{Key: "3", Label: "VLESS", Run: openProto(accounts.ProtoVLESS)},
			{Key: "4", Label: "Trojan", Run: openProto(accounts.ProtoTrojan)},
			{Key: "5", Label: "System", Run: goView(viewSystem)},
			{Key: "6", Label: "Services", Run: goView(viewServices)},
			{Key: "7", Label: "SlowDNS", Run: goView(viewSlowDNS)},
			{Key: "8", Label: "Update", Run: runUpdateScript()},
			{Key: "9", Label: "Backup", Run: goView(viewBackup)},
			{Key: "0", Label: "Classic Menu", Run: goView(viewRollbackConfirm)},
		}
	case viewProtoMenu:
		if m.proto == accounts.ProtoSSH {
			return []menuItem{
				{Key: "1", Label: "Create Account", Run: startCreateForm()},
				{Key: "2", Label: "Trial Account", Run: runQuickTrial()},
				{Key: "3", Label: "Renew Account", Run: openPicker(pickRenew)},
				{Key: "4", Label: "Active Logins", Run: runCheckLogins()},
				{Key: "5", Label: "Member List", Run: runListMembers()},
				{Key: "6", Label: "Delete Account", Run: openPicker(pickDelete)},
				{Key: "7", Label: "Clean Expired", Run: runMaintenance("EXPIRED SSH ACCOUNTS", accounts.CleanExpiredSSH, viewProtoMenu)},
				{Key: "8", Label: "Edit IP Limit", Run: openPicker(pickChangeIP)},
				{Key: "9", Label: "Lock Account", Run: openPicker(pickLock)},
				{Key: "a", Label: "Unlock Account", Run: openPicker(pickUnlock)},
				{Key: "b", Label: "Account Config", Run: openPicker(pickDetail)},
				{Key: "c", Label: "Autokill", Run: runExternal("autokill")},
				{Key: "d", Label: "Multi Login Check", Run: runExternal("ceklim")},
				{Key: "0", Label: "Back", Run: goView(viewDashboard)},
			}
		}
		return []menuItem{
			{Key: "1", Label: "Create Account", Run: startCreateForm()},
			{Key: "2", Label: "Trial Account", Run: runQuickTrial()},
			{Key: "3", Label: "Delete Account", Run: openPicker(pickDelete)},
			{Key: "4", Label: "Renew Account", Run: openPicker(pickRenew)},
			{Key: "5", Label: "Active Logins", Run: runCheckLogins()},
			{Key: "6", Label: "Account Config", Run: openPicker(pickDetail)},
			{Key: "7", Label: "Edit IP Limit", Run: openPicker(pickChangeIP)},
			{Key: "8", Label: "Edit Quota", Run: openPicker(pickChangeQuota)},
			{Key: "9", Label: "Member List", Run: runListMembers()},
			{Key: "a", Label: "Lock Account", Run: openPicker(pickLock)},
			{Key: "b", Label: "Unlock Account", Run: openPicker(pickUnlock)},
			{Key: "0", Label: "Back", Run: goView(viewDashboard)},
		}
	case viewSystem:
		return []menuItem{
			{Key: "1", Label: "Clean Expired Accounts", Run: runMaintenance("CLEAN EXPIRED", accounts.CleanAllExpired, viewSystem)},
			{Key: "2", Label: "Clear Cache & Logs", Run: runMaintenance("CLEAR CACHE & LOGS", accounts.ClearCacheAndLogs, viewSystem)},
			{Key: "3", Label: "Bandwidth Monitor", Run: runExternal("bw")},
			{Key: "4", Label: "Speedtest", Run: runExternal("speedtest")},
			{Key: "5", Label: "Limit Speed", Run: runExternal("limitspeed")},
			{Key: "6", Label: "Change Domain", Run: runExternal("addhost")},
			{Key: "7", Label: "Renew SSL Certificate", Run: runExternal("fixcert")},
			{Key: "8", Label: "Auto Reboot", Run: runExternal("autoreboot")},
			{Key: "9", Label: "Telegram Bot", Run: runExternal("mbot")},
			{Key: "a", Label: "Bot Notifications", Run: runExternal("add-bot-notif")},
			{Key: "b", Label: "Port Information", Run: runExternal("prot")},
			{Key: "c", Label: "More Utilities", Run: runExternal("utility")},
			{Key: "0", Label: "Back", Run: goView(viewDashboard)},
		}
	case viewBackup:
		return []menuItem{
			{Key: "1", Label: "Backup Data", Run: runExternal("backup")},
			{Key: "2", Label: "Restore Data", Run: runExternal("restore")},
			{Key: "3", Label: "Auto Backup", Run: runExternal("autobackup")},
			{Key: "0", Label: "Back", Run: goView(viewDashboard)},
		}
	case viewServices:
		return []menuItem{
			{Key: "1", Label: "Reload Xray", Run: runServiceAction("xray", "reload")},
			{Key: "2", Label: "Restart Xray", Run: runServiceAction("xray", "restart")},
			{Key: "3", Label: "Reload Nginx", Run: runServiceAction("nginx", "reload")},
			{Key: "4", Label: "Reload HAProxy", Run: runServiceAction("haproxy", "reload")},
			{Key: "5", Label: "Restart WebSocket", Run: runServiceAction("ws", "restart")},
			{Key: "6", Label: "Restart Dropbear", Run: runServiceAction("dropbear", "restart")},
			{Key: "7", Label: "Restart SlowDNS", Run: runServiceAction("slowdns", "restart")},
			{Key: "8", Label: "Restart Quota Service", Run: runServiceAction("zevpn-limit", "restart")},
			{Key: "0", Label: "Back", Run: goView(viewDashboard)},
		}
	case viewSlowDNS:
		return []menuItem{
			{Key: "1", Label: "Restart SlowDNS", Run: runServiceAction("slowdns", "restart")},
			{Key: "0", Label: "Back", Run: goView(viewDashboard)},
		}
	case viewRollbackConfirm:
		return []menuItem{
			{Key: "y", Label: "Switch to Classic Menu", Run: runRollback()},
			{Key: "n", Label: "Cancel", Run: goView(viewDashboard)},
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
			m.fTitle = "CREATE SSH ACCOUNT"
			m.fFields = []formField{
				{Label: "Username     ", Value: ""},
				{Label: "Password     ", Value: ""},
				{Label: "IP Limit     ", Value: "2", Numeric: true},
				{Label: "Days Active  ", Value: "30", Numeric: true},
			}
		} else {
			m.fMode = formCreateXray
			m.fTitle = "CREATE " + strings.ToUpper(string(m.proto)) + " ACCOUNT"
			m.fFields = []formField{
				{Label: "Username     ", Value: ""},
				{Label: "IP Limit     ", Value: "2", Numeric: true},
				{Label: "Quota GB     ", Value: "100", Numeric: true},
				{Label: "Days Active  ", Value: "30", Numeric: true},
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
			m.notice = errStyle.Render("Failed: " + err.Error())
			return nil
		}
		m.snap = sysinfo.Collect()
		m.view = viewProtoMenu
		return showInTerminal(strings.ToUpper(string(m.proto))+" TRIAL ACCOUNT", detail)
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
				m.notice = warnStyle.Render("No locked accounts")
			} else {
				m.notice = warnStyle.Render("No accounts found")
			}
			return nil
		}
		m.pAction = act
		m.pUsers = list
		m.pOffset = 0
		m.pQuery = ""
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
		return showInTerminal(strings.ToUpper(string(m.proto))+" MEMBERS", body)
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
		return showInTerminal(strings.ToUpper(string(m.proto))+" ACTIVE LOGINS", body)
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
	_, _ = fmt.Fprintf(f, "\033[1;37m%s\033[0m\n%s\n%s\n", title, strings.Repeat("─", 48), body)
	_ = f.Close()

	script := `clear; cat "$1"; rm -f "$1"; printf "\n\033[90mPress Enter to return...\033[0m"; read -r _ || true`
	cmd := exec.Command("bash", "-c", script, "_", tmpPath)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return execFinishedMsg{err: nil}
	})
}

func (m Model) pickerVisibleRows() int {
	rows := m.height - 11
	if m.height <= 0 {
		rows = 15
	}
	if rows < 6 {
		rows = 6
	}
	return rows
}

func (m Model) filteredPickerUsers() []sysinfo.Account {
	if m.pQuery == "" {
		return m.pUsers
	}
	q := strings.ToLower(m.pQuery)
	out := make([]sysinfo.Account, 0, len(m.pUsers))
	for _, u := range m.pUsers {
		if strings.Contains(strings.ToLower(u.Username), q) {
			out = append(out, u)
		}
	}
	return out
}

func (m *Model) syncPickerViewport(total int) {
	vis := m.pickerVisibleRows()
	if total <= 0 {
		m.cursor = 0
		m.pOffset = 0
		return
	}
	if m.cursor >= total {
		m.cursor = total - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor < m.pOffset {
		m.pOffset = m.cursor
	} else if m.cursor >= m.pOffset+vis {
		m.pOffset = m.cursor - vis + 1
	}
	maxOff := total - vis
	if maxOff < 0 {
		maxOff = 0
	}
	if m.pOffset > maxOff {
		m.pOffset = maxOff
	}
	if m.pOffset < 0 {
		m.pOffset = 0
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.view == viewPickUser {
			m.syncPickerViewport(len(m.filteredPickerUsers()))
		}
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
			m.notice = errStyle.Render(fmt.Sprintf("Failed to %s %s", msg.action, msg.service))
		} else {
			m.notice = okStyle.Render(fmt.Sprintf("Service %s %sed", msg.service, msg.action))
		}
		return m, nil

	case rollbackDoneMsg:
		if msg.err != nil {
			m.notice = errStyle.Render("Rollback failed: " + msg.err.Error())
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
			m.notice = okStyle.Render("Refreshed")
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
		return m, showInTerminal("SSH ACCOUNT CREATED", detail)

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
		return m, showInTerminal(strings.ToUpper(string(m.proto))+" ACCOUNT CREATED", detail)

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
		m.notice = okStyle.Render(fmt.Sprintf("Renewed %s until %s", m.fTargetUsr, newExp))
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
		m.notice = okStyle.Render(fmt.Sprintf("Updated IP limit for %s to %d", m.fTargetUsr, newLim))
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
		m.notice = okStyle.Render(fmt.Sprintf("Updated quota for %s to %d GB", m.fTargetUsr, newQ))
		m.view = viewProtoMenu
		m.cursor = 0
		return m, nil
	}
	return m, nil
}

func (m Model) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	filtered := m.filteredPickerUsers()
	total := len(filtered)
	vis := m.pickerVisibleRows()

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		if m.pQuery != "" {
			m.pQuery = ""
			m.cursor = 0
			m.pOffset = 0
			return m, nil
		}
		m.view = viewProtoMenu
		m.cursor = 0
		m.notice = ""
		return m, nil
	case "backspace":
		if len(m.pQuery) > 0 {
			m.pQuery = m.pQuery[:len(m.pQuery)-1]
			m.cursor = 0
			m.pOffset = 0
			return m, nil
		}
		m.view = viewProtoMenu
		m.cursor = 0
		m.notice = ""
		return m, nil
	case "up":
		if total > 0 {
			if m.cursor > 0 {
				m.cursor--
			} else {
				m.cursor = total - 1
			}
			m.syncPickerViewport(total)
		}
		return m, nil
	case "down":
		if total > 0 {
			m.cursor = (m.cursor + 1) % total
			m.syncPickerViewport(total)
		}
		return m, nil
	case "pgup":
		if total > 0 {
			m.cursor -= vis
			if m.cursor < 0 {
				m.cursor = 0
			}
			m.syncPickerViewport(total)
		}
		return m, nil
	case "pgdown":
		if total > 0 {
			m.cursor += vis
			if m.cursor >= total {
				m.cursor = total - 1
			}
			m.syncPickerViewport(total)
		}
		return m, nil
	case "home":
		m.cursor = 0
		m.syncPickerViewport(total)
		return m, nil
	case "end":
		if total > 0 {
			m.cursor = total - 1
			m.syncPickerViewport(total)
		}
		return m, nil
	case "enter":
		if m.cursor < 0 || m.cursor >= total {
			return m, nil
		}
		target := filtered[m.cursor].Username
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
			return m, showInTerminal(strings.ToUpper(string(m.proto))+" CONFIG — "+target, detail)

		case pickRenew:
			m.fMode = formRenewAccount
			m.fTargetUsr = target
			m.fTitle = fmt.Sprintf("RENEW %s — %s", strings.ToUpper(string(m.proto)), target)
			m.fFields = []formField{{Label: "Add Days     ", Value: "30", Numeric: true}}
			m.fFocus = 0
			m.notice = ""
			m.view = viewForm
			return m, nil

		case pickChangeIP:
			m.fMode = formChangeIPLimit
			m.fTargetUsr = target
			m.fTitle = fmt.Sprintf("EDIT IP LIMIT — %s", target)
			m.fFields = []formField{{Label: "New IP Limit ", Value: "2", Numeric: true}}
			m.fFocus = 0
			m.notice = ""
			m.view = viewForm
			return m, nil

		case pickChangeQuota:
			m.fMode = formChangeQuotaGB
			m.fTargetUsr = target
			m.fTitle = fmt.Sprintf("EDIT QUOTA — %s", target)
			m.fFields = []formField{{Label: "New Quota GB ", Value: "100", Numeric: true}}
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
				m.notice = errStyle.Render("Lock failed: " + err.Error())
			} else {
				m.notice = okStyle.Render(fmt.Sprintf("Locked %s", target))
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
				m.notice = errStyle.Render("Unlock failed: " + err.Error())
			} else {
				m.notice = okStyle.Render(fmt.Sprintf("Unlocked %s", target))
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
				m.notice = errStyle.Render("Delete failed: " + err.Error())
			} else {
				m.notice = okStyle.Render(fmt.Sprintf("Deleted %s", target))
			}
			m.snap = sysinfo.Collect()
			m.view = viewProtoMenu
			m.cursor = 0
			return m, nil
		}
	default:
		if len(msg.Runes) > 0 {
			changed := false
			for _, r := range msg.Runes {
				if r >= 32 && r <= 126 {
					m.pQuery += string(r)
					changed = true
				}
			}
			if changed {
				m.cursor = 0
				m.pOffset = 0
			}
		}
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder

	b.WriteString(mainLine() + "\n")
	b.WriteString(bannerStyle.Render("ZE-VPN PANEL") + "\n")
	b.WriteString(mainLine() + "\n")

	if m.view == viewDashboard {
		b.WriteString(m.renderDashboard())
		return b.String()
	}

	if m.view == viewForm {
		b.WriteString("\n  " + titleStyle.Render(m.fTitle) + "\n")
		b.WriteString(thinLine() + "\n")
		for i, f := range m.fFields {
			cursorMark := "  "
			valDisplay := valStyle.Render(f.Value)
			if i == m.fFocus {
				cursorMark = accStyle.Render("▸ ")
				valDisplay = accStyle.Render(f.Value + "█")
			}
			b.WriteString(fmt.Sprintf("%s%s : %s\n", cursorMark, labelStyle.Render(f.Label), valDisplay))
		}
		if m.notice != "" {
			b.WriteString("\n  " + m.notice + "\n")
		}
		b.WriteString(mainLine() + "\n")
		b.WriteString(mutedStyle.Render("  Tab Next  •  Enter Save  •  Esc Cancel") + "\n")
		return b.String()
	}

	if m.view == viewPickUser {
		actLabel := "SELECT ACCOUNT"
		switch m.pAction {
		case pickDetail:
			actLabel = "ACCOUNT CONFIG — " + strings.ToUpper(string(m.proto))
		case pickRenew:
			actLabel = "RENEW ACCOUNT — " + strings.ToUpper(string(m.proto))
		case pickDelete:
			actLabel = "DELETE ACCOUNT — " + strings.ToUpper(string(m.proto))
		case pickChangeIP:
			actLabel = "EDIT IP LIMIT — " + strings.ToUpper(string(m.proto))
		case pickChangeQuota:
			actLabel = "EDIT QUOTA — " + strings.ToUpper(string(m.proto))
		case pickLock:
			actLabel = "LOCK ACCOUNT — " + strings.ToUpper(string(m.proto))
		case pickUnlock:
			actLabel = "UNLOCK ACCOUNT — " + strings.ToUpper(string(m.proto))
		}

		filtered := m.filteredPickerUsers()
		total := len(filtered)
		vis := m.pickerVisibleRows()
		m.syncPickerViewport(total)

		b.WriteString("\n  " + titleStyle.Render(actLabel) + "\n")
		if m.pQuery != "" {
			b.WriteString(fmt.Sprintf("  %s %s\n", labelStyle.Render("Search:"), accStyle.Render(m.pQuery+"█")))
		} else {
			b.WriteString(mutedStyle.Render("  Type to search or use arrows") + "\n")
		}
		b.WriteString(thinLine() + "\n")
		if total == 0 {
			b.WriteString(warnStyle.Render("  No matching accounts") + "\n")
		} else {
			end := m.pOffset + vis
			if end > total {
				end = total
			}
			for i := m.pOffset; i < end; i++ {
				a := filtered[i]
				row := fmt.Sprintf(" %2d. %-18s  %s", i+1, a.Username, a.Expired)
				if i == m.cursor {
					b.WriteString(selRowStyle.Width(panelWidth).Render("▸"+row) + "\n")
				} else {
					b.WriteString(textStyle.Render(" "+row) + "\n")
				}
			}
			b.WriteString(mainLine() + "\n")
			b.WriteString(mutedStyle.Render(fmt.Sprintf("  %d-%d of %d  •  Enter Select  •  Esc Back", m.pOffset+1, end, total)) + "\n")
		}
		return b.String()
	}

	if m.view == viewSlowDNS {
		b.WriteString("\n  " + titleStyle.Render("SLOWDNS") + "\n")
		b.WriteString(thinLine() + "\n")
		b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("Domain     "), accStyle.Render(m.snap.Domain)))
		b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("Nameserver "), accStyle.Render(m.snap.SlowDNSNS)))
		b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("Public Key "), warnStyle.Render(m.snap.SlowDNSPub)))
		b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("UDP Port   "), textStyle.Render("53")))
		b.WriteString(mainLine() + "\n")
	} else if m.view == viewRollbackConfirm {
		b.WriteString("\n  " + titleStyle.Render("CLASSIC MENU") + "\n")
		b.WriteString(thinLine() + "\n")
		b.WriteString(textStyle.Render("  Switch back to classic menu?") + "\n")
		b.WriteString(mainLine() + "\n")
	} else if m.view == viewProtoMenu {
		pTitle := strings.ToUpper(string(m.proto))
		b.WriteString(fmt.Sprintf("\n  %s  %s\n", titleStyle.Render(pTitle), mutedStyle.Render(fmt.Sprintf("%d accounts", len(m.currentAccounts())))))
		b.WriteString(thinLine() + "\n")
	} else if m.view == viewBackup {
		b.WriteString("\n  " + titleStyle.Render("BACKUP & RESTORE") + "\n")
		b.WriteString(thinLine() + "\n")
	} else if m.view == viewSystem {
		b.WriteString("\n  " + titleStyle.Render("SYSTEM") + "\n")
		b.WriteString(thinLine() + "\n")
	} else if m.view == viewServices {
		b.WriteString("\n  " + titleStyle.Render("SERVICES") + "\n")
		b.WriteString(thinLine() + "\n")
	}

	if m.notice != "" {
		b.WriteString("  " + m.notice + "\n")
	}

	items := m.itemsForCurrentView()
	for i, it := range items {
		if i == m.cursor {
			b.WriteString(selRowStyle.Width(panelWidth).Render(fmt.Sprintf(" ▸ %s  %s", it.Key, it.Label)) + "\n")
		} else {
			b.WriteString(fmt.Sprintf("   %s  %s\n", warnStyle.Render(it.Key), textStyle.Render(it.Label)))
		}
	}
	b.WriteString(mainLine() + "\n")
	b.WriteString(mutedStyle.Render("  ↑/↓ Navigate  •  Enter Select  •  Esc Back") + "\n")
	return b.String()
}

func (m Model) renderDashboard() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("OS     "), textStyle.Render(m.snap.OSName)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("RAM    "), textStyle.Render(fmt.Sprintf("%dM / %dM", m.snap.MemUsedMB, m.snap.MemTotalMB))))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("SWAP   "), textStyle.Render(fmt.Sprintf("%dM", m.snap.SwapTotalMB))))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("CITY   "), textStyle.Render(m.snap.City)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("ISP    "), textStyle.Render(m.snap.ISP)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("IP     "), accStyle.Render(m.snap.IP)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("DOMAIN "), accStyle.Render(m.snap.Domain)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("UPTIME "), textStyle.Render(m.snap.Uptime)))
	b.WriteString(thinLine() + "\n")
	b.WriteString(fmt.Sprintf("  %s : %-13s %s\n", labelStyle.Render("MONTH  "), textStyle.Render(m.snap.BW.MonthTotal), mutedStyle.Render(m.snap.BW.MonthName)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("RX     "), textStyle.Render(m.snap.BW.MonthRX)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("TX     "), textStyle.Render(m.snap.BW.MonthTX)))
	b.WriteString(thinLine() + "\n")
	b.WriteString(fmt.Sprintf("  %s : %-13s %s\n", labelStyle.Render("DAY    "), textStyle.Render(m.snap.BW.DayTotal), mutedStyle.Render(m.snap.BW.DayName)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("RX     "), textStyle.Render(m.snap.BW.DayRX)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("TX     "), textStyle.Render(m.snap.BW.DayTX)))
	b.WriteString(fmt.Sprintf("  %s : %s\n", labelStyle.Render("RATE   "), textStyle.Render(m.snap.BW.TrafficRate)))
	b.WriteString(mainLine() + "\n")

	svcBadge := func(name string) string {
		for _, s := range m.snap.Services {
			if s.Name == name {
				if s.Active {
					return okStyle.Render("ON")
				}
				return errStyle.Render("OFF")
			}
		}
		return errStyle.Render("OFF")
	}
	b.WriteString(fmt.Sprintf("  %s %s   %s %s   %s %s   %s %s\n",
		labelStyle.Render("XRAY"), svcBadge("xray"),
		labelStyle.Render("WS"), svcBadge("ws"),
		labelStyle.Render("HAPROXY"), svcBadge("haproxy"),
		labelStyle.Render("DNS"), svcBadge("slowdns"),
	))
	b.WriteString(mainLine() + "\n")

	b.WriteString(lipgloss.NewStyle().Width(panelWidth).Align(lipgloss.Center).Foreground(colorLabel).Render("ACCOUNTS") + "\n")
	b.WriteString(thinLine() + "\n")
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", labelStyle.Render("SSH    "), warnStyle.Render(fmt.Sprintf("%d", len(m.snap.SSHAccounts))), mutedStyle.Render("active")))
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", labelStyle.Render("VMESS  "), warnStyle.Render(fmt.Sprintf("%d", len(m.snap.VMessAccs))), mutedStyle.Render("active")))
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", labelStyle.Render("VLESS  "), warnStyle.Render(fmt.Sprintf("%d", len(m.snap.VLESSAccs))), mutedStyle.Render("active")))
	b.WriteString(fmt.Sprintf("    %s : %-4s %s\n", labelStyle.Render("TROJAN "), warnStyle.Render(fmt.Sprintf("%d", len(m.snap.TrojanAccs))), mutedStyle.Render("active")))
	b.WriteString(mainLine() + "\n")

	if m.notice != "" {
		b.WriteString("  " + m.notice + "\n")
	}

	items := m.itemsForCurrentView()
	half := (len(items) + 1) / 2
	for i := 0; i < half; i++ {
		left := renderMenuCell(items[i], i == m.cursor, 24)
		right := ""
		if i+half < len(items) {
			right = renderMenuCell(items[i+half], i+half == m.cursor, 24)
		}
		b.WriteString("  " + left + "  " + right + "\n")
	}
	b.WriteString(mainLine() + "\n")
	b.WriteString(mutedStyle.Render("  ↑/↓ Select  •  Enter Open  •  r Refresh  •  q Quit") + "\n")
	return b.String()
}

func renderMenuCell(it menuItem, selected bool, width int) string {
	if selected {
		return selRowStyle.Width(width).Render(fmt.Sprintf("▸ %s  %s", it.Key, it.Label))
	}
	plain := fmt.Sprintf("  %s  %s", it.Key, it.Label)
	pad := width - len(plain)
	if pad < 0 {
		pad = 0
	}
	return fmt.Sprintf("  %s  %s%s", warnStyle.Render(it.Key), textStyle.Render(it.Label), strings.Repeat(" ", pad))
}
