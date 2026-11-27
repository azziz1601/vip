package tui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/azziz1601/vip/vip-menu/internal/rollback"
	"github.com/azziz1601/vip/vip-menu/internal/sysinfo"
)

type viewID int

const (
	viewDashboard viewID = iota
	viewSSH
	viewVMess
	viewVLESS
	viewTrojan
	viewSystem
	viewServices
	viewSlowDNS
	viewRollbackConfirm
)

type menuItem struct {
	Key   string
	Label string
	Desc  string
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
	cursor  int
	width   int
	height  int
	snap    sysinfo.Snapshot
	notice  string
}

var (
	colorCyan   = lipgloss.Color("#22D3EE")
	colorBlue   = lipgloss.Color("#38BDF8")
	colorGreen  = lipgloss.Color("#4ADE80")
	colorRed    = lipgloss.Color("#F87171")
	colorYellow = lipgloss.Color("#FACC15")
	colorMuted  = lipgloss.Color("#94A3B8")
	colorBorder = lipgloss.Color("#334155")
	colorText   = lipgloss.Color("#F8FAFC")

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0F172A")).
			Background(colorCyan).
			Padding(0, 2)

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(colorBlue)
	labelStyle = lipgloss.NewStyle().Foreground(colorMuted)
	valStyle   = lipgloss.NewStyle().Foreground(colorText).Bold(true)
	okStyle    = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	errStyle   = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	warnStyle  = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0F172A")).
			Background(colorCyan).
			Padding(0, 1)

	normalItemStyle = lipgloss.NewStyle().
			Foreground(colorText).
			Padding(0, 1)

	keyBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorYellow)

	helpStyle = lipgloss.NewStyle().Foreground(colorMuted)
)

func NewModel(version string) Model {
	return Model{
		version: version,
		view:    viewDashboard,
		snap:    sysinfo.Collect(),
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) itemsForCurrentView() []menuItem {
	switch m.view {
	case viewDashboard:
		return []menuItem{
			{Key: "1", Label: "SSH & SlowDNS", Desc: fmt.Sprintf("%d akun • tambah, trial, cek login, NS/PubKey", len(m.snap.SSHAccounts)), Run: goView(viewSSH)},
			{Key: "2", Label: "VMess", Desc: fmt.Sprintf("%d akun • WS, gRPC, HTTPUpgrade, XHTTP", len(m.snap.VMessAccs)), Run: goView(viewVMess)},
			{Key: "3", Label: "VLESS", Desc: fmt.Sprintf("%d akun • WS, gRPC, HTTPUpgrade, XHTTP", len(m.snap.VLESSAccs)), Run: goView(viewVLESS)},
			{Key: "4", Label: "Trojan", Desc: fmt.Sprintf("%d akun • WS, gRPC, HTTPUpgrade, XHTTP", len(m.snap.TrojanAccs)), Run: goView(viewTrojan)},
			{Key: "5", Label: "System & Utility", Desc: "Bandwidth, speedtest, limit speed, backup, utility", Run: goView(viewSystem)},
			{Key: "6", Label: "Service Control", Desc: "Reload/Restart Xray, Nginx, HAProxy, WS, SlowDNS", Run: goView(viewServices)},
			{Key: "7", Label: "Info SlowDNS", Desc: "Lihat Name Server, Pub Key, & status UDP 53", Run: goView(viewSlowDNS)},
			{Key: "8", Label: "Update Script", Desc: "Jalankan update terbaru dari GitHub", Run: runScript("utility")},
			{Key: "9", Label: "Rollback ke Menu Klasik", Desc: "Kembalikan perintah 'menu' ke versi Bash lama", Run: goView(viewRollbackConfirm)},
		}
	case viewSSH:
		return []menuItem{
			{Key: "1", Label: "Buat Akun SSH", Desc: "addssh (otomatis tampilkan NS & Pub Key SlowDNS)", Run: runScript("addssh")},
			{Key: "2", Label: "Trial SSH", Desc: "trial", Run: runScript("trial")},
			{Key: "3", Label: "Perpanjang SSH", Desc: "renewssh", Run: runScript("renewssh")},
			{Key: "4", Label: "Hapus SSH", Desc: "delssh", Run: runScript("delssh")},
			{Key: "5", Label: "Cek User Login SSH", Desc: "cekssh", Run: runScript("cekssh")},
			{Key: "6", Label: "Detail Config SSH", Desc: "user-ssh", Run: runScript("user-ssh")},
			{Key: "7", Label: "Buka Sub-Menu SSH Klasik", Desc: "m-sshws", Run: runScript("m-sshws")},
			{Key: "0", Label: "Kembali ke Dashboard", Desc: "Esc / Backspace", Run: goView(viewDashboard)},
		}
	case viewVMess:
		return []menuItem{
			{Key: "1", Label: "Buat Akun VMess", Desc: "addws", Run: runScript("addws")},
			{Key: "2", Label: "Trial VMess", Desc: "trialws", Run: runScript("trialws")},
			{Key: "3", Label: "Perpanjang VMess", Desc: "renewws", Run: runScript("renewws")},
			{Key: "4", Label: "Hapus VMess", Desc: "delws", Run: runScript("delws")},
			{Key: "5", Label: "Cek Login VMess", Desc: "cekws", Run: runScript("cekws")},
			{Key: "6", Label: "Detail Config VMess", Desc: "user-ws", Run: runScript("user-ws")},
			{Key: "7", Label: "Buka Sub-Menu VMess Klasik", Desc: "m-vmess", Run: runScript("m-vmess")},
			{Key: "0", Label: "Kembali ke Dashboard", Desc: "Esc / Backspace", Run: goView(viewDashboard)},
		}
	case viewVLESS:
		return []menuItem{
			{Key: "1", Label: "Buat Akun VLESS", Desc: "addvless", Run: runScript("addvless")},
			{Key: "2", Label: "Trial VLESS", Desc: "trialvless", Run: runScript("trialvless")},
			{Key: "3", Label: "Perpanjang VLESS", Desc: "renewvless", Run: runScript("renewvless")},
			{Key: "4", Label: "Hapus VLESS", Desc: "delvless", Run: runScript("delvless")},
			{Key: "5", Label: "Cek Login VLESS", Desc: "cekvless", Run: runScript("cekvless")},
			{Key: "6", Label: "Detail Config VLESS", Desc: "user-vless", Run: runScript("user-vless")},
			{Key: "7", Label: "Buka Sub-Menu VLESS Klasik", Desc: "m-vless", Run: runScript("m-vless")},
			{Key: "0", Label: "Kembali ke Dashboard", Desc: "Esc / Backspace", Run: goView(viewDashboard)},
		}
	case viewTrojan:
		return []menuItem{
			{Key: "1", Label: "Buat Akun Trojan", Desc: "addtr", Run: runScript("addtr")},
			{Key: "2", Label: "Trial Trojan", Desc: "trialtr", Run: runScript("trialtr")},
			{Key: "3", Label: "Perpanjang Trojan", Desc: "renewtr", Run: runScript("renewtr")},
			{Key: "4", Label: "Hapus Trojan", Desc: "deltr", Run: runScript("deltr")},
			{Key: "5", Label: "Cek Login Trojan", Desc: "cektr", Run: runScript("cektr")},
			{Key: "6", Label: "Detail Config Trojan", Desc: "user-tr", Run: runScript("user-tr")},
			{Key: "7", Label: "Buka Sub-Menu Trojan Klasik", Desc: "m-trojan", Run: runScript("m-trojan")},
			{Key: "0", Label: "Kembali ke Dashboard", Desc: "Esc / Backspace", Run: goView(viewDashboard)},
		}
	case viewSystem:
		return []menuItem{
			{Key: "1", Label: "Menu Utility & Update", Desc: "utility", Run: runScript("utility")},
			{Key: "2", Label: "Monitor Bandwidth", Desc: "bw", Run: runScript("bw")},
			{Key: "3", Label: "Speedtest VPS", Desc: "speedtest", Run: runScript("speedtest")},
			{Key: "4", Label: "Limit Speed", Desc: "limitspeed", Run: runScript("limitspeed")},
			{Key: "5", Label: "Backup & Restore", Desc: "menu-backup", Run: runScript("menu-backup")},
			{Key: "6", Label: "Hapus Akun Expired", Desc: "xp", Run: runScript("xp")},
			{Key: "7", Label: "Clear Cache & Log", Desc: "clearcache", Run: runScript("clearcache")},
			{Key: "0", Label: "Kembali ke Dashboard", Desc: "Esc / Backspace", Run: goView(viewDashboard)},
		}
	case viewServices:
		return []menuItem{
			{Key: "1", Label: "Hot-Reload Xray (SIGHUP)", Desc: "Tanpa memutus koneksi aktif", Run: runServiceAction("xray", "reload")},
			{Key: "2", Label: "Restart Xray", Desc: "systemctl restart xray", Run: runServiceAction("xray", "restart")},
			{Key: "3", Label: "Reload Nginx", Desc: "systemctl reload nginx", Run: runServiceAction("nginx", "reload")},
			{Key: "4", Label: "Reload HAProxy", Desc: "systemctl reload haproxy", Run: runServiceAction("haproxy", "reload")},
			{Key: "5", Label: "Restart WS Proxy (ws-rs)", Desc: "systemctl restart ws", Run: runServiceAction("ws", "restart")},
			{Key: "6", Label: "Restart Dropbear", Desc: "systemctl restart dropbear", Run: runServiceAction("dropbear", "restart")},
			{Key: "7", Label: "Restart SlowDNS", Desc: "systemctl restart slowdns", Run: runServiceAction("slowdns", "restart")},
			{Key: "8", Label: "Restart Quota Daemon", Desc: "systemctl restart zevpn-limit", Run: runServiceAction("zevpn-limit", "restart")},
			{Key: "0", Label: "Kembali ke Dashboard", Desc: "Esc / Backspace", Run: goView(viewDashboard)},
		}
	case viewSlowDNS:
		return []menuItem{
			{Key: "1", Label: "Restart SlowDNS", Desc: "systemctl restart slowdns", Run: runServiceAction("slowdns", "restart")},
			{Key: "0", Label: "Kembali ke Dashboard", Desc: "Esc / Backspace", Run: goView(viewDashboard)},
		}
	case viewRollbackConfirm:
		return []menuItem{
			{Key: "y", Label: "Ya, Kembalikan ke Menu Klasik (Bash)", Desc: "Switch /usr/local/sbin/menu -> menu-legacy", Run: runRollback()},
			{Key: "n", Label: "Batal & Kembali ke Dashboard", Desc: "Tetap gunakan TUI Go", Run: goView(viewDashboard)},
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

func runScript(name string) func(m *Model) tea.Cmd {
	return func(m *Model) tea.Cmd {
		path := "/usr/local/sbin/" + name
		if _, err := os.Stat(path); err != nil {
			if found, lerr := exec.LookPath(name); lerr == nil {
				path = found
			}
		}
		cmd := exec.Command(path)
		cmd.Env = append(os.Environ(), "VIP_MENU_NESTED=1")
		return tea.ExecProcess(cmd, func(err error) tea.Msg {
			return execFinishedMsg{err: err}
		})
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
		return func() tea.Msg {
			return rollbackDoneMsg{err: rollback.RollbackToLegacy()}
		}
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
			m.notice = errStyle.Render("Perintah selesai dengan error: " + msg.err.Error())
		} else {
			m.notice = ""
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
				cmd := items[m.cursor].Run(&m)
				return m, cmd
			}
			return m, nil
		default:
			key := strings.ToLower(msg.String())
			for idx, it := range items {
				if strings.ToLower(it.Key) == key && it.Run != nil {
					m.cursor = idx
					cmd := it.Run(&m)
					return m, cmd
				}
			}
		}
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder

	banner := headerStyle.Render(fmt.Sprintf(" ZE-VPN VIP PANEL  •  v%s ", m.version))
	b.WriteString(banner + "\n\n")

	if m.view == viewDashboard {
		b.WriteString(m.renderDashboardTop() + "\n")
	} else {
		b.WriteString(m.renderSubViewHeader() + "\n")
	}

	if m.notice != "" {
		b.WriteString(m.notice + "\n\n")
	}

	// Render interactive menu list
	items := m.itemsForCurrentView()
	var listLines []string
	for i, it := range items {
		badge := keyBadgeStyle.Render("[" + it.Key + "]")
		if i == m.cursor {
			line := selectedStyle.Render(fmt.Sprintf("▸ [%s] %s", it.Key, it.Label))
			if it.Desc != "" {
				line += "  " + labelStyle.Render(it.Desc)
			}
			listLines = append(listLines, line)
		} else {
			line := normalItemStyle.Render(fmt.Sprintf("  %s %s", badge, it.Label))
			if it.Desc != "" {
				line += "  " + labelStyle.Render("— "+it.Desc)
			}
			listLines = append(listLines, line)
		}
	}

	menuBox := cardStyle.Render(strings.Join(listLines, "\n"))
	b.WriteString(menuBox + "\n")

	if m.view == viewDashboard {
		b.WriteString(helpStyle.Render("  ↑/↓ Navigasi • Enter Pilih • 1-9 Pintasan • r Refresh • q Keluar") + "\n")
	} else {
		b.WriteString(helpStyle.Render("  ↑/↓ Navigasi • Enter Pilih • Esc/0 Kembali • r Refresh") + "\n")
	}

	return b.String()
}

func (m Model) renderDashboardTop() string {
	sysLines := []string{
		titleStyle.Render("SYSTEM"),
		fmt.Sprintf("%s %s", labelStyle.Render("Domain :"), valStyle.Render(m.snap.Domain)),
		fmt.Sprintf("%s %s (%s)", labelStyle.Render("IP/ISP :"), valStyle.Render(m.snap.IP), m.snap.City),
		fmt.Sprintf("%s %s", labelStyle.Render("OS     :"), m.snap.OSName),
		fmt.Sprintf("%s %s", labelStyle.Render("Uptime :"), m.snap.Uptime),
		fmt.Sprintf("%s %s", labelStyle.Render("Load   :"), valStyle.Render(m.snap.LoadAvg)),
		fmt.Sprintf("%s %d/%d MB (%d%%)", labelStyle.Render("RAM    :"), m.snap.MemUsedMB, m.snap.MemTotalMB, m.snap.MemPercent),
	}

	svcLines := []string{titleStyle.Render("SERVICES")}
	for i := 0; i < len(m.snap.Services); i += 2 {
		left := formatSvc(m.snap.Services[i])
		right := ""
		if i+1 < len(m.snap.Services) {
			right = "   " + formatSvc(m.snap.Services[i+1])
		}
		svcLines = append(svcLines, left+right)
	}
	svcLines = append(svcLines, "")
	svcLines = append(svcLines, fmt.Sprintf(
		"%s SSH:%s  VMess:%s  VLESS:%s  Trojan:%s",
		labelStyle.Render("Akun:"),
		valStyle.Render(fmt.Sprintf("%d", len(m.snap.SSHAccounts))),
		valStyle.Render(fmt.Sprintf("%d", len(m.snap.VMessAccs))),
		valStyle.Render(fmt.Sprintf("%d", len(m.snap.VLESSAccs))),
		valStyle.Render(fmt.Sprintf("%d", len(m.snap.TrojanAccs))),
	))

	leftCard := cardStyle.Width(42).Render(strings.Join(sysLines, "\n"))
	rightCard := cardStyle.Width(38).Render(strings.Join(svcLines, "\n"))

	if m.width > 0 && m.width < 84 {
		return lipgloss.JoinVertical(lipgloss.Left, leftCard, rightCard)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, leftCard, " ", rightCard)
}

func formatSvc(s sysinfo.ServiceStatus) string {
	dot := errStyle.Render("●")
	if s.Active {
		dot = okStyle.Render("●")
	}
	return fmt.Sprintf("%s %-10s", dot, s.Label)
}

func (m Model) renderSubViewHeader() string {
	switch m.view {
	case viewSSH:
		return m.renderAccountBox("AKUN SSH & SLOWDNS", m.snap.SSHAccounts)
	case viewVMess:
		return m.renderAccountBox("AKUN VMESS", m.snap.VMessAccs)
	case viewVLESS:
		return m.renderAccountBox("AKUN VLESS", m.snap.VLESSAccs)
	case viewTrojan:
		return m.renderAccountBox("AKUN TROJAN", m.snap.TrojanAccs)
	case viewSlowDNS:
		lines := []string{
			titleStyle.Render("KONFIGURASI SLOWDNS (HTTP CUSTOM)"),
			fmt.Sprintf("%s %s", labelStyle.Render("Domain      :"), valStyle.Render(m.snap.Domain)),
			fmt.Sprintf("%s %s", labelStyle.Render("Name Server :"), valStyle.Render(m.snap.SlowDNSNS)),
			fmt.Sprintf("%s %s", labelStyle.Render("Pub Key     :"), okStyle.Render(m.snap.SlowDNSPub)),
			fmt.Sprintf("%s %s", labelStyle.Render("Port UDP    :"), valStyle.Render("53")),
		}
		return cardStyle.Render(strings.Join(lines, "\n"))
	case viewRollbackConfirm:
		lines := []string{
			warnStyle.Render("KONFIRMASI ROLLBACK KE MENU KLASIK"),
			"Perintah 'menu' akan dikembalikan ke /usr/local/sbin/menu-legacy (Bash).",
			"Untuk mengaktifkan TUI Go lagi kapan saja, jalankan: menu-tui",
		}
		return cardStyle.Render(strings.Join(lines, "\n"))
	default:
		return titleStyle.Render("PANEL KONTROL")
	}
}

func (m Model) renderAccountBox(title string, accs []sysinfo.Account) string {
	lines := []string{fmt.Sprintf("%s (%d akun aktif)", titleStyle.Render(title), len(accs))}
	if len(accs) == 0 {
		lines = append(lines, labelStyle.Render("  Belum ada akun."))
	} else {
		limit := 8
		if len(accs) < limit {
			limit = len(accs)
		}
		for i := 0; i < limit; i++ {
			lines = append(lines, fmt.Sprintf("  %2d) %-18s  exp: %s", i+1, accs[i].Username, accs[i].Expired))
		}
		if len(accs) > limit {
			lines = append(lines, labelStyle.Render(fmt.Sprintf("  ... +%d akun lainnya", len(accs)-limit)))
		}
	}
	return cardStyle.Render(strings.Join(lines, "\n"))
}
