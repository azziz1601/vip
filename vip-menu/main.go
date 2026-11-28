package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/azziz1601/vip/vip-menu/internal/accounts"
	"github.com/azziz1601/vip/vip-menu/internal/sysops"
	"github.com/azziz1601/vip/vip-menu/internal/tui"
)

const version = "1.8.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version":
			fmt.Printf("vip-menu v%s\n", version)
			return
		case "-h", "--help":
			fmt.Printf("vip-menu v%s\n", version)
			fmt.Println("Usage: menu")
			fmt.Println("  -v, --version                         Show version")
			fmt.Println("  --backup-now                          Run Telegram backup and exit")
			fmt.Println("  --delete-account <proto> <username>   Delete an account and exit")
			fmt.Println("  -h, --help                            Show help")
			return
		case "--backup-now":
			res, err := sysops.BackupToTelegram()
			if err != nil {
				fmt.Fprintf(os.Stderr, "backup error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(res)
			return
		case "--delete-account":
			if len(os.Args) < 4 {
				fmt.Fprintln(os.Stderr, "usage: vip-menu --delete-account <ssh|vmess|vless|trojan> <username>")
				os.Exit(1)
			}
			proto := accounts.Protocol(strings.ToLower(strings.TrimSpace(os.Args[2])))
			user := strings.TrimSpace(os.Args[3])
			var err error
			switch proto {
			case accounts.ProtoSSH:
				err = accounts.DeleteSSHAccount(user)
			case accounts.ProtoVMess, accounts.ProtoVLESS, accounts.ProtoTrojan:
				err = accounts.DeleteXrayAccount(proto, user)
			default:
				err = fmt.Errorf("unknown protocol: %s", proto)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "delete error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// Prevent nested TUI when external helper scripts invoke `menu` on exit.
	if os.Getenv("VIP_MENU_NESTED") == "1" {
		return
	}

	// Anti-orphan guard: exit immediately if stdin is not an interactive TTY.
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return
	}

	// Exit cleanly on SIGHUP/SIGTERM when SSH session drops.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Exit(0)
	}()

	p := tea.NewProgram(tui.NewModel(version), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "vip-menu error: %v\n", err)
		os.Exit(1)
	}
}
