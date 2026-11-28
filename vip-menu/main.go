package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/azziz1601/vip/vip-menu/internal/tui"
)

const version = "1.6.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version":
			fmt.Printf("vip-menu v%s\n", version)
			return
		case "-h", "--help":
			fmt.Printf("vip-menu v%s\n", version)
			fmt.Println("Usage: menu")
			fmt.Println("  -v, --version   Show version")
			fmt.Println("  -h, --help      Show help")
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
