package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/azziz1601/vip/vip-menu/internal/rollback"
	"github.com/azziz1601/vip/vip-menu/internal/tui"
)

const version = "1.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version":
			fmt.Printf("vip-menu v%s\n", version)
			return
		case "--rollback":
			if err := rollback.RollbackToLegacy(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Rollback berhasil: perintah 'menu' sekarang menggunakan versi Bash klasik (/usr/local/sbin/menu-legacy).")
			fmt.Println("Untuk kembali ke TUI Go kapan saja, jalankan: vip-menu --enable")
			return
		case "--enable":
			if err := rollback.EnableTUI(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("TUI Go aktif: perintah 'menu' sekarang menggunakan /usr/local/bin/vip-menu.")
			return
		case "--legacy":
			cmd := exec.Command(rollback.LegacyMenuPath)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				os.Exit(1)
			}
			return
		case "-h", "--help":
			fmt.Printf("vip-menu v%s — Panel TUI VPS (Go + Bubble Tea)\n", version)
			fmt.Println("Penggunaan:")
			fmt.Println("  menu / vip-menu       Buka dashboard TUI interaktif")
			fmt.Println("  vip-menu --rollback   Kembalikan 'menu' ke versi Bash klasik")
			fmt.Println("  vip-menu --enable     Aktifkan kembali TUI Go sebagai 'menu'")
			fmt.Println("  vip-menu --legacy     Jalankan menu Bash klasik sekali saja")
			fmt.Println("  vip-menu --version    Tampilkan versi")
			return
		}
	}

	// Prevent nested TUI when legacy sub-scripts call `menu` upon exit.
	if os.Getenv("VIP_MENU_NESTED") == "1" {
		return
	}

	// Anti-orphan guard: exit immediately if stdin is not an interactive terminal (TTY).
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
