package rollback

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	MenuLinkPath   = "/usr/local/sbin/menu"
	LegacyMenuPath = "/usr/local/sbin/menu-legacy"
	TUIBinPath     = "/usr/local/bin/vip-menu"
	OptOutMarker   = "/etc/xray/.use-legacy-menu"
)

// RollbackToLegacy atomically switches `/usr/local/sbin/menu` back to `/usr/local/sbin/menu-legacy`
// and writes the opt-out marker so future `update.sh` runs preserve the classic Bash menu.
func RollbackToLegacy() error {
	if _, err := os.Stat(LegacyMenuPath); err != nil {
		return fmt.Errorf("menu klasik (%s) tidak ditemukan: %w", LegacyMenuPath, err)
	}
	if err := atomicSymlink(LegacyMenuPath, MenuLinkPath); err != nil {
		return fmt.Errorf("gagal mengembalikan symlink menu: %w", err)
	}
	_ = os.MkdirAll(filepath.Dir(OptOutMarker), 0755)
	_ = os.WriteFile(OptOutMarker, []byte("legacy\n"), 0644)
	return nil
}

// EnableTUI switches `/usr/local/sbin/menu` to `/usr/local/bin/vip-menu` while ensuring
// the classic Bash menu is preserved at `/usr/local/sbin/menu-legacy`.
func EnableTUI() error {
	if _, err := os.Stat(TUIBinPath); err != nil {
		return fmt.Errorf("binary TUI (%s) tidak ditemukan: %w", TUIBinPath, err)
	}
	// Preserve original Bash menu if menu-legacy does not exist yet
	if _, err := os.Stat(LegacyMenuPath); os.IsNotExist(err) {
		if info, lerr := os.Lstat(MenuLinkPath); lerr == nil && info.Mode()&os.ModeSymlink == 0 {
			if data, rerr := os.ReadFile(MenuLinkPath); rerr == nil {
				_ = os.WriteFile(LegacyMenuPath, data, 0755)
			}
		}
	}
	if err := atomicSymlink(TUIBinPath, MenuLinkPath); err != nil {
		return fmt.Errorf("gagal mengaktifkan symlink TUI: %w", err)
	}
	_ = os.Remove(OptOutMarker)
	return nil
}

func atomicSymlink(target, linkPath string) error {
	tmp := linkPath + ".tmp.switch"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
