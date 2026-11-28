package accounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestXrayAddRenewDeleteRoundtrip(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	base := `{
  "inbounds": [
    {"clients": [
#vless
    ]},
    {"clients": [
#vlessgrpc
    ]},
    {"clients": [
#vlesshu
    ]},
    {"clients": [
#vlessxhttp
    ]}
  ]
}
`
	if err := os.WriteFile(cfg, []byte(base), 0644); err != nil {
		t.Fatal(err)
	}

	uuid, exp, err := AddXrayAccountToFile(cfg, XrayCreateParams{
		Proto:    ProtoVLESS,
		Username: "putra",
		Days:     30,
	})
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}
	if len(uuid) != 36 || len(exp) != 10 {
		t.Fatalf("invalid uuid/exp: %s / %s", uuid, exp)
	}

	raw, _ := os.ReadFile(cfg)
	if strings.Count(string(raw), "#& putra ") != 4 {
		t.Fatalf("expected 4 transport entries, got:\n%s", string(raw))
	}

	newExp, err := RenewXrayAccountInFile(cfg, ProtoVLESS, "putra", 15)
	if err != nil || newExp == exp {
		t.Fatalf("renew failed: newExp=%s err=%v", newExp, err)
	}

	removed, err := DeleteXrayAccountFromFile(cfg, ProtoVLESS, "putra")
	if err != nil || !removed {
		t.Fatalf("delete failed: removed=%v err=%v", removed, err)
	}
	after, _ := os.ReadFile(cfg)
	if strings.Contains(string(after), "putra") {
		t.Fatalf("putra still present after delete:\n%s", string(after))
	}
}

func TestCheckXrayLoginsExactMatch(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	sample := "2026/11/27 21:00:00 tcp:114.10.20.30:0 accepted tcp:1.1.1.1:443 [vless-ws] email: adi\n" +
		"2026/11/27 21:00:01 tcp:114.10.20.31:0 accepted tcp:1.1.1.1:443 [vless-ws] email: aditya\n" +
		"2026/11/27 21:00:02 tcp:127.0.0.1:0 accepted tcp:1.1.1.1:443 [vless-ws] email: adi\n"
	if err := os.WriteFile(logPath, []byte(sample), 0644); err != nil {
		t.Fatal(err)
	}

	out := CheckXrayLoginsFromLog(logPath, []string{"adi"}, ProtoVLESS)
	if !strings.Contains(out, "114.10.20.30") || strings.Contains(out, "114.10.20.31") || strings.Contains(out, "127.0.0.1") {
		t.Fatalf("unexpected login output:\n%s", out)
	}
}

func TestParseSSHLoginsMatchesLivePIDs(t *testing.T) {
	logs := `Nov 28 11:45:01 localhost dropbear[1234]: Password auth succeeded for 'putra' from 127.0.0.1:51234
Nov 28 11:45:02 localhost dropbear[9999]: Password auth succeeded for 'stale' from 127.0.0.1:51235
Nov 28 11:46:00 localhost sshd[5678]: Accepted password for linda from 114.10.20.30 port 44321 ssh2`
	db, ssh := ParseSSHLoginsFromText(logs, map[string]bool{"1234": true}, map[string]bool{"5678": true})
	if len(db) != 1 || db[0].Username != "putra" || db[0].PID != "1234" {
		t.Fatalf("unexpected dropbear sessions: %+v", db)
	}
	if len(ssh) != 1 || ssh[0].Username != "linda" || ssh[0].PID != "5678" {
		t.Fatalf("unexpected sshd sessions: %+v", ssh)
	}
}


func TestRandomPassword(t *testing.T) {
	for i := 0; i < 20; i++ {
		pw := RandomPassword(6)
		if len(pw) != 6 {
			t.Fatalf("expected length 6, got %d (%q)", len(pw), pw)
		}
		hasLetter, hasDigit := false, false
		for _, r := range pw {
			if r >= 'a' && r <= 'z' {
				hasLetter = true
			} else if r >= '0' && r <= '9' {
				hasDigit = true
			} else {
				t.Fatalf("unexpected char %q in %q", r, pw)
			}
		}
		if !hasLetter || !hasDigit {
			t.Fatalf("password %q must contain both lowercase letter and digit", pw)
		}
	}
}

func TestParseTrialDuration(t *testing.T) {
	d, lbl, err := ParseTrialDuration("30m")
	if err != nil || d != 30*time.Minute || lbl != "30m" {
		t.Fatalf("30m parse failed: %v %q %v", d, lbl, err)
	}
	d, lbl, err = ParseTrialDuration("1H")
	if err != nil || d != time.Hour || lbl != "1h" {
		t.Fatalf("1H parse failed: %v %q %v", d, lbl, err)
	}
	if _, _, err := ParseTrialDuration("30s"); err == nil {
		t.Fatalf("expected error for 30s")
	}
	if _, _, err := ParseTrialDuration(""); err == nil {
		t.Fatalf("expected error for empty duration")
	}
}
