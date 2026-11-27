package accounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
