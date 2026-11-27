package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseXrayAccountsDeduplicatesMultiTransport(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	sample := `{
  "inbounds": [
    { "clients": [
#vmess
### alice 2027-01-01
},{"id":"1111","email":"alice"
#vmessgrpc
### alice 2027-01-01
},{"id":"1111","email":"alice"
#vless
#& bob 2027-02-02
},{"id":"2222","email":"bob"
#vlessxhttp
#& bob 2027-02-02
},{"id":"2222","email":"bob"
#trojanws
#! charlie 2027-03-03
},{"password":"secret","email":"charlie"
    ]}
  ]
}`
	if err := os.WriteFile(cfgPath, []byte(sample), 0644); err != nil {
		t.Fatal(err)
	}

	vm, vl, tr := ParseXrayAccounts(cfgPath)
	if len(vm) != 1 || vm[0].Username != "alice" || vm[0].Expired != "2027-01-01" {
		t.Fatalf("unexpected vmess: %+v", vm)
	}
	if len(vl) != 1 || vl[0].Username != "bob" || vl[0].Expired != "2027-02-02" {
		t.Fatalf("unexpected vless: %+v", vl)
	}
	if len(tr) != 1 || tr[0].Username != "charlie" || tr[0].Expired != "2027-03-03" {
		t.Fatalf("unexpected trojan: %+v", tr)
	}
}

func TestParseSSHAccounts(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, ".ssh.db")
	sample := "#ssh# putra pass123 10 2 27 Dec, 2026\n#ssh# putra pass123 10 2 27 Dec, 2026\n"
	if err := os.WriteFile(dbPath, []byte(sample), 0644); err != nil {
		t.Fatal(err)
	}
	accs := ParseSSHAccounts(dbPath)
	if len(accs) != 1 || accs[0].Username != "putra" || accs[0].Expired != "27 Dec, 2026" {
		t.Fatalf("unexpected ssh accounts: %+v", accs)
	}
}
