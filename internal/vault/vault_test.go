package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	// cheap key derivation for tests
	KDFTime, KDFMemory, KDFThreads = 1, 1024, 1
	os.Exit(m.Run())
}

func TestTokenFormatAndCounters(t *testing.T) {
	v := New()
	cases := []struct {
		k    Kind
		val  string
		want string
		new  bool
	}{
		{Host, "pc01", "HOST_0001", true},
		{Host, "pc02", "HOST_0002", true},
		{User, "alice", "USER_0001", true},
		{Host, "pc01", "HOST_0001", false},
		{IP, "10.1.2.3", "IP_0001", true},
		{ExtIP, "203.0.113.7", "EXTIP_0001", true},
		{Secret, "hunter2", "SECRET_0001", true},
	}
	for _, c := range cases {
		got, isNew := v.Token(c.k, c.val)
		if got != c.want || isNew != c.new {
			t.Errorf("Token(%s,%q) = %s,%v want %s,%v", c.k, c.val, got, isNew, c.want, c.new)
		}
	}
	if v.Len() != 6 {
		t.Errorf("Len = %d, want 6", v.Len())
	}
}

func TestKeysMergeCaseButNotForSecrets(t *testing.T) {
	v := New()
	a, _ := v.Token(Host, "ACME-DC01")
	b, _ := v.Token(Host, "acme-dc01")
	if a != b {
		t.Errorf("hostname case variants got %s and %s", a, b)
	}
	// host, user, domain share one namespace so "ACME" is the same everywhere
	c, _ := v.Token(Domain, "acme")
	d, _ := v.Token(Org, "ACME")
	if c != d {
		t.Errorf("domain/org got %s and %s", c, d)
	}
	s1, _ := v.Token(Secret, "Passw0rd")
	s2, _ := v.Token(Secret, "passw0rd")
	if s1 == s2 {
		t.Error("secrets must be case-sensitive")
	}
	i1, _ := v.Token(IP, "010.001.002.003")
	i2, _ := v.Token(IP, "10.1.2.3")
	if i1 != i2 {
		t.Errorf("leading zeros: %s vs %s", i1, i2)
	}
	m1, _ := v.Token(MAC, "00-1A-2B-3C-4D-5E")
	m2, _ := v.Token(MAC, "001a.2b3c.4d5e")
	if m1 != m2 {
		t.Errorf("MAC formats: %s vs %s", m1, m2)
	}
}

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"00:1A:2B:3C:4D:5E": "00:1a:2b:3c:4d:5e",
		"00-1a-2b-3c-4d-5e": "00:1a:2b:3c:4d:5e",
		"001a.2b3c.4d5e":    "00:1a:2b:3c:4d:5e",
		"nonsense":          "nonsense",
	} {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrefixAndPattern(t *testing.T) {
	v := New()
	v.Prefix = "ANON_"
	tok, _ := v.Token(Host, "x1")
	if tok != "ANON_HOST_0001" {
		t.Fatalf("got %s", tok)
	}
	re := v.TokenPattern()
	if !re.MatchString("see ANON_HOST_0001.") || re.MatchString("see HOST_0001.") {
		t.Error("pattern must require the prefix")
	}
	if got := TokenPattern("").FindString("x EXTIP_0012 y"); got != "EXTIP_0012" {
		t.Errorf("EXTIP not matched whole: %q", got)
	}
}

func TestIsTokenStart(t *testing.T) {
	cases := []struct {
		s    string
		i    int
		want bool
	}{
		{"HOST_0001", 0, true},
		{" HOST_0001", 1, true},
		{"xHOST_0001", 1, false},
		{"9HOST_0001", 1, false},
		{"USER_0001%40DOMAIN_0002", 12, true}, // after %40
		{"a%4GDOMAIN_0002", 4, false},
		{"S-1-5-21-SID_0001", 9, true},
	}
	for _, c := range cases {
		if got := IsTokenStart(c.s, c.i); got != c.want {
			t.Errorf("IsTokenStart(%q,%d) = %v", c.s, c.i, got)
		}
	}
}

func filled() *Vault {
	v := New()
	v.Token(Host, "secret-host-01")
	v.Token(User, "somchai")
	v.Token(IP, "10.9.8.7")
	return v
}

func TestSaveLoadEncrypted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.anonmap")
	if err := Save(path, filled(), []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, s := range []string{"secret-host-01", "somchai", "10.9.8.7"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("encrypted map contains %q in clear text", s)
		}
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("map permissions %v, want 0600", st.Mode().Perm())
		}
	}
	info, err := Stat(path)
	if err != nil || !info.Encrypted {
		t.Fatalf("Stat = %+v, %v", info, err)
	}
	v, pass, err := Load(path, func() ([]byte, error) { return []byte("correct horse"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if string(pass) != "correct horse" {
		t.Error("Load must return the passphrase used")
	}
	e, ok := v.Lookup("USER_0001")
	if !ok || e.Original != "somchai" {
		t.Errorf("Lookup after load = %+v %v", e, ok)
	}
	// indexes are rebuilt: an existing value keeps its token, counters continue
	if tok, isNew := v.Token(Host, "SECRET-HOST-01"); tok != "HOST_0001" || isNew {
		t.Errorf("existing value got %s new=%v", tok, isNew)
	}
	if tok, _ := v.Token(Host, "another"); tok != "HOST_0002" {
		t.Errorf("counter did not continue: %s", tok)
	}
}

func TestWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.anonmap")
	if err := Save(path, filled(), []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load(path, func() ([]byte, error) { return []byte("wrong horse"), nil })
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("err = %v, want ErrWrongPassphrase", err)
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.anonmap")
	if err := Save(path, filled(), []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &env)
	ct := []byte(env["ciphertext"].(string))
	ct[10] ^= 1 // base64 text: changes one decoded byte
	if ct[10] == '+' || ct[10] == '/' || ct[10] == '=' {
		ct[10] = 'A'
	}
	env["ciphertext"] = string(ct)
	data, _ = json.Marshal(env)
	os.WriteFile(path, data, 0o600)
	_, _, err := Load(path, func() ([]byte, error) { return []byte("correct horse"), nil })
	if err == nil {
		t.Fatal("tampered map was accepted")
	}
}

func TestSavePlain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.anonmap")
	if err := Save(path, filled(), nil); err != nil {
		t.Fatal(err)
	}
	called := false
	v, _, err := Load(path, func() ([]byte, error) { called = true; return nil, nil })
	if err != nil || called {
		t.Fatalf("plain map: err=%v passphrase asked=%v", err, called)
	}
	if v.Len() != 3 {
		t.Errorf("Len = %d", v.Len())
	}
	if info, _ := Stat(path); info.Encrypted {
		t.Error("plain map reported as encrypted")
	}
}

func TestLoadRejectsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.json")
	os.WriteFile(p1, []byte(`{"hello":"world"}`), 0o600)
	if _, _, err := Load(p1, nil); err == nil {
		t.Error("random JSON accepted as a map")
	}
	p2 := filepath.Join(dir, "b.txt")
	os.WriteFile(p2, []byte("not json"), 0o600)
	if _, _, err := Load(p2, nil); err == nil {
		t.Error("text accepted as a map")
	}
}
