package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

func TestMain(m *testing.M) {
	vault.KDFTime, vault.KDFMemory, vault.KDFThreads = 1, 1024, 1
	os.Exit(m.Run())
}

func sample(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fw.log")
	os.WriteFile(p, []byte("HOST=fw-01 src=10.1.1.1 user=somchai.k\n"), 0o644)
	return p
}

func TestAnonymizeEncryptedThenRestore(t *testing.T) {
	in := sample(t)
	res, err := Anonymize(AnonOptions{Input: in, Profile: profile.Default(), Encrypt: true, Pass: Passphrases{Env: "long enough pass"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.MapPath != filepath.Join(filepath.Dir(in), "fw.anonmap") || !res.Encrypted {
		t.Errorf("result %+v", res)
	}
	if info, err := vault.Stat(res.MapPath); err != nil || !info.Encrypted {
		t.Errorf("map not encrypted: %v %v", info, err)
	}
	if !strings.Contains(FormatAnon(res), "encrypted") {
		t.Error("summary does not mention encryption")
	}
	if _, err := Restore(res.Report.Output, "", "", Passphrases{Env: "wrong pass 123"}, false); !errors.Is(err, vault.ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	rep, err := Restore(res.Report.Output, "", "", Passphrases{Env: "long enough pass"}, false)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(rep.Output)
	want, _ := os.ReadFile(in)
	if string(got) != string(want) {
		t.Errorf("round trip: %q vs %q", got, want)
	}
}

func TestPassphraseRules(t *testing.T) {
	if _, err := (Passphrases{Env: "short"}).New(); err == nil {
		t.Error("short env passphrase accepted")
	}
	if _, err := (Passphrases{}).New(); err == nil || !strings.Contains(err.Error(), "-no-encrypt") {
		t.Errorf("no prompt, no env: %v", err)
	}
	answers := []string{"first pass 1", "other pass 2"}
	p := Passphrases{Prompt: func(string) ([]byte, error) { a := answers[0]; answers = answers[1:]; return []byte(a), nil }}
	if _, err := p.New(); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Errorf("mismatch: %v", err)
	}
	if _, err := (Passphrases{}).Existing(); !errors.Is(err, vault.ErrNeedPassphrase) {
		t.Errorf("existing without source: %v", err)
	}
}

func TestExistingMapIsNotOverwritten(t *testing.T) {
	in := sample(t)
	mp := filepath.Join(filepath.Dir(in), "fw.anonmap")
	os.WriteFile(mp, []byte("someone else's map"), 0o600)
	_, err := Anonymize(AnonOptions{Input: in, Profile: profile.Default()})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(in), "fw.anon.log")); err == nil {
		t.Error("output was written although the map could not be")
	}
	if b, _ := os.ReadFile(mp); string(b) != "someone else's map" {
		t.Error("existing map was touched")
	}
}

func TestExtendMapAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	b := filepath.Join(dir, "b.log")
	os.WriteFile(a, []byte("HOST=fw-01\n"), 0o644)
	os.WriteFile(b, []byte("HOST=fw-02 HOST=fw-01\n"), 0o644)
	mp := filepath.Join(dir, "case.anonmap")
	pass := Passphrases{Env: "long enough pass"}
	if _, err := Anonymize(AnonOptions{Input: a, Map: mp, Profile: profile.Default(), Encrypt: true, Pass: pass}); err != nil {
		t.Fatal(err)
	}
	res, err := Anonymize(AnonOptions{Input: b, Map: mp, Profile: profile.Default(), Encrypt: true, Pass: pass})
	if err != nil {
		t.Fatal(err)
	}
	if !res.MapReused || !res.Encrypted {
		t.Errorf("result %+v", res)
	}
	got, _ := os.ReadFile(res.Report.Output)
	if string(got) != "HOST=HOST_0002 HOST=HOST_0001\n" {
		t.Errorf("got %q", got)
	}
	v, err := LoadMap(mp, pass)
	if err != nil || v.Len() != 2 || len(v.Sources) != 2 {
		t.Errorf("map after two runs: %v entries, %v sources, %v", v.Len(), len(v.Sources), err)
	}
}

func TestVerifyAndFindMap(t *testing.T) {
	in := sample(t)
	res, err := Anonymize(AnonOptions{Input: in, Profile: profile.Default()})
	if err != nil {
		t.Fatal(err)
	}
	if FindMap(res.Report.Output) != res.MapPath {
		t.Errorf("FindMap = %q", FindMap(res.Report.Output))
	}
	rep, err := Verify(res.Report.Output, res.MapPath, profile.Default(), Passphrases{})
	if err != nil || rep.LeakCount != 0 {
		t.Errorf("verify output: %+v %v", rep, err)
	}
	rep, err = Verify(in, res.MapPath, profile.Default(), Passphrases{})
	if err != nil || rep.LeakCount == 0 {
		t.Errorf("verify original should find values: %+v %v", rep, err)
	}
	other := sample(t) // a file with no map next to it
	if _, err := Restore(other, "", "", Passphrases{}, false); err == nil || !strings.Contains(err.Error(), "no map found") {
		t.Errorf("restore without map: %v", err)
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/tmp/a.log":   "/tmp/a.log",
		"my logs/a":    `"my logs/a"`,
		`C:\logs\a`:    `"C:\logs\a"`,
		`say "hi".log`: `"say \"hi\".log"`,
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s", in, got)
		}
	}
}

func TestShow(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.log")
	os.WriteFile(in, []byte("HOST=fw-01 user=somchai.k password=Winter2026!\nHOST=fw-01 src=10.1.1.1\n"), 0o644)
	extra := filepath.Join(dir, "b.log")
	os.WriteFile(extra, []byte("user=other.person\n"), 0o644)
	mp := filepath.Join(dir, "case.anonmap")
	pass := Passphrases{Env: "long enough pass"}
	if _, err := Anonymize(AnonOptions{Input: extra, Map: mp, Profile: profile.Default(), Encrypt: true, Pass: pass}); err != nil {
		t.Fatal(err)
	}
	res, err := Anonymize(AnonOptions{Input: in, Map: mp, Profile: profile.Default(), Encrypt: true, Pass: pass})
	if err != nil {
		t.Fatal(err)
	}

	all, err := Show(mp, "", "", pass)
	if err != nil || len(all.Rows) != 5 || all.UsedIn != "" || !all.Encrypted {
		t.Fatalf("whole map: %+v %v", all, err)
	}
	text := FormatShow(all)
	if !strings.Contains(text, "HOSTNAMES") || !strings.Contains(text, "Wi*********") || strings.Contains(text, "Winter2026!") {
		t.Errorf("whole map output:\n%s", text)
	}

	used, err := Show(res.Report.Output, mp, "", pass)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range used.Rows {
		got[r.Original] = r.Count
	}
	if len(used.Rows) != 4 || got["fw-01"] != 2 || got["other.person"] != 0 {
		t.Errorf("used rows: %+v", used.Rows)
	}

	one, err := Show(res.Report.Output, mp, "secret_0001", pass)
	if err != nil || len(one.Rows) != 1 || !strings.Contains(FormatShow(one), "Winter2026!") {
		t.Errorf("find reveals the secret: %+v %v", one, err)
	}
	if _, err := Show(in, "", "", pass); err == nil {
		t.Error("a file without a map next to it must fail")
	}
}
