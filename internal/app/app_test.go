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

// scripted answers the prompts in order and records the notices.
type scripted struct {
	answers []string
	asked   []string
	notices []string
}

func (s *scripted) pass() Passphrases {
	return Passphrases{
		Prompt: func(p string) ([]byte, error) {
			s.asked = append(s.asked, p)
			if len(s.answers) == 0 {
				return nil, errors.New("no more answers")
			}
			a := s.answers[0]
			s.answers = s.answers[1:]
			return []byte(a), nil
		},
		Notice: func(m string) { s.notices = append(s.notices, m) },
	}
}

func TestNewPassphraseRetries(t *testing.T) {
	cases := []struct {
		name    string
		answers []string
		want    string // passphrase, or "" for an error
		errHas  string
		notices []string
	}{
		{"first try", []string{"long enough 1", "long enough 1"}, "long enough 1", "", nil},
		{"empty then ok", []string{"", "long enough 1", "long enough 1"}, "long enough 1", "",
			[]string{"empty passphrase: the map needs one to stay private (or run with -no-encrypt), try again (2 tries left)"}},
		{"short then mismatch then ok", []string{"short", "long enough 1", "typo typo 1", "long enough 1", "long enough 1"}, "long enough 1", "",
			[]string{"too short: use at least 8 characters, try again (2 tries left)", "the two passphrases do not match, try again (last try)"}},
		{"three empties give up", []string{"", "", ""}, "", "empty passphrase", []string{"", ""}},
		{"three mismatches give up", []string{"aaaaaaaa", "b", "aaaaaaaa", "c", "aaaaaaaa", "d"}, "", "do not match", []string{"", ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := &scripted{answers: c.answers}
			got, err := sc.pass().New()
			if c.want != "" && (err != nil || string(got) != c.want) {
				t.Errorf("got %q, %v", got, err)
			}
			if c.errHas != "" && (err == nil || !strings.Contains(err.Error(), c.errHas)) {
				t.Errorf("err = %v, want %q", err, c.errHas)
			}
			if len(sc.notices) != len(c.notices) {
				t.Fatalf("notices %q", sc.notices)
			}
			for i, n := range c.notices {
				if n != "" && sc.notices[i] != n {
					t.Errorf("notice %d = %q\nwant %q", i, sc.notices[i], n)
				}
			}
		})
	}
	if _, err := (Passphrases{Env: "short"}).New(); err == nil {
		t.Error("short env passphrase accepted")
	}
	if _, err := (Passphrases{}).New(); err == nil || !strings.Contains(err.Error(), "-no-encrypt") {
		t.Errorf("no prompt, no env: %v", err)
	}
	if _, err := (Passphrases{}).Existing(); !errors.Is(err, vault.ErrNeedPassphrase) {
		t.Errorf("existing without source: %v", err)
	}
}

func TestOpenMapRetries(t *testing.T) {
	dir := t.TempDir()
	mp := filepath.Join(dir, "m.anonmap")
	v := vault.New()
	v.Token(vault.Host, "pc-1")
	if err := vault.Save(mp, v, []byte("right pass 1")); err != nil {
		t.Fatal(err)
	}
	sc := &scripted{answers: []string{"", "wrong pass", "right pass 1"}}
	got, err := LoadMap(mp, sc.pass())
	if err != nil || got.Len() != 1 {
		t.Fatalf("empty, wrong, right: %v", err)
	}
	if len(sc.asked) != 3 || len(sc.notices) != 2 ||
		!strings.HasPrefix(sc.notices[0], "empty passphrase") || !strings.HasPrefix(sc.notices[1], "wrong passphrase, try again (last try)") {
		t.Errorf("asked %d times, notices %q", len(sc.asked), sc.notices)
	}

	sc = &scripted{answers: []string{"wrong 1", "wrong 2", "wrong 3", "right pass 1"}}
	if _, err := LoadMap(mp, sc.pass()); !errors.Is(err, vault.ErrWrongPassphrase) || len(sc.asked) != 3 {
		t.Errorf("three wrong: %v, asked %d times", err, len(sc.asked))
	}
	sc = &scripted{answers: []string{"", "", ""}}
	if _, err := LoadMap(mp, sc.pass()); err == nil || !strings.Contains(err.Error(), "no passphrase entered") {
		t.Errorf("three empty: %v", err)
	}
	// the environment variable is never asked again
	if _, err := LoadMap(mp, Passphrases{Env: "wrong pass", Prompt: sc.pass().Prompt}); !errors.Is(err, vault.ErrWrongPassphrase) {
		t.Errorf("env: %v", err)
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
	if err == nil && (v.Sources[1].Input != b || v.Sources[1].SHA256 == "" || v.Sources[1].Time.IsZero()) {
		t.Errorf("source must be the path as given, with the input hash: %+v", v.Sources[1])
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
