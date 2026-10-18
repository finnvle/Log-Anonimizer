package tui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

func TestMain(m *testing.M) {
	vault.KDFTime, vault.KDFMemory, vault.KDFThreads = 1, 1024, 1
	os.Exit(m.Run())
}

const (
	up    = "\x1b[A"
	down  = "\x1b[B"
	enter = "\r"
)

func TestParseKeys(t *testing.T) {
	keys, rest := parseKeys([]byte("a\x1b[A\x1b[B\r\n\x7f\t\x03\x15\x1bก"), true)
	want := []keyKind{kChar, kUp, kDown, kEnter, kBackspace, kTab, kCtrlC, kCtrlU, kEsc, kChar}
	if len(keys) != len(want) || rest != nil {
		t.Fatalf("got %d keys %+v rest %v", len(keys), keys, rest)
	}
	for i, k := range keys {
		if k.k != want[i] {
			t.Errorf("key %d = %v want %v", i, k.k, want[i])
		}
	}
	if keys[9].r != 'ก' {
		t.Errorf("Thai rune = %q", keys[9].r)
	}
}

// oneByte delivers input one byte per Read, like a slow terminal.
type oneByte struct{ r io.Reader }

func (o oneByte) Read(p []byte) (int, error) { return o.r.Read(p[:1]) }

func TestKeyReaderJoinsSplitRunes(t *testing.T) {
	kr := newKeyReader(oneByte{strings.NewReader("ทดสอบ\r")})
	var got []rune
	for {
		k, err := kr.next()
		if err != nil {
			t.Fatal(err)
		}
		if k.k == kEnter {
			break
		}
		got = append(got, k.r)
	}
	if string(got) != "ทดสอบ" {
		t.Errorf("got %q", string(got))
	}
}

func newUI(script string) (*ui, *bytes.Buffer) {
	var out bytes.Buffer
	return &ui{keys: newKeyReader(strings.NewReader(script)), out: &out, width: 80}, &out
}

func TestSelectOne(t *testing.T) {
	u, _ := newUI(down + down + up + enter)
	if i, err := u.selectOne("pick", []string{"a", "b", "c"}, 0); err != nil || i != 1 {
		t.Errorf("arrows: %d %v", i, err)
	}
	u, _ = newUI("3" + enter)
	if i, _ := u.selectOne("pick", []string{"a", "b", "c"}, 0); i != 2 {
		t.Errorf("number key: %d", i)
	}
	u, _ = newUI(up + enter)
	if i, _ := u.selectOne("pick", []string{"a", "b", "c"}, 0); i != 2 {
		t.Errorf("wrap around: %d", i)
	}
	u, _ = newUI("\x03")
	if _, err := u.selectOne("pick", []string{"a"}, 0); err != errCancel {
		t.Errorf("ctrl-c: %v", err)
	}
}

func TestMultiSelect(t *testing.T) {
	items := []checkItem{{"one", true}, {"two", true}, {"three", false}}
	u, out := newUI(" " + down + down + " " + enter)
	got, err := u.multiSelect("what", items)
	if err != nil || got[0].on || !got[1].on || !got[2].on {
		t.Errorf("toggle: %+v %v", got, err)
	}
	if !strings.Contains(out.String(), "2 of 3 selected") {
		t.Errorf("summary missing: %q", out.String())
	}
	u, _ = newUI("a" + enter) // not all on -> all on
	got, _ = u.multiSelect("what", []checkItem{{"one", true}, {"two", false}})
	if !got[0].on || !got[1].on {
		t.Errorf("a = all: %+v", got)
	}
}

func TestInput(t *testing.T) {
	u, _ := newUI("ab\x7fc" + enter)
	if v, _ := u.input("x", inputOpts{}); v != "ac" {
		t.Errorf("backspace: %q", v)
	}
	u, _ = newUI(enter)
	if v, _ := u.input("x", inputOpts{def: "dflt"}); v != "dflt" {
		t.Errorf("default: %q", v)
	}
	u, out := newUI(enter + "ok" + enter)
	v, _ := u.input("x", inputOpts{validate: mustExistOrOK})
	if v != "ok" || !strings.Contains(out.String(), "required") {
		t.Errorf("validation: %q %q", v, out.String())
	}
	u, out = newUI("hunter22" + enter)
	if v, _ := u.input("pass", inputOpts{mask: true}); v != "hunter22" || strings.Contains(out.String(), "hunter22") {
		t.Errorf("mask: %q, screen shows the secret: %v", v, strings.Contains(out.String(), "hunter22"))
	}
}

func mustExistOrOK(s string) error {
	if s == "ok" {
		return nil
	}
	return mustExist(s)
}

func TestPathHelpers(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "alpha.log"), nil, 0o644)
	os.Mkdir(filepath.Join(dir, "alpine"), 0o755)
	got, cands := completePath(filepath.Join(dir, "al"))
	if got != filepath.Join(dir, "alp") || len(cands) != 2 {
		t.Errorf("common prefix: %q %v", got, cands)
	}
	if got, _ := completePath(filepath.Join(dir, "alph")); got != filepath.Join(dir, "alpha.log") {
		t.Errorf("unique: %q", got)
	}
	if got, _ := completePath(filepath.Join(dir, "alpi")); got != filepath.Join(dir, "alpine")+string(filepath.Separator) {
		t.Errorf("directory: %q", got)
	}
	if cleanPath(`'/tmp/a b'`) != "/tmp/a b" || cleanPath(` "/tmp/x" `) != "/tmp/x" {
		t.Error("quotes from drag and drop not removed")
	}
	if runtime.GOOS != "windows" && cleanPath(`/tmp/a\ b`) != "/tmp/a b" {
		t.Error("escaped space not handled")
	}
}

func TestFitIgnoresEscapes(t *testing.T) {
	u := &ui{width: 25}
	s := u.fit(sBold + strings.Repeat("x", 50) + sReset)
	plain := strings.NewReplacer(sBold, "", sReset, "").Replace(s)
	if len(plain) != 24 {
		t.Errorf("visible width %d", len(plain))
	}
}

// --- whole wizard ------------------------------------------------------------

func runWizard(t *testing.T, script string, env map[string]string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := Run(Options{Reader: strings.NewReader(script), Out: &out, Width: 120,
		Getenv: func(k string) string { return env[k] }})
	return code, out.String()
}

func setup(t *testing.T) (dir, in string) {
	t.Helper()
	dir = t.TempDir()
	t.Setenv("LOGANON_PROFILE_DIR", filepath.Join(dir, "profiles"))
	in = filepath.Join(dir, "fw.log")
	os.WriteFile(in, []byte("ORIGIN=ACMEDC01 src=10.0.0.1 dst=198.51.100.7 user=acme\\jdoe\n"), 0o644)
	return dir, in
}

func TestWizardAnonymize(t *testing.T) {
	dir, in := setup(t)
	script := enter + // Anonymize
		in + enter + // input
		down + " " + enter + // untick "Public IP addresses"
		"acme" + enter + // sensitive terms
		enter + // new map
		down + enter + // no passphrase
		enter + // automatic output
		"case1" + enter + // save profile
		enter // start
	code, out := runWizard(t, script, nil)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	got, err := os.ReadFile(filepath.Join(dir, "fw.anon.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ORIGIN=HOST_0001 src=IP_0001 dst=198.51.100.7 user=DOMAIN_0001\\USER_0001\n" {
		t.Errorf("output %q", got)
	}
	p, err := profile.Load("case1")
	if err != nil || p.Anonymize.PublicIP || p.SensitiveTerms[0] != "acme" || p.EncryptMap {
		t.Errorf("saved profile %+v %v", p, err)
	}
	if !strings.Contains(out, "log_anonimizer -a "+in+" -p case1\n") {
		t.Errorf("equivalent command missing:\n%s", out)
	}
	if info, err := vault.Stat(filepath.Join(dir, "fw.anonmap")); err != nil || info.Encrypted {
		t.Errorf("map: %+v %v", info, err)
	}
}

func TestWizardEncryptedRoundTrip(t *testing.T) {
	dir, in := setup(t)
	script := enter + in + enter + enter + enter + // anonymize, input, toggles as they are, no terms
		enter + // new map
		enter + // passphrase: yes
		"short" + enter + "long enough 1" + enter + // too short, then ok
		"typo typo 1" + enter + "long enough 1" + enter + // repeat: mismatch, then ok
		enter + enter + enter // output, don't save, start
	if code, out := runWizard(t, script, nil); code != 0 {
		t.Fatalf("anonymize exit %d\n%s", code, out)
	}
	if info, _ := vault.Stat(filepath.Join(dir, "fw.anonmap")); !info.Encrypted {
		t.Fatal("map not encrypted")
	}
	script = down + enter + // de-anonymize
		filepath.Join(dir, "fw.anon.log") + enter +
		enter + // the map found next to it
		"wrong pass 1" + enter + "long enough 1" + enter +
		enter // automatic output
	code, out := runWizard(t, script, nil)
	if code != 0 {
		t.Fatalf("restore exit %d\n%s", code, out)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "fw.restored.log"))
	want, _ := os.ReadFile(in)
	if string(got) != string(want) {
		t.Errorf("round trip %q", got)
	}
	if !strings.Contains(out, "wrong passphrase") {
		t.Error("wrong passphrase was not reported")
	}
}

func TestWizardVerifyAndCancel(t *testing.T) {
	dir, in := setup(t)
	runWizard(t, enter+in+enter+enter+enter+enter+down+enter+enter+enter+enter, nil)
	code, out := runWizard(t, down+down+enter+filepath.Join(dir, "fw.anon.log")+enter+enter, nil)
	if code != 0 || !strings.Contains(out, "map       OK") {
		t.Errorf("verify exit %d\n%s", code, out)
	}
	if code, out := runWizard(t, "\x03", nil); code != 130 || !strings.Contains(out, "cancelled") {
		t.Errorf("ctrl-c: %d %s", code, out)
	}
	if code, _ := runWizard(t, enter+in+enter, nil); code != 130 {
		t.Errorf("end of input mid-wizard: %d", code)
	}
}

func TestWizardShow(t *testing.T) {
	dir, in := setup(t)
	runWizard(t, enter+in+enter+enter+enter+enter+down+enter+enter+enter+enter, nil) // plain map
	code, out := runWizard(t, down+down+down+enter+filepath.Join(dir, "fw.anon.log")+enter+enter+enter, nil)
	if code != 0 || !strings.Contains(out, "USER_0001") || !strings.Contains(out, "jdoe") || !strings.Contains(out, "-show ") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// screen replays terminal output (cursor moves, clears) and returns the
// lines a user would see.
func screen(out string) []string {
	var lines [][]rune
	row, col := 0, 0
	at := func() {
		for len(lines) <= row {
			lines = append(lines, nil)
		}
	}
	rs := []rune(out)
	for i := 0; i < len(rs); i++ {
		at()
		switch c := rs[i]; {
		case c == 0x1b && i+1 < len(rs) && rs[i+1] == '[':
			j := i + 2
			for j < len(rs) && !(rs[j] >= 0x40 && rs[j] <= 0x7e) {
				j++
			}
			n := 1
			if j > i+2 {
				fmt.Sscanf(string(rs[i+2:j]), "%d", &n)
			}
			switch rs[j] {
			case 'A':
				row -= n
			case 'C':
				col += n
			case 'K':
				if col < len(lines[row]) {
					lines[row] = lines[row][:col]
				}
			case 'J':
				if col < len(lines[row]) {
					lines[row] = lines[row][:col]
				}
				lines = lines[:row+1]
			}
			i = j
		case c == '\r':
			col = 0
		case c == '\n':
			row++
		default:
			for len(lines[row]) < col {
				lines[row] = append(lines[row], ' ')
			}
			if col < len(lines[row]) {
				lines[row][col] = c
			} else {
				lines[row] = append(lines[row], c)
			}
			col++
		}
	}
	var res []string
	for _, l := range lines {
		res = append(res, strings.TrimRight(string(l), " "))
	}
	return res
}

func TestTypedTextStaysVisible(t *testing.T) {
	long := "Sensitive terms - org names, project codes, internal domains (comma separated, - = none)"
	for _, c := range []struct {
		width int
		title string
	}{{40, long}, {80, long}, {80, "Sensitive terms"}, {30, "Sensitive terms"}} {
		var out bytes.Buffer
		u := &ui{keys: newKeyReader(strings.NewReader("acme, acme.co.th")), out: &out, width: c.width}
		u.input(c.title, inputOpts{hint: "org names, project codes, internal domains · e.g. acme, acme.co.th · - = none"})
		lines := screen(out.String())
		typing := false
		for _, l := range lines {
			if len([]rune(l)) > c.width-1 {
				t.Errorf("width %d: line wider than the screen: %q", c.width, l)
			}
			typing = typing || strings.HasSuffix(l, "acme, acme.co.th")
		}
		if !typing {
			t.Errorf("width %d %q: typed text not visible:\n%s", c.width, c.title, strings.Join(lines, "\n"))
		}

		out.Reset()
		u = &ui{keys: newKeyReader(strings.NewReader("acme, acme.co.th\r")), out: &out, width: c.width}
		v, _ := u.input(c.title, inputOpts{hint: "a hint"})
		lines = screen(out.String())
		last := lines[len(lines)-1]
		if last == "" && len(lines) > 1 {
			last = lines[len(lines)-2]
		}
		want := "acme, acme.co.th"
		if c.width < 40 {
			want = "acme.co.th" // very narrow: the start of a long answer is cut
		}
		if v != "acme, acme.co.th" || !strings.HasSuffix(last, want) || strings.Contains(strings.Join(lines, "\n"), "a hint") {
			t.Errorf("width %d: answer line %q (value %q), screen:\n%s", c.width, last, v, strings.Join(lines, "\n"))
		}
	}
}
