package main

import (
	"bytes"
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

type result struct {
	code           int
	stdout, stderr string
}

func cli(t *testing.T, envVars map[string]string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	e := &env{
		stdout: &out, stderr: &errb,
		getenv: func(k string) string { return envVars[k] },
	}
	code := run(args, e)
	return result{code, out.String(), errb.String()}
}

var pass = map[string]string{"LOGANON_PASSPHRASE": "correct horse battery"}

func logFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	os.WriteFile(p, []byte("Oct  6 00:49:00 web04 sshd[1]: Accepted password for alice from 203.0.113.50 port 22\n"), 0o644)
	t.Setenv("LOGANON_PROFILE_DIR", filepath.Join(dir, "profiles"))
	return p
}

func TestUsageAndVersion(t *testing.T) {
	if r := cli(t, nil); r.code != exitUsage || !strings.Contains(r.stderr, "Usage:") {
		t.Errorf("no args without a terminal: %+v", r)
	}
	if r := cli(t, nil, "-version"); r.code != 0 || !strings.Contains(r.stdout, "log_anonimizer") {
		t.Errorf("-version: %+v", r)
	}
	if r := cli(t, nil, "-a", "x", "-d", "y"); r.code != exitUsage {
		t.Errorf("two modes: %+v", r)
	}
	if r := cli(t, nil, "-a", "x", "extra"); r.code != exitUsage || !strings.Contains(r.stderr, "unexpected argument") {
		t.Errorf("stray argument: %+v", r)
	}
	if r := cli(t, nil, "-h"); r.code != 0 {
		t.Errorf("-h: %+v", r)
	}
}

func TestAnonymizeRestoreVerify(t *testing.T) {
	in := logFile(t)
	dir := filepath.Dir(in)
	r := cli(t, pass, "-a", in, "-q")
	if r.code != 0 {
		t.Fatalf("-a: %+v", r)
	}
	out := filepath.Join(dir, "auth.anon.log")
	got, _ := os.ReadFile(out)
	if string(got) != "Oct  6 00:49:00 HOST_0001 sshd[1]: Accepted password for USER_0001 from EXTIP_0001 port 22\n" {
		t.Errorf("anonymized: %q", got)
	}
	if !strings.Contains(r.stdout, "verify    OK") || strings.Contains(r.stdout, "alice") {
		t.Errorf("summary: %s", r.stdout)
	}
	if r := cli(t, pass, "-a", in); r.code != exitError || !strings.Contains(r.stderr, "already exists") {
		t.Errorf("second run without -f: %+v", r)
	}

	r = cli(t, pass, "-d", out)
	if r.code != 0 {
		t.Fatalf("-d: %+v", r)
	}
	restored, _ := os.ReadFile(filepath.Join(dir, "auth.restored.log"))
	orig, _ := os.ReadFile(in)
	if string(restored) != string(orig) {
		t.Errorf("restored %q", restored)
	}

	mp := filepath.Join(dir, "auth.anonmap")
	if r := cli(t, pass, "-verify", out, "-m", mp); r.code != 0 {
		t.Errorf("verify output: %+v", r)
	}
	if r := cli(t, pass, "-verify", in, "-m", mp); r.code != exitLeak {
		t.Errorf("verify original must exit %d: %+v", exitLeak, r)
	}
	if r := cli(t, nil, "-d", out); r.code != exitError || !strings.Contains(r.stderr, "passphrase") {
		t.Errorf("no passphrase available: %+v", r)
	}
	if r := cli(t, map[string]string{"LOGANON_PASSPHRASE": "wrong passphrase"}, "-d", out, "-f"); r.code != exitError || !strings.Contains(r.stderr, "wrong passphrase") {
		t.Errorf("wrong passphrase: %+v", r)
	}
}

func TestNoEncryptAndOutputFlags(t *testing.T) {
	in := logFile(t)
	dir := filepath.Dir(in)
	out := filepath.Join(dir, "shared", "auth-clean.log")
	os.MkdirAll(filepath.Dir(out), 0o755)
	mp := filepath.Join(dir, "private", "case42.anonmap")
	os.MkdirAll(filepath.Dir(mp), 0o700)
	r := cli(t, nil, "-a", in, "-o", out, "-m", mp, "-no-encrypt", "-q")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if info, err := vault.Stat(mp); err != nil || info.Encrypted {
		t.Errorf("map should be plain: %v %v", info, err)
	}
	if !strings.Contains(r.stdout, "NOT encrypted") {
		t.Errorf("summary must warn about the plain map: %s", r.stdout)
	}
	if r := cli(t, nil, "-d", out, "-m", mp, "-o", filepath.Join(dir, "back.log")); r.code != 0 {
		t.Errorf("restore: %+v", r)
	}
	if r := cli(t, nil, "-d", out); r.code != exitError || !strings.Contains(r.stderr, "no map found") {
		t.Errorf("restore without -m when the map is elsewhere: %+v", r)
	}
}

func TestEncryptedNeedsPassphrase(t *testing.T) {
	in := logFile(t)
	if r := cli(t, nil, "-a", in); r.code != exitError || !strings.Contains(r.stderr, "LOGANON_PASSPHRASE") {
		t.Errorf("%+v", r)
	}
}

func TestProfiles(t *testing.T) {
	in := logFile(t)
	if r := cli(t, nil, "-print-profile"); r.code != 0 || !strings.Contains(r.stdout, "sensitive_terms:") {
		t.Errorf("-print-profile: %+v", r)
	}
	if r := cli(t, nil, "-a", in, "-p", "missing"); r.code != exitError {
		t.Errorf("missing profile: %+v", r)
	}
	pf := filepath.Join(filepath.Dir(in), "keep-ioc.yaml")
	os.WriteFile(pf, []byte("anonymize:\n  public_ip: false\nencrypt_map: false\n"), 0o644)
	if r := cli(t, nil, "-a", in, "-p", pf, "-q"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	got, _ := os.ReadFile(filepath.Join(filepath.Dir(in), "auth.anon.log"))
	if !strings.Contains(string(got), "from 203.0.113.50 port") {
		t.Errorf("public IP should be kept by the profile: %q", got)
	}
	if r := cli(t, nil, "-profiles"); r.code != 0 || !strings.Contains(r.stdout, "default") {
		t.Errorf("-profiles: %+v", r)
	}
}

func TestShowFlag(t *testing.T) {
	in := logFile(t)
	dir := filepath.Dir(in)
	if r := cli(t, pass, "-a", in, "-q"); r.code != 0 {
		t.Fatal(r)
	}
	r := cli(t, pass, "-show", filepath.Join(dir, "auth.anon.log"))
	if r.code != 0 || !strings.Contains(r.stdout, "USER_0001") || !strings.Contains(r.stdout, "alice") || !strings.Contains(r.stdout, "1×") {
		t.Errorf("-show anonymized file: %+v", r)
	}
	r = cli(t, pass, "-show", filepath.Join(dir, "auth.anonmap"), "-find", "web04")
	if r.code != 0 || !strings.Contains(r.stdout, "HOST_0001") || strings.Contains(r.stdout, "alice") {
		t.Errorf("-show map -find: %+v", r)
	}
	if r := cli(t, pass, "-show", in, "-a", in); r.code != exitUsage {
		t.Errorf("two modes: %+v", r)
	}
}

func TestDefaultProfileWarning(t *testing.T) {
	in := logFile(t)
	r := cli(t, pass, "-a", in, "-q")
	if r.code != 0 || !strings.Contains(r.stderr, "! no -p given: created and using the default profile") ||
		!strings.Contains(r.stderr, "! no sensitive_terms") {
		t.Fatalf("first run: %+v", r)
	}
	dir, _ := profile.Dir()
	if _, err := os.Stat(filepath.Join(dir, "default.yaml")); err != nil {
		t.Errorf("default.yaml not created: %v", err)
	}
	// the default file is used from now on: edit it like a user would
	os.WriteFile(filepath.Join(dir, "default.yaml"), []byte("sensitive_terms: [web04]\n"), 0o600)
	r = cli(t, pass, "-a", in, "-q", "-f")
	if !strings.Contains(r.stderr, "! no -p given: using the default profile") || strings.Contains(r.stderr, "sensitive_terms") {
		t.Errorf("second run: %+v", r)
	}
	pf := filepath.Join(filepath.Dir(in), "acme.yaml")
	os.WriteFile(pf, []byte("sensitive_terms: [acme]\n"), 0o600)
	if r := cli(t, pass, "-a", in, "-q", "-f", "-p", pf); strings.Contains(r.stderr, "!") {
		t.Errorf("with -p and terms there is nothing to warn about: %+v", r)
	}
}
