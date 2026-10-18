package profile

import (
	"strings"
	"testing"
)

func TestDefaultEverythingOn(t *testing.T) {
	p := Default()
	a := p.Anonymize
	if !(a.InternalIP && a.PublicIP && a.Hostname && a.Domain && a.User && a.MAC && a.SID && a.Secrets && a.DeviceID && a.FileNames) {
		t.Errorf("default toggles: %+v", a)
	}
	if !p.EncryptMap {
		t.Error("map must be encrypted by default")
	}
}

func TestParseKeepsDefaultsForMissingFields(t *testing.T) {
	p, err := Parse([]byte("anonymize:\n  public_ip: false\nsensitive_terms: [acme, ' acme.co.th ']\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Anonymize.PublicIP {
		t.Error("public_ip should be off")
	}
	if !p.Anonymize.Hostname || !p.Anonymize.InternalIP {
		t.Error("toggles missing from the file must keep their default (on)")
	}
	if len(p.SecretKeys) == 0 {
		t.Error("secret keys default lost")
	}
	if strings.Join(p.SensitiveTerms, "|") != "acme|acme.co.th" {
		t.Errorf("terms not trimmed: %q", p.SensitiveTerms)
	}
}

func TestParseRejectsUnknownFieldsAndShortTerms(t *testing.T) {
	if _, err := Parse([]byte("anonymise: {}\n")); err == nil {
		t.Error("misspelled field accepted")
	}
	if _, err := Parse([]byte("sensitive_terms: [ab]\n")); err == nil {
		t.Error("2-character term accepted")
	}
	if p, err := Parse(nil); err != nil || p.Name != "default" {
		t.Errorf("empty file: %v %v", p, err)
	}
}

func TestSaveLoadListRoundTrip(t *testing.T) {
	t.Setenv("LOGANON_PROFILE_DIR", t.TempDir())
	p := Default()
	p.Anonymize.MAC = false
	p.SensitiveTerms = []string{"acme"}
	path, err := Save(p, "customer-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "customer-a.yaml") {
		t.Errorf("path %s", path)
	}
	q, err := Load("customer-a")
	if err != nil {
		t.Fatal(err)
	}
	if q.Name != "customer-a" || q.Anonymize.MAC || q.SensitiveTerms[0] != "acme" {
		t.Errorf("loaded %+v", q)
	}
	names, err := List()
	if err != nil || len(names) != 1 || names[0] != "customer-a" {
		t.Errorf("List = %v %v", names, err)
	}
	if q2, err := Load(path); err != nil || q2.Anonymize.MAC {
		t.Errorf("load by path: %v %v", q2, err)
	}
	if _, err := Load("missing"); err == nil {
		t.Error("missing profile loaded")
	}
	if d, err := Load("default"); err != nil || d.Name != "default" {
		t.Errorf("built-in default: %v %v", d, err)
	}
}

func TestMarshalHasHelpComment(t *testing.T) {
	data, err := Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.HasPrefix(s, "# log_anonimizer profile") || !strings.Contains(s, "sensitive_terms:") {
		t.Errorf("unexpected YAML:\n%s", s)
	}
	p, err := Parse(data)
	if err != nil || p.Anonymize != Default().Anonymize {
		t.Errorf("marshal/parse round trip: %v %v", p, err)
	}
}

func TestValidNameAndParseTerms(t *testing.T) {
	for _, ok := range []string{"a", "customer-a", "case_2026.10"} {
		if !ValidName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", ".hidden", "a/b", "a b", `a\b`} {
		if ValidName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
	if got := ParseTerms(" acme, , acme.co.th ,x "); strings.Join(got, "|") != "acme|acme.co.th|x" {
		t.Errorf("ParseTerms = %q", got)
	}
}
