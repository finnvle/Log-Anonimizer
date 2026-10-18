// Package profile holds the user-tunable options. Options that rarely change
// between runs live in a profile (YAML) instead of on the command line.
package profile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Toggles chooses which kinds of value are anonymized.
type Toggles struct {
	InternalIP bool `yaml:"internal_ip"`
	PublicIP   bool `yaml:"public_ip"`
	Hostname   bool `yaml:"hostname"`
	Domain     bool `yaml:"domain"`
	User       bool `yaml:"user"`
	MAC        bool `yaml:"mac"`
	SID        bool `yaml:"sid"`
	Secrets    bool `yaml:"secrets"`
	DeviceID   bool `yaml:"device_id"`
	FileNames  bool `yaml:"file_names"`
}

// Allow lists values that are never anonymized, on top of the built-in lists.
type Allow struct {
	IPs     []string `yaml:"ips,omitempty"`     // addresses or CIDRs
	Hosts   []string `yaml:"hosts,omitempty"`   // exact, case-insensitive
	Domains []string `yaml:"domains,omitempty"` // the domain and all its subdomains
	Users   []string `yaml:"users,omitempty"`   // exact, case-insensitive
}

// Profile is one saved set of options.
type Profile struct {
	Name      string  `yaml:"name"`
	Anonymize Toggles `yaml:"anonymize"`
	// SensitiveTerms are organisation names, project codes and similar words
	// that must never appear in the output. Any word containing one is
	// replaced as a whole. A term with a dot (acme.co.th) is also treated as
	// an internal domain.
	SensitiveTerms []string `yaml:"sensitive_terms"`
	// InternalSuffixes are DNS suffixes that are always internal.
	InternalSuffixes []string `yaml:"internal_suffixes"`
	// SecretKeys are key names (key=value, URL parameters, headers) whose
	// value is a secret.
	SecretKeys []string `yaml:"secret_keys"`
	Allow      Allow    `yaml:"allow"`
	EncryptMap bool     `yaml:"encrypt_map"`
}

// Default returns the built-in profile.
func Default() *Profile {
	return &Profile{
		Name: "default",
		Anonymize: Toggles{
			InternalIP: true, PublicIP: true, Hostname: true, Domain: true, User: true,
			MAC: true, SID: true, Secrets: true, DeviceID: true, FileNames: true,
		},
		SensitiveTerms:   []string{},
		InternalSuffixes: []string{"local", "lan", "corp", "internal", "localdomain", "home.arpa"},
		SecretKeys: []string{
			"password", "passwd", "pwd", "pass", "passphrase", "secret", "client_secret",
			"token", "access_token", "refresh_token", "id_token", "auth_token", "x-auth-token",
			"apikey", "api_key", "api-key", "x-api-key", "subscription-key",
			"sig", "signature", "sessionid", "session_id", "jsessionid", "phpsessid",
			"asp.net_sessionid", "authorization", "cookie", "set-cookie",
		},
		EncryptMap: true,
	}
}

// Clone returns a deep copy.
func (p *Profile) Clone() *Profile {
	c := *p
	c.SensitiveTerms = append([]string(nil), p.SensitiveTerms...)
	c.InternalSuffixes = append([]string(nil), p.InternalSuffixes...)
	c.SecretKeys = append([]string(nil), p.SecretKeys...)
	c.Allow.IPs = append([]string(nil), p.Allow.IPs...)
	c.Allow.Hosts = append([]string(nil), p.Allow.Hosts...)
	c.Allow.Domains = append([]string(nil), p.Allow.Domains...)
	c.Allow.Users = append([]string(nil), p.Allow.Users...)
	return &c
}

// Normalize trims list values, drops empty ones and validates terms.
func (p *Profile) Normalize() error {
	clean := func(in []string) []string {
		out := in[:0]
		seen := map[string]bool{}
		for _, s := range in {
			s = strings.TrimSpace(s)
			if s == "" || seen[strings.ToLower(s)] {
				continue
			}
			seen[strings.ToLower(s)] = true
			out = append(out, s)
		}
		return out
	}
	p.SensitiveTerms = clean(p.SensitiveTerms)
	p.InternalSuffixes = clean(p.InternalSuffixes)
	p.SecretKeys = clean(p.SecretKeys)
	p.Allow.IPs = clean(p.Allow.IPs)
	p.Allow.Hosts = clean(p.Allow.Hosts)
	p.Allow.Domains = clean(p.Allow.Domains)
	p.Allow.Users = clean(p.Allow.Users)
	for i, s := range p.InternalSuffixes {
		p.InternalSuffixes[i] = strings.Trim(strings.ToLower(s), ".")
	}
	var short []string
	for _, t := range p.SensitiveTerms {
		if len(t) < 3 {
			short = append(short, t)
		}
	}
	if len(short) > 0 {
		return fmt.Errorf("sensitive terms must be at least 3 characters: %s", strings.Join(short, ", "))
	}
	return nil
}

// ParseTerms splits a comma separated list as typed in the wizard.
func ParseTerms(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Dir is where named profiles are stored.
func Dir() (string, error) {
	if d := os.Getenv("LOGANON_PROFILE_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "log_anonimizer", "profiles"), nil
}

func isPath(s string) bool {
	return strings.HasSuffix(s, ".yaml") || strings.HasSuffix(s, ".yml") || strings.ContainsAny(s, `/\`)
}

// ValidName reports whether s can be used as a profile name.
func ValidName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return !strings.HasPrefix(s, ".")
}

// Path resolves a profile name or file path to a file path.
func Path(nameOrPath string) (string, error) {
	if isPath(nameOrPath) {
		return nameOrPath, nil
	}
	if !ValidName(nameOrPath) {
		return "", fmt.Errorf("invalid profile name %q (use letters, digits, - _ .)", nameOrPath)
	}
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, nameOrPath+".yaml"), nil
}

// Load reads a profile by name or path. "default" without a saved file is
// the built-in profile. Fields missing from the file keep their defaults.
func Load(nameOrPath string) (*Profile, error) {
	path, err := Path(nameOrPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && nameOrPath == "default" {
			return Default(), nil
		}
		return nil, fmt.Errorf("profile %q: %w", nameOrPath, err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", path, err)
	}
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return p, nil
}

// Parse decodes YAML on top of the defaults.
func Parse(data []byte) (*Profile, error) {
	p := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(p); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	return p, nil
}

const header = `# log_anonimizer profile
#
# anonymize:         which kinds of value are replaced with tokens
# sensitive_terms:   organisation names, project codes ... (min 3 chars).
#                    Any word that contains one is replaced as a whole.
#                    A term with a dot (acme.co.th) is also an internal domain.
# internal_suffixes: DNS suffixes that are always internal
# secret_keys:       key=value / URL parameter / header names whose value is secret
# allow:             values that are never anonymized (added to built-in lists)
# encrypt_map:       protect the .anonmap file with a passphrase
`

// Marshal encodes a profile as commented YAML.
func Marshal(p *Profile) ([]byte, error) {
	body, err := yaml.Marshal(p)
	if err != nil {
		return nil, err
	}
	return append([]byte(header), body...), nil
}

// Save writes a profile under its name and returns the path.
func Save(p *Profile, name string) (string, error) {
	path, err := Path(name)
	if err != nil {
		return "", err
	}
	if !isPath(name) {
		p.Name = name
	}
	data, err := Marshal(p)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o600)
}

// List returns the names of saved profiles.
func List() ([]string, error) {
	d, err := Dir()
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	sort.Strings(names)
	return names, nil
}
