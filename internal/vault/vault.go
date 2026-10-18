// Package vault holds the mapping between original values and the tokens
// that replace them. The vault is what makes de-anonymization possible, so it
// is stored encrypted by default (see file.go).
package vault

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Kind is the category of a sensitive value. Each kind has its own token
// prefix and counter.
type Kind string

const (
	IP     Kind = "ip"     // private / internal address
	ExtIP  Kind = "extip"  // public address
	Host   Kind = "host"   // hostname or the first label of an FQDN
	Domain Kind = "domain" // DNS domain or NetBIOS domain
	User   Kind = "user"   // account name, e-mail local part
	Org    Kind = "org"    // a sensitive term itself (organisation name, project code)
	Name   Kind = "name"   // a word that contains a sensitive term
	MAC    Kind = "mac"
	SID    Kind = "sid"    // the domain part of a Windows SID
	Secret Kind = "secret" // passwords, tokens, cookies
	Device Kind = "device" // device IDs (ActiveSync DeviceId, IMEI)
	Card   Kind = "card"   // payment card numbers
	NatID  Kind = "natid"  // national ID numbers (Thai)
	Phone  Kind = "phone"  // phone numbers
)

// Kinds lists every kind in a stable order for reports.
var Kinds = []Kind{IP, ExtIP, Host, Domain, User, Org, Name, MAC, SID, Secret, Device, Card, NatID, Phone}

var prefixes = map[Kind]string{
	IP: "IP", ExtIP: "EXTIP", Host: "HOST", Domain: "DOMAIN", User: "USER", Org: "ORG",
	Name: "NAME", MAC: "MAC", SID: "SID", Secret: "SECRET", Device: "DEVICE",
	Card: "CARD", NatID: "NATID", Phone: "PHONE",
}

// Prefix returns the token prefix for a kind, e.g. "HOST".
func (k Kind) Prefix() string { return prefixes[k] }

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { _, ok := prefixes[k]; return ok }

// Entry is one original value and its token.
type Entry struct {
	Token    string `json:"token"`
	Kind     Kind   `json:"kind"`
	Original string `json:"original"`
}

// Source records one anonymization run that used this vault.
type Source struct {
	Input  string    `json:"input"`
	Output string    `json:"output"`
	SHA256 string    `json:"sha256,omitempty"`
	Time   time.Time `json:"time"`
}

// Vault is the original<->token mapping.
type Vault struct {
	Version  int            `json:"version"`
	Created  time.Time      `json:"created"`
	Updated  time.Time      `json:"updated"`
	Prefix   string         `json:"prefix"`
	Counters map[string]int `json:"counters"`
	Sources  []Source       `json:"sources"`
	Entries  []Entry        `json:"entries"`

	byKey   map[string]int
	byToken map[string]int
	tokenRe *regexp.Regexp
}

// New returns an empty vault.
func New() *Vault {
	now := time.Now().UTC()
	v := &Vault{Version: 1, Created: now, Updated: now, Counters: map[string]int{}}
	v.reindex()
	return v
}

func (v *Vault) reindex() {
	if v.Counters == nil {
		v.Counters = map[string]int{}
	}
	v.byKey = make(map[string]int, len(v.Entries))
	v.byToken = make(map[string]int, len(v.Entries))
	for i, e := range v.Entries {
		v.byKey[Key(e.Kind, e.Original)] = i
		v.byToken[e.Token] = i
	}
	v.tokenRe = nil
}

// Key is the normalised lookup key for a value. Values that differ only in
// letter case (hostnames, accounts, domains) share one token so correlation
// across sources keeps working. Secrets are case-sensitive.
func Key(k Kind, s string) string {
	switch k {
	case Secret:
		return "secret:" + s
	case IP, ExtIP:
		if a, err := netip.ParseAddr(trimIPv4Zeros(s)); err == nil {
			return "ip:" + a.String()
		}
		return "ip:" + strings.ToLower(s)
	case MAC:
		return "mac:" + NormalizeMAC(s)
	case SID:
		return "sid:" + strings.ToLower(s)
	case Device:
		return "device:" + strings.ToLower(s)
	case Card, NatID, Phone:
		// "4111 1111 1111 1111" and "4111-1111-1111-1111" are one card
		return string(k) + ":" + digitsOnly(s)
	default:
		return "name:" + strings.ToLower(s)
	}
}

// digitsOnly keeps the digits and a leading "+" (an international number
// stays apart from the same digits without a country code).
func digitsOnly(s string) string {
	var b strings.Builder
	if strings.HasPrefix(s, "+") {
		b.WriteByte('+')
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// trimIPv4Zeros turns 010.001.002.003 into 10.1.2.3 (netip rejects leading
// zeros).
func trimIPv4Zeros(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return s
	}
	for i, p := range parts {
		if len(p) > 1 {
			p = strings.TrimLeft(p, "0")
			if p == "" {
				p = "0"
			}
		}
		parts[i] = p
	}
	return strings.Join(parts, ".")
}

// NormalizeMAC converts aa-bb-cc-dd-ee-ff, AA:BB:.. and aabb.ccdd.eeff to
// aa:bb:cc:dd:ee:ff.
func NormalizeMAC(s string) string {
	h := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + 32
		}
		return -1
	}, s)
	if len(h) != 12 {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// Token returns the token for a value, assigning a new one if needed. The
// second result is true when a new entry was created.
func (v *Vault) Token(k Kind, original string) (string, bool) {
	key := Key(k, original)
	if i, ok := v.byKey[key]; ok {
		return v.Entries[i].Token, false
	}
	p := k.Prefix()
	v.Counters[p]++
	tok := fmt.Sprintf("%s%s_%04d", v.Prefix, p, v.Counters[p])
	v.Entries = append(v.Entries, Entry{Token: tok, Kind: k, Original: original})
	v.byKey[key] = len(v.Entries) - 1
	v.byToken[tok] = len(v.Entries) - 1
	return tok, true
}

// Find looks a value up without creating an entry.
func (v *Vault) Find(k Kind, original string) (Entry, bool) {
	i, ok := v.byKey[Key(k, original)]
	if !ok {
		return Entry{}, false
	}
	return v.Entries[i], true
}

// Lookup returns the entry for a token.
func (v *Vault) Lookup(token string) (Entry, bool) {
	i, ok := v.byToken[token]
	if !ok {
		return Entry{}, false
	}
	return v.Entries[i], true
}

// Len is the number of entries.
func (v *Vault) Len() int { return len(v.Entries) }

// CountByKind returns the number of entries per kind.
func (v *Vault) CountByKind() map[Kind]int {
	m := map[Kind]int{}
	for _, e := range v.Entries {
		m[e.Kind]++
	}
	return m
}

// AddSource records a run.
func (v *Vault) AddSource(s Source) {
	now := time.Now().UTC()
	if s.Time.IsZero() {
		s.Time = now
	}
	v.Sources = append(v.Sources, s)
	v.Updated = now
}

// TokenPattern matches tokens written with this vault's prefix. Callers must
// still check that the character before a match is not a letter or digit
// (see IsTokenStart); RE2 has no look-behind.
func (v *Vault) TokenPattern() *regexp.Regexp {
	if v.tokenRe == nil {
		v.tokenRe = TokenPattern(v.Prefix)
	}
	return v.tokenRe
}

// TokenPattern builds the token regexp for a prefix.
func TokenPattern(prefix string) *regexp.Regexp {
	alts := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		alts = append(alts, k.Prefix())
	}
	return regexp.MustCompile(regexp.QuoteMeta(prefix) + `(?:` + strings.Join(alts, "|") + `)_[0-9]{4,}`)
}

// Resolve finds the token in a match of TokenPattern. A token can be
// followed directly by digits ("HOST_0001" + "20221010" in a file name), so
// the longest prefix that is a known token wins. It returns the entry and
// the length of the token.
func (v *Vault) Resolve(match string) (Entry, int, bool) {
	us := strings.LastIndexByte(match, '_')
	for end := len(match); end >= us+5; end-- {
		if e, ok := v.Lookup(match[:end]); ok {
			return e, end, true
		}
	}
	return Entry{}, 0, false
}

// IsTokenStart reports whether a token match starting at i is a real token
// boundary: the previous byte is not alphanumeric, or it closes a
// percent-encoded byte such as the "%40" in "USER_0001%40DOMAIN_0002", or
// an escape such as the "\n" in "\r\nHOST_0001".
func IsTokenStart(s string, i int) bool {
	if i == 0 || !isAlnum(s[i-1]) {
		return true
	}
	if i >= 2 && s[i-2] == '\\' && (s[i-1] == 'n' || s[i-1] == 'r' || s[i-1] == 't') {
		return true // after an escape written out, as in "\r\nHOST_0001"
	}
	return i >= 3 && s[i-3] == '%' && isHex(s[i-2]) && isHex(s[i-1])
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
