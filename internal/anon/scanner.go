// Package anon finds sensitive values in log text and replaces them with
// vault tokens.
package anon

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

// part is one piece of a replacement. Kind "" means keep the text.
type part struct {
	text string
	kind vault.Kind
}

// span is a region of the input to replace by its parts.
type span struct {
	start, end int
	parts      []part
	prio       int
}

func lit(s string) part { return part{text: s} }

func allLiteral(ps []part) bool {
	for _, p := range ps {
		if p.kind != "" {
			return false
		}
	}
	return true
}

// Detector priorities, used when two candidate spans have the same length.
const (
	prioContext   = 10 // key=value, XML field, syslog header, CSV column
	prioStructure = 9  // e-mail, SID, DOMAIN\user, profile path
	prioAddress   = 8  // IP, MAC
	prioFQDN      = 6
	prioDict      = 5
	prioTerm      = 4
)

// Scanner detects sensitive values and maps them to tokens.
type Scanner struct {
	p     *profile.Profile
	v     *vault.Vault
	allow *allowSet

	terms      []string // lower case sensitive terms
	termSet    map[string]bool
	termAC     *acMatcher
	termsDirty bool

	suffixes       map[string]bool // internal DNS suffixes (lower case)
	configSuffixes map[string]bool
	knownDomains   map[string]bool

	dict      *acMatcher
	dictKinds []vault.Kind
	dictSize  int // vault length when dict was built

	kv *kvDetector

	// Replaced counts tokens written per kind during apply.
	Replaced map[vault.Kind]int
	// KeptDomains, when not nil, counts domains left in clear text (as
	// registrable names) so the operator can spot their own.
	KeptDomains map[string]int
	// ctxVersion changes whenever a sensitive term or internal domain is
	// added, i.e. when earlier text may now be classified differently.
	ctxVersion int

	// While learning, words that merely contain a sensitive term wait until
	// the end of the pass, so a column or field that says what they are
	// (a hostname, say) names them first.
	deferNames  bool
	pending     []part
	pendingSeen map[string]bool

	// urlMode / uaMode are set while a URL or User-Agent field is scanned.
	urlMode, uaMode bool
	// escaped is set for text with \r\n, \t escapes written out.
	escaped bool
}

// NewScanner creates a scanner for a profile and vault.
func NewScanner(p *profile.Profile, v *vault.Vault) (*Scanner, error) {
	a, err := newAllowSet(p)
	if err != nil {
		return nil, err
	}
	sc := &Scanner{
		p: p, v: v, allow: a,
		termSet:        map[string]bool{},
		suffixes:       map[string]bool{},
		configSuffixes: map[string]bool{},
		knownDomains:   map[string]bool{},
		Replaced:       map[vault.Kind]int{},
	}
	for _, s := range p.InternalSuffixes {
		s = strings.Trim(strings.ToLower(s), ".")
		sc.suffixes[s] = true
		sc.configSuffixes[s] = true
	}
	for _, t := range p.SensitiveTerms {
		sc.addTerm(t)
	}
	for _, e := range v.Entries {
		switch e.Kind {
		case vault.Domain:
			sc.noteDomain(e.Original)
		case vault.Org:
			sc.addTerm(e.Original)
		}
	}
	sc.kv = newKVDetector(p.SecretKeys)
	return sc, nil
}

func (sc *Scanner) addTerm(t string) {
	t = strings.ToLower(strings.TrimSpace(t))
	if len(t) < 3 || sc.termSet[t] || sc.allow.null(t) {
		return
	}
	sc.termSet[t] = true
	sc.terms = append(sc.terms, t)
	sc.termsDirty = true
	sc.ctxVersion++
	if strings.Contains(t, ".") {
		sc.suffixes[strings.Trim(t, ".")] = true
	}
}

// AddTerm registers a sensitive term found in the data (e.g. a LogRhythm
// entity name).
func (sc *Scanner) AddTerm(t string) { sc.addTerm(t) }

// Terms returns the sensitive terms in use.
func (sc *Scanner) Terms() []string { return append([]string(nil), sc.terms...) }

func (sc *Scanner) noteDomain(d string) {
	d = strings.ToLower(d)
	if !sc.knownDomains[d] {
		sc.knownDomains[d] = true
		sc.ctxVersion++
	}
	if strings.Contains(d, ".") && !sc.suffixes[d] {
		sc.suffixes[d] = true
		sc.ctxVersion++
	}
}

func (sc *Scanner) hasTerm(lower string) bool {
	for _, t := range sc.terms {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// internalDomain reports whether d is, or is under, an internal suffix, or
// contains a sensitive term.
func (sc *Scanner) internalDomain(d string) bool {
	d = strings.ToLower(d)
	if sc.hasTerm(d) {
		return true
	}
	for s := d; ; {
		if sc.suffixes[s] {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return false
		}
		s = s[i+1:]
	}
}

func (sc *Scanner) tokenFor(k vault.Kind, text string) string {
	tok, isNew := sc.v.Token(k, text)
	if isNew && k == vault.Domain {
		sc.noteDomain(text)
	}
	return tok
}

// learnParts assigns tokens without rewriting.
func (sc *Scanner) learnParts(ps []part) {
	for _, p := range ps {
		if p.kind == "" {
			continue
		}
		if p.kind == vault.Name && sc.deferNames {
			if _, ok := sc.v.Find(p.kind, p.text); !ok {
				k := vault.Key(p.kind, p.text)
				if sc.pendingSeen == nil {
					sc.pendingSeen = map[string]bool{}
				}
				if !sc.pendingSeen[k] {
					sc.pendingSeen[k] = true
					sc.pending = append(sc.pending, p)
				}
			}
			continue
		}
		sc.tokenFor(p.kind, p.text)
	}
}

// SetLearning switches deferred naming on for a learn pass; switching it off
// assigns tokens to the words that are still unnamed.
func (sc *Scanner) SetLearning(on bool) {
	sc.deferNames = on
	if on {
		return
	}
	for _, p := range sc.pending {
		sc.tokenFor(p.kind, p.text)
	}
	sc.pending, sc.pendingSeen = nil, nil
}

func (sc *Scanner) renderParts(b *strings.Builder, ps []part) {
	for _, p := range ps {
		if p.kind == "" {
			b.WriteString(p.text)
			continue
		}
		tok := sc.tokenFor(p.kind, p.text)
		b.WriteString(tok)
		k := p.kind
		if e, ok := sc.v.Lookup(tok); ok {
			k = e.Kind // count under the kind the token was created with
		}
		sc.Replaced[k]++
	}
}

// Learn records every sensitive value in text.
func (sc *Scanner) Learn(text string) {
	for _, s := range sc.find(text, false) {
		sc.learnParts(s.parts)
	}
}

// Apply returns text with sensitive values replaced by tokens.
func (sc *Scanner) Apply(text string) string {
	spans := sc.find(text, true)
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, s := range spans {
		b.WriteString(text[last:s.start])
		sc.renderParts(&b, s.parts)
		last = s.end
	}
	b.WriteString(text[last:])
	return b.String()
}

// FieldKind is the meaning of a structured field (CSV column, W3C field).
type FieldKind int

const (
	FieldText       FieldKind = iota // free text
	FieldIP                          // an address
	FieldHost                        // a host that identifies the log source: learn its domain
	FieldHostRemote                  // a host that may be external: only anonymize if internal
	FieldUser
	FieldDomain       // a domain of the organisation: learn it
	FieldDomainRemote // a domain that may be external
	FieldMAC
	FieldOrg       // organisation / entity name: becomes a sensitive term
	FieldSecret    // the whole value is a secret (cookies)
	FieldURL       // a URL or request: paths in it are not profile folders
	FieldUserAgent // a User-Agent: only addresses and known values are replaced
)

func (sc *Scanner) fieldParts(value string, k FieldKind) []part {
	v := strings.TrimSpace(value)
	if v == "" || sc.allow.null(v) {
		return nil
	}
	lead, trail := value[:strings.Index(value, v)], value[strings.Index(value, v)+len(v):]
	var ps []part
	switch k {
	case FieldIP:
		if ad, ok := parseIP(v); ok {
			ps = sc.ipParts(v, ad)
		}
	case FieldHost, FieldHostRemote:
		ps = sc.hostParts(v, k == FieldHost)
	case FieldUser:
		if !strings.ContainsAny(v, " \t") {
			ps = sc.userParts(v)
		}
	case FieldDomain, FieldDomainRemote:
		ps = sc.domainParts(v, k == FieldDomain)
	case FieldMAC:
		ps = sc.macParts(v)
	case FieldOrg:
		if sc.allow.null(v) || strings.EqualFold(v, "Global Entity") || strings.EqualFold(v, "Primary Site") {
			return nil
		}
		sc.addTerm(v)
		ps = []part{{text: v, kind: vault.Org}}
	case FieldSecret:
		if sc.p.Anonymize.Secrets {
			ps = []part{{text: v, kind: vault.Secret}}
		}
	}
	if ps == nil {
		return nil
	}
	out := make([]part, 0, len(ps)+2)
	if lead != "" {
		out = append(out, lit(lead))
	}
	out = append(out, ps...)
	if trail != "" {
		out = append(out, lit(trail))
	}
	return out
}

// setMode switches the URL / User-Agent rules for one field.
func (sc *Scanner) setMode(k FieldKind) func() {
	sc.urlMode, sc.uaMode = k == FieldURL, k == FieldUserAgent
	return func() { sc.urlMode, sc.uaMode = false, false }
}

func structured(k FieldKind) bool { return k != FieldText && k != FieldURL && k != FieldUserAgent }

// LearnField learns a structured field.
func (sc *Scanner) LearnField(value string, k FieldKind) {
	defer sc.setMode(k)()
	if structured(k) {
		if ps := sc.fieldParts(value, k); ps != nil {
			sc.learnParts(ps)
			if !allLiteral(ps) {
				return
			}
		}
	}
	sc.Learn(value)
}

// ApplyField anonymizes a structured field. A value the column kind cannot
// explain falls back to free-text detection.
func (sc *Scanner) ApplyField(value string, k FieldKind) string {
	defer sc.setMode(k)()
	if structured(k) {
		if ps := sc.fieldParts(value, k); ps != nil && !allLiteral(ps) {
			var b strings.Builder
			sc.renderParts(&b, ps)
			return b.String()
		}
	}
	return sc.Apply(value)
}

// find runs all detectors and returns non-overlapping spans in order.
func (sc *Scanner) find(text string, useDict bool) []span {
	if len(text) == 0 {
		return nil
	}
	sc.escaped = strings.Contains(text, `\r\n`) || strings.Count(text, `\n`)+strings.Count(text, `\t`) >= 2
	var c []span
	if !sc.uaMode {
		c = sc.kv.detect(sc, text, c)
		c = sc.detectXML(text, c)
		c = sc.detectSyslog(text, c)
		c = sc.detectAuthUser(text, c)
		c = sc.detectEmail(text, c)
		c = sc.detectSID(text, c)
		c = sc.detectDomainUser(text, c)
		c = sc.detectUNC(text, c)
		c = sc.detectUserPath(text, c)
	}
	c = sc.detectIPv4(text, c)
	c = sc.detectIPv6(text, c)
	c = sc.detectMAC(text, c)
	c = sc.detectFQDN(text, c)
	c = sc.detectTerms(text, c)
	if useDict {
		c = sc.detectDict(text, c)
	}
	return resolve(c)
}

// resolve keeps the longest candidates, then the highest priority, and drops
// candidates that overlap one already kept.
func resolve(c []span) []span {
	n := 0
	for _, s := range c {
		if s.end > s.start && !allLiteral(s.parts) {
			c[n] = s
			n++
		}
	}
	c = c[:n]
	if len(c) <= 1 {
		return c
	}
	sort.SliceStable(c, func(i, j int) bool {
		li, lj := c[i].end-c[i].start, c[j].end-c[j].start
		if li != lj {
			return li > lj
		}
		if c[i].prio != c[j].prio {
			return c[i].prio > c[j].prio
		}
		return c[i].start < c[j].start
	})
	kept := make([]span, 0, len(c))
	for _, s := range c {
		ok := true
		for _, k := range kept {
			if s.start < k.end && k.start < s.end {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, s)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].start < kept[j].start })
	return kept
}

// --- classification of a value whose meaning is known --------------------

func parseIP(s string) (netip.Addr, bool) {
	if strings.Count(s, ".") == 3 && !strings.Contains(s, ":") {
		return parseIPv4(s)
	}
	if strings.Contains(s, ":") {
		ad, err := netip.ParseAddr(s)
		return ad, err == nil
	}
	return netip.Addr{}, false
}

// parseIPv4 accepts leading zeros, which netip rejects.
func parseIPv4(s string) (netip.Addr, bool) {
	var b [4]byte
	n, val, digits := 0, 0, 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if digits == 0 || n > 3 || val > 255 {
				return netip.Addr{}, false
			}
			b[n] = byte(val)
			n, val, digits = n+1, 0, 0
			continue
		}
		c := s[i]
		if c < '0' || c > '9' || digits == 3 {
			return netip.Addr{}, false
		}
		val = val*10 + int(c-'0')
		digits++
	}
	if n != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(b), true
}

func isPrivate(ad netip.Addr) bool {
	if ad.Is4In6() {
		ad = ad.Unmap()
	}
	if ad.IsPrivate() || ad.IsLoopback() || ad.IsLinkLocalUnicast() || ad.IsUnspecified() {
		return true
	}
	if ad.Is4() {
		b := ad.As4()
		if b[0] == 100 && b[1]&0xc0 == 64 { // 100.64.0.0/10 carrier-grade NAT
			return true
		}
	}
	return false
}

func (sc *Scanner) ipParts(text string, ad netip.Addr) []part {
	if sc.allow.ip(ad) {
		return []part{lit(text)}
	}
	if isPrivate(ad) {
		if !sc.p.Anonymize.InternalIP {
			return []part{lit(text)}
		}
		return []part{{text: text, kind: vault.IP}}
	}
	if !sc.p.Anonymize.PublicIP {
		return []part{lit(text)}
	}
	return []part{{text: text, kind: vault.ExtIP}}
}

func isHostChar(c byte) bool { return isAlnum(c) || c == '-' || c == '_' || c == '.' }

func hostShaped(v string) bool {
	if v == "" || v[0] == '.' || v[0] == '-' || v[len(v)-1] == '.' || v[len(v)-1] == '-' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !isHostChar(v[i]) {
			return false
		}
	}
	return true
}

func isNumeric(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= '0' && c <= '9' || c == '.' || c == '-' || c == '+' || c == ',') {
			return false
		}
	}
	return true
}

func allDigitLabels(v string) bool {
	for _, l := range strings.Split(v, ".") {
		if l == "" {
			return false
		}
		for i := 0; i < len(l); i++ {
			if l[i] < '0' || l[i] > '9' {
				return false
			}
		}
	}
	return true
}

// hostPart is a single host label.
func (sc *Scanner) hostPart(label string) part {
	ll := strings.ToLower(label)
	if !sc.p.Anonymize.Hostname && !sc.hasTerm(ll) {
		return lit(label)
	}
	if !sc.hasTerm(ll) && (sc.allow.host(ll) || isNumeric(label)) {
		return lit(label)
	}
	return part{text: label, kind: vault.Host}
}

// hostParts classifies a hostname, FQDN or address. learn means the value
// identifies a machine of the organisation, so the domain of an FQDN is
// recorded as internal.
func (sc *Scanner) hostParts(v string, learn bool) []part {
	if ad, ok := parseIP(v); ok {
		return sc.ipParts(v, ad)
	}
	if !hostShaped(v) || isNumeric(v) {
		return nil
	}
	lv := strings.ToLower(v)
	if sc.allow.host(lv) && !sc.hasTerm(lv) {
		return []part{lit(v)}
	}
	i := strings.IndexByte(v, '.')
	if i < 0 {
		return []part{sc.hostPart(v)}
	}
	if allDigitLabels(v) {
		return nil
	}
	if sc.knownDomains[lv] || sc.configTLDDomain(lv) {
		return sc.domainParts(v, learn)
	}
	label, rest := v[:i], v[i+1:]
	lrest := strings.ToLower(rest)
	if sc.allow.domain(lrest) && !sc.hasTerm(lv) {
		return []part{lit(v)}
	}
	if !sc.internalDomain(lrest) && !(learn && hasLetterTLD(lrest)) {
		return nil
	}
	dp := sc.domainParts(rest, true)
	if dp == nil {
		dp = []part{lit(rest)}
	}
	lp := sc.hostPart(label)
	if sc.allow.labels[strings.ToLower(label)] {
		lp = lit(label)
	}
	return append([]part{lp, lit(".")}, dp...)
}

// configTLDDomain reports "corp.local" style names: one label under a
// configured single-label suffix, which is a domain rather than a host.
func (sc *Scanner) configTLDDomain(lv string) bool {
	i := strings.IndexByte(lv, '.')
	return i > 0 && sc.configSuffixes[lv[i+1:]] && !strings.Contains(lv[i+1:], ".")
}

func hasLetterTLD(d string) bool {
	i := strings.LastIndexByte(d, '.')
	tld := d[i+1:]
	if len(tld) < 2 {
		return false
	}
	for j := 0; j < len(tld); j++ {
		if !(tld[j] >= 'a' && tld[j] <= 'z' || tld[j] >= 'A' && tld[j] <= 'Z') {
			return false
		}
	}
	return true
}

// domainParts classifies a DNS or NetBIOS domain. learn means the domain is
// known to belong to the organisation.
func (sc *Scanner) domainParts(v string, learn bool) []part {
	if !hostShaped(v) || isNumeric(v) {
		return nil
	}
	lv := strings.ToLower(v)
	if sc.allow.null(lv) || sc.allow.host(lv) && !sc.hasTerm(lv) {
		return []part{lit(v)}
	}
	if strings.Contains(lv, ".") {
		if sc.allow.domain(lv) && !sc.hasTerm(lv) {
			return []part{lit(v)}
		}
		if !learn && !sc.internalDomain(lv) {
			return nil
		}
	}
	if !sc.p.Anonymize.Domain && !sc.hasTerm(lv) || !strings.Contains(lv, ".") && sc.allow.common[lv] && !sc.hasTerm(lv) {
		return []part{lit(v)}
	}
	return []part{{text: v, kind: vault.Domain}}
}

// userParts classifies an account: user, DOMAIN\user, user@domain (also
// percent-encoded), or a machine account HOST$.
func (sc *Scanner) userParts(v string) []part {
	if sc.allow.null(v) {
		return nil
	}
	if ad, ok := parseIP(v); ok {
		return sc.ipParts(v, ad)
	}
	if m := reSIDWhole.FindStringSubmatchIndex(v); m != nil { // "S-1-5-21-...-1105" in a user list
		if !sc.p.Anonymize.SID {
			return []part{lit(v)}
		}
		return []part{lit(v[:m[2]]), {text: v[m[2]:m[3]], kind: vault.SID}, lit(v[m[3]:])}
	}
	if strings.HasPrefix(strings.ToUpper(v), "S-1-") {
		return []part{lit(v)} // a well-known SID such as S-1-5-18
	}
	if i := strings.IndexByte(v, '\\'); i > 0 {
		j := i
		for j < len(v) && v[j] == '\\' {
			j++
		}
		if j < len(v) {
			return sc.domainAccountParts(v[:i], v[i:j], v[j:])
		}
	}
	for _, sep := range []string{"%5C", "%5c"} {
		if i := strings.Index(v, sep); i > 0 && i+len(sep) < len(v) {
			return sc.domainAccountParts(v[:i], sep, v[i+len(sep):])
		}
	}
	for _, sep := range []string{"@", "%40"} {
		if i := strings.LastIndex(v, sep); i > 0 && i+len(sep) < len(v) {
			return sc.emailParts(v[:i], sep, v[i+len(sep):], true)
		}
	}
	return sc.accountParts(v)
}

func (sc *Scanner) domainAccountParts(dom, sep, usr string) []part {
	if sc.allow.netbiosBefore(strings.ToLower(dom)) {
		return []part{lit(dom + sep + usr)}
	}
	dp := sc.domainParts(dom, true)
	if dp == nil {
		dp = []part{lit(dom)}
	}
	up := sc.userParts(usr) // "corp%5Cjdoe%40acme.example": the user part is an e-mail
	if up == nil {
		up = []part{lit(usr)}
	}
	return append(append(dp, lit(sep)), up...)
}

// accountParts classifies a bare account name.
func (sc *Scanner) accountParts(u string) []part {
	lu := strings.ToLower(u)
	if strings.HasSuffix(u, "$") && len(u) > 1 { // machine account
		return []part{sc.hostPart(u[:len(u)-1]), lit("$")}
	}
	if isNumeric(u) || isGUID(u) || (!sc.hasTerm(lu) && sc.allow.user(lu)) || !sc.p.Anonymize.User && !sc.hasTerm(lu) {
		return []part{lit(u)}
	}
	return []part{{text: u, kind: vault.User}}
}

var reGUID = regexp.MustCompile(`^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`)

// isGUID: object and mailbox GUIDs identify nobody outside the organisation.
func isGUID(s string) bool { return len(s) >= 36 && reGUID.MatchString(s) }

var reSIDWhole = regexp.MustCompile(`(?i)^S-1-5-21-(\d+-\d+-\d+)(?:-\d+)?$`)

// emailParts classifies user@domain. learn records the domain as internal;
// it is false inside URLs, where addresses are often attacker input.
func (sc *Scanner) emailParts(local, sep, domain string, learn bool) []part {
	ld := strings.ToLower(domain)
	lp := sc.accountParts(local)
	if ad, ok := parseIP(local); ok {
		// "http://203.0.113.9@evil.example" in an SSRF probe: not an account,
		// so the domain is kept unless it is internal (an IOC)
		lp, learn = sc.ipParts(local, ad), false
	}
	var dp []part
	switch {
	case !hostShaped(domain) || !hasLetterTLD(ld):
		return nil
	case sc.allow.domain(ld) && !sc.hasTerm(ld):
		dp = []part{lit(domain)}
	default:
		dp = sc.domainParts(domain, learn)
		if dp == nil {
			dp = []part{lit(domain)}
		}
	}
	return append(append(lp, lit(sep)), dp...)
}

func (sc *Scanner) macParts(v string) []part {
	n := vault.NormalizeMAC(v)
	if len(n) != 17 {
		return nil
	}
	if n == "ff:ff:ff:ff:ff:ff" || n == "00:00:00:00:00:00" || strings.HasPrefix(n, "01:00:5e") || strings.HasPrefix(n, "33:33") {
		return []part{lit(v)}
	}
	if !sc.p.Anonymize.MAC {
		return []part{lit(v)}
	}
	return []part{{text: v, kind: vault.MAC}}
}
