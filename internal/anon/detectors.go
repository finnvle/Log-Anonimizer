package anon

import (
	"net/netip"
	"regexp"
	"strings"

	"log_anonimizer/internal/vault"
)

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// --- IPv4 -------------------------------------------------------------------

var reIPv4 = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

func (sc *Scanner) detectIPv4(t string, out []span) []span {
	if strings.IndexByte(t, '.') < 0 {
		return out
	}
	for _, m := range reIPv4.FindAllStringIndex(t, -1) {
		s, e := m[0], m[1]
		// the match may start inside a percent-encoded byte: "%2210.1.2.3"
		// matches "210.1.2.3"
		if s >= 2 && t[s-2] == '%' && isHex(t[s-1]) && isDigit(t[s+1]) {
			s++
		} else if s >= 1 && t[s-1] == '%' && isHex(t[s+1]) && isDigit(t[s+2]) {
			s += 2
		}
		if !ipBoundary(t, s, e) || sc.allow.isVersion(t, s, e) {
			continue
		}
		ad, ok := parseIPv4(t[s:e])
		if !ok {
			continue
		}
		out = append(out, span{s, e, sc.ipParts(t[s:e], ad), prioAddress})
	}
	return out
}

// isVersion reports whether the dotted quad t[s:e] is a version number,
// not an address:
//   - after a product and a slash: "Chrome/120.0.0.0", "Chrome+/123.0.0.0",
//     or a capitalised word when the number has a zero part ("SUSE/1.5.0.6");
//     "GET /IP/198.51.100.77" stays an address
//   - after a version word or product: "rv:1.8.0.6", "Version=4.0.0.0",
//     "Firefox+1.5.0.11", "v4.0", also with %3A / %3D / %20
//   - a .NET GAC folder: "v4.0_4.0.0.0__b77a5c561934e089"
func (a *allowSet) isVersion(t string, s, e int) bool {
	if strings.HasPrefix(t[e:], "__") {
		return true
	}
	if s == 0 {
		return false
	}
	i := s
	slash := false
	switch {
	case t[i-1] == '/':
		slash = true
		i--
		for i > 0 && (t[i-1] == '+' || t[i-1] == ' ') {
			i--
		}
	case strings.IndexByte(" :=+", t[i-1]) >= 0:
		i--
	case i >= 3 && t[i-3] == '%' && isHex(t[i-2]) && isHex(t[i-1]):
		i -= 3
	}
	end := i
	for i > 0 && (isAlnum(t[i-1]) || t[i-1] == '-' || t[i-1] == '_') {
		i--
	}
	if i > 0 && t[i-1] == '%' && end-i > 2 && isHex(t[i]) && isHex(t[i+1]) {
		i += 2 // "%20Version": the word starts after the encoded byte
	}
	w := t[i:end]
	if w == "" {
		return false
	}
	lw := strings.ToLower(w)
	if a.products[lw] || end == s && versionWords[lw] {
		return true
	}
	if !slash && versionWords[lw] {
		return true
	}
	if !slash || len(w) < 3 || w[0] < 'A' || w[0] > 'Z' || !strings.Contains(t[s:e]+".", ".0.") {
		return false
	}
	for j := 0; j < len(w); j++ {
		if !(w[j] >= 'a' && w[j] <= 'z' || w[j] >= 'A' && w[j] <= 'Z') {
			return false
		}
	}
	return true
}

var versionWords = map[string]bool{"rv": true, "version": true, "ver": true, "v": true, "build": true, "release": true, "firmware": true}

// ipBoundary: no digit right before or after, no letter before (letters
// after are fine, as in the probe "http://10.1.2.3admin/"), a digit before may close a
// percent-encoded byte ("%2210.1.2.3%22"), and a 5th dotted part must be a
// file extension ("10.1.2.3.7z"), not a number ("1.2.3.4.5").
func ipBoundary(t string, s, e int) bool {
	if s > 0 {
		c := t[s-1]
		if isDigit(c) && !(s >= 3 && t[s-3] == '%' && isHex(t[s-2])) {
			return false
		}
		if isLetter(c) && !(s >= 3 && t[s-3] == '%' && isHex(t[s-2])) {
			return false // "UCWEB7.0.2.37", "v1.2.3.4": a version glued to a word
		}
		if c == '.' && s >= 2 && isDigit(t[s-2]) {
			return false
		}
	}
	if e < len(t) {
		if isDigit(t[e]) {
			return false
		}
		if t[e] == '.' && e+1 < len(t) && isDigit(t[e+1]) && !extensionAt(t, e+1) {
			return false
		}
	}
	return true
}

// extensionAt reports a file extension such as "7z" or "bak" at i, as in
// "/10.1.2.3.7z": a short alphanumeric run that contains a letter.
func extensionAt(t string, i int) bool {
	j, letter := i, false
	for j < len(t) && isAlnum(t[j]) {
		if !isDigit(t[j]) {
			letter = true
		}
		j++
	}
	return letter && j-i <= 5
}

// --- IPv6 -------------------------------------------------------------------

var reIPv6 = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)

func (sc *Scanner) detectIPv6(t string, out []span) []span {
	if !strings.Contains(t, "::") && strings.Count(t, ":") < 7 {
		return out
	}
	for _, m := range reIPv6.FindAllStringIndex(t, -1) {
		s, e := m[0], m[1]
		for e > s && t[e-1] == '.' {
			e--
		}
		if s > 0 && (isAlnum(t[s-1]) || t[s-1] == '_') || e < len(t) && (isAlnum(t[e]) || t[e] == '_') {
			continue
		}
		cand := t[s:e]
		ad, err := netip.ParseAddr(cand)
		if err != nil && strings.HasSuffix(cand, ":") && !strings.HasSuffix(cand, "::") {
			e--
			cand = t[s:e]
			ad, err = netip.ParseAddr(cand)
		}
		if err != nil || !ad.Is6() {
			continue
		}
		out = append(out, span{s, e, sc.ipParts(cand, ad), prioAddress})
	}
	return out
}

// --- MAC --------------------------------------------------------------------

var (
	reMAC      = regexp.MustCompile(`[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5,}`)
	reMACCisco = regexp.MustCompile(`[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}`)
)

// hasMACShape is a cheap test for "hh:hh:hh" or "hh-hh-hh".
func hasMACShape(t string) bool {
	for i := 0; i+7 < len(t); i++ {
		c := t[i+2]
		if (c == ':' || c == '-') && t[i+5] == c && isHex(t[i]) && isHex(t[i+1]) && isHex(t[i+3]) && isHex(t[i+4]) && isHex(t[i+6]) && isHex(t[i+7]) {
			return true
		}
	}
	return false
}

func (sc *Scanner) detectMAC(t string, out []span) []span {
	if hasMACShape(t) {
		for _, m := range reMAC.FindAllStringIndex(t, -1) {
			s, e := m[0], m[1]
			if s > 0 && (isAlnum(t[s-1]) || t[s-1] == ':' || t[s-1] == '-') || e < len(t) && isAlnum(t[e]) {
				continue
			}
			v := t[s:e]
			sep := v[2]
			if strings.Count(v, string(sep)) != (len(v)-2)/3 {
				continue // mixed separators
			}
			switch (len(v) + 1) / 3 {
			case 6:
				out = append(out, span{s, e, sc.macParts(v), prioAddress})
			case 14:
				// iptables MAC= field: destination MAC, source MAC, ethertype
				if sep == ':' {
					ps := append(sc.macParts(v[0:17]), lit(":"))
					ps = append(ps, sc.macParts(v[18:35])...)
					ps = append(ps, lit(v[35:]))
					out = append(out, span{s, e, ps, prioAddress})
				}
			}
		}
	}
	if strings.Count(t, ".") >= 2 {
		for _, m := range reMACCisco.FindAllStringIndex(t, -1) {
			s, e := m[0], m[1]
			if s > 0 && (isAlnum(t[s-1]) || t[s-1] == '.') || e < len(t) && (isAlnum(t[e]) || t[e] == '.') {
				continue
			}
			if allDigitLabels(t[s:e]) {
				continue
			}
			out = append(out, span{s, e, sc.macParts(t[s:e]), prioAddress})
		}
	}
	return out
}

// --- SID --------------------------------------------------------------------

var reSID = regexp.MustCompile(`(?i)S-1-5-21-(\d+-\d+-\d+)`)

func (sc *Scanner) detectSID(t string, out []span) []span {
	if !sc.p.Anonymize.SID || !strings.Contains(t, "-21-") {
		return out
	}
	for _, m := range reSID.FindAllStringSubmatchIndex(t, -1) {
		s, e := m[0], m[1]
		if s > 0 && (isAlnum(t[s-1]) || t[s-1] == '-') {
			continue
		}
		out = append(out, span{s, e, []part{lit(t[s:m[2]]), {text: t[m[2]:m[3]], kind: vault.SID}}, prioStructure})
	}
	return out
}

// --- e-mail -----------------------------------------------------------------

var reEmail = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._+'-]*(@|%40)([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)`)

func (sc *Scanner) detectEmail(t string, out []span) []span {
	if strings.IndexByte(t, '@') < 0 && !strings.Contains(t, "%40") {
		return out
	}
	for _, m := range reEmail.FindAllStringSubmatchIndex(t, -1) {
		s, e := m[0], m[1]
		if e < len(t) && (isAlnum(t[e]) || t[e] == '-') {
			continue
		}
		// keep a percent-encoded byte before the local part ("%3Auser%40...")
		// out of the account name
		if s > 0 && t[s-1] == '%' && m[2]-s > 2 && isHex(t[s]) && isHex(t[s+1]) {
			s += 2
		}
		local, sep, dom := t[s:m[2]], t[m[2]:m[3]], t[m[4]:m[5]]
		if botContact(t, s, local) {
			continue // "(compatible; ExampleBot/1.0; +bot@example.com)"
		}
		if ps := sc.emailParts(local, sep, dom); ps != nil {
			out = append(out, span{s, e, ps, prioStructure})
		}
	}
	return out
}

// botContact reports the contact address of a crawler in a User-Agent.
func botContact(t string, s int, local string) bool {
	ll := strings.ToLower(local)
	for _, w := range []string{"bot", "crawl", "spider", "search", "scan"} {
		if strings.Contains(ll, w) {
			return true
		}
	}
	lo := s - 160
	if lo < 0 {
		lo = 0
	}
	return strings.Contains(strings.ToLower(t[lo:s]), "compatible")
}

// --- DOMAIN\user ------------------------------------------------------------

var reDomainUser = regexp.MustCompile(`([A-Za-z0-9][A-Za-z0-9_-]{0,14})(\\\\|\\|%5[Cc])([A-Za-z0-9][A-Za-z0-9._$-]{0,63})`)

func isSegmentStop(c byte) bool {
	switch c {
	case '=', ',', ';', '|', '"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', '\t', '\n', '\r':
		return true
	}
	return false
}

// pathContinues reports a following word that holds a backslash, which
// means the match was part of a path with spaces.
func pathContinues(t string, i int) bool {
	if i >= len(t) || t[i] != ' ' {
		return false
	}
	for j := i + 1; j < len(t) && j-i < 64; j++ {
		switch c := t[j]; {
		case c == '\\':
			return true
		case c == ' ' || isSegmentStop(c):
			return false
		}
	}
	return false
}

// pathBefore reports that the word before the match follows a backslash,
// as in "settings\local policies\user rights".
func pathBefore(t string, i int) bool {
	if i == 0 || t[i-1] != ' ' {
		return false
	}
	j := i - 1
	for j > 0 && t[j-1] != ' ' && t[j-1] != '\\' && !isSegmentStop(t[j-1]) {
		j--
	}
	return j > 0 && t[j-1] == '\\'
}

func (sc *Scanner) detectDomainUser(t string, out []span) []span {
	if strings.IndexByte(t, '\\') < 0 && !strings.Contains(t, "%5C") && !strings.Contains(t, "%5c") {
		return out
	}
	jsonEscaped := strings.Contains(t, `\"`)
	for _, m := range reDomainUser.FindAllStringSubmatchIndex(t, -1) {
		ds, de, ss, se, us, ue := m[2], m[3], m[4], m[5], m[6], m[7]
		if ds > 0 {
			c := t[ds-1]
			if isAlnum(c) || strings.IndexByte(`_-.\/:$%@`, c) >= 0 {
				continue
			}
		}
		if ue < len(t) && (t[ue] == '\\' || t[ue] == '/') {
			continue // a path, not an account
		}
		if pathContinues(t, ue) || pathBefore(t, ds) {
			continue // "computer configuration\windows settings\security settings"
		}
		sep := t[ss:se]
		if jsonEscaped && sep == `\` && strings.IndexByte(`nrtbfu"`, t[us]) >= 0 {
			continue // JSON escape such as \n
		}
		// path context: look back to the start of this value
		i := ds
		for i > 0 && !isSegmentStop(t[i-1]) {
			i--
		}
		if seg := t[i:ds]; strings.Contains(seg, `\`) || strings.Contains(seg, ":/") {
			continue // inside a path such as C:\x\y or Microsoft\Windows\Some Folder\Task
		}
		lo := ds - 20
		if lo < 0 {
			lo = 0
		}
		if sc.allow.netbiosBefore(strings.ToLower(t[lo:de])) {
			continue
		}
		dp := sc.domainParts(t[ds:de], true)
		if dp == nil {
			dp = []part{lit(t[ds:de])}
		}
		ps := append(append(dp, lit(sep)), sc.accountParts(t[us:ue])...)
		out = append(out, span{ds, ue, ps, prioStructure})
	}
	return out
}

// --- UNC paths: \\SERVER\share ----------------------------------------------

var reUNC = regexp.MustCompile(`\\\\([A-Za-z0-9][A-Za-z0-9_.-]{0,62})\\`)

func (sc *Scanner) detectUNC(t string, out []span) []span {
	if !strings.Contains(t, `\\`) {
		return out
	}
	for _, m := range reUNC.FindAllStringSubmatchIndex(t, -1) {
		if m[0] > 0 && (t[m[0]-1] == '\\' || t[m[0]-1] == ':') {
			continue // longer run of backslashes, or an escaped path "C:\\Users\\"
		}
		if ps := sc.hostParts(t[m[2]:m[3]], true); ps != nil {
			out = append(out, span{m[2], m[3], ps, prioStructure})
		}
	}
	return out
}

// --- profile paths: C:\Users\name, /home/name, /Users/name ------------------

var reUserPath = regexp.MustCompile(`(?i)(?:[A-Za-z]:)?(?:^|\\\\|\\|/)(?:Users|home|Documents and Settings)(?:\\\\|\\|/)`)

func isPathStop(c byte) bool {
	switch c {
	case '"', '\'', '<', '>', '|', '\t', '\r', '\n', ',', ';', '=', ':', '*', '?':
		return true
	}
	return false
}

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "HEAD": true, "PUT": true, "DELETE": true, "OPTIONS": true,
	"PATCH": true, "PROPFIND": true, "CONNECT": true, "TRACE": true,
}

// urlContext reports a URL: the token holds "://", or the previous word is
// an HTTP method.
func urlContext(t string, s int) bool {
	i := s
	for i > 0 && t[i-1] != ' ' && t[i-1] != '\t' && t[i-1] != '"' {
		i--
	}
	if strings.Contains(t[i:s], "://") {
		return true
	}
	if i == 0 {
		return false
	}
	j := i - 1
	for j > 0 && t[j-1] != ' ' && t[j-1] != '"' {
		j--
	}
	return httpMethods[t[j:i-1]]
}

func (sc *Scanner) detectUserPath(t string, out []span) []span {
	lt := strings.ToLower(t)
	if !strings.Contains(lt, "users") && !strings.Contains(lt, "home") && !strings.Contains(lt, "documents and settings") {
		return out
	}
	for _, m := range reUserPath.FindAllStringIndex(t, -1) {
		s, e := m[0], m[1]
		if s > 0 && t[s+1] == ':' && isAlnum(t[s-1]) {
			continue // "XC:\Users" is not a drive
		}
		if t[s] == '/' && (sc.urlMode || urlContext(t, s)) {
			continue // "GET /home/ubuntu/.config" is a URL an attacker probed
		}
		// the name runs to the next separator; without one, to the next space
		end := -1
		for j := e; j < len(t) && j-e <= 64; j++ {
			c := t[j]
			if c == '\\' || c == '/' {
				end = j
				break
			}
			if isPathStop(c) {
				break
			}
		}
		if end < 0 {
			end = e
			for end < len(t) && t[end] != ' ' && t[end] != '\\' && t[end] != '/' && !isPathStop(t[end]) {
				end++
			}
		}
		name := t[e:end]
		if name == "" || strings.TrimSpace(name) != name {
			continue
		}
		ps := sc.accountParts(name)
		out = append(out, span{e, end, ps, prioStructure})
	}
	return out
}

// --- key=value, key: value, URL parameters, JSON ----------------------------

type kvKind int

const (
	kvHostLearn kvKind = iota
	kvHost
	kvUser
	kvUserList
	kvDomain
	kvSecret
	kvSecretRest // value runs to end of line (Cookie:, Authorization:)
	kvDevice
)

var kvKeys = map[string]kvKind{
	"hostname": kvHostLearn, "host_name": kvHostLearn, "host name": kvHostLearn,
	"computer": kvHostLearn, "computername": kvHostLearn, "computer_name": kvHostLearn, "computer name": kvHostLearn,
	"workstation": kvHostLearn, "workstationname": kvHostLearn, "workstation_name": kvHostLearn,
	"workstation name": kvHostLearn, "source workstation": kvHostLearn,
	"machine": kvHostLearn, "machinename": kvHostLearn, "machine_name": kvHostLearn, "machine name": kvHostLearn,
	"devicename": kvHostLearn, "device_name": kvHostLearn, "device name": kvHostLearn, "dvchost": kvHostLearn,
	"shost": kvHostLearn, "src_host": kvHostLearn, "srchost": kvHostLearn, "origin": kvHostLearn,
	"client name": kvHostLearn, "clientname": kvHostLearn, "client_name": kvHostLearn,
	"dnshostname": kvHostLearn, "sourcehostname": kvHostLearn, "source host": kvHostLearn,
	"host": kvHost, "dhost": kvHost, "dst_host": kvHost, "dsthost": kvHost, "destination host": kvHost,
	"servername": kvHost, "server_name": kvHost, "server name": kvHost, "fqdn": kvHost,
	"user": kvUser, "username": kvUser, "user_name": kvUser, "user name": kvUser, "usr": kvUser,
	"suser": kvUser, "duser": kvUser, "account": kvUser, "accountname": kvUser, "account_name": kvUser,
	"account name": kvUser, "acct": kvUser, "logon account": kvUser, "logonuser": kvUser,
	"targetusername": kvUser, "subjectusername": kvUser, "target user name": kvUser,
	"login": kvUser, "loginname": kvUser, "login_name": kvUser, "principal": kvUser, "upn": kvUser,
	"samaccountname": kvUser, "src_user": kvUser, "dst_user": kvUser, "srcuser": kvUser, "dstuser": kvUser,
	"logonusers": kvUserList, "processusers": kvUserList, "netsessionusers": kvUserList, "users": kvUserList,
	"domain": kvDomain, "domainname": kvDomain, "domain_name": kvDomain, "account domain": kvDomain,
	"user domain": kvDomain, "logon domain": kvDomain, "dnsdomain": kvDomain,
	"targetdomainname": kvDomain, "subjectdomainname": kvDomain,
	"deviceid": kvDevice, "device_id": kvDevice, "devid": kvDevice, "imei": kvDevice,
}

var restKeys = map[string]bool{"authorization": true, "cookie": true, "set-cookie": true}

type kvDetector struct {
	keys map[string]kvKind
}

func newKVDetector(secretKeys []string) *kvDetector {
	keys := map[string]kvKind{}
	for k, v := range kvKeys {
		keys[k] = v
	}
	for _, k := range secretKeys {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if restKeys[k] {
			keys[k] = kvSecretRest
		} else {
			keys[k] = kvSecret
		}
	}
	return &kvDetector{keys: keys}
}

func isKeyChar(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == '-' }

// lookupKey finds the longest known key of up to three words that ends at
// ke ("Account Name", "user").
func (d *kvDetector) lookupKey(t string, ke int) (kvKind, bool) {
	var best kvKind
	found := false
	end := ke
	for words := 0; words < 3; words++ {
		s := end
		for s > 0 && isKeyChar(t[s-1]) {
			s--
		}
		if s == end {
			break
		}
		if s == 0 || t[s-1] != '<' {
			key := t[s:ke]
			if words > 0 {
				key = strings.Join(strings.Fields(key), " ")
			}
			if k, ok := d.keys[strings.ToLower(key)]; ok {
				best, found = k, true
			}
		}
		j := s
		for j > 0 && (t[j-1] == ' ' || t[j-1] == '\t') {
			j--
		}
		if j == s || j == 0 {
			break
		}
		end = j
	}
	return best, found
}

// detect finds key=value, "key: value" (whitespace after the colon, so
// "<USER:NOTE>" and "12:30" are not pairs) and JSON "key":"value".
func (d *kvDetector) detect(sc *Scanner, t string, out []span) []span {
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c != '=' && c != ':' {
			continue
		}
		vs := i + 1
		if c == ':' && !(vs < len(t) && (t[vs] == '"' || t[vs] == '\'')) {
			j := vs
			for j < len(t) && (t[j] == ' ' || t[j] == '\t') {
				j++
			}
			if j == vs {
				continue
			}
			vs = j
		}
		ke := i
		for ke > 0 && (t[ke-1] == ' ' || t[ke-1] == '\t') {
			ke--
		}
		if ke > 0 && (t[ke-1] == '"' || t[ke-1] == '\'') {
			ke--
		}
		kind, ok := d.lookupKey(t, ke)
		if !ok || vs >= len(t) {
			continue
		}
		var ve int
		if q := t[vs]; q == '"' || q == '\'' {
			end := strings.IndexByte(t[vs+1:], q)
			if end < 0 {
				continue
			}
			vs++
			ve = vs + end
		} else {
			ve = vs
			for ve < len(t) {
				c := t[ve]
				if kind == kvSecretRest {
					if c == '\r' || c == '\n' || c == '"' {
						break
					}
				} else if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '&' || c == ';' || c == '|' ||
					c == '"' || c == '\'' || c == '<' || c == '>' || c == ')' || c == ']' || c == '}' ||
					c == ',' && kind != kvUserList {
					break
				}
				ve++
			}
		}
		if ve <= vs {
			continue
		}
		val := t[vs:ve]
		if sc.allow.null(val) {
			continue
		}
		switch kind {
		case kvHostLearn, kvHost:
			if ps := sc.hostParts(val, kind == kvHostLearn); ps != nil {
				out = append(out, span{vs, ve, ps, prioContext})
			}
		case kvUser:
			if ps := sc.userParts(val); ps != nil {
				out = append(out, span{vs, ve, ps, prioContext})
			}
		case kvUserList:
			pos := vs
			for _, item := range strings.Split(val, ",") {
				if item != "" && !sc.allow.null(item) {
					if ps := sc.userParts(item); ps != nil {
						out = append(out, span{pos, pos + len(item), ps, prioContext})
					}
				}
				pos += len(item) + 1
			}
		case kvDomain:
			if ps := sc.domainParts(val, true); ps != nil {
				out = append(out, span{vs, ve, ps, prioContext})
			}
		case kvSecret, kvSecretRest:
			if sc.p.Anonymize.Secrets && strings.Trim(val, "*x") != "" {
				out = append(out, span{vs, ve, []part{{text: val, kind: vault.Secret}}, prioContext})
			}
		case kvDevice:
			if sc.p.Anonymize.DeviceID && len(val) >= 4 {
				out = append(out, span{vs, ve, []part{{text: val, kind: vault.Device}}, prioContext})
			}
		}
	}
	return out
}

// --- Linux authentication messages ------------------------------------------

var reAuthUser = regexp.MustCompile(`(?:(?:Accepted|Failed) (?:password|publickey|keyboard-interactive/pam|none|gssapi-with-mic) for (?:invalid user )?|[Ii]nvalid user |session (?:opened|closed) for user |authentication failure for |FAILED SU \(to \S+\) |by user |for user )([A-Za-z0-9._@$\\-]+)`)

func (sc *Scanner) detectAuthUser(t string, out []span) []span {
	if !strings.Contains(t, "user") && !strings.Contains(t, "for ") {
		return out
	}
	for _, m := range reAuthUser.FindAllStringSubmatchIndex(t, -1) {
		if strings.Contains(t[m[0]:m[2]], "nvalid user") {
			continue // a name an attacker tried, not an account: keep it as an IOC
		}
		v := strings.TrimRight(t[m[2]:m[3]], ".")
		if ps := sc.userParts(v); ps != nil {
			out = append(out, span{m[2], m[2] + len(v), ps, prioContext})
		}
	}
	return out
}

// --- Windows event XML and EvtxECmd JSON payloads ---------------------------

var (
	reXMLData     = regexp.MustCompile(`<Data Name=['"]([A-Za-z0-9_]+)['"]>([^<]+)</Data>`)
	reXMLComputer = regexp.MustCompile(`<Computer>([^<]+)</Computer>`)
	reJSONData    = regexp.MustCompile(`"@Name"\s*:\s*"([A-Za-z0-9_]+)"\s*,\s*"#text"\s*:\s*"([^"]+)"`)
)

func xmlFieldKind(name string) (FieldKind, bool) {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, "username") || n == "user" || strings.HasSuffix(n, "accountname") ||
		n == "principalsamname" || n == "samaccountname":
		return FieldUser, true
	case strings.HasSuffix(n, "domainname") || n == "domain":
		return FieldDomain, true
	case n == "workstationname" || n == "workstation" || n == "computername" || n == "computer" ||
		n == "machinename" || n == "clientname" || n == "hostname" || n == "dnshostname" ||
		n == "sourcehostname" || n == "clientmachine" || n == "callercomputername":
		return FieldHost, true
	case n == "targetservername" || n == "servername":
		return FieldHostRemote, true
	}
	return FieldText, false
}

func (sc *Scanner) detectXML(t string, out []span) []span {
	if strings.Contains(t, "<Data") {
		for _, m := range reXMLData.FindAllStringSubmatchIndex(t, -1) {
			if k, ok := xmlFieldKind(t[m[2]:m[3]]); ok {
				if ps := sc.fieldParts(t[m[4]:m[5]], k); ps != nil {
					out = append(out, span{m[4], m[5], ps, prioContext})
				}
			}
		}
	}
	if strings.Contains(t, "<Computer>") {
		for _, m := range reXMLComputer.FindAllStringSubmatchIndex(t, -1) {
			if ps := sc.fieldParts(t[m[2]:m[3]], FieldHost); ps != nil {
				out = append(out, span{m[2], m[3], ps, prioContext})
			}
		}
	}
	if strings.Contains(t, "#text") {
		for _, m := range reJSONData.FindAllStringSubmatchIndex(t, -1) {
			if k, ok := xmlFieldKind(t[m[2]:m[3]]); ok {
				if ps := sc.fieldParts(t[m[4]:m[5]], k); ps != nil {
					out = append(out, span{m[4], m[5], ps, prioContext})
				}
			}
		}
	}
	return out
}

// --- syslog header hostname -------------------------------------------------

var (
	// <PRI>1 2026-10-06T00:49:00+07:00 HOST app ...   and the same without "1 "
	reSyslog5424 = regexp.MustCompile(`<[A-Za-z0-9:]{1,20}>\s*(?:1\s+)?\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?\s+(\S+)\s`)
	// <PRI>Oct  6 00:49:00 HOST app ...   or a line starting with the date
	reSyslogBSD = regexp.MustCompile(`(?:^|<[A-Za-z0-9:]{1,20}>\s*)[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s`)
)

func startsWithMonth(t string) bool {
	return len(t) > 4 && t[0] >= 'A' && t[0] <= 'Z' && t[1] >= 'a' && t[1] <= 'z' && t[2] >= 'a' && t[2] <= 'z' && t[3] == ' '
}

func (sc *Scanner) detectSyslog(t string, out []span) []span {
	res := []*regexp.Regexp{reSyslog5424, reSyslogBSD}
	switch {
	case strings.IndexByte(t, '<') >= 0:
	case startsWithMonth(t):
		res = res[1:]
	default:
		return out
	}
	for _, re := range res {
		for _, m := range re.FindAllStringSubmatchIndex(t, -1) {
			h := t[m[2]:m[3]]
			if strings.HasSuffix(h, ":") || strings.ContainsAny(h, "[]") {
				continue
			}
			if ps := sc.hostParts(h, true); ps != nil {
				out = append(out, span{m[2], m[3], ps, prioContext})
			}
		}
	}
	return out
}

// --- FQDNs under an internal domain -----------------------------------------

func isFQDNChar(c byte) bool { return isAlnum(c) || c == '.' || c == '-' }

// validFQDN checks labels: 1-63 characters, no leading or trailing hyphen.
func validFQDN(v string) bool {
	if !strings.Contains(v, ".") {
		return false
	}
	for _, l := range strings.Split(v, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	return true
}

func (sc *Scanner) detectFQDN(t string, out []span) []span {
	if strings.IndexByte(t, '.') < 0 || len(sc.suffixes) == 0 && len(sc.terms) == 0 {
		return out
	}
	for i := 0; i < len(t); {
		if !isFQDNChar(t[i]) {
			i++
			continue
		}
		s := i
		for i < len(t) && isFQDNChar(t[i]) {
			i++
		}
		e := i
		if s > 0 && t[s-1] == '_' || e < len(t) && t[e] == '_' {
			continue
		}
		for s < e && (t[s] == '.' || t[s] == '-') {
			s++
		}
		for e > s && (t[e-1] == '.' || t[e-1] == '-') {
			e--
		}
		v := t[s:e]
		if !validFQDN(v) || allDigitLabels(v) {
			continue
		}
		if !sc.internalDomain(v) {
			if sc.KeptDomains != nil {
				sc.countKept(v)
			}
			continue
		}
		if ps := sc.hostParts(v, false); ps != nil {
			out = append(out, span{s, e, ps, prioFQDN})
		}
	}
	return out
}

var commonTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true, "int": true,
	"info": true, "biz": true, "io": true, "app": true, "dev": true, "cloud": true, "online": true,
	"site": true, "xyz": true, "top": true, "tech": true, "ai": true, "asia": true, "name": true,
}

// two-letter file extensions that are not worth reporting as domains
var fileExtensions = map[string]bool{
	"js": true, "gz": true, "xz": true, "bz": true, "py": true, "cs": true, "rb": true,
	"ts": true, "so": true, "md": true, "sh": true, "pm": true, "db": true,
}

var secondLevels = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "ac": true, "go": true, "or": true,
	"mi": true, "in": true, "gov": true, "edu": true, "ne": true, "gob": true,
}

// registrable returns the part of a name an organisation registers:
// mail.corp.example.com -> example.com, www.agency.go.th -> agency.go.th.
func registrable(d string) (string, bool) {
	labels := strings.Split(strings.ToLower(d), ".")
	n := len(labels)
	tld := labels[n-1]
	if fileExtensions[tld] || !commonTLDs[tld] && !(len(tld) == 2 && hasLetterTLD("x."+tld)) {
		return "", false // most likely a file name: report.log, default.aspx
	}
	if n >= 3 && len(tld) == 2 && secondLevels[labels[n-2]] {
		return strings.Join(labels[n-3:], "."), true
	}
	return strings.Join(labels[n-2:], "."), true
}

func (sc *Scanner) countKept(v string) {
	r, ok := registrable(v)
	if !ok || sc.allow.domain(r) {
		return
	}
	sc.KeptDomains[r]++
}

// --- sensitive terms ------------------------------------------------------------

func isWordChar(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == '-' }

func (sc *Scanner) detectTerms(t string, out []span) []span {
	if len(sc.terms) == 0 {
		return out
	}
	if sc.termsDirty || sc.termAC == nil {
		sc.termAC = newAC(sc.terms)
		sc.termsDirty = false
	}
	seen := map[[2]int]bool{}
	sc.termAC.findAll(t, func(s, e, _ int) {
		// grow to the whole word, but not across a percent-encoded byte
		for s > 0 && isWordChar(t[s-1]) {
			if s >= 3 && t[s-3] == '%' && isHex(t[s-2]) && isHex(t[s-1]) {
				break
			}
			s--
		}
		for e < len(t) && isWordChar(t[e]) {
			e++
		}
		for s < e && strings.IndexByte("._-", t[s]) >= 0 {
			s++
		}
		for e > s && strings.IndexByte("._-", t[e-1]) >= 0 {
			e--
		}
		if e <= s || seen[[2]int{s, e}] {
			return
		}
		seen[[2]int{s, e}] = true
		w := t[s:e]
		lw := strings.ToLower(w)
		var ps []part
		switch {
		case sc.termSet[lw]:
			ps = []part{{text: w, kind: vault.Org}}
		case strings.Contains(w, "."):
			if ps = sc.hostParts(w, false); ps == nil || allLiteral(ps) {
				ps = []part{{text: w, kind: vault.Domain}}
			}
		default:
			if _, ok := sc.v.Find(vault.Host, w); ok {
				ps = []part{{text: w, kind: vault.Host}}
			} else {
				ps = []part{{text: w, kind: vault.Name}}
			}
		}
		out = append(out, span{s, e, ps, prioTerm})
	})
	return out
}

// --- dictionary of values already learned -------------------------------------

// dictKinds are the kinds that are searched for anywhere in the text once
// learned. Addresses are found by their own detectors.
var dictEligible = map[vault.Kind]bool{
	vault.Host: true, vault.Domain: true, vault.User: true, vault.Org: true, vault.Name: true,
	vault.Device: true, vault.Secret: true,
}

// dictValue reports whether a learned value is searched for in free text.
// User, host and NetBIOS domain names must be distinctive: not a common
// word, and either at least 5 characters or containing a digit or . _ -
func (a *allowSet) dictValue(e vault.Entry) bool {
	if !dictEligible[e.Kind] {
		return false
	}
	v := e.Original
	min := 3
	if e.Kind == vault.Secret {
		min = 6
	}
	if len(v) < min || isNumeric(v) {
		return false
	}
	netbios := e.Kind == vault.Domain && !strings.Contains(v, ".")
	if e.Kind != vault.User && e.Kind != vault.Host && !netbios {
		return true
	}
	lo := strings.ToLower(v)
	if a.common[lo] || e.Kind == vault.User && a.user(lo) || e.Kind == vault.Host && a.host(lo) {
		return false
	}
	return len(v) >= 5 || strings.ContainsAny(v, "0123456789._-")
}

func (sc *Scanner) dictPatterns() ([]string, []vault.Kind) {
	var pats []string
	var kinds []vault.Kind
	for _, e := range sc.v.Entries {
		if sc.allow.dictValue(e) {
			pats = append(pats, e.Original)
			kinds = append(kinds, e.Kind)
		}
	}
	return pats, kinds
}

// dictBoundary: a learned value must not be part of a longer word. For
// names of 6+ characters a change between letter and digit also counts as
// a boundary, so "SRV-FILE-APP20220721.log" still hides "SRV-FILE-APP".
// An underscore is a boundary only for distinctive values (with a digit,
// '-' or '.'): "BSID_Site_SRV-APP01" hides SRV-APP01, "Cyber_team_rule" keeps
// the plain word "cyber".
func dictBoundary(t string, s, e int, k vault.Kind) bool {
	relaxed := e-s >= 6 && (k == vault.Host || k == vault.Org || k == vault.Name || k == vault.Domain)
	underscore := strings.ContainsAny(t[s:e], "0123456789-.")
	if s > 0 {
		c := t[s-1]
		if c == '_' && !underscore || isAlnum(c) && !(relaxed && isDigit(c) != isDigit(t[s])) {
			return false
		}
	}
	if e < len(t) {
		c := t[e]
		if c == '_' && !underscore || isAlnum(c) && !(relaxed && isDigit(c) != isDigit(t[e-1])) {
			return false
		}
	}
	return true
}

// RebuildDict refreshes the dictionary from the vault.
func (sc *Scanner) RebuildDict() {
	pats, kinds := sc.dictPatterns()
	sc.dict = newAC(pats)
	sc.dictKinds = kinds
	sc.dictSize = sc.v.Len()
}

// DictStale reports whether entries were added since the dictionary was built.
func (sc *Scanner) DictStale() bool { return sc.dict == nil || sc.v.Len() != sc.dictSize }

func (sc *Scanner) detectDict(t string, out []span) []span {
	if sc.dict == nil {
		return out
	}
	sc.dict.findAll(t, func(s, e, idx int) {
		if !dictBoundary(t, s, e, sc.dictKinds[idx]) {
			return
		}
		out = append(out, span{s, e, []part{{text: t[s:e], kind: sc.dictKinds[idx]}}, prioDict})
	})
	return out
}
