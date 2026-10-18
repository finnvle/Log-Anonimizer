package anon

import (
	"regexp"
	"strings"

	"log_anonimizer/internal/vault"
)

// --- credentials recognisable by their shape --------------------------------

// reTokenSecret finds credentials that need no key name in front: JWTs, AWS
// access key IDs, GitHub, Slack, Google and Stripe keys.
var reTokenSecret = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*` +
	`|(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}` +
	`|gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}` +
	`|xox[abposr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|[rs]k_live_[0-9A-Za-z]{16,}`)

var tokenMarkers = []string{"eyJ", "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "APKA",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "AIza", "k_live_"}

func (sc *Scanner) detectTokenSecrets(t string, out []span) []span {
	if !sc.p.Anonymize.Secrets {
		return out
	}
	found := false
	for _, m := range tokenMarkers {
		if strings.Contains(t, m) {
			found = true
			break
		}
	}
	if !found {
		return out
	}
	for _, m := range reTokenSecret.FindAllStringIndex(t, -1) {
		s, e := m[0], m[1]
		if s > 0 && (isAlnum(t[s-1]) || t[s-1] == '_' || t[s-1] == '-') || e < len(t) && isAlnum(t[e]) {
			continue // part of a longer word
		}
		out = append(out, span{s, e, []part{{text: t[s:e], kind: vault.Secret}}, prioStructure})
	}
	return out
}

// --- private keys -------------------------------------------------------------

var (
	rePEMBegin  = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	rePEMEnd    = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	rePEMHeader = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*: `) // Proc-Type:, DEK-Info:, Comment:
)

// ResetLines forgets what earlier lines said (an open private key); call it
// at the start and end of every file.
func (sc *Scanner) ResetLines() { sc.inKey = false }

// detectPrivateKey replaces the body of a private key: within one line
// (a key in a JSON field, with "\n" written out), or across lines, from the
// BEGIN line to the END line of a key file.
func (sc *Scanner) detectPrivateKey(t string, out []span) []span {
	if !sc.p.Anonymize.Secrets {
		return out
	}
	pos := 0
	if sc.inKey {
		end := len(t)
		if m := rePEMEnd.FindStringIndex(t); m != nil {
			end, pos = m[0], m[1]
			sc.inKey = false
		}
		n := len(out)
		out = keyBody(t, 0, end, out)
		if sc.inKey && len(out) == n && strings.TrimSpace(t) != "" && !rePEMHeader.MatchString(t) {
			sc.inKey = false // not a key line: the key was cut short
		}
		if sc.inKey {
			return out
		}
	}
	if !strings.Contains(t[pos:], "PRIVATE KEY") {
		return out
	}
	for {
		m := rePEMBegin.FindStringIndex(t[pos:])
		if m == nil {
			return out
		}
		bs := pos + m[1]
		if e := rePEMEnd.FindStringIndex(t[bs:]); e != nil {
			out = keyBody(t, bs, bs+e[0], out)
			pos = bs + e[1]
			continue
		}
		out = keyBody(t, bs, len(t), out)
		sc.inKey = true
		return out
	}
}

// lineBreakAt is the length of a line break at i: a real one, or "\n" /
// "\r\n" written out.
func lineBreakAt(t string, i, e int) int {
	switch {
	case t[i] == '\n':
		return 1
	case t[i] == '\r' && i+1 < e && t[i+1] == '\n':
		return 2
	case t[i] == '\\' && i+1 < e && (t[i+1] == 'n' || t[i+1] == 'r'):
		if i+3 < e && t[i+1] == 'r' && t[i+2] == '\\' && t[i+3] == 'n' {
			return 4
		}
		return 2
	}
	return 0
}

// keyBody marks the base64 of a key in t[s:e] as a secret. Header lines
// ("Proc-Type: 4,ENCRYPTED") are skipped; anything else that is not base64
// means it is not a key.
func keyBody(t string, s, e int, out []span) []span {
	for s < e {
		if n := lineBreakAt(t, s, e); n > 0 {
			s += n
		} else if t[s] == ' ' || t[s] == '\t' {
			s++
		} else if rePEMHeader.MatchString(t[s:e]) {
			for s < e && lineBreakAt(t, s, e) == 0 {
				s++
			}
		} else {
			break
		}
	}
	for e > s {
		c := t[e-1]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			e--
		} else if e-2 >= s && t[e-2] == '\\' && (c == 'n' || c == 'r') {
			e -= 2
		} else {
			break
		}
	}
	n := 0
	for i := s; i < e; i++ {
		c := t[i]
		switch {
		case isAlnum(c) || c == '+' || c == '/' || c == '=':
			n++
		case c == ' ' || c == '\t':
		default:
			if k := lineBreakAt(t, i, e); k > 0 {
				i += k - 1
				continue
			}
			return out
		}
	}
	if n < 16 {
		return out
	}
	return append(out, span{s, e, []part{{text: t[s:e], kind: vault.Secret}}, prioStructure})
}

// --- database connection strings ------------------------------------------------

var (
	// a line with one of these is a connection string
	reConnString = regexp.MustCompile(`(?i)(?:initial catalog|database|integrated security|trusted_connection|persist security info|user id|uid)\s*=`)
	reConnPair   = regexp.MustCompile(`(?i)(?:^|[;"'\s])(server|data source|address|addr|network address|user id|uid)\s*=([^;"']*)`)
)

var connProtocols = map[string]bool{"tcp": true, "np": true, "lpc": true, "admin": true}

// detectConnString finds the server and the account in
// "Server=tcp:sql01.corp.example,1433;Database=hr;User Id=svc_app;Password=…".
// The password is a secret key already.
func (sc *Scanner) detectConnString(t string, out []span) []span {
	if strings.IndexByte(t, ';') < 0 || !reConnString.MatchString(t) {
		return out
	}
	for _, m := range reConnPair.FindAllStringSubmatchIndex(t, -1) {
		key := strings.ToLower(t[m[2]:m[3]])
		vs, ve := m[4], m[5]
		for vs < ve && t[vs] == ' ' {
			vs++
		}
		for ve > vs && t[ve-1] == ' ' {
			ve--
		}
		if vs >= ve {
			continue
		}
		if key == "user id" || key == "uid" {
			if ps := sc.userParts(t[vs:ve]); ps != nil {
				out = append(out, span{vs, ve, ps, prioContext})
			}
			continue
		}
		// [protocol:]host[\instance][,port]
		hs := vs
		if i := strings.IndexByte(t[vs:ve], ':'); i > 0 && connProtocols[strings.ToLower(t[vs:vs+i])] {
			hs = vs + i + 1
		}
		he := hs
		for he < ve && t[he] != ',' && t[he] != '\\' && t[he] != ':' {
			he++
		}
		if he <= hs {
			continue
		}
		if ps := sc.hostParts(t[hs:he], false); ps != nil {
			out = append(out, span{hs, he, ps, prioContext})
		}
	}
	return out
}
