package anon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

const maxLeaksListed = 50

type verifyTarget struct{ path, rel string }

// leakPatterns returns every original the output must not contain: the
// values the dictionary searches for, plus addresses and SIDs.
func leakPatterns(v *vault.Vault, a *allowSet) ([]string, []vault.Entry) {
	var pats []string
	var ents []vault.Entry
	for _, e := range v.Entries {
		switch e.Kind {
		case vault.IP, vault.ExtIP, vault.MAC, vault.SID, vault.Card, vault.NatID, vault.Phone:
			if len(e.Original) < 3 {
				continue
			}
		default:
			if !a.dictValue(e) {
				continue
			}
		}
		pats = append(pats, e.Original)
		ents = append(ents, e)
	}
	return pats, ents
}

func boundaryOK(t string, s, e int, k vault.Kind) bool {
	if k == vault.IP || k == vault.ExtIP {
		return ipBoundary(t, s, e)
	}
	return dictBoundary(t, s, e, k)
}

// findLeaks searches the files for original values from the vault.
func findLeaks(targets []verifyTarget, v *vault.Vault, a *allowSet) ([]Leak, int, error) {
	pats, ents := leakPatterns(v, a)
	if len(pats) == 0 {
		return nil, 0, nil
	}
	ac := newAC(pats)
	var leaks []Leak
	count := 0
	for _, tg := range targets {
		_, enc, err := sniff(tg.path)
		if err != nil {
			return nil, 0, err
		}
		r, closeFn, err := openText(tg.path, enc)
		if err != nil {
			return nil, 0, err
		}
		line := 0
		err = eachLine(r, func(body, _ string) error {
			line++
			ac.findAll(body, func(s, e, idx int) {
				en := ents[idx]
				if !boundaryOK(body, s, e, en.Kind) {
					return
				}
				if (en.Kind == vault.IP || en.Kind == vault.ExtIP) && a.isVersion(body, s, e) {
					return // the detectors keep version numbers on purpose
				}
				count++
				if len(leaks) < maxLeaksListed {
					leaks = append(leaks, Leak{File: tg.rel, Line: line, Token: en.Token, Kind: en.Kind})
				}
			})
			return nil
		})
		closeFn()
		if err != nil {
			return nil, 0, err
		}
	}
	return leaks, count, nil
}

// VerifyReport is the result of Verify.
type VerifyReport struct {
	Files     int
	Leaks     []Leak
	LeakCount int
	// Residual counts values the detectors would still anonymize, per kind
	// (e.g. an address that was never seen while learning).
	Residual        map[vault.Kind]int
	ResidualSamples []Leak
}

// Verify checks anonymized output. With a vault it looks for every original
// value; it always re-runs the detectors to find values left in clear text.
func Verify(path string, v *vault.Vault, p *profile.Profile) (*VerifyReport, error) {
	targets, err := verifyTargets(path)
	if err != nil {
		return nil, err
	}
	rep := &VerifyReport{Files: len(targets), Residual: map[vault.Kind]int{}}
	a, err := newAllowSet(p)
	if err != nil {
		return nil, err
	}
	if v != nil {
		rep.Leaks, rep.LeakCount, err = findLeaks(targets, v, a)
		if err != nil {
			return nil, err
		}
	}
	prefix := ""
	if v != nil {
		prefix = v.Prefix
	}
	tokRe := vault.TokenPattern(prefix)
	sc, err := NewScanner(p, vault.New())
	if err != nil {
		return nil, err
	}
	for _, tg := range targets {
		sc.ResetLines()
		_, enc, err := sniff(tg.path)
		if err != nil {
			return nil, err
		}
		r, closeFn, err := openText(tg.path, enc)
		if err != nil {
			return nil, err
		}
		line := 0
		err = eachLine(r, func(body, _ string) error {
			line++
			for _, s := range sc.find(body, false) {
				if hasTokenPart(s.parts, tokRe) {
					continue // "EXTIP_0005@evil.example": already handled when anonymizing
				}
				for _, pt := range s.parts {
					if pt.kind == "" {
						continue
					}
					rep.Residual[pt.kind]++
					if len(rep.ResidualSamples) < maxLeaksListed {
						rep.ResidualSamples = append(rep.ResidualSamples, Leak{File: tg.rel, Line: line, Kind: pt.kind})
					}
				}
			}
			return nil
		})
		closeFn()
		if err != nil {
			return nil, err
		}
	}
	return rep, nil
}

func hasTokenPart(ps []part, re interface{ MatchString(string) bool }) bool {
	for _, p := range ps {
		if p.kind != "" && re.MatchString(p.text) {
			return true
		}
	}
	return false
}

func verifyTargets(path string) ([]verifyTarget, error) {
	jobs, isDir, err := collect(path)
	if err != nil {
		return nil, err
	}
	var out []verifyTarget
	for _, j := range jobs {
		typ, _, err := sniff(j.abs)
		if err != nil {
			return nil, err
		}
		if typ == ftBinary {
			continue
		}
		rel := j.rel
		if !isDir {
			rel = filepath.Base(path)
		}
		out = append(out, verifyTarget{path: j.abs, rel: rel})
	}
	return out, nil
}

// FormatVerify renders a verify report.
func FormatVerify(r *VerifyReport, withMap bool) string {
	var b strings.Builder
	files := "1 file"
	if r.Files != 1 {
		files = fmt.Sprintf("%d files", r.Files)
	}
	fmt.Fprintf(&b, "checked   %s\n", files)
	switch {
	case !withMap:
		b.WriteString("map       not checked (add -m <map> to look for every known value)\n")
	case r.LeakCount == 0:
		b.WriteString("map       OK: no value from the map found\n")
	default:
		fmt.Fprintf(&b, "map       FAILED: %d original value(s) found\n", r.LeakCount)
		for _, l := range r.Leaks {
			fmt.Fprintf(&b, "          %s:%d  %s\n", l.File, l.Line, l.Token)
		}
	}
	total := 0
	var kinds []string
	for _, k := range vault.Kinds {
		if n := r.Residual[k]; n > 0 {
			total += n
			kinds = append(kinds, fmt.Sprintf("%s %d", k.Prefix(), n))
		}
	}
	if total == 0 {
		b.WriteString("detectors OK: nothing they recognise is in clear text\n")
	} else {
		fmt.Fprintf(&b, "detectors WARNING: %d value(s) in clear text (%s)\n", total, strings.Join(kinds, " · "))
		for _, l := range r.ResidualSamples {
			fmt.Fprintf(&b, "          %s:%d  %s\n", l.File, l.Line, l.Kind)
		}
	}
	return b.String()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
