package app

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"log_anonimizer/internal/vault"
)

// ShowRow is one token and what it stands for.
type ShowRow struct {
	Token, Original string
	Kind            vault.Kind
	Count           int // occurrences in the anonymized input; 0 when showing a whole map
}

// ShowResult is the outcome of Show.
type ShowResult struct {
	MapPath   string
	Encrypted bool
	Total     int    // entries in the map
	UsedIn    string // anonymized file or folder the rows were taken from, if any
	Rows      []ShowRow
	Masked    bool // secrets are partly hidden
}

var kindLabels = map[vault.Kind]string{
	vault.IP: "internal IP addresses", vault.ExtIP: "public IP addresses", vault.Host: "hostnames",
	vault.Domain: "domains", vault.User: "users", vault.Org: "sensitive terms",
	vault.Name: "words that contain a sensitive term", vault.MAC: "MAC addresses",
	vault.SID: "SIDs (domain part)", vault.Secret: "secrets", vault.Device: "device IDs",
}

// Show lists what tokens stand for. target is either a map, or an
// anonymized file or folder; for the latter only the tokens it contains are
// listed, with how often each occurs. find keeps rows whose token or value
// contains it (case-insensitive); it also reveals secrets, which are
// otherwise partly masked.
func Show(target, mapPath, find string, pass Passphrases) (*ShowResult, error) {
	res := &ShowResult{}
	if _, err := vault.Stat(target); err == nil {
		mapPath = target
	} else {
		if mapPath == "" {
			if mapPath = FindMap(target); mapPath == "" {
				return nil, fmt.Errorf("%s is not a map and no map was found next to it: give it with -m <file.anonmap>", target)
			}
		}
		res.UsedIn = target
	}
	info, err := vault.Stat(mapPath)
	if err != nil {
		return nil, err
	}
	v, err := LoadMap(mapPath, pass)
	if err != nil {
		return nil, err
	}
	res.MapPath, res.Encrypted, res.Total = mapPath, info.Encrypted, v.Len()

	counts := map[string]int{}
	if res.UsedIn != "" {
		if err := countTokens(res.UsedIn, v, counts); err != nil {
			return nil, err
		}
	}
	lf := strings.ToLower(find)
	res.Masked = find == ""
	for _, e := range v.Entries {
		if res.UsedIn != "" && counts[e.Token] == 0 {
			continue
		}
		if lf != "" && !strings.Contains(strings.ToLower(e.Token), lf) && !strings.Contains(strings.ToLower(e.Original), lf) {
			continue
		}
		res.Rows = append(res.Rows, ShowRow{Token: e.Token, Original: e.Original, Kind: e.Kind, Count: counts[e.Token]})
	}
	order := map[vault.Kind]int{}
	for i, k := range vault.Kinds {
		order[k] = i
	}
	sort.SliceStable(res.Rows, func(i, j int) bool {
		a, b := res.Rows[i], res.Rows[j]
		if a.Kind != b.Kind {
			return order[a.Kind] < order[b.Kind]
		}
		return tokenNumber(a.Token) < tokenNumber(b.Token)
	})
	return res, nil
}

func tokenNumber(tok string) int {
	n, _ := strconv.Atoi(tok[strings.LastIndexByte(tok, '_')+1:])
	return n
}

// countTokens counts the map's tokens in a file or in every file of a folder.
func countTokens(path string, v *vault.Vault, counts map[string]int) error {
	re := v.TokenPattern()
	count := func(p string) error {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(data)
		for _, m := range re.FindAllStringIndex(s, -1) {
			if vault.IsTokenStart(s, m[0]) {
				if e, _, ok := v.Resolve(s[m[0]:m[1]]); ok {
					counts[e.Token]++
				}
			}
		}
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return count(path)
	}
	return filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return err
		}
		if rel, _ := filepath.Rel(path, p); rel != "" {
			for _, m := range re.FindAllStringIndex(filepath.ToSlash(rel), -1) {
				counts[filepath.ToSlash(rel)[m[0]:m[1]]]++
			}
		}
		return count(p)
	})
}

func mask(s string) string {
	r := []rune(s)
	if len(r) <= 2 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-2)
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// FormatShow renders the table, grouped by kind.
func FormatShow(r *ShowResult) string {
	var b strings.Builder
	state := "encrypted"
	if !r.Encrypted {
		state = "not encrypted"
	}
	fmt.Fprintf(&b, "map:     %s (%s, %d values)\n", r.MapPath, state, r.Total)
	if r.UsedIn != "" {
		distinct, total := len(r.Rows), 0
		for _, row := range r.Rows {
			total += row.Count
		}
		fmt.Fprintf(&b, "used in: %s (%d distinct tokens, %d occurrences)\n", r.UsedIn, distinct, total)
	}
	if len(r.Rows) == 0 {
		b.WriteString("\nnothing to show\n")
		return b.String()
	}
	wTok, wVal := len("TOKEN"), len("REAL VALUE")
	vals := make([]string, len(r.Rows))
	for i, row := range r.Rows {
		v := row.Original
		if row.Kind == vault.Secret && r.Masked {
			v = mask(v)
		}
		vals[i] = clip(v, 70)
		wTok = max(wTok, len(row.Token))
		wVal = max(wVal, utf8.RuneCountInString(vals[i]))
	}
	var last vault.Kind
	for i, row := range r.Rows {
		if row.Kind != last {
			fmt.Fprintf(&b, "\n%s\n", strings.ToUpper(kindLabels[row.Kind]))
			last = row.Kind
		}
		line := fmt.Sprintf("  %-*s  %s", wTok, row.Token, vals[i])
		if r.UsedIn != "" {
			line += strings.Repeat(" ", wVal-utf8.RuneCountInString(vals[i])) + fmt.Sprintf("  %6d×", row.Count)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")
	if r.Masked {
		b.WriteString("Secrets are partly hidden; look one up with -find SECRET_0001.\n")
	}
	b.WriteString("These are the REAL values: do not paste this output where the anonymized logs go.\n")
	return b.String()
}
