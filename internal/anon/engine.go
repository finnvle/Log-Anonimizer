package anon

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

// maxLearnPasses bounds how often the input is re-read while new internal
// domains or sensitive terms keep appearing.
const maxLearnPasses = 3

// Engine anonymizes a file or a directory tree.
type Engine struct {
	P  *profile.Profile
	V  *vault.Vault
	SC *Scanner
	// Progress receives one line per phase; nil discards.
	Progress io.Writer
	// BeforeWrite, if set, is called with the output path after learning and
	// before anything is written; an error aborts the run.
	BeforeWrite func(output string) error
}

// NewEngine prepares an engine.
func NewEngine(p *profile.Profile, v *vault.Vault) (*Engine, error) {
	sc, err := NewScanner(p, v)
	if err != nil {
		return nil, err
	}
	return &Engine{P: p, V: v, SC: sc}, nil
}

// FileResult describes one input file. Paths are relative and anonymized.
type FileResult struct {
	Out      string
	Type     string
	Encoding string
	Skipped  bool
	Reason   string
}

// Leak is an original value found in the output.
type Leak struct {
	File  string
	Line  int
	Token string
	Kind  vault.Kind
}

// Report summarises a run. It never contains original values.
type Report struct {
	Input, Output string
	IsDir         bool
	Files         []FileResult
	Replaced      map[vault.Kind]int
	NewEntries    map[vault.Kind]int
	TotalEntries  int
	Prefix        string
	PrefixChanged bool
	LearnPasses   int
	Leaks         []Leak
	LeakCount     int
	InputSHA256   string
	Duration      time.Duration
	// KeptDomains are the most frequent domains left in clear text. They
	// are shown on screen only, never written into the output report.
	KeptDomains []DomainCount
	NoTerms     bool // no sensitive term was configured or learned
}

// DomainCount is a domain and how often it was left in clear text.
type DomainCount struct {
	Domain string
	Count  int
}

func topCounts(m map[string]int, n int) []DomainCount {
	out := make([]DomainCount, 0, len(m))
	for d, c := range m {
		out = append(out, DomainCount{d, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type job struct {
	abs, rel string
	typ      fileType
	enc      textEncoding
	outRel   string
	reason   string
}

func (e *Engine) logf(format string, a ...any) {
	if e.Progress != nil {
		fmt.Fprintf(e.Progress, format+"\n", a...)
	}
}

// DefaultOutput is the output path used when none is given:
// dir/name.csv -> dir/name.anon.csv, dir/logs -> dir/logs.anon. The name is
// anonymized too, so call it after learning.
func (e *Engine) defaultOutput(input string, isDir bool) string {
	dir, base := filepath.Split(filepath.Clean(input))
	if isDir {
		return filepath.Join(dir, e.anonName(base)+".anon")
	}
	ext := filepath.Ext(base)
	return filepath.Join(dir, e.anonName(strings.TrimSuffix(base, ext))+".anon"+ext)
}

func (e *Engine) anonName(s string) string {
	if !e.P.Anonymize.FileNames {
		return s
	}
	return e.SC.Apply(s)
}

// MapPathFor derives the map path from an output path:
// name.anon.csv -> name.anonmap, logs.anon -> logs.anonmap.
func MapPathFor(output string) string {
	dir, base := filepath.Split(filepath.Clean(output))
	if strings.HasSuffix(base, ".anon") {
		return filepath.Join(dir, strings.TrimSuffix(base, ".anon")+".anonmap")
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(base, filepath.Ext(base)), ".anon")
	return filepath.Join(dir, stem+".anonmap")
}

func collect(input string) ([]*job, bool, error) {
	st, err := os.Stat(input)
	if err != nil {
		return nil, false, err
	}
	if !st.IsDir() {
		return []*job{{abs: input, rel: filepath.Base(input)}}, false, nil
	}
	var jobs []*job
	err = filepath.WalkDir(input, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(input, p)
		if err != nil {
			return err
		}
		jobs = append(jobs, &job{abs: p, rel: filepath.ToSlash(rel)})
		return nil
	})
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].rel < jobs[j].rel })
	return jobs, true, err
}

// Anonymize processes input into output ("" = default location). It refuses
// to overwrite existing output unless force is set.
func (e *Engine) Anonymize(input, output string, force bool) (*Report, error) {
	start := time.Now()
	jobs, isDir, err := collect(input)
	if err != nil {
		return nil, err
	}
	rep := &Report{Input: input, IsDir: isDir, Replaced: e.SC.Replaced}
	before := e.V.CountByKind()

	for _, j := range jobs {
		j.typ, j.enc, err = sniff(j.abs)
		if err != nil {
			return nil, err
		}
		if j.typ == ftBinary {
			j.reason = "binary"
		}
	}
	if !isDir && jobs[0].typ == ftBinary {
		return nil, fmt.Errorf("%s looks like a binary file; convert it to CSV/text first (EZ Tools: EvtxECmd, RECmd, MFTECmd)", input)
	}

	if e.V.Len() == 0 {
		if err := e.choosePrefix(jobs); err != nil {
			return nil, err
		}
		rep.PrefixChanged = e.V.Prefix != ""
	}
	rep.Prefix = e.V.Prefix

	// learn until no new internal domain or sensitive term shows up
	for pass := 1; pass <= maxLearnPasses; pass++ {
		e.logf("learning (pass %d) ...", pass)
		ctx := e.SC.ctxVersion
		e.SC.SetLearning(true)
		for _, j := range jobs {
			if isDir {
				e.SC.Learn(j.rel)
			} else {
				e.SC.Learn(strings.TrimSuffix(j.rel, filepath.Ext(j.rel)))
			}
			if j.typ == ftBinary {
				continue
			}
			if err := e.process(j, nil); err != nil {
				return nil, fmt.Errorf("%s: %w", j.rel, err)
			}
		}
		e.SC.SetLearning(false)
		rep.LearnPasses = pass
		if e.SC.ctxVersion == ctx {
			break
		}
	}
	e.SC.RebuildDict()

	if output == "" {
		output = e.defaultOutput(input, isDir)
	}
	rep.Output = output
	if _, err := os.Stat(output); err == nil && !force {
		return nil, fmt.Errorf("%s already exists (use -f to overwrite)", output)
	}
	if e.BeforeWrite != nil {
		if err := e.BeforeWrite(output); err != nil {
			return nil, err
		}
	}

	used := map[string]bool{}
	for _, j := range jobs {
		if !isDir {
			j.outRel = filepath.Base(output)
			continue
		}
		out := j.rel
		if e.P.Anonymize.FileNames {
			out = e.SC.Apply(j.rel)
		}
		base, n := out, 2
		for used[strings.ToLower(out)] {
			ext := filepath.Ext(base)
			out = fmt.Sprintf("%s~%d%s", strings.TrimSuffix(base, ext), n, ext)
			n++
		}
		used[strings.ToLower(out)] = true
		j.outRel = out
	}

	e.logf("writing %s ...", output)
	e.SC.KeptDomains = map[string]int{}
	for _, j := range jobs {
		fr := FileResult{Out: j.outRel, Type: j.typ.String(), Encoding: j.enc.String()}
		if j.typ == ftBinary {
			fr.Skipped, fr.Reason = true, j.reason
			rep.Files = append(rep.Files, fr)
			continue
		}
		dst := output
		if isDir {
			dst = filepath.Join(output, filepath.FromSlash(j.outRel))
		}
		counts := copyCounts(e.SC.Replaced)
		if err := e.writeFile(j, dst); err != nil {
			return nil, err
		}
		// a value first seen while writing may occur earlier in the file
		if e.SC.DictStale() {
			e.SC.RebuildDict()
			for k := range e.SC.Replaced {
				e.SC.Replaced[k] = counts[k]
			}
			if err := e.writeFile(j, dst); err != nil {
				return nil, err
			}
		}
		rep.Files = append(rep.Files, fr)
	}

	e.logf("verifying ...")
	var outs []verifyTarget
	for _, j := range jobs {
		if j.typ == ftBinary {
			continue
		}
		dst := output
		if isDir {
			dst = filepath.Join(output, filepath.FromSlash(j.outRel))
		}
		outs = append(outs, verifyTarget{path: dst, rel: j.outRel})
	}
	leaks, count, err := findLeaks(outs, e.V, e.SC.allow)
	if err != nil {
		return nil, err
	}
	rep.Leaks, rep.LeakCount = leaks, count

	if !isDir {
		rep.InputSHA256, _ = fileSHA256(input)
	}
	after := e.V.CountByKind()
	rep.NewEntries = map[vault.Kind]int{}
	for _, k := range vault.Kinds {
		if d := after[k] - before[k]; d > 0 {
			rep.NewEntries[k] = d
		}
	}
	rep.TotalEntries = e.V.Len()
	rep.KeptDomains = topCounts(e.SC.KeptDomains, 10)
	rep.NoTerms = len(e.SC.terms) == 0
	rep.Duration = time.Since(start)
	if isDir {
		if err := writeReportFile(filepath.Join(output, "ANONYMIZATION_REPORT.txt"), rep); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

func (e *Engine) writeFile(j *job, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	if j.enc == encUTF8BOM || j.enc == encUTF16LE || j.enc == encUTF16BE {
		w.Write(bomUTF8)
	}
	err = e.process(j, w)
	if ferr := w.Flush(); err == nil {
		err = ferr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%s: %w", j.rel, err)
	}
	return os.Rename(tmp, dst)
}

// process learns (w == nil) or rewrites (w != nil) one file.
func (e *Engine) process(j *job, w *bufio.Writer) error {
	r, closeFn, err := openText(j.abs, j.enc)
	if err != nil {
		return err
	}
	defer closeFn()
	if j.typ == ftCSV {
		err := e.processCSV(r, w, csvComma(j.abs))
		if err == nil || w != nil {
			return err
		}
		// not really CSV: treat as text from now on
		j.typ = ftText
		r2, close2, err := openText(j.abs, j.enc)
		if err != nil {
			return err
		}
		defer close2()
		r = r2
	}
	return e.processText(r, w)
}

func (e *Engine) processText(r io.Reader, w *bufio.Writer) error {
	sc := e.SC
	var w3c []FieldKind
	return eachLine(r, func(body, eol string) error {
		out := body
		switch {
		case strings.HasPrefix(body, "#Fields:"):
			w3c = w3cKinds(body)
		case w3c != nil && !strings.HasPrefix(body, "#"):
			fields := strings.Split(body, " ")
			if len(fields) == len(w3c) {
				for i, f := range fields {
					if w == nil {
						sc.LearnField(f, w3c[i])
					} else {
						fields[i] = sc.ApplyField(f, w3c[i])
					}
				}
				out = strings.Join(fields, " ")
				break
			}
			fallthrough
		default:
			if w == nil {
				sc.Learn(body)
			} else {
				out = sc.Apply(body)
			}
		}
		if w != nil {
			w.WriteString(out)
			_, err := w.WriteString(eol)
			return err
		}
		return nil
	})
}

func (e *Engine) processCSV(r io.Reader, w *bufio.Writer, comma rune) error {
	br, peek := peekReader(r)
	format := detectCSVFormat(peek, comma)
	cr := newCSVReader(br, comma)
	header, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	header = append([]string(nil), header...)
	kinds := headerKinds(header)
	if w != nil {
		if err := writeCSVRecord(w, format, header); err != nil {
			return err
		}
	}
	sc := e.SC
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for i, f := range rec {
			if f == "" {
				continue
			}
			k := FieldText
			if i < len(kinds) {
				k = kinds[i]
			}
			if w == nil {
				sc.LearnField(f, k)
			} else {
				rec[i] = sc.ApplyField(f, k)
			}
		}
		if w != nil {
			if err := writeCSVRecord(w, format, rec); err != nil {
				return err
			}
		}
	}
}

// choosePrefix picks a token prefix that does not already occur in the input,
// so de-anonymization cannot confuse input text with tokens.
func (e *Engine) choosePrefix(jobs []*job) error {
	candidates := []string{"", "ANON_", "ANON1_", "ANON2_", "ANON3_", "ANON4_", "ANON5_"}
	re := vault.TokenPattern("")
	clash := make([]bool, len(candidates))
	for _, j := range jobs {
		check := func(s string) {
			if !hasTokenShape(s) {
				return
			}
			for _, m := range re.FindAllStringIndex(s, -1) {
				for ci, c := range candidates {
					st := m[0] - len(c)
					if st >= 0 && s[st:m[0]] == c && vault.IsTokenStart(s, st) {
						clash[ci] = true
					}
				}
			}
		}
		check(j.rel)
		if j.typ == ftBinary {
			continue
		}
		r, closeFn, err := openText(j.abs, j.enc)
		if err != nil {
			return err
		}
		err = eachLine(r, func(body, _ string) error { check(body); return nil })
		closeFn()
		if err != nil {
			return err
		}
	}
	for ci, c := range candidates {
		if !clash[ci] {
			e.V.Prefix = c
			return nil
		}
	}
	return errors.New("input already contains anonymization tokens with every candidate prefix")
}

// hasTokenShape is a cheap test for "_dddd".
func hasTokenShape(s string) bool {
	for i := strings.IndexByte(s, '_'); i >= 0 && i+4 < len(s); {
		if isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) && isDigit(s[i+4]) {
			return true
		}
		n := strings.IndexByte(s[i+1:], '_')
		if n < 0 {
			return false
		}
		i += n + 1
	}
	return false
}

func copyCounts(m map[vault.Kind]int) map[vault.Kind]int {
	c := make(map[vault.Kind]int, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FormatReport renders a report as plain text without original values.
func FormatReport(r *Report) string { return formatReport(r, 20, true) }

// formatReport lists at most maxSkipped skipped files (-1 = all) and, for
// the screen, the domains kept in clear text.
func formatReport(r *Report, maxSkipped int, withDomains bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "output:        %s\n", r.Output)
	processed, skipped := 0, 0
	for _, f := range r.Files {
		if f.Skipped {
			skipped++
		} else {
			processed++
		}
	}
	fmt.Fprintf(&b, "files:         %d anonymized, %d skipped\n", processed, skipped)
	fmt.Fprintf(&b, "learn passes:  %d\n", r.LearnPasses)
	if r.PrefixChanged {
		fmt.Fprintf(&b, "token prefix:  %q (the input already contained text that looks like tokens)\n", r.Prefix)
	}
	fmt.Fprintf(&b, "replacements:")
	any := false
	for _, k := range vault.Kinds {
		if n := r.Replaced[k]; n > 0 {
			fmt.Fprintf(&b, " %s=%d", k.Prefix(), n)
			any = true
		}
	}
	if !any {
		b.WriteString(" none")
	}
	fmt.Fprintf(&b, "\nnew values:   ")
	for _, k := range vault.Kinds {
		if n := r.NewEntries[k]; n > 0 {
			fmt.Fprintf(&b, " %s=%d", k.Prefix(), n)
		}
	}
	fmt.Fprintf(&b, "  (map total %d)\n", r.TotalEntries)
	if skipped > 0 {
		b.WriteString("skipped binary files (not copied to the output; parse them to CSV first, e.g. EvtxECmd / RECmd / MFTECmd):\n")
		n := 0
		for _, f := range r.Files {
			if !f.Skipped {
				continue
			}
			if maxSkipped >= 0 && n == maxSkipped {
				fmt.Fprintf(&b, "  ... and %d more (all listed in ANONYMIZATION_REPORT.txt)\n", skipped-n)
				break
			}
			fmt.Fprintf(&b, "  - %s\n", f.Out)
			n++
		}
	}
	if r.LeakCount == 0 {
		b.WriteString("verify:        OK - no known original value found in the output\n")
	} else {
		fmt.Fprintf(&b, "verify:        FAILED - %d occurrence(s) of original values remain:\n", r.LeakCount)
		for _, l := range r.Leaks {
			fmt.Fprintf(&b, "  - %s:%d  %s (%s)\n", l.File, l.Line, l.Token, l.Kind)
		}
	}
	fmt.Fprintf(&b, "time:          %s\n", r.Duration.Round(time.Millisecond))
	if withDomains && len(r.KeptDomains) > 0 {
		b.WriteString("\ndomains kept in clear text (external domains are kept as IOCs).\n")
		b.WriteString("If one of these is your organisation's, add it to sensitive_terms and run again:\n")
		for _, d := range r.KeptDomains {
			fmt.Fprintf(&b, "  %9d  %s\n", d.Count, d.Domain)
		}
		if r.NoTerms {
			b.WriteString("(no sensitive terms were set: names that appear only in URLs or free text cannot be recognised)\n")
		}
	}
	return b.String()
}

func writeReportFile(path string, r *Report) error {
	var b strings.Builder
	b.WriteString("log_anonimizer report\n=====================\n")
	fmt.Fprintf(&b, "created: %s\n", time.Now().UTC().Format(time.RFC3339))
	cp := *r
	cp.Output = filepath.Base(r.Output)
	b.WriteString(formatReport(&cp, -1, false))
	b.WriteString("\nTokens look like HOST_0001, USER_0001, IP_0001 (internal), EXTIP_0001 (public).\n")
	b.WriteString("The same original value always has the same token across all files.\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
