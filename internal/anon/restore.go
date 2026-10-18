package anon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"log_anonimizer/internal/vault"
)

// RestoreReport summarises a de-anonymization.
type RestoreReport struct {
	Output        string
	Files         int
	Replaced      int
	Unknown       int
	UnknownTokens []string
}

func (r *RestoreReport) unknown(tok string) {
	r.Unknown++
	if len(r.UnknownTokens) < 20 {
		for _, t := range r.UnknownTokens {
			if t == tok {
				return
			}
		}
		r.UnknownTokens = append(r.UnknownTokens, tok)
	}
}

// RestoreString replaces every known token in s with its original value.
func RestoreString(s string, v *vault.Vault, rep *RestoreReport) string {
	re := v.TokenPattern()
	ms := re.FindAllStringIndex(s, -1)
	if len(ms) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range ms {
		if !vault.IsTokenStart(s, m[0]) {
			continue
		}
		tok := s[m[0]:m[1]]
		e, n, ok := v.Resolve(tok)
		if !ok {
			if rep != nil {
				rep.unknown(tok)
			}
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(e.Original)
		last = m[0] + n
		if rep != nil {
			rep.Replaced++
		}
	}
	b.WriteString(s[last:])
	return b.String()
}

// DefaultRestoreOutput: x.anon.csv -> x.restored.csv, report.md ->
// report.restored.md, logs.anon -> logs.restored.
func DefaultRestoreOutput(input string, isDir bool) string {
	dir, base := filepath.Split(filepath.Clean(input))
	if isDir {
		return filepath.Join(dir, strings.TrimSuffix(base, ".anon")+".restored")
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(strings.TrimSuffix(base, ext), ".anon")
	return filepath.Join(dir, stem+".restored"+ext)
}

// Restore de-anonymizes a file or directory with the vault.
func Restore(input, output string, v *vault.Vault, force bool) (*RestoreReport, error) {
	jobs, isDir, err := collect(input)
	if err != nil {
		return nil, err
	}
	if output == "" {
		output = DefaultRestoreOutput(input, isDir)
	}
	if exists(output) && !force {
		return nil, fmt.Errorf("%s already exists (use -f to overwrite)", output)
	}
	rep := &RestoreReport{Output: output}
	for _, j := range jobs {
		dst := output
		if isDir {
			dst = filepath.Join(output, filepath.FromSlash(RestoreString(j.rel, v, rep)))
		}
		if err := restoreFile(j.abs, dst, v, rep); err != nil {
			return nil, fmt.Errorf("%s: %w", j.rel, err)
		}
		rep.Files++
	}
	return rep, nil
}

func restoreFile(src, dst string, v *vault.Vault, rep *RestoreReport) error {
	typ, enc, err := sniff(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if typ == ftBinary {
		return copyFile(src, dst)
	}
	if typ == ftCSV {
		snapshot := *rep
		snapshot.UnknownTokens = append([]string(nil), rep.UnknownTokens...)
		if err := writeRestored(src, dst, enc, true, v, rep); err == nil {
			return nil
		}
		*rep = snapshot // not parseable as CSV: start over as text
	}
	return writeRestored(src, dst, enc, false, v, rep)
}

func writeRestored(src, dst string, enc textEncoding, asCSV bool, v *vault.Vault, rep *RestoreReport) error {
	r, closeFn, err := openText(src, enc)
	if err != nil {
		return err
	}
	defer closeFn()
	tmp := dst + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	if enc != encUTF8 {
		w.Write(bomUTF8)
	}
	if asCSV {
		err = restoreCSV(r, w, csvComma(src), v, rep)
	} else {
		err = eachLine(r, func(body, eol string) error {
			w.WriteString(RestoreString(body, v, rep))
			_, err := w.WriteString(eol)
			return err
		})
	}
	if ferr := w.Flush(); err == nil {
		err = ferr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// restoreCSV writes fields with proper quoting, so originals that contain
// quotes or commas cannot break the CSV structure.
func restoreCSV(r io.Reader, w *bufio.Writer, comma rune, v *vault.Vault, rep *RestoreReport) error {
	br, peek := peekReader(r)
	format := detectCSVFormat(peek, comma)
	cr := newCSVReader(br, comma)
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for i, f := range rec {
			rec[i] = RestoreString(f, v, rep)
		}
		if err := writeCSVRecord(w, format, rec); err != nil {
			return err
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
