// Package app runs the three operations (anonymize, restore, verify). The
// command line and the interactive wizard both call it.
package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"log_anonimizer/internal/anon"
	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

// Version of the tool.
const Version = "0.2.3"

// PassEnv is the environment variable that holds the map passphrase.
const PassEnv = "LOGANON_PASSPHRASE"

// MinPassphrase is the minimum length of a new passphrase.
const MinPassphrase = 8

// MaxTries is how often a typed passphrase may be wrong before giving up.
const MaxTries = 3

// Passphrases supplies map passphrases from the environment or a prompt.
// Typed passphrases are asked again, up to MaxTries times, when they are
// empty, too short, do not match, or do not open the map.
type Passphrases struct {
	Env    string                              // value of LOGANON_PASSPHRASE
	Prompt func(prompt string) ([]byte, error) // nil when not interactive
	Notice func(msg string)                    // shows why a passphrase is asked again
}

func (p Passphrases) notice(msg string) {
	if p.Notice != nil {
		p.Notice(msg)
	}
}

func tryAgain(msg string, tries int) string {
	if left := MaxTries - tries; left > 1 {
		return fmt.Sprintf("%s, try again (%d tries left)", msg, left)
	}
	return msg + ", try again (last try)"
}

// Existing returns the passphrase of an existing map. Use LoadMap to also
// re-ask when the passphrase is wrong.
func (p Passphrases) Existing() ([]byte, error) {
	tries := 0
	return p.existing(&tries)
}

func (p Passphrases) existing(tries *int) ([]byte, error) {
	if p.Env != "" {
		return []byte(p.Env), nil
	}
	if p.Prompt == nil {
		return nil, fmt.Errorf("%w (set %s or run in a terminal)", vault.ErrNeedPassphrase, PassEnv)
	}
	for {
		*tries++
		b, err := p.Prompt("Map passphrase: ")
		if err != nil || len(b) > 0 {
			return b, err
		}
		if *tries >= MaxTries {
			return nil, errors.New("no passphrase entered")
		}
		p.notice(tryAgain("empty passphrase: type the one you chose when the map was made", *tries))
	}
}

// New returns a passphrase for a new map, asking twice when prompting.
func (p Passphrases) New() ([]byte, error) {
	if p.Env != "" {
		if len(p.Env) < MinPassphrase {
			return nil, fmt.Errorf("%s must be at least %d characters", PassEnv, MinPassphrase)
		}
		return []byte(p.Env), nil
	}
	if p.Prompt == nil {
		return nil, fmt.Errorf("a passphrase is needed to encrypt the map: set %s, run in a terminal, or use -no-encrypt", PassEnv)
	}
	for tries := 1; ; tries++ {
		a, err := p.Prompt(fmt.Sprintf("New map passphrase (min %d chars): ", MinPassphrase))
		if err != nil {
			return nil, err
		}
		var msg string
		switch {
		case len(a) == 0:
			msg = "empty passphrase: the map needs one to stay private (or run with -no-encrypt)"
		case len(a) < MinPassphrase:
			msg = fmt.Sprintf("too short: use at least %d characters", MinPassphrase)
		default:
			b, err := p.Prompt("Repeat passphrase: ")
			if err != nil {
				return nil, err
			}
			if string(a) == string(b) {
				return a, nil
			}
			msg = "the two passphrases do not match"
		}
		if tries >= MaxTries {
			return nil, errors.New(msg)
		}
		p.notice(tryAgain(msg, tries))
	}
}

// load opens a map, asking again when a typed passphrase is wrong.
func load(path string, p Passphrases) (*vault.Vault, []byte, error) {
	tries := 0
	for {
		v, used, err := vault.Load(path, func() ([]byte, error) { return p.existing(&tries) })
		if errors.Is(err, vault.ErrWrongPassphrase) && p.Env == "" && p.Prompt != nil && tries < MaxTries {
			p.notice(tryAgain("wrong passphrase", tries))
			continue
		}
		return v, used, err
	}
}

// AnonOptions configures Anonymize.
type AnonOptions struct {
	Input, Output string
	Map           string // existing map to extend, or where to write the new one ("" = next to output)
	Profile       *profile.Profile
	Encrypt       bool
	Force         bool
	Pass          Passphrases
	Progress      io.Writer
}

// AnonResult is the outcome of Anonymize.
type AnonResult struct {
	Report    *anon.Report
	MapPath   string
	MapReused bool
	Encrypted bool
}

// Anonymize runs a full anonymization and saves the map.
func Anonymize(o AnonOptions) (*AnonResult, error) {
	if _, err := os.Stat(o.Input); err != nil {
		return nil, err
	}
	res := &AnonResult{}
	v := vault.New()
	var pass []byte
	if o.Map != "" && fileExists(o.Map) {
		var err error
		v, pass, err = load(o.Map, o.Pass)
		if err != nil {
			return nil, err
		}
		res.MapReused = true
		res.MapPath = o.Map
	} else if o.Encrypt {
		var err error
		if pass, err = o.Pass.New(); err != nil {
			return nil, err
		}
	}
	res.Encrypted = len(pass) > 0

	eng, err := anon.NewEngine(o.Profile, v)
	if err != nil {
		return nil, err
	}
	eng.Progress = o.Progress
	eng.BeforeWrite = func(output string) error {
		if res.MapPath == "" {
			res.MapPath = o.Map
			if res.MapPath == "" {
				res.MapPath = anon.MapPathFor(output)
			}
		}
		if !res.MapReused && fileExists(res.MapPath) && !o.Force {
			return fmt.Errorf("map %s already exists (use -m to extend it, or -f to overwrite)", res.MapPath)
		}
		if same(res.MapPath, output) {
			return errors.New("the map must not be written over the output")
		}
		return nil
	}
	rep, err := eng.Anonymize(o.Input, o.Output, o.Force)
	if err != nil {
		return nil, err
	}
	res.Report = rep
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	v.AddSource(vault.Source{Input: abs(o.Input), Output: abs(rep.Output), SHA256: rep.InputSHA256})
	if err := vault.Save(res.MapPath, v, pass); err != nil {
		return nil, fmt.Errorf("output written but saving the map failed: %w", err)
	}
	return res, nil
}

// LoadMap opens a map, asking for the passphrase if needed.
func LoadMap(path string, p Passphrases) (*vault.Vault, error) {
	v, _, err := load(path, p)
	return v, err
}

// FindMap returns the map that belongs to an anonymized path, if it exists.
func FindMap(anonPath string) string {
	m := anon.MapPathFor(anonPath)
	if fileExists(m) {
		return m
	}
	return ""
}

// Restore de-anonymizes input.
func Restore(input, output, mapPath string, pass Passphrases, force bool) (*anon.RestoreReport, error) {
	if mapPath == "" {
		if mapPath = FindMap(input); mapPath == "" {
			return nil, fmt.Errorf("no map found next to %s: give it with -m <file.anonmap>", input)
		}
	}
	v, err := LoadMap(mapPath, pass)
	if err != nil {
		return nil, err
	}
	return anon.Restore(input, output, v, force)
}

// Verify checks an anonymized file or folder.
func Verify(path, mapPath string, p *profile.Profile, pass Passphrases) (*anon.VerifyReport, error) {
	var v *vault.Vault
	if mapPath != "" {
		var err error
		if v, err = LoadMap(mapPath, pass); err != nil {
			return nil, err
		}
	}
	return anon.Verify(path, v, p)
}

// FormatAnon renders the result of Anonymize.
func FormatAnon(r *AnonResult) string {
	var b strings.Builder
	b.WriteString(anon.FormatReport(r.Report))
	state := "encrypted"
	if !r.Encrypted {
		state = "NOT encrypted"
	}
	if r.MapReused {
		state += ", updated"
	}
	fmt.Fprintf(&b, "map       %s  (%s; keep it private, never share it)\n", anon.ShortPath(r.MapPath), state)
	return b.String()
}

// FormatRestore renders the result of Restore.
func FormatRestore(r *anon.RestoreReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "output    %s\n", anon.ShortPath(r.Output))
	fmt.Fprintf(&b, "restored  %d tokens\n", r.Replaced)
	if r.Unknown > 0 {
		fmt.Fprintf(&b, "unknown   %s (not in this map, left as-is)\n", strings.Join(r.UnknownTokens, ", "))
	}
	return b.String()
}

// Quote quotes a path for the equivalent command line when needed.
func Quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'$&|;<>()*?[]#~`!{}\\") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func same(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && aa == bb
}
