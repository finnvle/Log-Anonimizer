// Package tui is the interactive wizard: options are picked with arrow keys
// and checkboxes instead of typed as flags.
package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"log_anonimizer/internal/anon"
	"log_anonimizer/internal/app"
	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

// Options configures Run.
type Options struct {
	In      *os.File  // terminal input, switched to raw mode
	Out     io.Writer // where the wizard draws (stderr, so stdout stays clean)
	Command string    // program name shown in the equivalent command

	// Reader replaces In for tests: keys are read from it and the terminal
	// mode is left alone.
	Reader io.Reader
	Width  int
	Getenv func(string) string
}

type wizard struct {
	u       *ui
	o       Options
	fd      int
	raw     *term.State
	undoCon func()
	isTerm  bool
}

// Run starts the wizard and returns the process exit code.
func Run(o Options) int {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Command == "" {
		o.Command = "log_anonimizer"
	}
	w := &wizard{o: o, undoCon: func() {}}
	r := o.Reader
	width := o.Width
	if r == nil {
		w.isTerm = true
		w.fd = int(o.In.Fd())
		r = o.In
		if f, ok := o.Out.(*os.File); ok {
			w.undoCon = setupConsole(f)
			if cw, _, err := term.GetSize(int(f.Fd())); err == nil {
				width = cw
			}
		}
		if err := w.enterRaw(); err != nil {
			fmt.Fprintln(o.Out, "cannot use the terminal:", err)
			return 1
		}
	}
	if width <= 0 {
		width = 100
	}
	w.u = &ui{keys: newKeyReader(r), out: o.Out, width: width}
	defer func() {
		w.leaveRaw()
		w.undoCon()
	}()

	w.u.println(sBold + "log_anonimizer " + app.Version + sReset + sDim + "   Ctrl+C to quit" + sReset)
	choice, err := w.u.selectOne("What do you want to do?", []string{
		"Anonymize a file or folder",
		"De-anonymize (restore real values) with a map",
		"Verify an anonymized file or folder",
		"Show what each token stands for",
		"Quit",
	}, 0)
	if err != nil {
		return w.cancelled(err)
	}
	switch choice {
	case 0:
		return w.anonymize()
	case 1:
		return w.restore()
	case 2:
		return w.verify()
	case 3:
		return w.show()
	}
	return 0
}

func (w *wizard) enterRaw() error {
	if !w.isTerm || w.raw != nil {
		return nil
	}
	st, err := term.MakeRaw(w.fd)
	if err != nil {
		return err
	}
	w.raw = st
	return nil
}

func (w *wizard) leaveRaw() {
	if w.raw != nil {
		term.Restore(w.fd, w.raw)
		w.raw = nil
	}
}

func (w *wizard) cancelled(err error) int {
	w.leaveRaw()
	if errors.Is(err, errCancel) || errors.Is(err, io.EOF) {
		fmt.Fprintln(w.o.Out, "\ncancelled")
		return 130
	}
	fmt.Fprintln(w.o.Out, "\nerror:", err)
	return 1
}

// say prints a message, in raw mode or not.
func (w *wizard) say(s string) {
	if w.raw != nil {
		w.u.println(s)
	} else {
		fmt.Fprintln(w.o.Out, s)
	}
}

func either(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func mustExist(p string) error {
	if p == "" {
		return errors.New("required")
	}
	if _, err := os.Stat(p); err != nil {
		return errors.New("not found")
	}
	return nil
}

func mustBeFile(p string) error {
	st, err := os.Stat(p)
	if err != nil {
		return errors.New("not found")
	}
	if st.IsDir() {
		return errors.New("this is a folder, a map is a file")
	}
	return nil
}

// --- anonymize -------------------------------------------------------------

type toggleItem struct {
	label string
	field *bool
}

func toggleItems(t *profile.Toggles) []toggleItem {
	return []toggleItem{
		{"Internal IP addresses (10.x, 172.16-31.x, 192.168.x, fe80::)", &t.InternalIP},
		{"Public IP addresses (untick to keep them as IOCs)", &t.PublicIP},
		{"Hostnames", &t.Hostname},
		{"Domains (internal DNS and NetBIOS)", &t.Domain},
		{"Usernames and e-mail accounts", &t.User},
		{"MAC addresses", &t.MAC},
		{"Windows SIDs (domain part)", &t.SID},
		{"Passwords, tokens, cookies, API keys", &t.Secrets},
		{"Device IDs (ActiveSync DeviceId, IMEI)", &t.DeviceID},
		{"Card numbers (Luhn-checked)", &t.CardNumber},
		{"Thai national ID numbers (checksum-checked)", &t.NationalID},
		{"Phone numbers (Thai and +country)", &t.Phone},
		{"File and folder names in the output", &t.FileNames},
	}
}

// pickProfile uses the default profile (creating default.yaml on first use)
// and asks only when the user has saved other profiles.
func (w *wizard) pickProfile() (*profile.Profile, string, error) {
	profile.EnsureDefault()
	names, err := profile.List()
	if err != nil || len(names) <= 1 {
		p, err := profile.Load("default")
		if err != nil {
			return profile.Default(), "", nil
		}
		return p, "default", nil
	}
	opts := []string{"default"}
	for _, n := range names {
		if n != "default" {
			opts = append(opts, n)
		}
	}
	i, err := w.u.selectOne("Profile", opts, 0)
	if err != nil {
		return nil, "", err
	}
	p, err := profile.Load(opts[i])
	return p, opts[i], err
}

func (w *wizard) newPassphrase() (string, error) {
	if env := w.o.Getenv(app.PassEnv); env != "" {
		w.u.println(sDim + "  using the passphrase from " + app.PassEnv + sReset)
		return env, nil
	}
	p1, err := w.u.input("Map passphrase", inputOpts{mask: true, validate: func(s string) error {
		if len(s) < app.MinPassphrase {
			return fmt.Errorf("at least %d characters", app.MinPassphrase)
		}
		return nil
	}})
	if err != nil {
		return "", err
	}
	_, err = w.u.input("Repeat passphrase", inputOpts{mask: true, validate: func(s string) error {
		if s != p1 {
			return errors.New("does not match")
		}
		return nil
	}})
	return p1, err
}

func (w *wizard) existingPassphrase(mapPath string) (string, error) {
	info, err := vault.Stat(mapPath)
	if err != nil {
		return "", err
	}
	if !info.Encrypted {
		return "", nil
	}
	try := func(s string) error {
		_, _, err := vault.Load(mapPath, func() ([]byte, error) { return []byte(s), nil })
		return err
	}
	if env := w.o.Getenv(app.PassEnv); env != "" && try(env) == nil {
		w.u.println(sDim + "  using the passphrase from " + app.PassEnv + sReset)
		return env, nil
	}
	return w.u.input("Map passphrase", inputOpts{mask: true, validate: func(s string) error {
		if try(s) != nil {
			return errors.New("wrong passphrase")
		}
		return nil
	}})
}

func sameOptions(a, b *profile.Profile) bool {
	if a.Anonymize != b.Anonymize || a.EncryptMap != b.EncryptMap || len(a.SensitiveTerms) != len(b.SensitiveTerms) {
		return false
	}
	for i := range a.SensitiveTerms {
		if a.SensitiveTerms[i] != b.SensitiveTerms[i] {
			return false
		}
	}
	return true
}

func (w *wizard) anonymize() int {
	u := w.u
	in, err := u.input("Input file or folder", inputOpts{path: true, validate: mustExist})
	if err != nil {
		return w.cancelled(err)
	}
	base, profName, err := w.pickProfile()
	if err != nil {
		return w.cancelled(err)
	}
	prof := base.Clone()

	tis := toggleItems(&prof.Anonymize)
	items := make([]checkItem, len(tis))
	for i, t := range tis {
		items[i] = checkItem{label: t.label, on: *t.field}
	}
	if items, err = u.multiSelect("What should be anonymized?", items); err != nil {
		return w.cancelled(err)
	}
	for i, t := range tis {
		*t.field = items[i].on
	}

	termsDef := strings.Join(prof.SensitiveTerms, ", ")
	termsStr, err := u.input("Sensitive terms",
		inputOpts{def: termsDef, shown: termsDef, hint: "org names, project codes, internal domains · e.g. acme, acme.co.th · - = none",
			validate: func(s string) error {
				if s == "-" {
					return nil
				}
				for _, t := range profile.ParseTerms(s) {
					if len(t) < 3 {
						return fmt.Errorf("%q is shorter than 3 characters", t)
					}
				}
				return nil
			}})
	if err != nil {
		return w.cancelled(err)
	}
	if termsStr == "-" {
		prof.SensitiveTerms = nil
	} else {
		prof.SensitiveTerms = profile.ParseTerms(termsStr)
	}
	if len(prof.SensitiveTerms) == 0 {
		u.println(sYellow + "  ! no sensitive terms: your organisation's names in URLs and text may stay visible" + sReset)
	}

	mapChoice, err := u.selectOne("Map file", []string{
		"Create a new map",
		"Extend an existing map (values seen before keep their tokens)",
	}, 0)
	if err != nil {
		return w.cancelled(err)
	}
	var mapPath, pass string
	encrypt := prof.EncryptMap
	if mapChoice == 1 {
		if mapPath, err = u.input("Existing map file", inputOpts{path: true, validate: mustBeFile}); err != nil {
			return w.cancelled(err)
		}
		if pass, err = w.existingPassphrase(mapPath); err != nil {
			return w.cancelled(err)
		}
		encrypt = pass != ""
	} else {
		def := 0
		if !encrypt {
			def = 1
		}
		c, err := u.selectOne("Protect the map with a passphrase?", []string{
			"Yes (recommended)",
			"No - plain JSON: anyone with the file can restore the real values",
		}, def)
		if err != nil {
			return w.cancelled(err)
		}
		encrypt = c == 0
		if encrypt {
			if pass, err = w.newPassphrase(); err != nil {
				return w.cancelled(err)
			}
		}
	}
	prof.EncryptMap = encrypt

	out, err := u.input("Output path", inputOpts{shown: "automatic, next to the input", path: true})
	if err != nil {
		return w.cancelled(err)
	}

	saveName := ""
	if profName == "" || !sameOptions(prof, base) {
		saveName, err = u.input("Save as profile", inputOpts{shown: "don't save", hint: "a name such as acme, to reuse these options with -p acme",
			validate: func(s string) error {
				if s != "" && !profile.ValidName(s) {
					return errors.New("use letters, digits, - _ .")
				}
				return nil
			}})
		if err != nil {
			return w.cancelled(err)
		}
	}
	ok, err := u.confirm("Start anonymizing?", true)
	if err != nil || !ok {
		if err == nil {
			err = errCancel
		}
		return w.cancelled(err)
	}
	// effective is the profile the equivalent command line will load
	effective := base
	if saveName != "" {
		path, err := profile.Save(prof, saveName)
		if err != nil {
			return w.cancelled(err)
		}
		w.say(sDim + "  profile saved: " + anon.ShortPath(path) + sReset)
		profName, effective = saveName, prof
	} else if !sameOptions(prof, base) {
		profName = ""
		if d, err := profile.Load("default"); err == nil {
			effective = d
		} else {
			effective = profile.Default()
		}
	}

	w.leaveRaw()
	opts := app.AnonOptions{
		Input: in, Output: out, Map: mapPath, Profile: prof, Encrypt: encrypt,
		Pass: app.Passphrases{Env: pass}, Progress: w.o.Out,
	}
	res, err := app.Anonymize(opts)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		fmt.Fprintln(w.o.Out, err)
		if w.enterRaw() == nil {
			again, cerr := u.confirm("Overwrite the existing output and map?", false)
			w.leaveRaw()
			if cerr != nil || !again {
				return w.cancelled(errCancel)
			}
			opts.Force = true
			res, err = app.Anonymize(opts)
		}
	}
	if err != nil {
		return w.cancelled(err)
	}
	fmt.Fprint(w.o.Out, "\n"+app.FormatAnon(res))

	cmd := []string{w.o.Command, "-a", app.Quote(in)}
	if profName != "" && profName != "default" {
		cmd = append(cmd, "-p", app.Quote(profName))
	}
	if mapPath != "" {
		cmd = append(cmd, "-m", app.Quote(mapPath))
	}
	if out != "" {
		cmd = append(cmd, "-o", app.Quote(out))
	}
	if !encrypt && mapPath == "" && effective.EncryptMap {
		cmd = append(cmd, "-no-encrypt")
	}
	fmt.Fprintln(w.o.Out, "\nSame run from the command line:")
	fmt.Fprintln(w.o.Out, "  "+strings.Join(cmd, " "))
	if profName == "" && !sameOptions(prof, effective) {
		fmt.Fprintln(w.o.Out, "  (options not saved, so this command uses the default profile)")
	}
	if res.Report.LeakCount > 0 {
		return 3
	}
	return 0
}

// --- restore ---------------------------------------------------------------

func (w *wizard) restore() int {
	u := w.u
	in, err := u.input("File or folder to restore", inputOpts{path: true, hint: "anonymized output, or any text with tokens such as a report", validate: mustExist})
	if err != nil {
		return w.cancelled(err)
	}
	def := app.FindMap(in)
	mapPath, err := u.input("Map file", inputOpts{def: def, path: true, validate: mustBeFile})
	if err != nil {
		return w.cancelled(err)
	}
	pass, err := w.existingPassphrase(mapPath)
	if err != nil {
		return w.cancelled(err)
	}
	out, err := u.input("Output path", inputOpts{shown: "automatic, next to the input", path: true})
	if err != nil {
		return w.cancelled(err)
	}
	force := false
	target := out
	if target == "" {
		st, _ := os.Stat(in)
		target = anon.DefaultRestoreOutput(in, st != nil && st.IsDir())
	}
	if _, err := os.Stat(target); err == nil {
		if force, err = u.confirm(target+" exists. Overwrite?", false); err != nil || !force {
			return w.cancelled(errCancel)
		}
	}
	w.leaveRaw()
	rep, err := app.Restore(in, out, mapPath, app.Passphrases{Env: pass}, force)
	if err != nil {
		return w.cancelled(err)
	}
	fmt.Fprint(w.o.Out, "\n"+app.FormatRestore(rep))
	cmd := []string{w.o.Command, "-d", app.Quote(in), "-m", app.Quote(mapPath)}
	if out != "" {
		cmd = append(cmd, "-o", app.Quote(out))
	}
	fmt.Fprintln(w.o.Out, "\nSame run from the command line:\n  "+strings.Join(cmd, " "))
	return 0
}

// --- verify ----------------------------------------------------------------

func (w *wizard) verify() int {
	u := w.u
	path, err := u.input("Anonymized file or folder", inputOpts{path: true, validate: mustExist})
	if err != nil {
		return w.cancelled(err)
	}
	def := app.FindMap(path)
	mapPath, err := u.input("Map file", inputOpts{def: def, shown: either(def == "", "none - detectors only", def), path: true,
		hint: "with a map, every known real value is searched for",
		validate: func(s string) error {
			if s == "" {
				return nil
			}
			return mustBeFile(s)
		}})
	if err != nil {
		return w.cancelled(err)
	}
	pass := ""
	if mapPath != "" {
		if pass, err = w.existingPassphrase(mapPath); err != nil {
			return w.cancelled(err)
		}
	}
	prof, _, err := w.pickProfile()
	if err != nil {
		return w.cancelled(err)
	}
	w.leaveRaw()
	rep, err := app.Verify(path, mapPath, prof, app.Passphrases{Env: pass})
	if err != nil {
		return w.cancelled(err)
	}
	fmt.Fprint(w.o.Out, "\n"+anon.FormatVerify(rep, mapPath != ""))
	if rep.LeakCount > 0 {
		return 3
	}
	return 0
}

// --- show ------------------------------------------------------------------

func (w *wizard) show() int {
	u := w.u
	target, err := u.input("Map or anonymized file", inputOpts{path: true, hint: "a .anonmap, or an anonymized file or folder (its map is found next to it)", validate: mustExist})
	if err != nil {
		return w.cancelled(err)
	}
	mapPath := ""
	if _, err := vault.Stat(target); err == nil {
		mapPath = target
	} else {
		def := app.FindMap(target)
		if mapPath, err = u.input("Map file", inputOpts{def: def, path: true, validate: mustBeFile}); err != nil {
			return w.cancelled(err)
		}
	}
	pass, err := w.existingPassphrase(mapPath)
	if err != nil {
		return w.cancelled(err)
	}
	find, err := u.input("Filter", inputOpts{shown: "show everything", hint: "only tokens or values containing this text, e.g. somchai or HOST_0003"})
	if err != nil {
		return w.cancelled(err)
	}
	w.leaveRaw()
	m := mapPath
	if m == target {
		m = ""
	}
	res, err := app.Show(target, m, find, app.Passphrases{Env: pass})
	if err != nil {
		return w.cancelled(err)
	}
	fmt.Fprint(w.o.Out, "\n"+app.FormatShow(res))
	cmd := []string{w.o.Command, "-show", app.Quote(target)}
	if m != "" && m != app.FindMap(target) {
		cmd = append(cmd, "-m", app.Quote(m))
	}
	if find != "" {
		cmd = append(cmd, "-find", app.Quote(find))
	}
	fmt.Fprintln(w.o.Out, "\nSame from the command line:\n  "+strings.Join(cmd, " "))
	return 0
}
