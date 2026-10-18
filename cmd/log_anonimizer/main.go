// Command log_anonimizer replaces sensitive values in logs with tokens and
// restores them with the matching map file.
//
//	log_anonimizer                         interactive wizard
//	log_anonimizer -a <file|dir>           anonymize
//	log_anonimizer -d <file|dir> -m <map>  restore (de-anonymize)
//	log_anonimizer -verify <file|dir>      check anonymized output
//	log_anonimizer -show <map|file|dir>    show what each token stands for
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"log_anonimizer/internal/anon"
	"log_anonimizer/internal/app"
	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/tui"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	exitLeak  = 3 // verification found original values in the output
)

func main() {
	e := newEnv()
	restore := func() {}
	if e.color {
		restore = tui.SetupConsole(os.Stderr)
	}
	code := run(os.Args[1:], e)
	restore()
	os.Exit(code)
}

// env is everything run needs from the outside world, so tests can fake it.
type env struct {
	stdin       *os.File
	stdout      io.Writer
	stderr      io.Writer
	getenv      func(string) string
	interactive bool
	color       bool // stderr is a terminal that shows colours
	prompt      func(prompt string) ([]byte, error)
}

func newEnv() *env {
	e := &env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv}
	e.interactive = term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
	e.color = term.IsTerminal(int(os.Stderr.Fd())) && os.Getenv("NO_COLOR") == ""
	if e.interactive {
		e.prompt = func(p string) ([]byte, error) {
			fmt.Fprint(os.Stderr, p)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return b, err
		}
	}
	return e
}

const usage = `log_anonimizer %s - replace sensitive values in logs with tokens

Usage:
  log_anonimizer                         interactive wizard (pick options with checkboxes)
  log_anonimizer -a <file|dir> [options] anonymize
  log_anonimizer -d <file|dir> [options] de-anonymize with the matching map
  log_anonimizer -verify <file|dir>      check anonymized output (add -m to check every known value)
  log_anonimizer -show <map>             show what each token stands for
  log_anonimizer -show <anon file|dir>   ... only the tokens used in that output (map next to it, or -m)

Options:
  -o <path>       output file or folder (default: next to the input,
                  name.anon.csv / name.restored.csv / folder.anon)
  -m <map>        map file. With -a: an existing map is extended so the same
                  values keep the same tokens; default is name.anonmap next to
                  the output. With -d: default is the map next to the input.
  -find <text>    with -show: only tokens or values that contain the text
  -p <profile>    profile name or .yaml file (default "default")
  -no-encrypt     write the map as plain JSON (not recommended)
  -f              overwrite existing output and map
  -q              no progress messages
  -profiles       list saved profiles
  -print-profile  print the effective profile as YAML (save it, edit it, use -p file.yaml)
  -version        print the version

Environment:
  LOGANON_PASSPHRASE   map passphrase (otherwise you are asked for it)
  LOGANON_PROFILE_DIR  where named profiles are stored

Exit codes: 0 ok, 1 error, 2 usage, 3 original values found in the output.
`

func run(args []string, e *env) int {
	fs := flag.NewFlagSet("log_anonimizer", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.Usage = func() { fmt.Fprintf(e.stderr, usage, app.Version) }
	var (
		aIn, dIn, vIn, sIn    string
		find                  string
		out, mapPath, profArg string
		noEncrypt, force      bool
		quiet, listProfiles   bool
		printProfile, showVer bool
		interactive           bool
	)
	fs.StringVar(&aIn, "a", "", "")
	fs.StringVar(&dIn, "d", "", "")
	fs.StringVar(&vIn, "verify", "", "")
	fs.StringVar(&sIn, "show", "", "")
	fs.StringVar(&find, "find", "", "")
	fs.StringVar(&out, "o", "", "")
	fs.StringVar(&mapPath, "m", "", "")
	fs.StringVar(&profArg, "p", "default", "")
	fs.BoolVar(&noEncrypt, "no-encrypt", false, "")
	fs.BoolVar(&force, "f", false, "")
	fs.BoolVar(&quiet, "q", false, "")
	fs.BoolVar(&listProfiles, "profiles", false, "")
	fs.BoolVar(&printProfile, "print-profile", false, "")
	fs.BoolVar(&showVer, "version", false, "")
	fs.BoolVar(&interactive, "i", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(e.stderr, "unexpected argument %q (put the path right after -a, -d, -verify or -show)\n", fs.Arg(0))
		return exitUsage
	}

	if showVer {
		fmt.Fprintln(e.stdout, "log_anonimizer", app.Version)
		return exitOK
	}
	if listProfiles {
		names, err := profile.List()
		if err != nil {
			return fail(e, err)
		}
		dir, _ := profile.Dir()
		fmt.Fprintf(e.stdout, "profiles in %s:\n", anon.ShortPath(dir))
		hasDefault := false
		for _, n := range names {
			hasDefault = hasDefault || n == "default"
		}
		if !hasDefault {
			fmt.Fprintln(e.stdout, "  default (built-in, created on the first -a run)")
		}
		for _, n := range names {
			fmt.Fprintf(e.stdout, "  %s\n", n)
		}
		return exitOK
	}

	modes := 0
	for _, s := range []string{aIn, dIn, vIn, sIn} {
		if s != "" {
			modes++
		}
	}
	if modes == 0 && !printProfile {
		if interactive || len(args) == 0 {
			if !e.interactive {
				fs.Usage()
				return exitUsage
			}
			return tui.Run(tui.Options{In: e.stdin, Out: e.stderr, Command: "log_anonimizer"})
		}
		fs.Usage()
		return exitUsage
	}
	if modes > 1 {
		fmt.Fprintln(e.stderr, "use only one of -a, -d, -verify and -show")
		return exitUsage
	}

	pGiven := false
	fs.Visit(func(f *flag.Flag) { pGiven = pGiven || f.Name == "p" })
	if aIn != "" && !pGiven {
		// new users rarely know about profiles: give them a default one to edit
		path, created, err := profile.EnsureDefault()
		switch {
		case err != nil:
			warn(e, "no -p given: using the built-in default profile")
		case created:
			warn(e, "no -p given: created and using the default profile "+anon.ShortPath(path))
		default:
			warn(e, "no -p given: using the default profile "+anon.ShortPath(path))
		}
	}
	prof, err := profile.Load(profArg)
	if err != nil {
		return fail(e, err)
	}
	if aIn != "" && len(prof.SensitiveTerms) == 0 {
		warn(e, "no sensitive_terms in the profile: your organisation's names in URLs and text may stay visible")
	}
	if printProfile {
		data, err := profile.Marshal(prof)
		if err != nil {
			return fail(e, err)
		}
		e.stdout.Write(data)
		return exitOK
	}

	pass := app.Passphrases{Env: e.getenv(app.PassEnv), Prompt: e.prompt}
	var progress io.Writer = e.stderr
	st := &statusLine{w: e.stderr}
	if e.color {
		progress = st
	}
	if quiet {
		progress = nil
	}

	switch {
	case aIn != "":
		res, err := app.Anonymize(app.AnonOptions{
			Input: aIn, Output: out, Map: mapPath, Profile: prof,
			Encrypt: prof.EncryptMap && !noEncrypt, Force: force, Pass: pass, Progress: progress,
		})
		st.clear()
		if err != nil {
			return fail(e, err)
		}
		fmt.Fprint(e.stdout, app.FormatAnon(res))
		if res.Report.LeakCount > 0 {
			return exitLeak
		}
	case dIn != "":
		rep, err := app.Restore(dIn, out, mapPath, pass, force)
		if err != nil {
			return fail(e, err)
		}
		fmt.Fprint(e.stdout, app.FormatRestore(rep))
	case sIn != "":
		res, err := app.Show(sIn, mapPath, find, pass)
		if err != nil {
			return fail(e, err)
		}
		fmt.Fprint(e.stdout, app.FormatShow(res))
	case vIn != "":
		rep, err := app.Verify(vIn, mapPath, prof, pass)
		if err != nil {
			return fail(e, err)
		}
		fmt.Fprint(e.stdout, anon.FormatVerify(rep, mapPath != ""))
		if rep.LeakCount > 0 {
			return exitLeak
		}
	}
	return exitOK
}

// statusLine shows progress on one terminal line that is rewritten in place.
type statusLine struct {
	w     io.Writer
	dirty bool
}

func (s *statusLine) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	fmt.Fprintf(s.w, "\r\x1b[K\x1b[2m%s …\x1b[0m", msg)
	s.dirty = true
	return len(p), nil
}

func (s *statusLine) clear() {
	if s.dirty {
		fmt.Fprint(s.w, "\r\x1b[K")
		s.dirty = false
	}
}

// warn prints a yellow line on stderr.
func warn(e *env, msg string) {
	if e.color {
		fmt.Fprintf(e.stderr, "\x1b[33m! %s\x1b[0m\n", msg)
		return
	}
	fmt.Fprintf(e.stderr, "! %s\n", msg)
}

func fail(e *env, err error) int {
	msg := err.Error()
	if !strings.HasPrefix(msg, "log_anonimizer") {
		msg = "log_anonimizer: " + msg
	}
	fmt.Fprintln(e.stderr, msg)
	return exitError
}
