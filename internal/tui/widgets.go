package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"
)

var errCancel = errors.New("cancelled")

const (
	sBold   = "\x1b[1m"
	sDim    = "\x1b[2m"
	sCyan   = "\x1b[36m"
	sGreen  = "\x1b[32m"
	sRed    = "\x1b[31m"
	sYellow = "\x1b[33m"
	sReset  = "\x1b[0m"
)

// ui draws one widget at a time below the previous answers.
type ui struct {
	keys  *keyReader
	out   io.Writer
	width int
	prev  int // lines drawn by the active widget
}

// fit cuts a line to the terminal width so redrawing stays aligned.
// Escape sequences do not count toward the width.
func (u *ui) fit(s string) string {
	max := u.width - 1
	if max < 20 {
		max = 20
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i + 1
			for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e && s[j] != '[') {
				j++
			}
			if j < len(s) {
				j++
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if n >= max {
			b.WriteString(sReset)
			break
		}
		b.WriteRune(r)
		n++
		i += size
	}
	return b.String()
}

func visibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i + 1
			for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e && s[j] != '[') {
				j++
			}
			i = j + 1
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		n++
		i += size
	}
	return n
}

func (u *ui) draw(lines []string) {
	var b strings.Builder
	if u.prev > 1 {
		fmt.Fprintf(&b, "\x1b[%dA", u.prev-1)
	}
	b.WriteString("\r\x1b[J")
	for i, l := range lines {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(u.fit(l))
	}
	io.WriteString(u.out, b.String())
	u.prev = len(lines)
}

// commit replaces the widget by a one-line answer.
func (u *ui) commit(title, answer string) {
	u.draw([]string{sGreen + "* " + sReset + sBold + title + sReset + " " + sCyan + answer + sReset})
	io.WriteString(u.out, "\r\n")
	u.prev = 0
}

func (u *ui) println(s string) {
	io.WriteString(u.out, strings.ReplaceAll(s, "\n", "\r\n")+"\r\n")
}

func (u *ui) selectOne(title string, opts []string, def int) (int, error) {
	cur := def
	for {
		lines := []string{sBold + "? " + title + sReset + sDim + "  (up/down, enter)" + sReset}
		for i, o := range opts {
			if i == cur {
				lines = append(lines, sCyan+"  > "+o+sReset)
			} else {
				lines = append(lines, "    "+o)
			}
		}
		u.draw(lines)
		k, err := u.keys.next()
		if err != nil {
			return 0, err
		}
		switch {
		case k.k == kCtrlC:
			return 0, errCancel
		case k.k == kUp || k.k == kChar && k.r == 'k':
			cur = (cur + len(opts) - 1) % len(opts)
		case k.k == kDown || k.k == kTab || k.k == kChar && k.r == 'j':
			cur = (cur + 1) % len(opts)
		case k.k == kChar && k.r >= '1' && k.r <= '9' && int(k.r-'1') < len(opts):
			cur = int(k.r - '1')
		case k.k == kEnter:
			u.commit(title, opts[cur])
			return cur, nil
		}
	}
}

func (u *ui) confirm(title string, def bool) (bool, error) {
	hint := "Y/n"
	if !def {
		hint = "y/N"
	}
	for {
		u.draw([]string{sBold + "? " + title + sReset + sDim + " (" + hint + ")" + sReset})
		k, err := u.keys.next()
		if err != nil {
			return false, err
		}
		v := def
		switch {
		case k.k == kCtrlC:
			return false, errCancel
		case k.k == kChar && (k.r == 'y' || k.r == 'Y'):
			v = true
		case k.k == kChar && (k.r == 'n' || k.r == 'N'):
			v = false
		case k.k != kEnter:
			continue
		}
		ans := "No"
		if v {
			ans = "Yes"
		}
		u.commit(title, ans)
		return v, nil
	}
}

type checkItem struct {
	label string
	on    bool
}

func (u *ui) multiSelect(title string, items []checkItem) ([]checkItem, error) {
	cur := 0
	for {
		lines := []string{sBold + "? " + title + sReset + sDim + "  (up/down, space = tick, a = all, enter = done)" + sReset}
		for i, it := range items {
			box := "[ ]"
			if it.on {
				box = "[" + sGreen + "x" + sReset + "]"
			}
			pointer := "  "
			if i == cur {
				pointer = sCyan + "> " + sReset
			}
			lines = append(lines, "  "+pointer+box+" "+it.label)
		}
		u.draw(lines)
		k, err := u.keys.next()
		if err != nil {
			return nil, err
		}
		switch {
		case k.k == kCtrlC:
			return nil, errCancel
		case k.k == kUp || k.k == kChar && k.r == 'k':
			cur = (cur + len(items) - 1) % len(items)
		case k.k == kDown || k.k == kTab || k.k == kChar && k.r == 'j':
			cur = (cur + 1) % len(items)
		case k.k == kChar && (k.r == ' ' || k.r == 'x'):
			items[cur].on = !items[cur].on
		case k.k == kChar && k.r == 'a':
			all := true
			for _, it := range items {
				all = all && it.on
			}
			for i := range items {
				items[i].on = !all
			}
		case k.k == kEnter:
			n := 0
			for _, it := range items {
				if it.on {
					n++
				}
			}
			u.commit(title, fmt.Sprintf("%d of %d selected", n, len(items)))
			return items, nil
		}
	}
}

type inputOpts struct {
	def      string // used when the answer is empty
	shown    string // what to show for an empty default
	path     bool   // tab completion of paths
	mask     bool   // hide what is typed
	validate func(string) error
}

func (u *ui) input(title string, o inputOpts) (string, error) {
	var buf []rune
	msg := ""
	for {
		text := string(buf)
		shown := text
		if o.mask {
			shown = strings.Repeat("*", len(buf))
		}
		head := sBold + "? " + title + sReset
		if o.def != "" || o.shown != "" {
			d := o.shown
			if d == "" {
				d = o.def
			}
			head += sDim + " [" + d + "]" + sReset
		}
		// long paths: show the end, where the typing happens
		if room := u.width - 1 - visibleLen(head) - 2; room > 10 && utf8.RuneCountInString(shown) > room {
			r := []rune(shown)
			shown = "…" + string(r[len(r)-room+1:])
		}
		lines := []string{head + " " + shown}
		if msg != "" {
			lines = append(lines, msg)
		}
		u.draw(lines)
		k, err := u.keys.next()
		if err != nil {
			return "", err
		}
		msg = ""
		switch k.k {
		case kCtrlC:
			return "", errCancel
		case kChar:
			buf = append(buf, k.r)
		case kBackspace:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		case kCtrlU, kEsc:
			buf = buf[:0]
		case kTab:
			if o.path {
				var cands []string
				text, cands = completePath(cleanPath(text))
				buf = []rune(text)
				if len(cands) > 1 {
					if len(cands) > 8 {
						cands = append(cands[:8], "...")
					}
					msg = sDim + "  " + strings.Join(cands, "  ") + sReset
				}
			}
		case kEnter:
			v := text
			if o.path {
				v = cleanPath(v)
			}
			if v == "" {
				v = o.def
			}
			if o.validate != nil {
				if err := o.validate(v); err != nil {
					msg = sRed + "  " + err.Error() + sReset
					if o.mask {
						buf = buf[:0] // hidden text cannot be corrected, start over
					}
					continue
				}
			}
			ans := v
			if o.mask {
				ans = strings.Repeat("*", len(buf))
			}
			if ans == "" {
				ans = o.shown
			}
			u.commit(title, ans)
			return v, nil
		}
	}
}

// cleanPath accepts paths pasted or dragged into the terminal: quoted,
// with backslash-escaped spaces, or starting with ~.
func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		s = s[1 : len(s)-1]
	}
	if runtime.GOOS != "windows" {
		s = strings.ReplaceAll(s, `\ `, " ")
	}
	if s == "~" || strings.HasPrefix(s, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			s = h + s[1:]
		}
	}
	return s
}

// completePath completes the last path element and lists candidates when
// several match.
func completePath(s string) (string, []string) {
	dir, prefix := filepath.Split(s)
	look := dir
	if look == "" {
		look = "."
	}
	ents, err := os.ReadDir(look)
	if err != nil {
		return s, nil
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(strings.ToLower(n), strings.ToLower(prefix)) && (prefix != "" || !strings.HasPrefix(n, ".")) {
			if e.IsDir() {
				n += string(filepath.Separator)
			}
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return s, nil
	}
	common := names[0]
	for _, n := range names[1:] {
		for !strings.HasPrefix(strings.ToLower(n), strings.ToLower(common)) {
			common = common[:len(common)-1]
		}
	}
	for !utf8.ValidString(common) {
		common = common[:len(common)-1]
	}
	if len(common) < len(prefix) {
		common = prefix
	}
	return dir + common, names
}
