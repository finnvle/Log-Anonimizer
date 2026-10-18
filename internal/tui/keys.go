package tui

import (
	"io"
	"unicode/utf8"
)

type keyKind int

const (
	kChar keyKind = iota
	kEnter
	kUp
	kDown
	kLeft
	kRight
	kTab
	kBackspace
	kCtrlC
	kCtrlU
	kEsc
	kUnknown
)

type key struct {
	k keyKind
	r rune
}

// keyReader turns raw terminal bytes into key presses.
type keyReader struct {
	r       io.Reader
	pending []byte
	queue   []key
}

func newKeyReader(r io.Reader) *keyReader { return &keyReader{r: r} }

func (kr *keyReader) next() (key, error) {
	for len(kr.queue) == 0 {
		buf := make([]byte, 512)
		n, err := kr.r.Read(buf)
		if n > 0 {
			data := append(kr.pending, buf[:n]...)
			var keys []key
			keys, kr.pending = parseKeys(data, err != nil)
			kr.queue = append(kr.queue, keys...)
		}
		if err != nil && len(kr.queue) == 0 {
			return key{}, err
		}
	}
	k := kr.queue[0]
	kr.queue = kr.queue[1:]
	return k, nil
}

// parseKeys decodes keys and returns bytes of an incomplete UTF-8 sequence
// at the end, to be completed by the next read.
func parseKeys(b []byte, final bool) ([]key, []byte) {
	var keys []key
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == 3 || c == 4: // Ctrl-C, Ctrl-D
			keys = append(keys, key{k: kCtrlC})
			i++
		case c == '\r' || c == '\n':
			keys = append(keys, key{k: kEnter})
			if c == '\r' && i+1 < len(b) && b[i+1] == '\n' {
				i++
			}
			i++
		case c == 0x7f || c == 0x08:
			keys = append(keys, key{k: kBackspace})
			i++
		case c == '\t':
			keys = append(keys, key{k: kTab})
			i++
		case c == 0x15: // Ctrl-U
			keys = append(keys, key{k: kCtrlU})
			i++
		case c == 0x1b:
			if i+1 < len(b) && (b[i+1] == '[' || b[i+1] == 'O') {
				j := i + 2
				for j < len(b) && !(b[j] >= 0x40 && b[j] <= 0x7e) {
					j++
				}
				if j >= len(b) {
					keys = append(keys, key{k: kUnknown})
					i = len(b)
					break
				}
				switch b[j] {
				case 'A':
					keys = append(keys, key{k: kUp})
				case 'B':
					keys = append(keys, key{k: kDown})
				case 'C':
					keys = append(keys, key{k: kRight})
				case 'D':
					keys = append(keys, key{k: kLeft})
				default:
					keys = append(keys, key{k: kUnknown})
				}
				i = j + 1
			} else {
				keys = append(keys, key{k: kEsc})
				i++
			}
		case c < 0x20:
			keys = append(keys, key{k: kUnknown})
			i++
		default:
			if !final && !utf8.FullRune(b[i:]) {
				return keys, append([]byte(nil), b[i:]...)
			}
			r, n := utf8.DecodeRune(b[i:])
			keys = append(keys, key{k: kChar, r: r})
			i += n
		}
	}
	return keys, nil
}
