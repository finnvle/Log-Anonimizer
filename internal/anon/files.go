package anon

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

type fileType int

const (
	ftBinary fileType = iota
	ftText
	ftCSV
)

func (t fileType) String() string {
	switch t {
	case ftText:
		return "text"
	case ftCSV:
		return "csv"
	}
	return "binary"
}

type textEncoding int

const (
	encUTF8 textEncoding = iota
	encUTF8BOM
	encUTF16LE
	encUTF16BE
)

func (e textEncoding) String() string {
	return [...]string{"utf-8", "utf-8 (bom)", "utf-16le", "utf-16be"}[e]
}

var bomUTF8 = []byte{0xEF, 0xBB, 0xBF}

// sniff decides how a file is handled from its first 8 KiB and extension.
func sniff(path string) (fileType, textEncoding, error) {
	f, err := os.Open(path)
	if err != nil {
		return ftBinary, encUTF8, err
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return ftBinary, encUTF8, err
	}
	buf = buf[:n]
	enc := encUTF8
	switch {
	case bytes.HasPrefix(buf, bomUTF8):
		enc = encUTF8BOM
	case bytes.HasPrefix(buf, []byte{0xFF, 0xFE}):
		enc = encUTF16LE
	case bytes.HasPrefix(buf, []byte{0xFE, 0xFF}):
		enc = encUTF16BE
	case bytes.IndexByte(buf, 0) >= 0:
		if !looksUTF16LE(buf) {
			return ftBinary, encUTF8, nil
		}
		enc = encUTF16LE
	default:
		if controlRatio(buf) > 0.05 {
			return ftBinary, encUTF8, nil
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".csv" || ext == ".tsv" {
		return ftCSV, enc, nil
	}
	return ftText, enc, nil
}

// looksUTF16LE spots UTF-16LE text without a BOM: mostly ASCII with a zero
// high byte.
func looksUTF16LE(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	zeros, pairs := 0, 0
	for i := 0; i+1 < len(b); i += 2 {
		pairs++
		if b[i+1] == 0 && b[i] != 0 {
			zeros++
		}
	}
	return float64(zeros)/float64(pairs) > 0.9
}

func controlRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	bad := 0
	for _, c := range b {
		if c < 0x09 || c > 0x0D && c < 0x20 && c != 0x1B {
			bad++
		}
	}
	return float64(bad) / float64(len(b))
}

// openText returns a UTF-8 reader for a text or CSV file. UTF-8 BOMs are
// removed (the caller writes them back); UTF-16 is converted to UTF-8.
func openText(path string, enc textEncoding) (io.Reader, func() error, error) {
	if enc == encUTF16LE || enc == encUTF16BE {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		return strings.NewReader(decodeUTF16(data, enc == encUTF16BE)), func() error { return nil }, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	if enc == encUTF8BOM {
		br.Discard(3)
	}
	return br, f.Close, nil
}

func decodeUTF16(b []byte, bigEndian bool) string {
	if len(b) >= 2 && (b[0] == 0xFF && b[1] == 0xFE || b[0] == 0xFE && b[1] == 0xFF) {
		b = b[2:]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		if bigEndian {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
	}
	return string(utf16.Decode(u))
}

// splitEOL separates a line from its terminator.
func splitEOL(line string) (string, string) {
	if strings.HasSuffix(line, "\r\n") {
		return line[:len(line)-2], "\r\n"
	}
	if strings.HasSuffix(line, "\n") {
		return line[:len(line)-1], "\n"
	}
	return line, ""
}

// eachLine calls fn for every line, keeping exact line terminators.
func eachLine(r io.Reader, fn func(body, eol string) error) error {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 1<<20)
	}
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			body, eol := splitEOL(line)
			if ferr := fn(body, eol); ferr != nil {
				return ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// csvField is one CSV value and whether it was written in quotes, so the
// output can be written exactly the way the input was.
type csvField struct {
	val    string
	quoted bool
}

// csvScanner is a lenient CSV reader that remembers quoting and line
// endings (encoding/csv forgets both): LogRhythm, for example, quotes text
// but leaves numbers and empty values bare.
type csvScanner struct {
	r     *bufio.Reader
	comma byte
}

func newCSVScanner(r io.Reader, comma rune) *csvScanner {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 1<<20)
	}
	return &csvScanner{r: br, comma: byte(comma)}
}

// next returns one record and its line ending ("" for a last line without
// one), or io.EOF when nothing is left.
func (c *csvScanner) next() ([]csvField, string, error) {
	var rec []csvField
	for {
		f, end, err := c.field()
		if err != nil {
			if errors.Is(err, io.EOF) && len(rec) == 0 {
				return nil, "", io.EOF
			}
			if !errors.Is(err, io.EOF) {
				return nil, "", err
			}
		}
		rec = append(rec, f)
		if end != "," {
			return rec, end, nil
		}
	}
}

// field reads one value and what ended it: "," for the separator, the line
// ending, or "" at the end of the input.
func (c *csvScanner) field() (csvField, string, error) {
	var b []byte
	ch, err := c.r.ReadByte()
	if err != nil {
		return csvField{}, "", err
	}
	if ch == '"' {
		for {
			if ch, err = c.r.ReadByte(); err != nil {
				return csvField{string(b), true}, "", nil // unterminated: keep what is there
			}
			if ch != '"' {
				b = append(b, ch)
				continue
			}
			nx, err := c.r.ReadByte()
			if err != nil {
				return csvField{string(b), true}, "", nil
			}
			switch {
			case nx == '"':
				b = append(b, '"')
			case nx == c.comma:
				return csvField{string(b), true}, ",", nil
			case nx == '\n':
				return csvField{string(b), true}, "\n", nil
			case nx == '\r' && c.peekLF():
				c.r.ReadByte()
				return csvField{string(b), true}, "\r\n", nil
			default: // a stray quote inside a quoted value
				b = append(b, '"', nx)
			}
		}
	}
	for {
		switch {
		case ch == c.comma:
			return csvField{string(b), false}, ",", nil
		case ch == '\n':
			return csvField{string(b), false}, "\n", nil
		case ch == '\r' && c.peekLF():
			c.r.ReadByte()
			return csvField{string(b), false}, "\r\n", nil
		default:
			b = append(b, ch)
		}
		if ch, err = c.r.ReadByte(); err != nil {
			return csvField{string(b), false}, "", nil
		}
	}
}

func (c *csvScanner) peekLF() bool {
	p, _ := c.r.Peek(1)
	return len(p) == 1 && p[0] == '\n'
}

// writeCSVFields writes a record with the original quoting. A value that
// now contains the separator or a line break is quoted even if it was not.
func writeCSVFields(w *bufio.Writer, comma rune, rec []csvField, eol string) error {
	for i, f := range rec {
		if i > 0 {
			w.WriteRune(comma)
		}
		if f.quoted || strings.ContainsRune(f.val, comma) || strings.ContainsAny(f.val, "\r\n") {
			w.WriteByte('"')
			w.WriteString(strings.ReplaceAll(f.val, `"`, `""`))
			w.WriteByte('"')
		} else {
			w.WriteString(f.val)
		}
	}
	_, err := w.WriteString(eol)
	return err
}

func csvComma(path string) rune {
	if strings.EqualFold(filepath.Ext(path), ".tsv") {
		return '\t'
	}
	return ','
}

// --- column meaning from CSV headers and W3C #Fields --------------------------

func normHeader(h string) string {
	var b strings.Builder
	for i := 0; i < len(h); i++ {
		c := lowerByte(h[i])
		if isAlnum(c) {
			b.WriteByte(c)
		}
	}
	return b.String()
}

var columnKinds = map[string]FieldKind{}

func init() {
	add := func(k FieldKind, names ...string) {
		for _, n := range names {
			columnKinds[n] = k
		}
	}
	// LogRhythm exports
	add(FieldIP, "ipaddressorigin", "ipaddressimpacted", "natipaddressorigin", "natipaddressimpacted")
	add(FieldHost, "hostorigin", "hostnameorigin", "knownhostorigin", "knownhostimpacted", "logsourcehost")
	add(FieldHostRemote, "hostimpacted", "hostnameimpacted")
	add(FieldMAC, "macaddressorigin", "macaddressimpacted")
	add(FieldUser, "userorigin", "userimpacted", "sender", "recipient")
	add(FieldDomain, "domainorigin")
	add(FieldDomainRemote, "domainimpacted")
	add(FieldOrg, "entityorigin", "entityimpacted", "logsourceentity")
	// generic exports, EvtxECmd, IIS W3C (cs-username -> csusername ...)
	add(FieldIP, "ip", "ipaddress", "srcip", "dstip", "sourceip", "destinationip", "destip", "clientip",
		"serverip", "remoteip", "localip", "sourceaddress", "destinationaddress", "sourcenetworkaddress",
		"ipaddr", "src", "dst", "srcaddr", "dstaddr", "cip", "sip", "clientaddress", "xforwardedfor")
	add(FieldHost, "computer", "computername", "hostname", "workstation", "workstationname", "machinename",
		"machine", "devicename", "sourcehost", "shost", "srchost", "sourcehostname", "dnshostname",
		"scomputername")
	add(FieldHostRemote, "host", "dhost", "desthost", "destinationhost", "remotehost", "targethost",
		"servername", "fqdn", "cshost")
	add(FieldUser, "user", "username", "accountname", "targetusername", "subjectusername", "email",
		"emailaddress", "upn", "userprincipalname", "suser", "duser", "login", "logonuser", "csusername",
		"samaccountname")
	add(FieldDomain, "domain", "domainname", "targetdomainname", "subjectdomainname")
	add(FieldMAC, "mac", "macaddress", "srcmac", "dstmac")
	add(FieldSecret, "cscookie")
	add(FieldURL, "url", "uri", "referer", "referrer", "request", "requesturl", "requesturi",
		"csuristem", "csuriquery", "csreferer")
	add(FieldUserAgent, "useragent", "csuseragent", "httpuseragent")
}

func headerKinds(header []string) []FieldKind {
	ks := make([]FieldKind, len(header))
	for i, h := range header {
		ks[i] = columnKinds[normHeader(h)]
	}
	return ks
}

func w3cKinds(fieldsLine string) []FieldKind {
	names := strings.Fields(strings.TrimPrefix(fieldsLine, "#Fields:"))
	return headerKinds(names)
}
