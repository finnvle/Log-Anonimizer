package anon

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func run(t *testing.T, p *profile.Profile, v *vault.Vault, in, out string) *Report {
	t.Helper()
	e, err := NewEngine(p, v)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Anonymize(in, out, false)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// A LogRhythm-style export: every field quoted, CRLF, UTF-8 BOM.
const lrCSV = "\ufeff\"Host (Origin)\",\"Host (Impacted)\",\"User (Impacted)\",\"Entity (Origin)\",\"Hostname (Impacted)\",\"Log Message\"\r\n" +
	"\"10.20.30.40\",\"203.0.113.10\",\"host\",\"ACME\",\"www.example.org\",\"logon ACME\\jdoe from ACMEDC01, Host header ok\"\r\n" +
	"\"10.20.30.41\",\"\",\"jdoe@acme.example\",\"Global Entity\",\"pc77\",\"msg with \"\"quotes\"\", a comma and pc77\"\r\n"

func TestCSVColumnsQuotingAndBOM(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "export.csv"), lrCSV)
	rep := run(t, testProfile(), vault.New(), in, "")
	if rep.Output != filepath.Join(dir, "export.anon.csv") {
		t.Errorf("default output %s", rep.Output)
	}
	got := read(t, rep.Output)
	if !strings.HasPrefix(got, "\ufeff\"Host (Origin)\",") {
		t.Error("BOM or quoted header lost")
	}
	if strings.Count(got, "\r\n") != 3 || strings.Contains(strings.ReplaceAll(got, "\r\n", ""), "\n") {
		t.Error("CRLF line endings not kept")
	}
	recs, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(got, "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	r1, r2 := recs[1], recs[2]
	if r1[0] != "IP_0001" || r1[1] != "EXTIP_0001" || r1[2] != "USER_0001" || r1[3] != "ORG_0001" {
		t.Errorf("row 1 columns: %q", r1)
	}
	if r1[4] != "www.example.org" {
		t.Errorf("public domain in an impacted column must stay (IOC): %q", r1[4])
	}
	// the entity column made ACME a sensitive term: words containing it go too
	if r1[5] != "logon ORG_0001\\USER_0002 from NAME_0001, Host header ok" {
		t.Errorf("row 1 message: %q", r1[5])
	}
	if r2[2] != "USER_0002@DOMAIN_0001" || r2[3] != "Global Entity" || r2[4] != "HOST_0001" {
		t.Errorf("row 2 columns: %q", r2)
	}
	if r2[5] != `msg with "quotes", a comma and HOST_0001` {
		t.Errorf("row 2 message: %q", r2[5])
	}
	if rep.LeakCount != 0 {
		t.Errorf("leaks: %+v", rep.Leaks)
	}
}

func TestW3CFields(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "u_ex261010.log"),
		"#Software: Microsoft Internet Information Services 10.0\n"+
			"#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status s-computername\n"+
			"2026-10-10 01:02:03 10.0.0.5 GET /owa/ user=x 443 CORP\\alice 198.51.100.20 Mozilla/5.0+Chrome/120.0.0.0 200 EXCH01\n"+
			"2026-10-10 01:02:04 10.0.0.5 GET /owa/ - 443 - 198.51.100.20 - 401 EXCH01\n")
	rep := run(t, testProfile(), vault.New(), in, "")
	lines := strings.Split(read(t, rep.Output), "\n")
	if lines[1] != "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status s-computername" {
		t.Errorf("header changed: %q", lines[1])
	}
	if lines[2] != "2026-10-10 01:02:03 IP_0001 GET /owa/ user=USER_0001 443 DOMAIN_0001\\USER_0002 EXTIP_0001 Mozilla/5.0+Chrome/120.0.0.0 200 HOST_0001" {
		t.Errorf("line: %q", lines[2])
	}
	if lines[3] != "2026-10-10 01:02:04 IP_0001 GET /owa/ - 443 - EXTIP_0001 - 401 HOST_0001" {
		t.Errorf("line: %q", lines[3])
	}
}

func TestUTF16Input(t *testing.T) {
	dir := t.TempDir()
	text := "user=somchai from 10.1.1.1\r\nตรวจสอบ host=pc-01\r\n"
	u := utf16.Encode([]rune(text))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	in := filepath.Join(dir, "evt.txt")
	os.WriteFile(in, b, 0o644)
	rep := run(t, testProfile(), vault.New(), in, "")
	got := read(t, rep.Output)
	if want := "\ufeffuser=USER_0001 from IP_0001\r\nตรวจสอบ host=HOST_0001\r\n"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "in", "C", "Windows", "System32", "config", "SYSTEM")
	os.MkdirAll(filepath.Dir(bin), 0o755)
	os.WriteFile(bin, []byte("regf\x00\x00\x01\x02binary\x00data"), 0o644)
	write(t, filepath.Join(dir, "in", "notes.txt"), "HOST=pc-01\n")

	e, _ := NewEngine(testProfile(), vault.New())
	if _, err := e.Anonymize(bin, "", false); err == nil || !strings.Contains(err.Error(), "binary") {
		t.Errorf("single binary file: err = %v", err)
	}
	rep := run(t, testProfile(), vault.New(), filepath.Join(dir, "in"), "")
	skipped := 0
	for _, f := range rep.Files {
		if f.Skipped {
			skipped++
		}
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	if _, err := os.Stat(filepath.Join(rep.Output, "C", "Windows", "System32", "config", "SYSTEM")); err == nil {
		t.Error("binary file was copied into the output")
	}
}

func kapeTree(t *testing.T, root string) {
	write(t, filepath.Join(root, "C", "Users", "somchai", "AppData", "notes.txt"), "user somchai on HOST=ws-somchai\n")
	write(t, filepath.Join(root, "C", "Users", "Public", "readme.txt"), "nothing here\n")
	write(t, filepath.Join(root, "ConsoleLog.txt"), "Machine name: FS-ACME01, 64-bit: true, User: Administrator\n")
}

func TestDirectoryNamesAndReport(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "triage")
	kapeTree(t, in)
	rep := run(t, testProfile(), vault.New(), in, "")
	if rep.Output != filepath.Join(dir, "triage.anon") {
		t.Errorf("output %s", rep.Output)
	}
	if _, err := os.Stat(filepath.Join(rep.Output, "C", "Users", "USER_0001", "AppData", "notes.txt")); err != nil {
		t.Errorf("user folder not renamed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rep.Output, "C", "Users", "Public", "readme.txt")); err != nil {
		t.Error("Public folder should keep its name")
	}
	if got := read(t, filepath.Join(rep.Output, "ConsoleLog.txt")); got != "Machine name: HOST_0002, 64-bit: true, User: Administrator\n" {
		t.Errorf("console log: %q", got)
	}
	report := read(t, filepath.Join(rep.Output, "ANONYMIZATION_REPORT.txt"))
	for _, secret := range []string{"somchai", "FS-ACME01", dir} {
		if strings.Contains(report, secret) {
			t.Errorf("report contains %q", secret)
		}
	}
	if !strings.Contains(report, "verify    OK: none of the replaced values is left\n") {
		t.Errorf("report:\n%s", report)
	}
}

func TestFileNamesToggle(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "triage")
	kapeTree(t, in)
	p := testProfile()
	p.Anonymize.FileNames = false
	rep := run(t, p, vault.New(), in, filepath.Join(dir, "out"))
	if _, err := os.Stat(filepath.Join(rep.Output, "C", "Users", "somchai", "AppData", "notes.txt")); err != nil {
		t.Errorf("names should be kept: %v", err)
	}
}

func TestRoundTripFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "triage")
	kapeTree(t, in)
	write(t, filepath.Join(in, "export.csv"), lrCSV)
	v := vault.New()
	rep := run(t, testProfile(), v, in, "")
	rr, err := Restore(rep.Output, "", v, false)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Output != filepath.Join(dir, "triage.restored") {
		t.Errorf("restore output %s", rr.Output)
	}
	// the report is extra; everything else must be byte-identical
	filepath.WalkDir(in, func(p string, d os.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(in, p)
		if got, want := read(t, filepath.Join(rr.Output, rel)), read(t, p); got != want {
			t.Errorf("%s differs after round trip:\n got  %q\n want %q", rel, got, want)
		}
		return nil
	})
	if rr.Unknown != 0 {
		t.Errorf("unknown tokens: %v", rr.UnknownTokens)
	}
}

func TestRestoreReportWithTokens(t *testing.T) {
	v := vault.New()
	v.Token(vault.Host, "dc01")
	v.Token(vault.User, "somchai")
	v.Token(vault.Domain, "acme.example")
	v.Token(vault.IP, "10.0.0.9")
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "ai-report.md"),
		"## Finding\nHOST_0001 (IP_0001) was used by USER_0001%40DOMAIN_0001 and USER_0001@DOMAIN_0001.\nHOST_9999 is unknown, xHOST_0001 is not a token.\n")
	rr, err := Restore(in, "", v, false)
	if err != nil {
		t.Fatal(err)
	}
	got := read(t, filepath.Join(dir, "ai-report.restored.md"))
	want := "## Finding\ndc01 (10.0.0.9) was used by somchai%40acme.example and somchai@acme.example.\nHOST_9999 is unknown, xHOST_0001 is not a token.\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if rr.Replaced != 6 || rr.Unknown != 1 || rr.UnknownTokens[0] != "HOST_9999" {
		t.Errorf("report %+v", rr)
	}
}

func TestRestoreCSVQuotesOriginals(t *testing.T) {
	v := vault.New()
	v.Token(vault.Secret, `pa"ss,word`)
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "x.anon.csv"), "a,b\nSECRET_0001,ok\n")
	if _, err := Restore(in, "", v, false); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(strings.NewReader(read(t, filepath.Join(dir, "x.restored.csv")))).ReadAll()
	if err != nil || recs[1][0] != `pa"ss,word` || recs[1][1] != "ok" {
		t.Errorf("records %q err %v", recs, err)
	}
}

func TestVerifyFindsLeaksAndResiduals(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "a.log"), "HOST=fileserver01 user=somchai.k ip 10.1.1.1\n")
	v := vault.New()
	rep := run(t, testProfile(), v, in, "")
	clean, err := Verify(rep.Output, v, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	if clean.LeakCount != 0 || len(clean.Residual) != 0 {
		t.Errorf("clean output flagged: %+v", clean)
	}
	// "OK" must say what was checked, not that the file is safe
	text := FormatVerify(clean, true)
	for _, want := range []string{"map       OK: no value from the map found\n",
		"detectors OK: nothing they recognise is in clear text\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	// someone edits the output and pastes a real value back in
	os.WriteFile(rep.Output, []byte(read(t, rep.Output)+"note: fileserver01 and 10.1.1.1 and new 10.9.9.9\n"), 0o644)
	dirty, err := Verify(rep.Output, v, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	if dirty.LeakCount != 2 || dirty.Leaks[0].Line != 2 {
		t.Errorf("leaks %+v", dirty.Leaks)
	}
	if dirty.Residual[vault.IP] != 2 || dirty.Residual[vault.Host] != 0 {
		t.Errorf("residual %v", dirty.Residual)
	}
	text = FormatVerify(dirty, true)
	if strings.Contains(text, "fileserver01") || strings.Contains(text, "10.9.9.9") {
		t.Errorf("verify report must not print original values:\n%s", text)
	}
}

func TestOverwriteNeedsForce(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "a.log"), "HOST=pc-1\n")
	run(t, testProfile(), vault.New(), in, "")
	e, _ := NewEngine(testProfile(), vault.New())
	if _, err := e.Anonymize(in, "", false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v", err)
	}
	e, _ = NewEngine(testProfile(), vault.New())
	if _, err := e.Anonymize(in, "", true); err != nil {
		t.Errorf("force: %v", err)
	}
}

func TestExtendingMapKeepsTokens(t *testing.T) {
	dir := t.TempDir()
	a := write(t, filepath.Join(dir, "day1.log"), "HOST=pc-1 user=somchai.k\n")
	b := write(t, filepath.Join(dir, "day2.log"), "user=new.person HOST=pc-1 also somchai.k\n")
	v := vault.New()
	run(t, testProfile(), v, a, "")
	path := filepath.Join(dir, "m.anonmap")
	if err := vault.Save(path, v, nil); err != nil {
		t.Fatal(err)
	}
	v2, _, err := vault.Load(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	rep := run(t, testProfile(), v2, b, "")
	if got := read(t, rep.Output); got != "user=USER_0002 HOST=HOST_0001 also USER_0001\n" {
		t.Errorf("day 2: %q", got)
	}
}

func TestDeterministicOutput(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "a.csv"), strings.TrimPrefix(lrCSV, "\ufeff"))
	r1 := run(t, testProfile(), vault.New(), in, filepath.Join(dir, "o1.csv"))
	r2 := run(t, testProfile(), vault.New(), in, filepath.Join(dir, "o2.csv"))
	if read(t, r1.Output) != read(t, r2.Output) {
		t.Error("two runs on the same input differ")
	}
}

func TestTokenPrefixAvoidsExistingTokens(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "a.log"), "earlier report said HOST_0001 at 10.1.1.1\n")
	v := vault.New()
	rep := run(t, testProfile(), v, in, "")
	if !rep.PrefixChanged || v.Prefix != "ANON_" {
		t.Fatalf("prefix = %q", v.Prefix)
	}
	if got := read(t, rep.Output); got != "earlier report said HOST_0001 at ANON_IP_0001\n" {
		t.Errorf("got %q", got)
	}
	if _, err := Restore(rep.Output, filepath.Join(dir, "r.log"), v, false); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(dir, "r.log")) != read(t, in) {
		t.Error("restore changed the text that only looked like a token")
	}
}

func TestNaming(t *testing.T) {
	for in, want := range map[string]string{
		"/x/name.anon.csv": "/x/name.anonmap",
		"/x/logs.anon":     "/x/logs.anonmap",
		"/x/out":           "/x/out.anonmap",
		"/x/report.txt":    "/x/report.anonmap",
	} {
		if got := MapPathFor(filepath.FromSlash(in)); got != filepath.FromSlash(want) {
			t.Errorf("MapPathFor(%s) = %s", in, got)
		}
	}
	if got := DefaultRestoreOutput(filepath.FromSlash("/x/name.anon.csv"), false); got != filepath.FromSlash("/x/name.restored.csv") {
		t.Errorf("DefaultRestoreOutput = %s", got)
	}
	if got := DefaultRestoreOutput(filepath.FromSlash("/x/logs.anon"), true); got != filepath.FromSlash("/x/logs.restored") {
		t.Errorf("DefaultRestoreOutput dir = %s", got)
	}
}

func TestAhoCorasickMatchesNaive(t *testing.T) {
	pats := []string{"he", "she", "his", "hers", "ACME", "acme-dc", "a"}
	text := "ushers ACME-DC01 acme his A"
	m := newAC(pats)
	var got [][3]int
	m.findAll(text, func(s, e, p int) { got = append(got, [3]int{s, e, p}) })
	var want [][3]int
	lt := strings.ToLower(text)
	for end := 1; end <= len(text); end++ {
		for p, pat := range pats {
			lp := strings.ToLower(pat)
			if end >= len(lp) && lt[end-len(lp):end] == lp {
				want = append(want, [3]int{end - len(lp), end, p})
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d matches, want %d\n%v\n%v", len(got), len(want), got, want)
	}
	seen := map[[3]int]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing match %v", w)
		}
	}
}

func TestSniff(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"a.csv":  []byte("a,b\n1,2\n"),
		"b.log":  []byte("hello\n"),
		"c.bin":  {0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00},
		"d.txt":  append([]byte{0xEF, 0xBB, 0xBF}, []byte("bom\n")...),
		"e.log":  {'h', 0, 'i', 0, '\n', 0}, // UTF-16LE without BOM
		"f.data": bytes.Repeat([]byte{1, 2, 3, 4}, 100),
	}
	want := map[string]fileType{"a.csv": ftCSV, "b.log": ftText, "c.bin": ftBinary, "d.txt": ftText, "e.log": ftText, "f.data": ftBinary}
	for name, data := range cases {
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0o644)
		typ, enc, err := sniff(p)
		if err != nil || typ != want[name] {
			t.Errorf("%s: %v %v %v", name, typ, enc, err)
		}
		if name == "e.log" && enc != encUTF16LE {
			t.Errorf("e.log encoding %v", enc)
		}
	}
}

func TestRestoreTokenFollowedByDigits(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "a.log"), "Machine name: SRV-FILE-APP, x\nC:\\Windows\\Recent\\BSID_Site_SRV-FILE-APP20220721.bsc.lnk\n")
	v := vault.New()
	rep := run(t, testProfile(), v, in, "")
	if got := read(t, rep.Output); !strings.Contains(got, "BSID_Site_HOST_000120220721.bsc") {
		t.Fatalf("output %q", got)
	}
	if _, err := Restore(rep.Output, filepath.Join(dir, "r.log"), v, false); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(dir, "r.log")) != read(t, in) {
		t.Errorf("restore: %q", read(t, filepath.Join(dir, "r.log")))
	}
}

func TestRoundTripEscapedText(t *testing.T) {
	dir := t.TempDir()
	in := write(t, filepath.Join(dir, "a.log"), "<Computer>DC01.corp.acme.example</Computer>\n"+
		`<Data>DC03.corp.acme.example\tCDG 1\r\nDC02.corp.acme.example\tCDG 1\r\nncoc-2.corp.acme.example</Data>`+"\n")
	v := vault.New()
	rep := run(t, testProfile(), v, in, "")
	if strings.Contains(read(t, rep.Output), "DC02") || strings.Contains(read(t, rep.Output), "ncoc") {
		t.Fatalf("not anonymized: %q", read(t, rep.Output))
	}
	if _, err := Restore(rep.Output, filepath.Join(dir, "r.log"), v, false); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dir, "r.log")); got != read(t, in) {
		t.Errorf("round trip:\n got  %q\n want %q", got, read(t, in))
	}
}

func TestCSVKeepsEmptyFieldStyle(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bare.csv":   "\"Host\",\"Note\",\"X\"\r\n\"pc-01\",,\"a\"\r\n\"pc-02\",,\"\"\"q\"\"\"\r\n",
		"quoted.csv": "\"Host\",\"Note\"\n\"pc-01\",\"\"\n\"pc-02\",\"\"\n",
		"plain.csv":  "Host,Note\npc-01,\npc-02,x\n",
	} {
		in := write(t, filepath.Join(dir, name), body)
		v := vault.New()
		rep := run(t, testProfile(), v, in, "")
		rr, err := Restore(rep.Output, "", v, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := read(t, rr.Output); got != body {
			t.Errorf("%s: round trip changed the CSV\n got  %q\n want %q", name, got, body)
		}
	}
}

func TestCSVScanner(t *testing.T) {
	in := "\"a\",1,,\"x \"\"q\"\" ,y\"\r\n\"multi\r\nline\",2,\"\",z\nlast,line,without,eol"
	cs := newCSVScanner(strings.NewReader(in), ',')
	type rec struct {
		f   []csvField
		eol string
	}
	want := []rec{
		{[]csvField{{"a", true}, {"1", false}, {"", false}, {`x "q" ,y`, true}}, "\r\n"},
		{[]csvField{{"multi\r\nline", true}, {"2", false}, {"", true}, {"z", false}}, "\n"},
		{[]csvField{{"last", false}, {"line", false}, {"without", false}, {"eol", false}}, ""},
	}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	for i, wr := range want {
		got, eol, err := cs.next()
		if err != nil || eol != wr.eol || len(got) != len(wr.f) {
			t.Fatalf("record %d: %+v %q %v", i, got, eol, err)
		}
		for j := range got {
			if got[j] != wr.f[j] {
				t.Errorf("record %d field %d: %+v want %+v", i, j, got[j], wr.f[j])
			}
		}
		writeCSVFields(w, ',', got, eol)
	}
	if _, _, err := cs.next(); err != io.EOF {
		t.Errorf("want EOF, got %v", err)
	}
	w.Flush()
	if out.String() != in {
		t.Errorf("write back differs:\n got  %q\n want %q", out.String(), in)
	}
}
