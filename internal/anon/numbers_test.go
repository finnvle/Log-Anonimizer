package anon

import (
	"strings"
	"testing"
)

// runRestoring checks the anonymized text and that -d brings the input back.
func runRestoring(t *testing.T, terms []string, cases []detCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, v := anonLines(t, testProfile(terms...), c.in)
			if got[0] != c.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", c.in, got[0], c.want)
			}
			if back := RestoreString(got[0], v, &RestoreReport{}); back != c.in {
				t.Errorf("restore:\n got:  %q\n want: %q", back, c.in)
			}
		})
	}
}

func TestCardNumbers(t *testing.T) {
	runRestoring(t, nil, []detCase{
		{"visa with spaces", "card 4111 1111 1111 1111 exp 12/28", "card CARD_0001 exp 12/28"},
		{"mastercard plain", "pan=5555555555554444;", "pan=CARD_0001;"},
		{"amex 4-6-5", "amex 3782 822463 10005 ok", "amex CARD_0001 ok"},
		{"amex plain", "amex 378282246310005", "amex CARD_0001"},
		{"discover dashes", "d 6011-1111-1111-1117", "d CARD_0001"},
		{"jcb", "jcb 3530111333300000", "jcb CARD_0001"},
		{"after another number", "ref 5512 4111 1111 1111 1111 ok", "ref 5512 CARD_0001 ok"},
		{"luhn fails", "card 4111 1111 1111 1112", "card 4111 1111 1111 1112"},
		{"epoch nanoseconds", "ts=1760774400123456789", "ts=1760774400123456789"},
		{"starts with 1", "order 1234567890123452", "order 1234567890123452"},
		{"glued to a word", "x4111111111111111", "x4111111111111111"},
		{"mixed separators", "4111 1111-1111 1111", "4111 1111-1111 1111"},
		{"decimal", "v 1.4111111111111111", "v 1.4111111111111111"},
	})
}

func TestCardSpellingsShareToken(t *testing.T) {
	got, _ := anonLines(t, testProfile(), "a 4111 1111 1111 1111", "b 4111-1111-1111-1111", "c 4111111111111111")
	for _, g := range got {
		if !strings.HasSuffix(g, " CARD_0001") {
			t.Errorf("%q", got)
		}
	}
}

func TestThaiNationalID(t *testing.T) {
	if !thaiIDCheck("1234567890121") || thaiIDCheck("1234567890122") {
		t.Fatal("check digit")
	}
	runRestoring(t, nil, []detCase{
		{"dashed", "citizen id 1-2345-67890-12-1 ok", "citizen id NATID_0001 ok"},
		{"dashed, no label", "x 1-2345-67890-12-1", "x NATID_0001"},
		{"spaces", "id 1 2345 67890 12 1", "id NATID_0001"},
		{"labelled", "citizen_id=1234567890121", "citizen_id=NATID_0001"},
		{"thai label", "เลขบัตรประชาชน 1234567890121", "เลขบัตรประชาชน NATID_0001"},
		{"no label: could be a time in ms", "ts=1234567890121", "ts=1234567890121"},
		{"wrong check digit", "citizen 1-2345-67890-12-2", "citizen 1-2345-67890-12-2"},
	})
}

func TestPhoneNumbers(t *testing.T) {
	runRestoring(t, nil, []detCase{
		{"mobile dashes", "phone 081-234-5678", "phone PHONE_0001"},
		{"mobile spaces", "tel 081 234 5678 ok", "tel PHONE_0001 ok"},
		{"mobile plain", "tel 0812345678.", "tel PHONE_0001."},
		{"bangkok", "bkk 02-123-4567", "bkk PHONE_0001"},
		{"international", "call +66 2 123 4567 now", "call PHONE_0001 now"},
		{"international dashes", "m=+66-81-234-5678", "m=PHONE_0001"},
		{"url-encoded space", "q=call+0812345678&x=1", "q=call+PHONE_0001&x=1"},
		{"date and time", "2026-10-10 08:15:02 up", "2026-10-10 08:15:02 up"},
		{"timezone", "at 08:15+07:00 and +0700", "at 08:15+07:00 and +0700"},
		{"longer number", "id 0812345678901", "id 0812345678901"},
		{"version", "Chrome/120.0.6099.224", "Chrome/120.0.6099.224"},
		{"mac is a mac", "mac 08-00-27-12-34-56", "mac MAC_0001"},
	})
}

func TestTokenSecrets(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lIn0.dGVzdHNpZ25hdHVyZQ"
	aws := "AKIA" + "IOSFODNN7EXAMPLE"
	gh := "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	slack := "xox" + "b-" + "1234567890-abcdefghij"
	runRestoring(t, nil, []detCase{
		{"jwt", "bearer " + jwt + " in body", "bearer SECRET_0001 in body"},
		{"aws access key", "key " + aws + " leaked", "key SECRET_0001 leaked"},
		{"github token", "GITHUB_TOKEN: " + gh, "GITHUB_TOKEN: SECRET_0001"},
		{"slack token", "hook " + slack + ".", "hook SECRET_0001."},
		{"glued", "x" + aws + "X", "x" + aws + "X"},
	})
}

func TestPrivateKeys(t *testing.T) {
	begin, end := "-----BEGIN RSA "+"PRIVATE KEY-----", "-----END RSA "+"PRIVATE KEY-----"
	body := "MIIEowIBAAKCAQEA7examplekeymaterialABCDEF"
	runRestoring(t, nil, []detCase{
		{"json, escaped line breaks", `{"pem":"` + begin + `\n` + body + `\n` + end + `\n"}`,
			`{"pem":"` + begin + `\nSECRET_0001\n` + end + `\n"}`},
		{"one line", begin + " " + body + " " + end, begin + " SECRET_0001 " + end},
	})

	// a key file: every body line is replaced, the lines around it are not
	lines := []string{"before", begin, "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0011AABB", "",
		body, body + "X", end, "after " + strings.Repeat("A", 20)}
	got, _ := anonLines(t, testProfile(), lines...)
	want := []string{"before", begin, "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0011AABB", "",
		"SECRET_0001", "SECRET_0002", end, "after " + strings.Repeat("A", 20)}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("key file:\n got:  %q\n want: %q", got, want)
	}

	// cut short: a normal line ends the key
	lines = []string{begin, body, "normal text", strings.Repeat("B", 24)}
	got, _ = anonLines(t, testProfile(), lines...)
	if got[1] != "SECRET_0001" || got[2] != "normal text" || got[3] != strings.Repeat("B", 24) {
		t.Errorf("cut short: %q", got)
	}
}

func TestConnectionStrings(t *testing.T) {
	runRestoring(t, nil, []detCase{
		{"sql server", "conn Server=sql01;Database=hr;User Id=svc_app;Password=Spring2026!;",
			"conn Server=HOST_0001;Database=hr;User Id=USER_0001;Password=SECRET_0001;"},
		{"data source with instance and port", `Data Source=tcp:SQL02\PROD,1433;Initial Catalog=hr;Integrated Security=True`,
			`Data Source=tcp:HOST_0001\PROD,1433;Initial Catalog=hr;Integrated Security=True`},
		{"not a connection string", "uid=0(root) gid=0(root) groups=0(root)", "uid=0(root) gid=0(root) groups=0(root)"},
	})
	runRestoring(t, []string{"acme"}, []detCase{
		{"internal fqdn", "Server=tcp:sql01.corp.acme.example,1433;Database=hr;",
			"Server=tcp:HOST_0001.DOMAIN_0001,1433;Database=hr;"},
	})
}

func TestISOTimeHeaderHost(t *testing.T) {
	runRestoring(t, nil, []detCase{
		{"host then level", "2026-10-10 08:00:01 app01 INFO order paid", "2026-10-10 08:00:01 HOST_0001 INFO order paid"},
		{"rsyslog high precision", "2026-10-10T08:15:02.123456+07:00 fw-edge01 sshd[22]: Accepted",
			"2026-10-10T08:15:02.123456+07:00 HOST_0001 sshd[22]: Accepted"},
		{"uppercase host with pid", "2026-10-10T08:15:02Z DC sshd[22]: Accepted", "2026-10-10T08:15:02Z HOST_0001 sshd[22]: Accepted"},
		{"level first", "2026-10-10 08:00:01 INFO com.example.App: started", "2026-10-10 08:00:01 INFO com.example.App: started"},
		{"thread first", "2026-10-10 08:00:01,123 [main] INFO started", "2026-10-10 08:00:01,123 [main] INFO started"},
		// sentences after a time, as found in real logs: not hosts
		{"sentence", "2026-10-10 08:00:01 Starting service: spooler", "2026-10-10 08:00:01 Starting service: spooler"},
		{"camel case word", "2026-10-10 08:00:01 UpdateAgent Downloading: kb1", "2026-10-10 08:00:01 UpdateAgent Downloading: kb1"},
		{"word then level", "2026-10-10 08:00:01 Service INFO started", "2026-10-10 08:00:01 Service INFO started"},
	})
}
