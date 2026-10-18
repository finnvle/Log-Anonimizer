package anon

import (
	"strings"
	"testing"

	"log_anonimizer/internal/profile"
	"log_anonimizer/internal/vault"
)

func testProfile(terms ...string) *profile.Profile {
	p := profile.Default()
	p.SensitiveTerms = terms
	return p
}

// anonLines learns all lines (as the engine does) and returns them rewritten.
func anonLines(t *testing.T, p *profile.Profile, lines ...string) ([]string, *vault.Vault) {
	t.Helper()
	v := vault.New()
	sc, err := NewScanner(p, v)
	if err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < maxLearnPasses; pass++ {
		ctx := sc.ctxVersion
		sc.SetLearning(true)
		for _, l := range lines {
			sc.Learn(l)
		}
		sc.SetLearning(false)
		if sc.ctxVersion == ctx {
			break
		}
	}
	sc.RebuildDict()
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = sc.Apply(l)
	}
	return out, v
}

type detCase struct {
	name, in, want string
}

func runCases(t *testing.T, p *profile.Profile, cases []detCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := anonLines(t, p, c.in)
			if got[0] != c.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", c.in, got[0], c.want)
			}
		})
	}
}

func TestIPv4(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"private and allowlisted resolver", "src=10.1.2.3 dst=8.8.8.8", "src=IP_0001 dst=8.8.8.8"},
		{"public", "from 203.0.113.5 port 22", "from EXTIP_0001 port 22"},
		{"CGNAT and link-local are internal", "a 100.64.1.1 b 169.254.10.1", "a IP_0001 b IP_0002"},
		{"loopback, broadcast, netmask kept", "127.0.0.1 255.255.255.255 mask 255.255.255.0", "127.0.0.1 255.255.255.255 mask 255.255.255.0"},
		{"RFC1918 range boundaries kept", "range 10.0.0.0-10.255.255.255", "range 10.0.0.0-10.255.255.255"},
		{"browser versions kept", "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"},
		{"capitalised product version kept", "Gecko/20060728+SUSE/1.5.0.6-0.1+Firefox/1.5.0.6", "Gecko/20060728+SUSE/1.5.0.6-0.1+Firefox/1.5.0.6"},
		{"Firefox revision kept", "Mozilla/5.0+(X11;+rv:1.8.0.6)+Gecko", "Mozilla/5.0+(X11;+rv:1.8.0.6)+Gecko"},
		{"product with plus before slash", "Gecko)+Chrome+/123.0.0.0+Safari+/537.36", "Gecko)+Chrome+/123.0.0.0+Safari+/537.36"},
		{"scanner probe path is an address", "GET /IP/198.51.100.77 - 443", "GET /IP/EXTIP_0001 - 443"},
		{"version word kept", "agent version 2.11.1.1 started", "agent version 2.11.1.1 started"},
		{"product then plus", "Gecko+Firefox+1.5.0.11+x", "Gecko+Firefox+1.5.0.11+x"},
		{"percent-encoded separator", "rv%3A1.8.1.11%29", "rv%3A1.8.1.11%29"},
		{".NET GAC folder", `GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089`, `GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089`},
		{"Version= in a query", "System.Web.Extensions,%20Version=4.0.0.0,%20Culture=neutral", "System.Web.Extensions,%20Version=4.0.0.0,%20Culture=neutral"},
		{"5-part versions and OIDs kept", "build 10.0.17763.1 oid 1.3.6.1.4.1.9", "build 10.0.17763.1 oid 1.3.6.1.4.1.9"},
		{"octet over 255 kept", "value 999.1.1.1", "value 999.1.1.1"},
		{"underscore after address", "10.20.30.31_vm-app01", "IP_0001_vm-app01"},
		{"address in a path", "ds:///vmfs/volumes/5f0c9a1e-77aa/10.1.1.9/10.1.1.9.vmx", "ds:///vmfs/volumes/5f0c9a1e-77aa/IP_0001/IP_0001.vmx"},
		{"leading zeros share the token", "a 010.001.002.003 b 10.1.2.3", "a IP_0001 b IP_0001"},
		{"with port", "10.1.1.1:443", "IP_0001:443"},
		{"letters glued on in a probe", "GET https://10.1.2.3admin/view", "GET https://IP_0001admin/view"},
		{"version glued to a word", "UCWEB7.0.2.37/28/999 and v10.1.2.3", "UCWEB7.0.2.37/28/999 and v10.1.2.3"},
		{"percent-encoded JSON", "%22ip%22%3a%2210.1.2.3%22", "%22ip%22%3a%22IP_0001%22"},
		{"file named after an address", "GET /backup/10.1.2.3.7z", "GET /backup/IP_0001.7z"},
	})
}

func TestPublicIPToggle(t *testing.T) {
	p := testProfile()
	p.Anonymize.PublicIP = false
	runCases(t, p, []detCase{{"public kept as IOC", "10.0.0.5 -> 198.51.100.7", "IP_0001 -> 198.51.100.7"}})
	p = testProfile()
	p.Anonymize.InternalIP = false
	runCases(t, p, []detCase{{"internal kept", "10.0.0.5 -> 198.51.100.7", "10.0.0.5 -> EXTIP_0001"}})
}

func TestIPv6(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"link-local", "addr fe80::1ff:fe23:4567:890a end", "addr IP_0001 end"},
		{"global", "client 2001:db8::1 said", "client EXTIP_0001 said"},
		{"bracketed with port", "[2001:db8::1]:443", "[EXTIP_0001]:443"},
		{"loopback kept", "GET ::1 /owa", "GET ::1 /owa"},
		{"times and C++ names kept", "12:30:45 VpxaMoVm::CheckMoVm", "12:30:45 VpxaMoVm::CheckMoVm"},
	})
}

func TestMAC(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"colon", "mac 00:1A:2B:3C:4D:5E ok", "mac MAC_0001 ok"},
		{"formats share the token", "00:1a:2b:3c:4d:5e 00-1A-2B-3C-4D-5E 001a.2b3c.4d5e", "MAC_0001 MAC_0001 MAC_0001"},
		{"iptables dst:src:type", "MAC=ff:ff:ff:ff:ff:ff:02:42:ac:11:00:02:08:00 SRC=x", "MAC=ff:ff:ff:ff:ff:ff:MAC_0001:08:00 SRC=x"},
		{"broadcast kept", "dst ff:ff:ff:ff:ff:ff", "dst ff:ff:ff:ff:ff:ff"},
		{"GUID kept", "{5f0c9a1e-0b7d4c22-8e31-a1b2c3d4e5f6}", "{5f0c9a1e-0b7d4c22-8e31-a1b2c3d4e5f6}"},
	})
}

func TestSID(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"domain part only, RID kept", "S-1-5-21-1111111111-2222222222-3333333333-500", "S-1-5-21-SID_0001-500"},
		{"same domain same token", "S-1-5-21-1-2-3-500 S-1-5-21-1-2-3-1105", "S-1-5-21-SID_0001-500 S-1-5-21-SID_0001-1105"},
		{"well-known kept", "S-1-5-18 S-1-5-32-544", "S-1-5-18 S-1-5-32-544"},
	})
}

func TestEmail(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"plain", "mail john.doe@acme.example sent", "mail USER_0001@DOMAIN_0001 sent"},
		{"percent-encoded", "Cmd=Ping&User=john.doe%40acme.example&x=1", "Cmd=Ping&User=USER_0001%40DOMAIN_0001&x=1"},
		{"public mail domain kept", "from bob@gmail.com", "from USER_0001@gmail.com"},
		{"role mailbox kept", "to info@acme.example", "to info@DOMAIN_0001"},
		{"SSRF probe hides the address, keeps the IOC domain", "url=http://203.0.113.9@evil.example/x", "url=http://EXTIP_0001@evil.example/x"},
		{"VMware originator is not mail", "[Originator@6876 sub=Alarm]", "[Originator@6876 sub=Alarm]"},
		{"crawler contact in a User-Agent kept", "Mozilla/5.0+(compatible;+Example-User/1.0;++Example-User@crawler.example)", "Mozilla/5.0+(compatible;+Example-User/1.0;++Example-User@crawler.example)"},
		{"bot contact kept", "contact searchbot@crawler.example", "contact searchbot@crawler.example"},
	})
}

func TestDomainUser(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"account", "logon CORP\\jdoe ok", "logon DOMAIN_0001\\USER_0001 ok"},
		{"JSON escaped", `"user":"CORP\\jdoe"`, `"user":"DOMAIN_0001\\USER_0001"`},
		{"double escaped", `"user":"CORP\\\\jdoe"`, `"user":"DOMAIN_0001\\\\USER_0001"`},
		{"machine account", "CORP\\PC01$ logged on", "DOMAIN_0001\\HOST_0001$ logged on"},
		{"built-in kept", "NT AUTHORITY\\SYSTEM and NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\SYSTEM and NT AUTHORITY\\LOCAL SERVICE"},
		{"windows path kept", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\cmd.exe"},
		{"GPO path kept", "computer configuration\\windows settings\\security settings\\local policies\\user rights", "computer configuration\\windows settings\\security settings\\local policies\\user rights"},
		{"task path kept", "<URI>Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip</URI>", "<URI>Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip</URI>"},
		{"WMI namespace kept", "from root\\StandardCimv2:MSFT", "from root\\StandardCimv2:MSFT"},
		{"device instance IDs kept", `PCI\VEN_15AD&DEV_0405 USBSTOR\Disk&Ven_x ACPI\PNP0A03`, `PCI\VEN_15AD&DEV_0405 USBSTOR\Disk&Ven_x ACPI\PNP0A03`},
		{"JSON newline escape kept", `{"msg":"line1\nline2 \"q\""}`, `{"msg":"line1\nline2 \"q\""}`},
	})
}

func TestPaths(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"windows profile", `copy C:\Users\somchai\Desktop\x.txt`, `copy C:\Users\USER_0001\Desktop\x.txt`},
		{"name with space", `C:\Users\John Smith\AppData`, `C:\Users\USER_0001\AppData`},
		{"escaped backslashes", `"C:\\Users\\bob99\\x"`, `"C:\\Users\\USER_0001\\x"`},
		{"public profile kept", `C:\Users\Public\Documents`, `C:\Users\Public\Documents`},
		{"linux home", "/home/alice/.ssh/id_rsa", "/home/USER_0001/.ssh/id_rsa"},
		{"probed URL is not a home folder", "10.0.0.5 GET /home/ubuntu/.config/gcloud 443", "IP_0001 GET /home/ubuntu/.config/gcloud 443"},
		{"full URL is not a home folder", "see https://site.example/Users/admin2/x", "see https://site.example/Users/admin2/x"},
		{"macOS", "/Users/bob99/Library", "/Users/USER_0001/Library"},
		{"UNC host", `open \\FS01\share\x`, `open \\HOST_0001\share\x`},
	})
}

func TestKeyValue(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"host", "HOST=LOG-SRV02 SEVERITY=High", "HOST=HOST_0001 SEVERITY=High"},
		{"origin", "ORIGIN=ACMEDC01 PROTOCOL=TCP", "ORIGIN=HOST_0001 PROTOCOL=TCP"},
		{"user list", "logonusers=CORP\\a1,CORP\\b2,NT AUTHORITY\\SYSTEM x=1", "logonusers=DOMAIN_0001\\USER_0001,DOMAIN_0001\\USER_0002,NT AUTHORITY\\SYSTEM x=1"},
		{"empty values", "processusers= netsessionusers=", "processusers= netsessionusers="},
		{"syslog facility is not a pair", "<USER:NOTE> 1 x", "<USER:NOTE> 1 x"},
		{"windows event text", "Account Name:\t\tbob99", "Account Name:\t\tUSER_0001"},
		{"JSON", `{"user":"carol","hostname": "pc-7"}`, `{"user":"USER_0001","hostname": "HOST_0001"}`},
		{"null values", "hostname=? addr=? user=-", "hostname=? addr=? user=-"},
		{"built-in account", `acct="root" exe="/usr/sbin/cron"`, `acct="root" exe="/usr/sbin/cron"`},
		{"URL secret", "/login?user=jdoe&password=S3cr3t&lang=en", "/login?user=USER_0001&password=SECRET_0001&lang=en"},
		{"header secret runs to end", "Authorization: Bearer abc.def", "Authorization: SECRET_0001"},
		{"masked secret kept", "password=****", "password=****"},
		{"device id", "DeviceId=a1b2c3d4e5&DeviceType=Outlook", "DeviceId=DEVICE_0001&DeviceType=Outlook"},
		{"multi-word key", "Machine name: SRV-X1, 64-bit: true", "Machine name: HOST_0001, 64-bit: true"},
	})
}

func TestSecretsToggle(t *testing.T) {
	p := testProfile()
	p.Anonymize.Secrets = false
	runCases(t, p, []detCase{{"kept", "password=S3cr3t", "password=S3cr3t"}})
}

func TestWindowsEvents(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"computer FQDN", "<Computer>PC1.corp.acme.example</Computer>", "<Computer>HOST_0001.DOMAIN_0001</Computer>"},
		{"data fields", "<Data Name='TargetUserName'>bob</Data><Data Name='TargetDomainName'>ACME</Data><Data Name='SubjectUserName'>-</Data><Data Name='WorkstationName'>WKS-22</Data>",
			"<Data Name='TargetUserName'>USER_0001</Data><Data Name='TargetDomainName'>DOMAIN_0001</Data><Data Name='SubjectUserName'>-</Data><Data Name='WorkstationName'>HOST_0001</Data>"},
		{"EvtxECmd payload", `{"@Name":"TargetUserName","#text":"dave"}`, `{"@Name":"TargetUserName","#text":"USER_0001"}`},
	})
}

func TestSyslogAndAuth(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"RFC5424", "<134>1 2026-10-06T00:49:00+07:00 FW-01 app - - msg", "<134>1 2026-10-06T00:49:00+07:00 HOST_0001 app - - msg"},
		{"LogRhythm relay prefix", "10 06 2026 00:49:00 10.0.0.9 <USER:NOTE> 2026-10-05T17:49:00.673Z hv01.acme.lab Vpxa: x", "10 06 2026 00:49:00 IP_0001 <USER:NOTE> 2026-10-05T17:49:00.673Z HOST_0001.DOMAIN_0001 Vpxa: x"},
		{"BSD and sshd", "Oct  6 00:49:00 web04 sshd[1]: Accepted password for alice from 203.0.113.50 port 22",
			"Oct  6 00:49:00 HOST_0001 sshd[1]: Accepted password for USER_0001 from EXTIP_0001 port 22"},
		{"names an attacker tried are kept", "Failed password for invalid user oracle1 from 10.0.0.1", "Failed password for invalid user oracle1 from IP_0001"},
		{"no host", "<13>Oct  6 00:49:00 kernel: boot", "<13>Oct  6 00:49:00 kernel: boot"},
	})
}

func TestInternalFQDN(t *testing.T) {
	got, _ := anonLines(t, testProfile(),
		"<Computer>dc1.corp.acme.example</Computer>",
		"ping dc2.corp.acme.example and www.corp.acme.example and www.google.com",
		"srv.corp.local and corp.local",
		"System.Net.Http.HttpClient",
	)
	want := []string{
		"<Computer>HOST_0001.DOMAIN_0001</Computer>",
		"ping HOST_0002.DOMAIN_0001 and www.DOMAIN_0001 and www.google.com",
		"HOST_0003.DOMAIN_0002 and DOMAIN_0002",
		"System.Net.Http.HttpClient",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d\n got:  %q\n want: %q", i, got[i], want[i])
		}
	}
}

func TestSensitiveTerms(t *testing.T) {
	runCases(t, testProfile("acme"), []detCase{
		{"words containing the term", "ACMEDC01 joined ACME-MBX1; rule Cyber_ACME_x; acme", "NAME_0001 joined NAME_0002; rule Cyber_ORG_0001_x; ORG_0001"},
		{"underscore separates names in VM files", "/vmfs/volumes/x/10.2.3.4_ACME-SRV01/10.2.3.4_ACME-SRV01.vmx", "/vmfs/volumes/x/IP_0001_HOST_0001/IP_0001_HOST_0001.vmx"},
		{"term overrides the allow list", "rtt to acmemail.microsoft.com", "rtt to DOMAIN_0001"},
		{"dotted term is an internal domain", "pc9.acme.co.th", "HOST_0001.DOMAIN_0001"},
	})
	// a word named by its context first keeps that kind
	got, _ := anonLines(t, testProfile("acme"), "HOST=ACME-MBX1", "mail on ACME-MBX1")
	if got[1] != "mail on HOST_0001" {
		t.Errorf("got %q", got[1])
	}
}

func TestDictionaryFindsLearnedValues(t *testing.T) {
	got, _ := anonLines(t, testProfile(),
		"HOST=log-srv02 user=somchai.k",
		"connect to log-srv02 now; log-srv021 and log-srv02_x; somchai.k said",
	)
	// a distinctive name is found next to "_" (file names), not inside a longer word
	if want := "connect to HOST_0001 now; log-srv021 and HOST_0001_x; USER_0001 said"; got[1] != want {
		t.Errorf("\n got:  %q\n want: %q", got[1], want)
	}
}

func TestCommonWordsAreNotSearchedInText(t *testing.T) {
	v := vault.New()
	sc, _ := NewScanner(testProfile(), v)
	sc.LearnField("host", FieldUser) // LogRhythm really puts such values in "User (Impacted)"
	sc.LearnField("Windows", FieldUser)
	sc.RebuildDict()
	if got := sc.ApplyField("host", FieldUser); got != "USER_0001" {
		t.Errorf("in its column the value is still tokenized, got %q", got)
	}
	if got := sc.Apply("Host (Origin) MS Windows Event Logging"); got != "Host (Origin) MS Windows Event Logging" {
		t.Errorf("common words replaced in text: %q", got)
	}
}

func TestSameValueSameTokenEverywhere(t *testing.T) {
	got, v := anonLines(t, testProfile(),
		"HOST=web01 ip=10.0.0.7",
		"10.0.0.7 called WEB01",
		"<Computer>web01</Computer>",
	)
	if !strings.Contains(got[0], "HOST_0001") || got[1] != "IP_0001 called HOST_0001" || got[2] != "<Computer>HOST_0001</Computer>" {
		t.Errorf("inconsistent tokens: %q", got)
	}
	if v.Len() != 2 {
		t.Errorf("vault has %d entries, want 2", v.Len())
	}
}

func TestTogglesOff(t *testing.T) {
	p := testProfile()
	p.Anonymize.User = false
	p.Anonymize.Hostname = false
	runCases(t, p, []detCase{
		{"users and hosts kept, domain still hidden", "CORP\\jdoe on HOST=pc1", "DOMAIN_0001\\jdoe on HOST=pc1"},
	})
}

func TestMapQualityFixes(t *testing.T) {
	runCases(t, testProfile(), []detCase{
		{"DOMAIN\\user@domain, URL-encoded", "Cmd=Ping&User=corp%5Cjdoe%40acme.example&x=1", "Cmd=Ping&User=DOMAIN_0001%5CUSER_0001%40DOMAIN_0002&x=1"},
		{"secret with brackets is read whole", "PSVersion=5.1&sessionID=Version_15.1_(Build_2506.0)=AbCdEfGh12&x=1", "PSVersion=5.1&sessionID=SECRET_0001&x=1"},
		{"systemd unit is not e-mail", "systemd[1]: user-runtime-dir@0.service: Succeeded.", "systemd[1]: user-runtime-dir@0.service: Succeeded."},
		{"SID in a user list", "logonusers=S-1-5-21-1-2-3-1106,CORP\\bob1,S-1-5-18", "logonusers=S-1-5-21-SID_0001-1106,DOMAIN_0001\\USER_0001,S-1-5-18"},
		{"Exchange health mailbox and probe kept", "User=HealthMailbox1234567890abcdef1234567890abcdef@corp.example&DeviceId=EASProbeDeviceId141&DeviceType=EASProbeDeviceType",
			"User=HealthMailbox1234567890abcdef1234567890abcdef@DOMAIN_0001&DeviceId=EASProbeDeviceId141&DeviceType=EASProbeDeviceType"},
		{"port before @ in a probe is not e-mail", "redirect_uri=https://localhost:80@oast.example", "redirect_uri=https://localhost:80@oast.example"},
		{"e-mail domain in a URL is kept", "GET /login?next=http://x.y@evil.example/ 443", "GET /login?next=http://USER_0001@evil.example/ 443"},
		{"mailbox GUID kept", "POST /mapi/emsmdb/ mailboxId=1a2b3c4d-1111-2222-3333-444455556666@acme.example", "POST /mapi/emsmdb/ mailboxId=1a2b3c4d-1111-2222-3333-444455556666@DOMAIN_0001"},
	})
	got, _ := anonLines(t, testProfile(),
		"<Computer>DC01.corp.acme.example</Computer>",
		`<Data>DC03.corp.acme.example\tCDG 1 7\r\nDC02.corp.acme.example\tCDG 1 7</Data>`,
		"url=https%3A%2F%2Fmail.corp.acme.example%2Fowa%2F",
		"/vmfs/volumes/x/10.2.3.4_kpi.corp.acme.example/10.2.3.4_kpi.corp.acme.example-flat.vmdk and kpi.corp.acme.example.vmx",
	)
	want := []string{
		"<Computer>HOST_0001.DOMAIN_0001</Computer>",
		`<Data>HOST_0002.DOMAIN_0001\tCDG 1 7\r\nHOST_0003.DOMAIN_0001\tCDG 1 7</Data>`,
		"url=https%3A%2F%2Fmail.DOMAIN_0001%2Fowa%2F",
		"/vmfs/volumes/x/IP_0001_HOST_0004.DOMAIN_0001/IP_0001_HOST_0004.DOMAIN_0001-flat.vmdk and HOST_0004.DOMAIN_0001.vmx",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d\n got:  %q\n want: %q", i, got[i], want[i])
		}
	}
}

func TestRegistrable(t *testing.T) {
	for in, want := range map[string]string{
		"mail.corp.example.com": "example.com",
		"www.agency.go.th":      "agency.go.th",
		"x.y.example.co.uk":     "example.co.uk",
		"output.go":             "", // Go source file, not a domain
		"jquery.min.js":         "",
		"iorm.sf":               "",
		"backup.tar.gz":         "",
	} {
		got, ok := registrable(in)
		if want == "" && ok || want != "" && got != want {
			t.Errorf("registrable(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}
