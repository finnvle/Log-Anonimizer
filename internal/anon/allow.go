package anon

import (
	"net/netip"
	"strings"

	"log_anonimizer/internal/profile"
)

// Built-in allow lists: values that identify nobody and are useful to keep.

var builtinAllowIPs = []string{
	"0.0.0.0", "255.255.255.255", "::",
	// RFC 1918 range boundaries, e.g. in firewall rules "10.0.0.0-10.255.255.255"
	"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255",
	// well-known public resolvers
	"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220",
}

var builtinAllowCIDRs = []string{"127.0.0.0/8", "::1/128", "224.0.0.0/4", "ff00::/8"}

// Public domains (and their subdomains) that are kept as they are.
var builtinAllowDomains = []string{
	"microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "msftconnecttest.com",
	"live.com", "office.com", "office365.com", "office.net", "outlook.com", "microsoftonline.com",
	"azure.com", "azureedge.net", "windows.net", "bing.com", "msn.com", "skype.com", "msedge.net",
	"google.com", "googleapis.com", "gstatic.com", "gmail.com", "youtube.com", "googleusercontent.com",
	"apple.com", "icloud.com", "mozilla.org", "mozilla.com", "firefox.com",
	"amazon.com", "amazonaws.com", "cloudfront.net", "cloudflare.com",
	"akamai.net", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net",
	"digicert.com", "verisign.com", "letsencrypt.org", "sectigo.com", "globalsign.com",
	"bitdefender.com", "bitdefender.net", "vmware.com", "cisco.com", "paloaltonetworks.com",
	"logrhythm.com", "github.com", "githubusercontent.com", "ubuntu.com", "debian.org",
	"redhat.com", "centos.org", "yahoo.com", "hotmail.com", "facebook.com", "fbcdn.net",
	"whatsapp.net", "line.me", "example.com", "example.org", "example.net", "w3.org",
	"xmlsoap.org", "proton.me", "protonmail.com",
}

// Account names that are built in or generic.
var builtinAllowUsers = []string{
	"system", "administrator", "administrators", "admin", "guest", "root", "defaultaccount",
	"wdagutilityaccount", "krbtgt", "local service", "network service", "localservice",
	"networkservice", "localsystem", "anonymous logon", "anonymous", "public", "default",
	"default user", "all users", "shared", "nobody", "daemon", "www-data", "iusr", "everyone",
	"defaultapppool", "classic .net apppool", "test", "user", "users", "service", "support",
	"info", "noreply", "no-reply", "postmaster", "abuse", "webmaster", "helpdesk", "operator",
	"backup", "sa", "dbo", "postgres", "mysql", "oracle", "apache", "nginx", "syslog", "cron",
	"nt", "unknown user", "invalid", "from",
}

var builtinAllowHosts = []string{
	"localhost", "localhost.localdomain", "local", "server", "client", "host", "hostname",
	"computer", "desktop", "domain", "workgroup", "unknown", "default", "workstation",
}

// NetBIOS-style domains that are part of Windows, matched against the text
// before a backslash, e.g. "NT AUTHORITY\SYSTEM".
var builtinAllowNetbios = []string{
	"nt authority", "nt service", "builtin", "iis apppool", "window manager", "font driver host",
	"nt virtual machine", "workgroup", "everyone", "root", // WMI namespaces: root\cimv2
	// device instance IDs: PCI\VEN_15AD&DEV_0405, USBSTOR\Disk..., ACPI\PNP0A03
	"pci", "usb", "usbstor", "acpi", "hid", "hdaudio", "scsi", "ide", "storage", "swd", "display",
	"monitor", "bth", "bthenum", "bthle", "bthledevice", "sbp2", "1394", "pcmcia", "sd", "umb",
	"wpdbusenum", "uefi", "vmbus", "intelaudio", "mmdevapi", "sw", "htree", "lpt", "com",
}

// First labels of an internal FQDN that say nothing about the organisation.
// "www.corp.example" becomes "www.DOMAIN_0001" instead of "HOST_0001.DOMAIN_0001".
var genericLabels = []string{
	"www", "mail", "smtp", "imap", "pop", "pop3", "mx", "mx1", "mx2", "ns", "ns1", "ns2", "ns3",
	"dns", "dns1", "dns2", "vpn", "ftp", "sftp", "webmail", "autodiscover", "owa", "portal",
	"api", "app", "apps", "web", "intranet", "extranet", "remote", "gw", "gateway", "proxy",
	"sso", "login", "auth", "cdn", "static", "img", "m", "mobile", "lyncdiscover", "sip",
	"wpad", "ntp", "time", "ldap", "exchange", "outlook", "enterpriseregistration",
	"enterpriseenrollment",
}

// Common words that log parsers put into user or host fields. They are
// still tokenized where they appear in such a field, but they are not
// searched for in free text, where they are almost always just words.
var commonWords = []string{
	"host", "hostname", "name", "user", "username", "users", "status", "error", "info", "warning",
	"warn", "debug", "trace", "success", "failure", "failed", "true", "false", "none", "null",
	"default", "local", "remote", "server", "client", "service", "services", "system", "network",
	"admin", "guest", "test", "unknown", "root", "data", "file", "path", "type", "code", "time",
	"date", "port", "protocol", "source", "destination", "target", "object", "action", "event",
	"process", "session", "login", "logon", "logoff", "logout", "account", "domain", "group",
	"policy", "rule", "allow", "deny", "drop", "accept", "reject", "block", "alert", "audit",
	"security", "application", "http", "https", "mail", "web", "www", "proxy", "gateway",
	"firewall", "router", "switch", "update", "install", "backup", "restore", "report", "monitor",
	"manager", "master", "main", "home", "public", "private", "internal", "external", "inside",
	"outside", "trust", "untrust", "any", "all", "other", "health", "check", "ping", "get", "post",
	"put", "delete", "head", "options", "connect", "request", "response", "message", "value",
	"start", "stop", "running", "stopped", "started", "enabled", "disabled", "online", "offline",
	"active", "inactive", "open", "close", "closed", "send", "receive", "read", "write", "access",
	"auth", "token", "key", "cert", "certificate", "agent", "manual", "auto", "automatic", "local",
	"kernel", "daemon", "cron", "sshd", "sudo", "su", "login", "console", "terminal", "tty",
	"operator", "support", "info", "sales", "office", "it", "hr", "finance", "dev", "prod",
	"staging", "lab", "demo", "sample", "example", "temp", "tmp", "anonymous", "everyone",
	"computer", "desktop", "laptop", "workstation", "device", "printer", "scanner", "camera",
	// role mailboxes and team names
	"cyber", "soc", "noc", "csirt", "cert", "itsupport", "helpdesk", "servicedesk", "contact",
	"marketing", "mailbox", "noreply", "alerts", "notification", "notifications", "reports",
	"windows", "linux", "microsoft", "configuration", "settings", "program", "files", "root",
	"ubuntu", "debian", "centos", "fedora", "kali", "redhat", "android", "iphone", "ipad",
	"macintosh", "engine", "requests", "python", "config", "index", "login", "upload",
	"web-inf", "meta-inf", "webroot", "wwwroot", "denied", "quick", "modules", "pci", "acpi",
}

// Values that mean "nothing" in logs.
var nullValues = []string{
	"", "-", "--", "?", "n/a", "na", "null", "nil", "none", "unknown", "<empty>", "empty",
	"any", "all", "true", "false", "(null)", "undefined", "not-applicable", "not applicable",
	"null sid", "*",
}

// Product tokens before a version that looks like an IPv4 address,
// e.g. "Chrome/120.0.0.0".
var uaProducts = []string{
	"chrome", "chromium", "crios", "firefox", "fxios", "safari", "edge", "edg", "edga", "edgios",
	"opr", "opera", "version", "applewebkit", "gecko", "trident", "msie", "mobile", "yabrowser",
	"samsungbrowser", "ucbrowser", "electron", "node", "curl", "wget", "python", "java", "okhttp",
	"dalvik", "outlook", "teams", "skype", "zoom", "vivaldi", "brave", "whale", "webview",
	"powershell", "windowspowershell", "mozilla", "build", "v",
}

type allowSet struct {
	ips      map[netip.Addr]bool
	prefixes []netip.Prefix
	domains  map[string]bool
	users    map[string]bool
	hosts    map[string]bool
	netbios  []string
	labels   map[string]bool
	nulls    map[string]bool
	products map[string]bool
	common   map[string]bool
}

func toSet(lists ...[]string) map[string]bool {
	m := map[string]bool{}
	for _, l := range lists {
		for _, s := range l {
			m[strings.ToLower(strings.TrimSpace(s))] = true
		}
	}
	return m
}

func newAllowSet(p *profile.Profile) (*allowSet, error) {
	a := &allowSet{
		ips:      map[netip.Addr]bool{},
		domains:  toSet(builtinAllowDomains, p.Allow.Domains),
		users:    toSet(builtinAllowUsers, p.Allow.Users),
		hosts:    toSet(builtinAllowHosts, p.Allow.Hosts),
		netbios:  builtinAllowNetbios,
		labels:   toSet(genericLabels),
		nulls:    toSet(nullValues),
		products: toSet(uaProducts),
		common:   toSet(commonWords),
	}
	for _, s := range append(append([]string{}, builtinAllowIPs...), p.Allow.IPs...) {
		if strings.Contains(s, "/") {
			pf, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, err
			}
			a.prefixes = append(a.prefixes, pf)
			continue
		}
		ad, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		a.ips[ad] = true
	}
	for _, s := range builtinAllowCIDRs {
		a.prefixes = append(a.prefixes, netip.MustParsePrefix(s))
	}
	return a, nil
}

func (a *allowSet) ip(ad netip.Addr) bool {
	if a.ips[ad] || isNetmask(ad) {
		return true
	}
	for _, p := range a.prefixes {
		if p.Contains(ad) {
			return true
		}
	}
	return false
}

// isNetmask reports contiguous IPv4 masks such as 255.255.255.0.
func isNetmask(ad netip.Addr) bool {
	if !ad.Is4() {
		return false
	}
	b := ad.As4()
	if b[0] != 255 {
		return false
	}
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	inv := ^v
	return inv&(inv+1) == 0
}

// domain reports whether d (lower case) or one of its parents is allowed.
func (a *allowSet) domain(d string) bool {
	for {
		if a.domains[d] {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
}

func (a *allowSet) user(u string) bool {
	u = strings.ToLower(u)
	if a.users[u] || a.nulls[u] {
		return true
	}
	// IIS application pool identities, Windows virtual accounts
	return strings.HasPrefix(u, ".net v") || strings.Contains(u, "apppool") ||
		strings.HasPrefix(u, "dwm-") || strings.HasPrefix(u, "umfd-") ||
		strings.HasPrefix(u, "healthmailbox") || strings.HasPrefix(u, "systemmailbox") // Exchange's own mailboxes
}

func (a *allowSet) host(h string) bool {
	h = strings.ToLower(h)
	return a.hosts[h] || a.nulls[h]
}

func (a *allowSet) null(s string) bool { return a.nulls[strings.ToLower(strings.TrimSpace(s))] }

// netbiosBefore reports whether the text ending at the backslash is a
// built-in Windows "domain" such as "NT AUTHORITY".
func (a *allowSet) netbiosBefore(lowerPrefix string) bool {
	for _, n := range a.netbios {
		if strings.HasSuffix(lowerPrefix, n) {
			i := len(lowerPrefix) - len(n)
			if i == 0 || !isAlnum(lowerPrefix[i-1]) {
				return true
			}
		}
	}
	return false
}
