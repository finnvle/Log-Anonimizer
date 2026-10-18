# Incident summary (written by an external analyst / AI from sample.anon.log)

1. EXTIP_0002 brute-forced SSH on HOST_0001 ("invalid user oracle") and later probed
   http://EXTIP_0005@evil.example/backup/IP_0004.7z, looking for a backup of the domain
   controller HOST_0004 (IP_0004).
2. USER_0001 logged on from EXTIP_0001 over SSH, then on workstation HOST_0003.DOMAIN_0002
   (IP_0003, SID S-1-5-21-SID_0001-1104).
3. USER_0001 copied salary-2026.xlsx from C:\Users\USER_0001\Desktop to \\HOST_0005\finance\.
4. USER_0002 sent a password in a URL (password=SECRET_0001): rotate it.

Recommended: block EXTIP_0002 and evil.example on HOST_0002, reset DOMAIN_0003\USER_0001,
review mailbox USER_0001@DOMAIN_0001 and device DEVICE_0001. HOST_9999 is mentioned by mistake.
