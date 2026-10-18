# Incident summary (written by an external analyst / AI from sample.anon.log)

1. 198.51.100.23 brute-forced SSH on fw-edge01 ("invalid user oracle") and later probed
   http://203.0.113.9@evil.example/backup/10.20.0.5.7z, looking for a backup of the domain
   controller ACMEDC01 (10.20.0.5).
2. somchai.k logged on from 203.0.113.45 over SSH, then on workstation WS-SOMCHAI01.corp.acme.example
   (10.20.8.44, SID S-1-5-21-3623811015-3361044348-30300820-1104).
3. somchai.k copied salary-2026.xlsx from C:\Users\somchai.k\Desktop to \\FS-ACME02\finance\.
4. jdoe sent a password in a URL (password=Winter2026!): rotate it.

Recommended: block 198.51.100.23 and evil.example on FW-ACME-01, reset ACME\somchai.k,
review mailbox somchai.k@acme.example and device 4f2a9c71b3e84d0f. HOST_9999 is mentioned by mistake.
