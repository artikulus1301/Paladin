# Demo evidence (synthetic)

Small, harmless evidence set for live demos of the forensic layer. It is mounted
read-only into the SIFT sandbox by `start_demo.ps1`.

| File | What the tools find |
|------|---------------------|
| `files/invoice_q3.pdf.exe` | Random bytes with an `MZ` header (not executable) plus IOC strings: C2 URL `http://185.141.63.10/payloads/spinlock.exe`, beacon config, exfil mailbox, shadow-copy deletion command, Run-key persistence |
| `files/proxy_access.log` | Proxy log with downloads from the C2 host |
| `net/capture.pcap` | Valid pcap: DNS query `update.spinlock-cdn.ru` and `GET /payloads/spinlock.exe` to `185.141.63.10` |
