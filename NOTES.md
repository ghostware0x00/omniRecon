
## TODO Project

### Features to Add in Project 

- Create a simple port scanner
- Web directory bruteforcing
- Web crawler, web scraping
- SSH, FTP bruteforcing
- DNS enumeration


### TOP 10 Ports to Scan

| Port     | Protocol | Associated Service                                      |
| :------- | :------- | :------------------------------------------------------ |
| **80**   | TCP      | **HTTP** (Unencrypted Web traffic)                      |
| **443**  | TCP      | **HTTPS** (Encrypted Web traffic)                       |
| **22**   | TCP      | **SSH** (Secure Shell for remote terminal access)       |
| **3389** | TCP      | **RDP** (Remote Desktop Protocol for Windows)           |
| **23**   | TCP      | **Telnet** (Unencrypted remote login)                   |
| **21**   | TCP      | **FTP** (File Transfer Protocol)                        |
| **53**   | TCP/UDP  | **DNS** (Domain Name System)                            |
| **25**   | TCP      | **SMTP** (Simple Mail Transfer Protocol)                |
| **445**  | TCP      | **SMB** (Server Message Block for Windows file sharing) |
| **3306** | TCP      | **MySQL** (Common database server port)                 |


- Find a port
- provide the version number
- service name
- whether the port is open, closed ...
- footprint the service

## Recommended Order

```bash
1. CLI Framework
2. Socket Basics
3. Single Port Scanner
4. Multi-Port Scanner
5. Threaded Scanner
6. Port State Detection
7. Service Mapping
8. Banner Grabbing
9. Service Fingerprinting
10. DNS Record Enumeration
11. Subdomain Enumeration
12. HTTP Request Engine
13. Directory Bruteforcer
14. Web Crawler
15. Web Scraper
16. FTP Enumeration
17. SSH Enumeration
18. Result Storage
19. JSON Export
20. Pretty Output
```

### WHAT TO DO NOW

```
Phase A
├── Accept arguments (domain/ip and port)
├── Validate arguments (check domain or ip provided and store both)
└── Resolve target(convert domain to ip)

Phase B
├── Create socket (we are trying to connect to target so we are client)
├── Set timeout (provide a timeout i.e. amt of time to wait for scan)
├── Connect to one port (check only one port first)
└── Report result (check open/closed/filtered)

Phase C
├── Generate port range
├── Loop ports
└── Store results
```

### WHAT TO USE

- `argparse` 
	- `nargs` in argsparse to take multiple inputs for a single argument (useful for taking multiple ports as input) use `nargs='*'` because `nargs='+'` only allows 3 arguments strict whereas `'*'` allows >=0 arguments.
- `socket`
	- `connect()`





