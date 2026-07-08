# omniRecon
A Python-based reconnaissance tool featuring TCP connect port scanning, protocol-specific banner grabbing (FTP/SSH/SMTP/POP3/HTTP/HTTPS/MySQL), and HTTP directory brute-forcing.

## Port Scanning
- Peform a full TCP Scan

```bash
python omniRecon.py -sT -t <TARGET IP/DOMAIN> -p <ports>
```

## Directory Bruteforcing

```bash
python omniRecon.py -dir -t <TARGET IP/DOMAIN> -w <wordlist path>
```

