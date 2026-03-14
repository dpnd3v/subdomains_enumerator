# subdomains_enumerator
Subdomain Enumerator | async OSINT tool for DNS brute-force. Resolves subdomains via a wordlist, returning IP, CDN fingerprint, and geolocation per hit. Built on `aiodns` with rate limiting and adaptive throttle to avoid network saturation. Auto-stops when idle.
