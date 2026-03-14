# Subdomain Enumerator

Async OSINT tool for DNS brute-force enumeration. Resolves subdomains via a wordlist, returning IP, CDN fingerprint, and geolocation per hit. Built on `aiodns` with rate limiting and adaptive throttle to avoid network saturation. Auto-stops when idle.

---

## Requirements

```
pip install aiodns
```

> Without `aiodns`, the tool falls back to a threaded `socket` engine. It works, but it's significantly slower.

---

## Usage

```bash
python subdomain_enum.py <domain> [options]
```

### Examples

```bash
# Basic scan
python subdomain_enum.py example.com

# Custom wordlist
python subdomain_enum.py example.com -w names_clean.txt

# Save output to file
python subdomain_enum.py example.com -o results.txt

# Lower rate for unstable Wi-Fi
python subdomain_enum.py example.com --qps 100

# Custom nameservers, higher concurrency
python subdomain_enum.py example.com --ns 1.1.1.1 8.8.8.8 -c 500

# Stop after 30s with no new hits
python subdomain_enum.py example.com --idle 30
```

---

## Options

| Flag | Default | Description |
|---|---|---|
| `domain` | — | Target domain (e.g. `example.com`) |
| `-w`, `--wordlist` | `names.txt` | Path to subdomain wordlist |
| `-c`, `--concurrency` | `300` | Max in-flight async queries |
| `--qps` | `200` | Max DNS queries per second |
| `-t`, `--timeout` | `3.0` | Per-query DNS timeout (seconds) |
| `--idle` | `60` | Stop if no new hit for this many seconds |
| `--ns` | `1.1.1.1 8.8.8.8 9.9.9.9` | Custom nameservers |
| `-o`, `--output` | — | Save results to file |
| `--threads` | `100` | Thread count for socket fallback only |

---

## Output format

```
SOTTODOMINIO               IP                CDN              POSIZIONE
-----------------------------------------------------------------------
api.example.com            104.21.10.5       Cloudflare       San Francisco, United States
mail.example.com           1.2.3.4           -                Amsterdam, Netherlands
vpn.example.com            127.0.0.1         localhost        localhost
```

- **CDN** is detected via CNAME chain matching and IP range fingerprinting (Cloudflare, Akamai, Fastly, AWS, Azure, Google, and more).
- **POSIZIONE** is resolved via [ip-api.com](http://ip-api.com) — no API key required. Results are cached per IP to avoid redundant requests.
- Private/loopback IPs (`127.x`, `10.x`, `192.168.x`, `172.16–31.x`) are marked as `localhost` in both CDN and POSIZIONE columns.

---

## Rate presets

| `--qps` | Profile | When to use |
|---|---|---|
| `100` | Safe | Home Wi-Fi, weak router |
| `200` | Balanced | Default, most setups |
| `500` | Fast | Wired / stable connection |
| `1000` | Aggressive | LAN or VPS only |

> Setting `--qps` too high on Wi-Fi can saturate the router's DNS buffer and cause connectivity drops. The adaptive throttle will auto-slow if it detects a timeout spike, but staying within a safe preset is recommended.

---

## How it works

1. Loads the wordlist and builds `word.domain` FQDNs.
2. Spawns async DNS tasks gated by a **token bucket** (`--qps`) and a **semaphore** (`--concurrency`).
3. For each resolved A record, attempts a CNAME query for CDN detection, then falls back to IP range matching.
4. Calls `ip-api.com` for geolocation — one request per unique IP.
5. Monitors time since last hit. If it exceeds `--idle` seconds, cancels all pending tasks and prints results.

---

## Idle timeout

The scan stops automatically if no new subdomain is found for `--idle` seconds (default: 60). The timer resets on every hit. This is useful for large wordlists where most entries resolve quickly near the start and the tail is dead weight.

```
[!] Idle timeout  : no new subdomains found for 60s — stopping early.
[*] Done  : 14 found  |  87.3s  |  183 q/s avg
```

---

## Wordlist

The included `names_clean.txt` is a filtered version of the original `names.txt` (129k entries → ~80k), with the following removed:

- Random keyboard garbage (`hgfgdf`, `zcvbnnn`, …)
- Chinese gambling/casino pinyin strings
- Personal blog names and compound hyphenated entries
- Hosting customer IDs (`cust30`–`cust126`)
- Legacy Windows/OS hostnames (`winnt`, `nt40`, `isaserver`, …)
- Low-level protocol service names (AFS, NetBIOS, Bacula, …)
- Underscore-prefixed service records (`_sip`, `_ftp`, …)

What remains: web, mail, DNS, VPN, API, database, game server (Minecraft, Rust, Ark), DevOps, monitoring, panel, and general infrastructure subdomains.

names.txt > sublist3r (thankssss)
