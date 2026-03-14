"""
Subdomain Enumerator - OSINT Tool
High-performance async DNS brute-force with IP resolution and CDN detection.
Rate-limited to avoid saturating local network / router DNS buffer.

Dependencies:
    pip install aiodns

Python >= 3.11 recommended.
"""

import sys
import asyncio
import argparse
import ipaddress
import time
import socket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
from collections import deque

try:
    import aiodns # type: ignore
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

CDN_CNAME_SUFFIXES: list[tuple[str, str]] = [
    ("cloudflare.net",           "Cloudflare"),
    ("cloudflare.com",           "Cloudflare"),
    ("akamaiedge.net",           "Akamai"),
    ("akamaihd.net",             "Akamai"),
    ("akamaitechnologies.com",   "Akamai"),
    ("edgekey.net",              "Akamai"),
    ("edgesuite.net",            "Akamai"),
    ("fastly.net",               "Fastly"),
    ("fastlylb.net",             "Fastly"),
    ("cloudfront.net",           "AWS CloudFront"),
    ("amazonaws.com",            "AWS"),
    ("awsglobalaccelerator.com", "AWS Global Accelerator"),
    ("azureedge.net",            "Azure CDN"),
    ("trafficmanager.net",       "Azure Traffic Manager"),
    ("azurewebsites.net",        "Azure App Service"),
    ("googleusercontent.com",    "Google Cloud"),
    ("googleplex.com",           "Google"),
    ("appspot.com",              "Google App Engine"),
    ("incapdns.net",             "Imperva / Incapsula"),
    ("impervadns.net",           "Imperva / Incapsula"),
    ("sucuri.net",               "Sucuri"),
    ("netlify.app",              "Netlify"),
    ("netlify.com",              "Netlify"),
    ("vercel.app",               "Vercel"),
    ("now.sh",                   "Vercel"),
    ("github.io",                "GitHub Pages"),
    ("herokuapp.com",            "Heroku"),
    ("squarespace.com",          "Squarespace"),
    ("shopify.com",              "Shopify"),
    ("myshopify.com",            "Shopify"),
    ("wordpress.com",            "WordPress.com"),
    ("pantheonsite.io",          "Pantheon"),
    ("rackcdn.com",              "Rackspace"),
    ("llnwd.net",                "Limelight"),
    ("stackpathcdn.com",         "StackPath"),
    ("netdna-cdn.com",           "StackPath / MaxCDN"),
    ("b-cdn.net",                "BunnyCDN"),
    ("kxcdn.com",                "KeyCDN"),
    ("cdn77.org",                "CDN77"),
    ("zendesk.com",              "Zendesk"),
]

CDN_IP_RANGES: list[tuple[str, str]] = [
    ("103.21.244.0/22",  "Cloudflare"), ("103.22.200.0/22",  "Cloudflare"),
    ("103.31.4.0/22",    "Cloudflare"), ("104.16.0.0/13",    "Cloudflare"),
    ("104.24.0.0/14",    "Cloudflare"), ("108.162.192.0/18", "Cloudflare"),
    ("131.0.72.0/22",    "Cloudflare"), ("141.101.64.0/18",  "Cloudflare"),
    ("162.158.0.0/15",   "Cloudflare"), ("172.64.0.0/13",    "Cloudflare"),
    ("173.245.48.0/20",  "Cloudflare"), ("188.114.96.0/20",  "Cloudflare"),
    ("190.93.240.0/20",  "Cloudflare"), ("197.234.240.0/22", "Cloudflare"),
    ("198.41.128.0/17",  "Cloudflare"),
    ("23.235.32.0/20",   "Fastly"),     ("43.249.72.0/22",   "Fastly"),
    ("103.244.50.0/24",  "Fastly"),     ("103.245.222.0/23", "Fastly"),
    ("104.156.80.0/20",  "Fastly"),     ("151.101.0.0/16",   "Fastly"),
    ("157.52.64.0/18",   "Fastly"),     ("167.82.0.0/17",    "Fastly"),
    ("172.111.64.0/18",  "Fastly"),     ("185.31.16.0/22",   "Fastly"),
    ("199.27.72.0/21",   "Fastly"),     ("199.232.0.0/16",   "Fastly"),
    ("13.32.0.0/15",     "AWS CloudFront"), ("13.224.0.0/14","AWS CloudFront"),
    ("52.46.0.0/18",     "AWS CloudFront"), ("54.192.0.0/16", "AWS CloudFront"),
    ("204.246.164.0/22", "AWS CloudFront"),("205.251.192.0/19","AWS CloudFront"),
]

_CDN_NETWORKS = [(ipaddress.ip_network(c), l) for c, l in CDN_IP_RANGES]

def cdn_from_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        for net, label in _CDN_NETWORKS:
            if addr in net:
                return label
    except ValueError:
        pass
    return "-"

def cdn_from_cname(cname: str) -> str:
    cname = cname.lower().rstrip(".")
    for suffix, label in CDN_CNAME_SUFFIXES:
        if cname.endswith(suffix):
            return label
    return "-"

class TokenBucket:
    """
    Async token bucket.
    capacity  = max burst size (tokens)
    rate      = tokens added per second
    """
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            if self._tokens >= 1:
                self._tokens -= 1
                return
        wait = (1 - self._tokens) / self.rate
        await asyncio.sleep(wait)
        await self.acquire()

class AdaptiveThrottle:
    """
    Tracks the rolling timeout rate over the last `window` queries.
    If rate exceeds `threshold`, inserts a pause before each query.
    """
    def __init__(self, window: int = 200, threshold: float = 0.40):
        self.window = window
        self.threshold = threshold
        self._results: deque[bool] = deque(maxlen=window)
        self._lock = asyncio.Lock()

    async def record(self, timed_out: bool):
        async with self._lock:
            self._results.append(timed_out)

    @property
    def timeout_rate(self) -> float:
        if not self._results:
            return 0.0
        return sum(self._results) / len(self._results)

    async def maybe_pause(self):
        rate = self.timeout_rate
        if rate > self.threshold:
            pause = rate * 2.0
            await asyncio.sleep(pause)

async def probe_async(
    word: str,
    domain: str,
    resolver,
    semaphore: asyncio.Semaphore,
    bucket: TokenBucket,
    throttle: AdaptiveThrottle,
) -> dict | None:
    fqdn = f"{word}.{domain}"

    await throttle.maybe_pause()
    await bucket.acquire()

    async with semaphore:
        timed_out = False
        try:
            a_result = await resolver.query(fqdn, "A")
            ip = a_result[0].host
        except aiodns.error.DNSError as e:
            timed_out = (e.args[0] == aiodns.error.ARES_ETIMEOUT)
            await throttle.record(timed_out)
            return None
        except Exception:
            await throttle.record(False)
            return None

        await throttle.record(False)

        cdn = "-"
        try:
            cname_result = await resolver.query(fqdn, "CNAME")
            cdn = cdn_from_cname(str(cname_result.cname))
        except Exception:
            pass

        if cdn == "-":
            cdn = cdn_from_ip(ip)

        if is_localhost(ip):
            cdn      = "localhost"
            location = "localhost"
        else:
            location = geolocate(ip)

        return {"subdomain": fqdn, "ip": ip, "cdn": cdn, "location": location}

def probe_sync(word: str, domain: str) -> dict | None:
    fqdn = f"{word}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
    except socket.gaierror:
        return None
    if is_localhost(ip):
        return {"subdomain": fqdn, "ip": ip, "cdn": "localhost", "location": "localhost"}
    cdn      = cdn_from_ip(ip)
    location = geolocate(ip)
    return {"subdomain": fqdn, "ip": ip, "cdn": cdn, "location": location}

import urllib.request
import json as _json

_GEO_CACHE: dict[str, str] = {}

LOCALHOST_RANGES = [
    "127.",
    "10.",
    "192.168.",
    "::1",
    "0.0.0.0",
]

def is_localhost(ip: str) -> bool:
    for prefix in LOCALHOST_RANGES:
        if ip.startswith(prefix):
            return True
    try:
        parts = ip.split(".")
        if len(parts) == 4 and int(parts[0]) == 172 and 16 <= int(parts[1]) <= 31:
            return True
    except Exception:
        pass
    return False

def geolocate(ip: str) -> str:
    """Return 'City, Country' for an IP, or '-' on failure. Results cached."""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    if is_localhost(ip):
        _GEO_CACHE[ip] = "localhost"
        return "localhost"
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,city,country"
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = _json.loads(resp.read())
        if data.get("status") == "success":
            city    = data.get("city", "")
            country = data.get("country", "")
            result  = f"{city}, {country}" if city else country or "-"
        else:
            result = "-"
    except Exception:
        result = "-"
    _GEO_CACHE[ip] = result
    return result

def format_results(found: list[dict]) -> str:
    found.sort(key=lambda r: r["subdomain"])
    col_sub = max((len(r["subdomain"])  for r in found), default=11)
    col_sub = max(col_sub, len("SOTTODOMINIO"))
    col_ip  = max((len(r["ip"])         for r in found), default=2)
    col_ip  = max(col_ip,  len("IP"))
    col_cdn = max((len(r["cdn"])        for r in found), default=3)
    col_cdn = max(col_cdn, len("CDN"))
    col_geo = max((len(r["location"])   for r in found), default=9)
    col_geo = max(col_geo, len("POSIZIONE"))

    header = (
        f"{'SOTTODOMINIO':<{col_sub}}   "
        f"{'IP':<{col_ip}}   "
        f"{'CDN':<{col_cdn}}   "
        f"{'POSIZIONE':<{col_geo}}"
    )
    sep = "-" * len(header)
    rows = [header, sep]
    for r in found:
        rows.append(
            f"{r['subdomain']:<{col_sub}}   "
            f"{r['ip']:<{col_ip}}   "
            f"{r['cdn']:<{col_cdn}}   "
            f"{r['location']:<{col_geo}}"
        )
    return "\n".join(rows)

async def _run_async(
    domain: str,
    words: list[str],
    concurrency: int,
    qps: float,
    nameservers: list[str] | None,
    timeout: float,
    idle_timeout: float,
) -> tuple[list[dict], str]:
    """
    Returns (found_list, stop_reason)
    stop_reason: "completed" | "idle_timeout"
    """

    resolver = aiodns.DNSResolver(
        nameservers=nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        timeout=timeout,
        tries=1,
    )

    bucket    = TokenBucket(rate=qps, capacity=qps * 2)
    throttle  = AdaptiveThrottle(window=200, threshold=0.40)
    semaphore = asyncio.Semaphore(concurrency)

    total     = len(words)
    found: list[dict] = []
    completed = 0
    stop_reason = "completed"

    last_hit = time.monotonic()

    tasks = [
        asyncio.create_task(
            probe_async(word, domain, resolver, semaphore, bucket, throttle)
        )
        for word in words
    ]

    pending = set(tasks)

    while pending:
        done, pending = await asyncio.wait(pending, timeout=1.0)

        for fut in done:
            result = fut.result()
            completed += 1
            if result:
                found.append(result)
                last_hit = time.monotonic()

        if done and (completed % 250 == 0 or completed == total):
            tr = throttle.timeout_rate
            throttle_tag = f"  throttle:{tr*100:4.1f}%" if tr > 0.05 else ""
            idle_secs = time.monotonic() - last_hit
            idle_tag  = f"  idle:{idle_secs:.0f}s/{idle_timeout:.0f}s" if idle_secs > 5 else ""
            print(
                f"\r[*] {completed:>7,}/{total:,}  found:{len(found):>5,}"
                f"  ~{int(qps)} q/s{throttle_tag}{idle_tag}   ",
                end="", flush=True,
            )

        if time.monotonic() - last_hit >= idle_timeout:
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            pending.clear()
            stop_reason = "idle_timeout"
            break

    print()
    return found, stop_reason

def enumerate_subdomains(
    domain: str,
    wordlist: Path,
    concurrency: int,
    qps: float,
    output_file: Path | None,
    nameservers: list[str] | None,
    timeout: float,
    fallback_threads: int,
    idle_timeout: float,
) -> None:
    with wordlist.open("r", encoding="utf-8", errors="ignore") as fh:
        words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    total = len(words)
    eta   = total / qps if qps > 0 else 0

    print(f"\n[*] Target        : {domain}")
    print(f"[*] Wordlist      : {wordlist}  ({total:,} entries)")
    if HAS_AIODNS:
        print(f"[*] Engine        : aiodns async")
        print(f"[*] Concurrency   : {concurrency} coroutines")
        print(f"[*] Rate limit    : {int(qps)} queries/s  (burst: {int(qps*2)})")
        ns_str = ", ".join(nameservers) if nameservers else "1.1.1.1, 8.8.8.8, 9.9.9.9"
        print(f"[*] Nameservers   : {ns_str}")
        print(f"[*] Timeout/query : {timeout}s")
        print(f"[*] Idle stop     : {idle_timeout:.0f}s without new hits")
        print(f"[*] ETA (approx)  : {eta/60:.1f} min")
        print(f"[*] Adaptive throttle active — auto-slows on timeout spike")
    else:
        print(f"[*] Engine        : socket/thread fallback  (pip install aiodns for async)")
        print(f"[*] Threads       : {fallback_threads}")
        print(f"[*] Idle stop     : {idle_timeout:.0f}s without new hits")
    print()

    t_start = time.monotonic()

    if HAS_AIODNS:
        found, stop_reason = asyncio.run(
            _run_async(domain, words, concurrency, qps, nameservers, timeout, idle_timeout)
        )
    else:
        found = []
        completed = 0
        last_hit = time.monotonic()
        stop_reason = "completed"

        with ThreadPoolExecutor(max_workers=fallback_threads) as executor:
            futures = {executor.submit(probe_sync, w, domain): w for w in words}
            for future in _as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    found.append(result)
                    last_hit = time.monotonic()
                if completed % 250 == 0 or completed == total:
                    idle_secs = time.monotonic() - last_hit
                    idle_tag  = f"  idle:{idle_secs:.0f}s/{idle_timeout:.0f}s" if idle_secs > 5 else ""
                    print(
                        f"\r[*] {completed:>7,}/{total:,}  found:{len(found):>5,}{idle_tag}   ",
                        end="", flush=True,
                    )
                if time.monotonic() - last_hit >= idle_timeout:
                    stop_reason = "idle_timeout"
                    for f in futures:
                        f.cancel()
                    break
        print()

    elapsed = time.monotonic() - t_start
    rate    = total / elapsed if elapsed > 0 else 0

    if stop_reason == "idle_timeout":
        print(f"\n[!] Idle timeout  : no new subdomains found for {idle_timeout:.0f}s — stopping early.")
    print(f"[*] Done  : {len(found)} found  |  {elapsed:.1f}s  |  {rate:,.0f} q/s avg\n")

    if not found:
        print("[-] No subdomains resolved.")
        return

    output = format_results(found)
    print(output)

    if output_file:
        output_file.write_text(output + "\n", encoding="utf-8")
        print(f"\n[*] Saved : {output_file}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Subdomain Enumerator — OSINT Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Rate presets (--qps):
  --qps 100   safe      — Wi-Fi / home router, no stress
  --qps 200   balanced  — default, good for most setups
  --qps 500   fast      — wired / stable connection
  --qps 1000  aggressive— LAN or VPS only

Install aiodns for async mode:
  pip install aiodns

Examples:
  python subdomain_enum.py example.com
  python subdomain_enum.py example.com --qps 150
  python subdomain_enum.py example.com --qps 500 -o results.txt
  python subdomain_enum.py example.com --ns 1.1.1.1 8.8.8.8 --qps 300
        """,
    )
    parser.add_argument("domain",
        help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", default="names.txt",
        help="Wordlist path (default: names.txt)")
    parser.add_argument("--qps", type=float, default=200,
        help="Max DNS queries per second — lower = gentler on router (default: 200)")
    parser.add_argument("-c", "--concurrency", type=int, default=300,
        help="Max simultaneous in-flight queries (default: 300)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0,
        help="DNS query timeout seconds (default: 3.0)")
    parser.add_argument("-o", "--output", default=None,
        help="Save results to file")
    parser.add_argument("--ns", nargs="+", default=None, metavar="NS",
        help="Custom nameservers e.g. --ns 1.1.1.1 8.8.8.8")
    parser.add_argument("--threads", type=int, default=100,
        help="Thread count for socket fallback (default: 100)")
    parser.add_argument("--idle", type=float, default=60.0,
        help="Stop after this many seconds with no new subdomains found (default: 60)")

    args = parser.parse_args()

    if not HAS_AIODNS:
        print("[!] aiodns not found — socket/thread fallback active.")
        print("[!] pip install aiodns  for async mode\n")

    wordlist = Path(args.wordlist)
    if not wordlist.is_file():
        print(f"[!] Wordlist not found: {wordlist}", file=sys.stderr)
        sys.exit(1)

    try:
        enumerate_subdomains(
            domain=args.domain.lower().strip(),
            wordlist=wordlist,
            concurrency=args.concurrency,
            qps=args.qps,
            output_file=Path(args.output) if args.output else None,
            nameservers=args.ns,
            timeout=args.timeout,
            fallback_threads=args.threads,
            idle_timeout=args.idle,
        )
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted.")
        sys.exit(0)

if __name__ == "__main__":
    main()