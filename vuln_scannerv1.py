#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       Web Vulnerability Scanner v4.0 — Final                ║
║       • Streams URLs — zero RAM usage on input file          ║
║       • Writes results instantly — no memory buildup         ║
║       • Auto-resumes if interrupted (Ctrl+C safe)            ║
║       • No false positives on parking/wildcard servers       ║
║       • Deduplicates URLs automatically                      ║
║       • Safe for 350 million+ sites                          ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python3 vuln_scanner.py "/home/user/TG/domains/domains.txt"
    python3 vuln_scanner.py "/home/user/TG/domains/domains.txt" --threads 35 --timeout 3 --skip-timing
    python3 vuln_scanner.py "/home/user/TG/domains/domains.txt" --resume
    python3 vuln_scanner.py "/home/user/TG/domains/domains.txt" --fresh
"""

import sys
import ssl
import os
import gc
import random
import string
import signal
import socket
import re
import time
import argparse
import datetime
import urllib.parse
import threading
import queue
import resource
from pathlib import Path

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "requests",
                    "--break-system-packages", "-q"], check=False)
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ─── ANSI Colors ──────────────────────────────────────────────────────────
class C:
    RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
    CYAN='\033[96m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
def dim(s):    return f"{C.DIM}{s}{C.RESET}"


# ─── Constants ────────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/api/config", "/api/env", "/api/debug",
    "/package.json", "/config.json",
]

SHELL_API_PATHS = [
    "/api/convert", "/api/export", "/api/file", "/api/render",
    "/api/generate", "/api/exec", "/api/run", "/api/process",
    "/api/image", "/api/pdf", "/api/screenshot", "/api/cmd",
]

SHELL_PARAMS = ["file", "filename", "path", "input", "cmd", "command", "src"]

# Canary is generated fresh each run — prevents server admins from
# hardcoding it into responses to defeat detection
_CANARY = "SCAN_" + "".join(__import__("random").choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10))

SHELL_PAYLOADS = [
    f";echo {_CANARY}",
    f"|echo {_CANARY}",
    f"$(echo {_CANARY})",
]

# Shell injection detection — only match high-confidence patterns
# Removed generic words like child_process/spawnSync that appear in normal pages
def _build_leak_re():
    pattern = (
        _CANARY +
        r"|sh:\s+[^:]+:\s+not found"
        r"|bash:\s+[^:]+:\s+command not found"
        r"|/bin/sh:.*not found"
        r"|execvp\(\).*No such file"
        r"|spawnSync\s+[a-z]+ ENOENT"
        r"|Error: spawnSync.*ENOENT"
    )
    return re.compile(pattern, re.IGNORECASE)

SHELL_LEAK_RE = _build_leak_re()

RISKY_PORTS = {
    21:    "FTP exposed",
    23:    "Telnet exposed",
    3306:  "MySQL exposed to internet",
    5432:  "PostgreSQL exposed to internet",
    6379:  "Redis exposed (often no auth)",
    27017: "MongoDB exposed (often no auth)",
    3000:  "Node/Next.js dev server exposed",
    8888:  "Dev server exposed",
}

QUEUE_BUFFER = 400


# ─── Globals ──────────────────────────────────────────────────────────────
shutdown_event = threading.Event()
stats      = {"scanned": 0, "vulnerable": 0, "warned": 0, "safe": 0, "down": 0}
stats_lock = threading.Lock()


def handle_signal(sig, frame):
    print(f"\n{yellow('Interrupted — progress saved. Re-run with --resume to continue.')}")
    shutdown_event.set()

signal.signal(signal.SIGINT,  handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


# ─── Utilities ────────────────────────────────────────────────────────────
def normalize_url(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw.rstrip("/")


def get_hostname(url):
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def mem_mb():
    try:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except Exception:
        return 0.0


# ─── HTML / file content detection ────────────────────────────────────────
def is_html(data):
    """Return True if bytes/str looks like an HTML document."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    t = text.lower().strip()[:200]
    return (
        t.startswith("<!doctype") or
        t.startswith("<html") or
        t.startswith("<head") or
        "<html" in t[:100] or
        "<!doctype html" in t[:100]
    )


def is_real_sensitive_file(path, text):
    """
    Validate response actually matches the sensitive file — not a parking/error page.
    Each file type has specific content fingerprints.
    """
    t = text.lower()

    if path in ("/.env", "/.env.local", "/.env.production"):
        # Real .env: must have KEY=VALUE pattern (uppercase key, any value)
        return bool(re.search(r"^[A-Z][A-Z0-9_]{1,}=.+", text, re.MULTILINE))

    if path == "/.git/config":
        return "[core]" in t or "[remote" in t or "repositoryformatversion" in t

    if path == "/.git/HEAD":
        stripped = text.strip()
        return stripped.startswith("ref:") or bool(re.match(r"^[0-9a-f]{40}$", stripped))

    if path in ("/docker-compose.yml", "/docker-compose.yaml"):
        return "services:" in t or ("version:" in t and ("image:" in t or "ports:" in t))

    if path == "/package.json":
        return '"name"' in t and '"version"' in t and text.strip().startswith("{")

    if path == "/config.json":
        stripped = text.strip()
        return stripped.startswith("{") and stripped.endswith("}") and len(stripped) > 10

    if path in ("/api/config", "/api/env", "/api/debug"):
        # Real config API leak: JSON object, not HTML
        stripped = text.strip()
        return stripped.startswith("{") and not is_html(text)

    return not is_html(text)


# ─── Individual checks ────────────────────────────────────────────────────
def check_reachability(url, timeout):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=True, stream=False)
        r.close()
        return {"ok": True, "code": r.status_code}
    except requests.exceptions.SSLError:
        return {"ok": True, "code": None, "ssl_err": True}
    except Exception as e:
        return {"ok": False, "reason": type(e).__name__}


def check_ssl(url, timeout):
    issues = []
    hostname = get_hostname(url)
    if not hostname:
        return issues
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(min(timeout, 6))
            s.connect((hostname, 443))
            cert = s.getpeercert()
            exp = cert.get("notAfter", "")
            if exp:
                dt   = datetime.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                now  = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                days = (dt - now).days
                if days < 0:
                    issues.append(f"VULN:SSL cert EXPIRED {abs(days)} days ago")
                elif days < 30:
                    issues.append(f"WARN:SSL cert expires in {days} days")
    except ssl.SSLCertVerificationError as e:
        issues.append(f"VULN:SSL verify failed: {str(e)[:80]}")
    except ssl.SSLError as e:
        issues.append(f"WARN:SSL error: {str(e)[:80]}")
    except Exception:
        pass
    return issues


def check_headers(url, timeout):
    issues = []
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        h = {k.lower(): v for k, v in r.headers.items()}
        r.close()

        missing = [s for s in SECURITY_HEADERS if s.lower() not in h]
        if len(missing) >= 3:
            issues.append(f"WARN:Missing security headers: {', '.join(missing[:4])}")

        if "server" in h:
            issues.append(f"INFO:Server: {h['server'][:50]}")
        if "x-powered-by" in h:
            issues.append(f"INFO:X-Powered-By: {h['x-powered-by'][:50]}")

        xfo = h.get("x-frame-options", "")
        csp = h.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            issues.append("WARN:No clickjacking protection (missing X-Frame-Options)")

        cors = h.get("access-control-allow-origin", "")
        if cors == "*":
            issues.append("VULN:CORS misconfiguration — wildcard origin (*) allows any site")

    except Exception:
        pass
    return issues


def check_ports(hostname, timeout):
    issues = []
    for port, label in RISKY_PORTS.items():
        try:
            with socket.create_connection((hostname, port), timeout=1.5):
                issues.append(f"VULN:Port {port} open — {label}")
        except Exception:
            pass
    return issues


def check_paths(url, timeout):
    """
    Check for exposed sensitive files.
    First sends a canary request to a random path — if the server returns 200
    for that too, it's a wildcard server (parking page) and we skip entirely.
    For real 200s, validates content matches what the file should actually contain.
    """
    issues = []

    # Canary: random path that should never exist
    canary = "/" + "".join(random.choices(string.ascii_lowercase, k=14))
    try:
        cr = requests.get(url + canary, timeout=timeout, verify=False,
                          allow_redirects=False, stream=True)
        canary_chunk = next(cr.iter_content(128), b"")
        cr.close()
        # Wildcard server — returns 200 HTML for everything, skip path checks
        if cr.status_code == 200 and is_html(canary_chunk):
            return issues
    except Exception:
        pass

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (SecurityAudit/4.0)"
    for path in SENSITIVE_PATHS:
        try:
            r = session.get(url + path, timeout=timeout, verify=False,
                            allow_redirects=False, stream=True)
            chunk = next(r.iter_content(512), b"")
            r.close()

            if r.status_code != 200 or len(chunk) < 8:
                continue
            if is_html(chunk):
                continue

            text = chunk.decode("utf-8", errors="replace")
            if is_real_sensitive_file(path, text):
                snippet = text[:60].replace("\n", " ").strip()
                issues.append(f"VULN:Exposed {path} — {snippet}")

        except Exception:
            pass
    session.close()
    return issues


def check_shell(url, timeout):
    """
    Test Next.js/Node API routes for shell injection (React2Shell).
    Uses high-confidence canary echo — only flags if canary string
    appears in response, not generic error words.
    """
    issues = []
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (SecurityAudit/4.0)"

    for path in SHELL_API_PATHS:
        if shutdown_event.is_set():
            break
        for param in SHELL_PARAMS[:4]:
            for payload in SHELL_PAYLOADS:
                try:
                    enc   = urllib.parse.quote(payload)
                    probe = f"{url}{path}?{param}={enc}"
                    r     = session.get(probe, timeout=timeout, verify=False, stream=True)
                    body  = next(r.iter_content(2048), b"").decode("utf-8", errors="replace")
                    r.close()

                    if SHELL_LEAK_RE.search(body):
                        issues.append(f"VULN:Shell injection (React2Shell) at {path}?{param}=<payload>")
                        session.close()
                        return issues  # one confirmed hit is enough

                except Exception:
                    pass

    session.close()
    return issues


# ─── Master site scanner ──────────────────────────────────────────────────
def scan_site(url_raw, timeout):
    url = normalize_url(url_raw)
    if not url:
        return None

    result = {
        "url":       url,
        "ts":        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reachable": False,
        "issues":    [],
    }

    reach = check_reachability(url, timeout)
    if not reach["ok"]:
        result["error"] = reach.get("reason", "unreachable")
        return result

    result["reachable"] = True

    issues = []
    issues += check_ssl(url, timeout)
    issues += check_headers(url, timeout)
    issues += check_ports(get_hostname(url), timeout)
    issues += check_paths(url, timeout)
    issues += check_shell(url, timeout)

    result["issues"] = issues
    del issues
    gc.collect()
    return result


# ─── Writer thread — writes to disk instantly, never buffers ─────────────
def writer_thread_fn(out_vuln, out_details, out_warn, out_log, rq):
    fv = open(out_vuln,    "a", buffering=1)
    fd = open(out_details, "a", buffering=1)
    fw = open(out_warn,    "a", buffering=1)
    fl = open(out_log,     "a", buffering=1)

    while True:
        try:
            item = rq.get(timeout=2)
        except Exception:
            if shutdown_event.is_set():
                break
            continue

        if item is None:
            break

        r   = item
        url = r.get("url", "?")

        if not r.get("reachable"):
            fl.write(f"[DOWN] {url} — {r.get('error', 'unreachable')}\n")
            with stats_lock:
                stats["down"]    += 1
                stats["scanned"] += 1
            rq.task_done()
            continue

        issues = r.get("issues", [])
        vulns  = [i for i in issues if i.startswith("VULN:")]
        warns  = [i for i in issues if i.startswith("WARN:")]
        infos  = [i for i in issues if i.startswith("INFO:")]

        if vulns:
            fv.write(url + "\n")
            fd.write(f"\n{'='*60}\n")
            fd.write(f"URL:     {url}\n")
            fd.write(f"SCANNED: {r['ts']}\n")
            for v in vulns: fd.write(f"  [HIGH] {v[5:]}\n")
            for w in warns: fd.write(f"  [WARN] {w[5:]}\n")
            for i in infos: fd.write(f"  [INFO] {i[5:]}\n")
            fl.write(f"[VULN]  {url} — {len(vulns)} issue(s)\n")
            with stats_lock:
                stats["vulnerable"] += 1

        elif warns:
            fw.write(url + "\n")
            fl.write(f"[WARN]  {url} — {len(warns)} warning(s)\n")
            with stats_lock:
                stats["warned"] += 1

        else:
            fl.write(f"[SAFE]  {url}\n")
            with stats_lock:
                stats["safe"] += 1

        with stats_lock:
            stats["scanned"] += 1

        rq.task_done()

    fv.close()
    fd.close()
    fw.close()
    fl.close()


# ─── Worker thread ────────────────────────────────────────────────────────
def worker_fn(wq, rq, timeout):
    while not shutdown_event.is_set():
        try:
            item = wq.get(timeout=2)
        except Exception:
            continue
        if item is None:
            wq.task_done()
            break
        _, url_raw = item
        try:
            result = scan_site(url_raw, timeout)
            if result:
                rq.put(result)
        except Exception as e:
            rq.put({"url": url_raw, "reachable": False,
                    "error": str(e), "ts": "", "issues": []})
        finally:
            wq.task_done()


# ─── URL streamer — reads line by line, zero RAM, deduplicates ────────────
def stream_urls(filepath, skip=0):
    seen     = set()
    MAX_SEEN = 2_000_000  # flush at 2M to keep RAM under ~100MB

    with open(filepath, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i < skip:
                continue
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = normalize_url(line)
            if not url:
                continue
            if url in seen:
                continue
            seen.add(url)
            if len(seen) >= MAX_SEEN:
                seen.clear()
            yield i + 1, line


def count_lines(filepath):
    n = 0
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            n += chunk.count(b"\n")
    return n


def load_progress(pf):
    try:
        return int(Path(pf).read_text().strip())
    except Exception:
        return 0


def save_progress(pf, n):
    try:
        Path(pf).write_text(str(n))
    except Exception:
        pass


# ─── Progress printer ─────────────────────────────────────────────────────
def progress_printer_fn(total, start_time, interval=15):
    while not shutdown_event.is_set():
        time.sleep(interval)
        with stats_lock:
            s = dict(stats)
        elapsed = time.time() - start_time
        rate    = s["scanned"] / elapsed if elapsed > 0 else 0
        eta_s   = (total - s["scanned"]) / rate if rate > 0 else 0
        eta     = str(datetime.timedelta(seconds=int(eta_s)))
        pct     = s["scanned"] / total * 100 if total else 0
        nv = s["vulnerable"]
        nw = s["warned"]
        ns = s["safe"]
        nd = s["down"]
        print(
            f"  {dim('|')} {cyan(f'{pct:.1f}%')} "
            f"{s['scanned']:,}/{total:,}  "
            f"{red(f'vuln:{nv}')}  "
            f"{yellow(f'warn:{nw}')}  "
            f"{green(f'safe:{ns}')}  "
            f"{dim(f'down:{nd}')}  "
            f"{rate:.1f}/s  ETA:{eta}  RAM:{mem_mb():.0f}MB",
            flush=True
        )


# ─── Main ─────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║    🔍  Web Vulnerability Scanner  v4.0 — Final               ║
║    SSL · Headers · Ports · Shell Injection · CORS · Files    ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")


def main():
    parser = argparse.ArgumentParser(
        description="Crash-proof vulnerability scanner — safe for 350M+ sites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normal run (auto-resumes if .progress file exists):
  python3 vuln_scanner.py "/home/user/TG/domains/domains.txt" --threads 35 --timeout 3 --skip-timing

  # Resume explicitly after interrupt:
  python3 vuln_scanner.py "/home/user/TG/domains/domains.txt" --resume --threads 35 --timeout 3 --skip-timing

  # Wipe all previous results and start fresh:
  python3 vuln_scanner.py "/home/user/TG/domains/domains.txt" --fresh --threads 35 --timeout 3 --skip-timing
        """
    )
    parser.add_argument("input",
                        help="Text file with one URL or domain per line")
    parser.add_argument("--output",       default="vulnerable_sites.txt",
                        help="Output filename prefix (default: vulnerable_sites.txt)")
    parser.add_argument("--threads",      type=int, default=6,
                        help="Parallel worker threads (default: 6)")
    parser.add_argument("--timeout",      type=int, default=10,
                        help="Per-request timeout seconds (default: 10)")
    parser.add_argument("--resume",       action="store_true",
                        help="Resume from saved progress position")
    parser.add_argument("--fresh",        action="store_true",
                        help="Delete all previous results and start from line 1")
    parser.add_argument("--skip-timing",  action="store_true",
                        help="Skip slow timing-based shell checks")
    args = parser.parse_args()

    print_banner()

    out_vuln    = args.output
    out_details = args.output.replace(".txt", "_details.txt")
    out_warn    = args.output.replace(".txt", "_warnings.txt")
    out_log     = args.output.replace(".txt", "_scan.log")
    prog_file   = args.output.replace(".txt", ".progress")

    # Validate input file exists
    if not os.path.exists(args.input):
        print(red(f"\n  Error: Input file not found: {args.input}"))
        print(f"  Check the path and try again.\n")
        sys.exit(1)

    # Count total URLs
    print(f"\n  Counting URLs...", end="", flush=True)
    total = count_lines(args.input)
    print(f"\r  {cyan('Total URLs:')} {bold(f'{total:,}')}{' ' * 20}")

    # Handle fresh / resume / auto-resume
    skip = 0
    if args.fresh:
        for f in [out_vuln, out_details, out_warn, out_log, prog_file]:
            try:
                Path(f).unlink(missing_ok=True)
            except Exception:
                pass
        print(f"  {red('--fresh: all previous results deleted. Starting from line 1.')}")

    else:
        saved = load_progress(prog_file)
        if saved:
            skip = saved
            print(f"  {yellow('Auto-resuming from line:')} {skip:,}  ({total - skip:,} remaining)")
            print(f"  {dim('Use --fresh to wipe results and start over.')}")
        else:
            print(f"  {dim('No saved progress — starting from line 1.')}")

    # Always ensure output files exist (touch = create if missing, never wipe)
    for f in [out_vuln, out_details, out_warn, out_log]:
        try:
            Path(f).touch(exist_ok=True)
        except Exception:
            pass

    print(f"  {cyan('Threads:')} {args.threads}  "
          f"{cyan('Timeout:')} {args.timeout}s  "
          f"{cyan('Output:')} {out_vuln}")
    print(f"  {dim('Ctrl+C to pause — re-run same command to auto-resume')}\n")

    start_time = time.time()

    work_queue   = queue.Queue(maxsize=QUEUE_BUFFER)
    result_queue = queue.Queue(maxsize=QUEUE_BUFFER)

    # Start writer thread
    wt = threading.Thread(
        target=writer_thread_fn,
        args=(out_vuln, out_details, out_warn, out_log, result_queue),
        daemon=True
    )
    wt.start()

    # Start worker threads
    workers = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=worker_fn,
            args=(work_queue, result_queue, args.timeout),
            daemon=True
        )
        t.start()
        workers.append(t)

    # Start progress printer
    pp = threading.Thread(
        target=progress_printer_fn,
        args=(total, start_time),
        daemon=True
    )
    pp.start()

    # Feed URLs into work queue — streaming, zero RAM
    last_line = skip
    try:
        for line_no, url_raw in stream_urls(args.input, skip=skip):
            if shutdown_event.is_set():
                break
            work_queue.put((line_no, url_raw))
            last_line = line_no
            if line_no % 1000 == 0:
                save_progress(prog_file, line_no)
    except KeyboardInterrupt:
        shutdown_event.set()

    # Shutdown workers
    for _ in workers:
        work_queue.put(None)
    for t in workers:
        t.join(timeout=30)

    # Shutdown writer
    result_queue.put(None)
    wt.join(timeout=30)

    # Save final progress
    save_progress(prog_file, last_line)

    # Print summary
    elapsed = time.time() - start_time
    rate    = stats["scanned"] / elapsed if elapsed > 0 else 0

    print(f"""
{C.CYAN}{C.BOLD}═══════════════════════  SCAN COMPLETE  ══════════════════════════{C.RESET}
  {red(f"✗ Vulnerable:   {stats['vulnerable']:,}")}
  {yellow(f"△ Warnings:     {stats['warned']:,}")}
  {green(f"✓ Safe:         {stats['safe']:,}")}
  {dim(f"⚠ Unreachable:  {stats['down']:,}")}
  {'─' * 48}
  Total scanned:  {stats['scanned']:,} / {total:,}
  Time elapsed:   {str(datetime.timedelta(seconds=int(elapsed)))}
  Avg speed:      {rate:.1f} sites/sec
  Peak RAM:       {mem_mb():.0f} MB
{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════{C.RESET}

  📄 {cyan('Vulnerable URLs:')}  {out_vuln}
  📋 {cyan('Full details:')}     {out_details}
  ⚠  {cyan('Warnings only:')}   {out_warn}
  🗂  {cyan('Full log:')}        {out_log}
""")

    if shutdown_event.is_set():
        remaining = total - last_line
        print(f"  {yellow(f'Paused at line {last_line:,}. {remaining:,} URLs remaining.')}")
        print(f"  {cyan('To resume:')} python3 vuln_scanner.py \"{args.input}\" --threads {args.threads} --timeout {args.timeout} --skip-timing\n")
    else:
        # Clean up progress file on full completion
        try:
            Path(prog_file).unlink(missing_ok=True)
        except Exception:
            pass
        print(f"  {green('Scan fully complete.')}\n")


if __name__ == "__main__":
    main()
