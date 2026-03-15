# 🔍 Python Port Scanner

A fast, multithreaded TCP port scanner with colored terminal output — built for authorized network diagnostics and cybersecurity portfolio projects.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)

---

## ✨ Features

| Feature | Details |
|---|---|
| **TCP Connect Scan** | Reliable open-port detection via `socket.connect_ex` |
| **Multithreading** | Configurable thread pool (up to 500 threads) for fast scans |
| **Live Progress Bar** | Real-time progress display with percentage and port counter |
| **Service Detection** | Maps 60+ well-known ports to service names (SSH, HTTP, MySQL…) |
| **Colored Output** | Clear, color-coded results using `colorama` |
| **Domain Resolution** | Accepts both IP addresses and domain names |
| **Preset Ranges** | Quick selection: common (1–1024), extended (1–10000), or full (1–65535) |
| **Error Handling** | Graceful handling of invalid hosts, timeouts, and keyboard interrupts |

---

## 📋 Requirements

- Python 3.10 or higher
- `colorama` (the only third-party dependency)

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/python-port-scanner.git
cd python-port-scanner

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python port_scanner.py
```

The scanner walks you through three interactive prompts:

```
[?] Enter target IP or domain:  192.168.1.1
[?] Select port range option:   1  (Common: 1–1024)
[?] Number of threads:          100
```

### Example Output

```
╔══════════════════════════════════════════════════╗
║         PYTHON PORT SCANNER  v1.0                ║
║         Fast · Multithreaded · Colorful          ║
╚══════════════════════════════════════════════════╝

[+] Resolved example.com → 93.184.216.34

════════════════════════════════════════════════════
  SCAN STARTED  2025-06-10 14:32:01
  Target   : 93.184.216.34
  Ports    : 1 – 1024
  Threads  : 100
════════════════════════════════════════════════════

  [OPEN] Port    80  (HTTP)
  [OPEN] Port   443  (HTTPS)

  Progress: [██████████████████████████████████████████████████] 100.0% (1024/1024)

════════════════════════════════════════════════════
  SCAN COMPLETE
════════════════════════════════════════════════════
  Target   : 93.184.216.34
  Range    : 1 – 1024
  Duration : 4.37s
  Scanned  : 1024 ports
────────────────────────────────────────────────────
  Open ports found: 2

  PORT     SERVICE
  ───────  ───────────────────
  80       HTTP
  443      HTTPS
════════════════════════════════════════════════════
```

---

## ⚙️ How It Works

```
User Input
    │
    ▼
Resolve Hostname ──► socket.gethostbyname()
    │
    ▼
Populate Queue ──► Queue(port_1, port_2, … port_N)
    │
    ▼
Thread Pool ──► N worker threads each pull from queue
    │
    ▼
TCP Probe ──► socket.connect_ex(target, port)  [timeout: 1 s]
    │
    ├── Result == 0  ──► Port OPEN  → recorded + printed
    └── Result != 0  ──► Port closed / filtered → skipped
    │
    ▼
Results Summary
```

- **Queue-based work distribution** ensures threads never scan the same port twice.
- **Thread-safe counters** (`threading.Lock`) protect shared state from race conditions.
- A `daemon=True` flag on each thread guarantees clean exits on `Ctrl+C`.

---

## 🛡️ Legal Disclaimer

> **This tool is intended for authorized use only.**  
> Always obtain explicit written permission before scanning any network or system you do not own. Unauthorized port scanning may violate local, national, or international law. The author assumes no liability for misuse.

---

## 📂 Project Structure

```
python-port-scanner/
├── port_scanner.py   # Main scanner — all logic lives here
├── requirements.txt  # Third-party dependencies (colorama only)
└── README.md         # This file
```

---

## 🔧 Customization

| Parameter | Location in code | Default |
|---|---|---|
| Connection timeout | `timeout = 1.0` in `main()` | 1 second |
| Max threads cap | `min(num_threads, 500)` | 500 |
| Service name map | `COMMON_PORTS` dict | 60+ entries |

---

## 📜 License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.
