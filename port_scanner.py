#!/usr/bin/env python3
"""
Python Port Scanner
===================
A fast, multithreaded TCP port scanner with colored terminal output.
Suitable for authorized network diagnostics and security auditing.

Usage: python port_scanner.py

Author: Your Name
License: MIT
"""

import socket
import threading
import time
import sys
from queue import Queue
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Missing dependency: colorama. Run 'pip install -r requirements.txt'")
    sys.exit(1)


# ─────────────────────────────────────────────
# Well-known port → service name mappings
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    119:  "NNTP",
    123:  "NTP",
    135:  "MS-RPC",
    137:  "NetBIOS",
    138:  "NetBIOS",
    139:  "NetBIOS",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP Trap",
    179:  "BGP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    514:  "Syslog",
    515:  "LPD",
    587:  "SMTP (Submission)",
    631:  "IPP",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    6443: "Kubernetes API",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    8888: "HTTP Dev",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Thread-safe list for storing discovered open ports
open_ports = []
open_ports_lock = threading.Lock()

# Queue holding ports yet to be scanned
port_queue = Queue()

# Shared progress counter
scanned_count = 0
scanned_lock = threading.Lock()
total_ports = 0


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
║         PYTHON PORT SCANNER  v1.0                ║
║         Fast · Multithreaded · Colorful          ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.YELLOW}  [!] Only scan systems you own or have permission to scan.{Style.RESET_ALL}
"""
    print(banner)


# ─────────────────────────────────────────────
# Input helpers
# ─────────────────────────────────────────────
def get_target() -> str:
    """Prompt for and validate the target host."""
    while True:
        target = input(f"{Fore.CYAN}[?]{Style.RESET_ALL} Enter target IP or domain: ").strip()
        if not target:
            print(f"{Fore.RED}[-] Target cannot be empty.{Style.RESET_ALL}")
            continue
        try:
            resolved = socket.gethostbyname(target)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Resolved {Fore.WHITE}{target}{Style.RESET_ALL} → {Fore.GREEN}{resolved}{Style.RESET_ALL}")
            return resolved
        except socket.gaierror:
            print(f"{Fore.RED}[-] Cannot resolve '{target}'. Check the hostname and try again.{Style.RESET_ALL}")


def get_port_range() -> tuple[int, int]:
    """Prompt for and validate start / end port numbers."""
    print(f"\n{Fore.CYAN}[?]{Style.RESET_ALL} Port range options:")
    print(f"    {Fore.WHITE}1{Style.RESET_ALL} – Common ports  (1–1024)")
    print(f"    {Fore.WHITE}2{Style.RESET_ALL} – Extended scan (1–10000)")
    print(f"    {Fore.WHITE}3{Style.RESET_ALL} – Full scan     (1–65535)")
    print(f"    {Fore.WHITE}4{Style.RESET_ALL} – Custom range")

    choice = input(f"\n{Fore.CYAN}[?]{Style.RESET_ALL} Select option [1-4]: ").strip()

    presets = {"1": (1, 1024), "2": (1, 10000), "3": (1, 65535)}
    if choice in presets:
        return presets[choice]

    # Custom range
    while True:
        try:
            start = int(input(f"{Fore.CYAN}[?]{Style.RESET_ALL} Start port: ").strip())
            end   = int(input(f"{Fore.CYAN}[?]{Style.RESET_ALL} End port  : ").strip())
            if 1 <= start <= end <= 65535:
                return start, end
            print(f"{Fore.RED}[-] Ports must be between 1 and 65535, and start ≤ end.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[-] Please enter valid integers.{Style.RESET_ALL}")


def get_thread_count() -> int:
    """Prompt for thread count with a sensible default."""
    raw = input(f"\n{Fore.CYAN}[?]{Style.RESET_ALL} Number of threads [default: 100]: ").strip()
    if not raw:
        return 100
    try:
        count = int(raw)
        if 1 <= count <= 500:
            return count
        print(f"{Fore.YELLOW}[!] Clamping threads to range 1–500.{Style.RESET_ALL}")
        return max(1, min(count, 500))
    except ValueError:
        print(f"{Fore.YELLOW}[!] Invalid input, using 100 threads.{Style.RESET_ALL}")
        return 100


# ─────────────────────────────────────────────
# Core scanning logic
# ─────────────────────────────────────────────
def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
    """
    Attempt a TCP connection to (target, port).
    Returns True if the port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return result == 0          # 0 means the connection succeeded
    except (socket.timeout, socket.error):
        return False


def worker(target: str, timeout: float):
    """
    Thread worker: pulls ports from the queue, scans them,
    and records any that are open.
    """
    global scanned_count

    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except Exception:
            break

        is_open = scan_port(target, port, timeout)

        if is_open:
            service = COMMON_PORTS.get(port, "Unknown")
            with open_ports_lock:
                open_ports.append((port, service))
            # Immediate feedback for each discovered open port
            print(f"\r{' ' * 60}\r"           # clear progress line
                  f"  {Fore.GREEN}[OPEN]{Style.RESET_ALL} "
                  f"Port {Fore.WHITE}{port:>5}{Style.RESET_ALL}  "
                  f"{Fore.CYAN}({service}){Style.RESET_ALL}")

        with scanned_lock:
            scanned_count += 1
            done = scanned_count
        # Overwrite the current line with a live progress indicator
        pct = (done / total_ports) * 100
        bar_filled = int(pct / 2)           # 50-char bar
        bar = "█" * bar_filled + "░" * (50 - bar_filled)
        sys.stdout.write(
            f"\r  {Fore.YELLOW}Progress:{Style.RESET_ALL} "
            f"[{Fore.GREEN}{bar}{Style.RESET_ALL}] "
            f"{Fore.WHITE}{pct:5.1f}%{Style.RESET_ALL} "
            f"({done}/{total_ports})"
        )
        sys.stdout.flush()

        port_queue.task_done()


# ─────────────────────────────────────────────
# Results display
# ─────────────────────────────────────────────
def display_results(target: str, start_port: int, end_port: int, elapsed: float):
    """Print a formatted summary of the scan results."""
    print(f"\n\n{Fore.CYAN}{'═' * 52}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 52}{Style.RESET_ALL}")
    print(f"  Target   : {Fore.WHITE}{target}{Style.RESET_ALL}")
    print(f"  Range    : {Fore.WHITE}{start_port} – {end_port}{Style.RESET_ALL}")
    print(f"  Duration : {Fore.WHITE}{elapsed:.2f}s{Style.RESET_ALL}")
    print(f"  Scanned  : {Fore.WHITE}{total_ports} ports{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 52}{Style.RESET_ALL}")

    if not open_ports:
        print(f"  {Fore.YELLOW}No open ports found in the specified range.{Style.RESET_ALL}")
    else:
        sorted_ports = sorted(open_ports, key=lambda x: x[0])
        print(f"  {Fore.GREEN}Open ports found: {len(sorted_ports)}{Style.RESET_ALL}\n")
        print(f"  {'PORT':<8} {'SERVICE':<20}")
        print(f"  {'─'*7}  {'─'*19}")
        for port, service in sorted_ports:
            print(f"  {Fore.GREEN}{port:<8}{Style.RESET_ALL} {Fore.CYAN}{service}{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{'═' * 52}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
def main():
    global total_ports, scanned_count

    print_banner()

    # Gather user inputs
    target               = get_target()
    start_port, end_port = get_port_range()
    num_threads          = get_thread_count()
    timeout              = 1.0      # seconds per connection attempt

    # Reset shared state (important if the script is imported / reused)
    open_ports.clear()
    scanned_count = 0

    # Populate the work queue
    total_ports = end_port - start_port + 1
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    print(f"\n{Fore.CYAN}{'═' * 52}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}SCAN STARTED{Style.RESET_ALL}  {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"  Target   : {Fore.WHITE}{target}{Style.RESET_ALL}")
    print(f"  Ports    : {Fore.WHITE}{start_port} – {end_port}{Style.RESET_ALL}")
    print(f"  Threads  : {Fore.WHITE}{num_threads}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 52}{Style.RESET_ALL}\n")

    start_time = time.time()

    # Launch worker threads
    threads = []
    for _ in range(min(num_threads, total_ports)):
        t = threading.Thread(target=worker, args=(target, timeout), daemon=True)
        t.start()
        threads.append(t)

    # Wait for all threads to finish
    for t in threads:
        t.join()

    elapsed = time.time() - start_time

    display_results(target, start_port, end_port, elapsed)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}\n")
        sys.exit(0)
