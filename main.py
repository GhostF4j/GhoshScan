#!/usr/bin/env python3
"""
GhostScan Tools Scanner Ip Addres
Usage: python3 main.py

Only run against hosts you OWN or have explicit permission to test.
Logs are appended to ./ghostscan_log.txt
"""
import socket
import sys
import threading
import datetime
import ipaddress
import os
import time
from queue import Queue

# --- Configuration ---
COMMON_PORTS = [
    21,22,23,25,53,67,68,80,110,111,123,135,139,143,161,162,
    179,389,443,445,465,514,587,631,993,995,1433,1521,3306,3389,5900,8080
]
RISKY_PORTS = {21,23,445,3389,3306,1433,1521,5900}
THREADS = 100
SOCKET_TIMEOUT = 1.5
LOGFILE = "ghostscan_bukti.txt"
# ----------------------

# ANSI colors (may not render on old Windows terminals)
CSI = "\033["
RESET = CSI + "0m"
GREEN = CSI + "32;1m"
DARKGREEN = CSI + "32m"
CYAN = CSI + "36;1m"
YELLOW = CSI + "33;1m"
RED = CSI + "31;1m"

_global_lock = threading.Lock()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(s, delay=0.002):
    for ch in s:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_hacker_theme():
    clear_screen()
    banner = r"""
  ____ _               _     ____                 
 / ___| |__   ___  ___| |__ / ___|  ___ __ _ _ __  
| |  _| '_ \ / _ \/ __| '_ \\___ \ / __/ _` | '_ \ 
| |_| | | | |  __/ (__| | | |___) | (_| (_| | | | |
 \____|_| |_|\___|\___|_| |_|____/ \___\__,_|_| |_|
"""
    slow_print(GREEN + banner + RESET, delay=0.001)
    sys.stdout.write(DARKGREEN + ":: GhostScan :: Tools By GhostF4j ::\n" + RESET + "\n")
    sys.stdout.write(GREEN + "Hacker sejati bukan yang membobol sistem — tapi yang tahu kapan harus berhenti." + RESET + "\n")
    for _ in range(3):
        line = "".join(["01"[i % 2] for i in range(0, 48)])
        sys.stdout.write(DARKGREEN + line + RESET + "\n")
        time.sleep(0.06)
    print()

def log_event(event):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    line = "{} | {}\n".format(ts, event)
    with _global_lock:
        try:
            with open(LOGFILE, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            # fallback to stderr if logging fails
            sys.stderr.write("Failed to write log: " + line)

def ask_questions_and_verify():
    sys.stdout.write("=== GhostScan — Pre-scan verification ===\n")
    name = input("1) Kenapa kamu ingin memakai tools GhostScan? (masukkan nama / identitasmu): ").strip()
    purpose = input("2) Untuk tujuan apa kamu menggunakan tools ini? (penjelasan singkat): ").strip()
    agree = input("3) Jika kamu melakukan tindakan ilegal maka sistem akan mendeteksi dan memberhentikan tools. Jika kamu setuju ketik y untuk lanjut: ").strip().lower()
    log_event("VERIFICATION_ANSWERS | name={} | purpose={} | agree={}".format(name, purpose, agree))
    if agree != 'y':
        sys.stdout.write(RED + "\n[!] Kamu tidak menyetujui persyaratan. Proses dibatalkan." + RESET + "\n")
        log_event("ABORT | user did not agree to terms.")
        sys.exit(1)
    return name, purpose

def is_private_or_loopback(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return ip.is_private or ip.is_loopback

def require_public_permission_flow(target_ip):
    sys.stdout.write(YELLOW + "\n!!! TARGET ADALAH IP PUBLIK !!!" + RESET + "\n")
    sys.stdout.write(YELLOW + "Untuk melanjutkan kamu harus mengetik KONFIRMASI persis: SAYA_MENGERTI" + RESET + "\n")
    confirm = input("Ketik konfirmasi: ").strip()
    if confirm != "SAYA_MENGERTI":
        sys.stdout.write(RED + "Konfirmasi tidak valid. Proses dibatalkan." + RESET + "\n")
        log_event("ABORT | public_target_without_confirmation | target={}".format(target_ip))
        sys.exit(1)
    owner_email = input("Masukkan alamat email pemilik/penanggung jawab yang memberi izin (untuk log audit): ").strip()
    if not owner_email or "@" not in owner_email:
        sys.stdout.write(RED + "Alamat email tidak valid. Proses dibatalkan." + RESET + "\n")
        log_event("ABORT | public_target_invalid_owner | target={}".format(target_ip))
        sys.exit(1)
    try:
        rev = socket.gethostbyaddr(target_ip)[0]
    except Exception:
        rev = "<no-reverse>"
    log_event("PUBLIC_SCAN_CONFIRMED | target={} | owner_email={} | reverse={}".format(target_ip, owner_email, rev))
    sys.stdout.write(GREEN + "Konfirmasi izin diterima (dicatat ke log). Melanjutkan scanning..." + RESET + "\n")
    time.sleep(0.6)

# scanner helpers (use local queue & open_ports per-run to avoid stale state)
def _scan_port_and_grab_banner(target, port, open_ports_list, timeout=SOCKET_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        banner = ""
        try:
            s.settimeout(1.0)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception:
            banner = ""
        with _global_lock:
            open_ports_list.append((port, banner))
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

def _worker_loop(target, q, open_ports_list):
    while True:
        try:
            port = q.get_nowait()
        except Exception:
            break
        try:
            _scan_port_and_grab_banner(target, port, open_ports_list)
        finally:
            q.task_done()

def classify_scan_results(open_ports_list):
    ports_only = {p for p, _ in open_ports_list}
    reasons = []
    if not open_ports_list:
        return "Aman", ["Tidak ditemukan port umum terbuka."]
    risky_found = ports_only.intersection(RISKY_PORTS)
    if risky_found:
        reasons.append("Port berisiko terbuka: {}".format(", ".join(str(p) for p in sorted(risky_found))))
    if len(open_ports_list) > 2:
        reasons.append("Jumlah port terbuka signifikan: {}".format(len(open_ports_list)))
    if reasons:
        return "Lemah", reasons
    return "Aman", ["Hanya {} port terbuka (tidak pada daftar 'risky').".format(len(open_ports_list))]

def run_scan(target):
    # local structures
    q = Queue()
    open_ports = []

    sys.stdout.write(CYAN + "\n[*] Scanning {} (common ports only) ...".format(target) + RESET + "\n")
    log_event("SCAN_START | target={} | ports={}".format(target, len(COMMON_PORTS)))
    for p in COMMON_PORTS:
        q.put(p)

    threads = []
    for _ in range(min(THREADS, q.qsize())):
        t = threading.Thread(target=_worker_loop, args=(target, q, open_ports), daemon=True)
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            sys.stdout.write(DARKGREEN + "." + RESET)
            sys.stdout.flush()
            time.sleep(0.4)
    except KeyboardInterrupt:
        sys.stdout.write(RED + "\nDibatalkan oleh pengguna (Ctrl+C)." + RESET + "\n")
        log_event("ABORT | keyboard_interrupt")
        sys.exit(1)

    q.join()

    if open_ports:
        open_ports.sort()
        sys.stdout.write(GREEN + "\n\nFound open ports on {}:".format(target) + RESET + "\n")
        for port, banner in open_ports:
            line = " - {}".format(port)
            if banner:
                snip = banner if len(banner) <= 120 else banner[:117] + "..."
                line += "  | banner: {}".format(snip)
            sys.stdout.write(DARKGREEN + line + RESET + "\n")
        log_event("SCAN_RESULT | target={} | open_ports={}".format(target, ",".join(str(p[0]) for p in open_ports)))
    else:
        sys.stdout.write(YELLOW + "\nNo open common ports found on {} (within timeout).".format(target) + RESET + "\n")
        log_event("SCAN_RESULT | target={} | open_ports=NONE".format(target))

    status, reasons = classify_scan_results(open_ports)

    if status == "Aman":
        detail = " | ".join(reasons)
        sys.stdout.write("\n" + GREEN + "[!] Info [!]" + RESET + "\n")
        sys.stdout.write("ip: {}\n".format(target))
        sys.stdout.write("status: aman\n")
        sys.stdout.write("pesan: mantap bree ip lu aman banget perketat lagi yaa\n")
        if detail:
            sys.stdout.write("Detail: {}\n".format(detail))
        log_event("SAFE_NOTICE | target={} | reasons={}".format(target, detail))
    else:
        detail = " | ".join(reasons)
        sys.stdout.write("\n" + RED + "[!]WARNING[!]" + RESET + "\n")
        sys.stdout.write("Ip: {}\n".format(target))
        sys.stdout.write("Status: Lemah\n")
        sys.stdout.write("Pesan: WADUH IP SYSTEM KEAMANAN KAMU LEMAH PERBAIKI LAGI YAA JANGAN SAMPAI DI BOBOL HACKER JAHAT\n")
        sys.stdout.write("Detail: {}\n".format(detail))
        log_event("WEAK_WARNING | target={} | reasons={}".format(target, detail))

def validate_ip_or_hostname(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        try:
            socket.gethostbyname(s)
            return True
        except Exception:
            return False

def main():
    sys.stdout.write("=== GhostScan  ===\n")
    sys.stdout.write("PENTING: Tools ini hanya untuk edukasi / audit internal. Jangan gunakan tanpa izin.\n\n")
    try:
        open(LOGFILE, "a").close()
    except Exception as e:
        sys.stdout.write(RED + "Cannot write to log file {}: {}\n".format(LOGFILE, e) + RESET)
        sys.exit(1)

    name, purpose = ask_questions_and_verify()
    show_hacker_theme()

    target = input(GREEN + ">> Masukkan target (IP atau hostname) yang akan discan: " + RESET).strip()
    if not target:
        sys.stdout.write(RED + "Tidak ada target diberikan. Keluar." + RESET + "\n")
        log_event("ABORT | no_target_given")
        sys.exit(1)

    if not validate_ip_or_hostname(target):
        sys.stdout.write(RED + "Target tidak valid (bukan IP/hostname resolvable). Keluar." + RESET + "\n")
        log_event("ABORT | invalid_target | target={}".format(target))
        sys.exit(1)

    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        sys.stdout.write(RED + "Gagal resolve target. Keluar." + RESET + "\n")
        log_event("ABORT | resolve_failed | target={}".format(target))
        sys.exit(1)

    if is_private_or_loopback(resolved_ip):
        log_event("PRIVATE_SCAN_ALLOWED | user={} | purpose={} | target={}".format(name, purpose, resolved_ip))
        run_scan(resolved_ip)
    else:
        require_public_permission_flow(resolved_ip)
        run_scan(resolved_ip)

    sys.stdout.write(GREEN + "\n[+] Scan selesai. Lihat ghostscan_log.txt untuk catatan." + RESET + "\n")
    log_event("SCAN_COMPLETE | user={} | target={}".format(name, resolved_ip))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            sys.stdout.write("\n" + RED + "Dibatalkan oleh pengguna (Ctrl+C)." + RESET + "\n")
            log_event("ABORT | keyboard_interrupt")
        except Exception:
            pass
        sys.exit(1)