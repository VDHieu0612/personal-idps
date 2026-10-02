import sys
import time
import socket
import argparse

# Force UTF-8 encoding on Windows terminal
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

TARGET_HOST = "127.0.0.1"

def print_header(text):
    print("\n" + "=" * 60)
    print(f"  [>] {text}")
    print("=" * 60)

def probe_port(host, port, timeout=0.2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
    except Exception:
        pass

def test_port_scan():
    print_header("Simulating Port Scan Attack (Scanning 20 distinct ports)...")
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]
    for p in ports_to_scan:
        print(f"  [-] Probing port {p}...")
        probe_port(TARGET_HOST, p)
        time.sleep(0.05)
    print("[+] Port scan traffic completed! Check dashboard for 'Port Scan Detection' alert.")

def test_ssh_brute_force():
    print_header("Simulating SSH Auth Brute Force Attack (Port 22 rapid attempts)...")
    for i in range(7):
        print(f"  [-] SSH Connection attempt #{i+1} to {TARGET_HOST}:22")
        probe_port(TARGET_HOST, 22)
        time.sleep(0.1)
    print("[+] SSH brute force traffic completed! Check dashboard for 'SSH Brute Force' alert.")

def test_rdp_brute_force():
    print_header("Simulating Windows RDP Brute Force Attack (Port 3389 rapid attempts)...")
    for i in range(7):
        print(f"  [-] RDP Connection attempt #{i+1} to {TARGET_HOST}:3389")
        probe_port(TARGET_HOST, 3389)
        time.sleep(0.1)
    print("[+] RDP brute force traffic completed! Check dashboard for 'RDP Brute Force Attempt' alert.")

def test_suspicious_c2_ports():
    print_header("Simulating Suspicious C2 & Tor Connections (Ports 9001, 4444, 50050)...")
    suspicious_ports = [
        (4444, "Metasploit Handler / Reverse Shell"),
        (9001, "Tor Relay / Exit Node Port"),
        (50050, "Cobalt Strike Team Server"),
        (1337, "Web Shell / Backdoor Port"),
        (3333, "Crypto Mining Stratum Pool")
    ]
    for port, label in suspicious_ports:
        print(f"  [-] Connecting to {label} (Port {port})...")
        probe_port(TARGET_HOST, port)
        time.sleep(0.2)
    print("[+] Suspicious C2 traffic sent! Check dashboard for C2 / Malware alerts.")

def test_dns_phishing_lookup():
    print_header("Simulating Suspicious Domain Lookup...")
    fake_domains = [
        "secure-login-verify-account-update.malicious-phishing.com",
        "a8f9c2d1e5b4a3f2e1d0c9b8a7f6e5d4c3b2a1.exfil-dns-tunnel.net"
    ]
    for domain in fake_domains:
        print(f"  [-] Simulating DNS query for: {domain}")
        try:
            socket.gethostbyname(domain)
        except Exception:
            pass
        time.sleep(0.2)
    print("[+] DNS queries sent! Check dashboard for DNS / Phishing alerts.")

def run_all_tests():
    print_header("RUNNING ALL ATTACK SIMULATION TESTS (5-SECOND DEMO)")
    test_port_scan()
    time.sleep(0.5)
    test_ssh_brute_force()
    time.sleep(0.5)
    test_suspicious_c2_ports()
    time.sleep(0.5)
    test_dns_phishing_lookup()
    print("\n" + "*" * 60)
    print("  [SUCCESS] All attack tests finished!")
    print("  Open your browser at: http://localhost:8000")
    print("  Check: Dashboard charts, Recent Alerts table & Logs page.")
    print("*" * 60)

def main():
    parser = argparse.ArgumentParser(description="AegisGuard IDS/IPS Attack Simulator")
    parser.add_argument("--all", action="store_true", help="Run all attack simulation tests")
    parser.add_argument("--scan", action="store_true", help="Test port scan")
    parser.add_argument("--ssh", action="store_true", help="Test SSH brute force")
    parser.add_argument("--c2", action="store_true", help="Test suspicious C2 ports")
    args = parser.parse_args()

    if args.all:
        run_all_tests()
        return
    if args.scan:
        test_port_scan()
        return
    if args.ssh:
        test_ssh_brute_force()
        return
    if args.c2:
        test_suspicious_c2_ports()
        return

    # Interactive CLI menu
    while True:
        print("\n" + "=" * 55)
        print("   🛡️  AEGISGUARD ATTACK SIMULATOR (TEST SUITE)")
        print("=" * 55)
        print("  [1] Test Port Scan (Probe 20 ports)")
        print("  [2] Test SSH Brute Force (Port 22)")
        print("  [3] Test RDP Brute Force (Port 3389)")
        print("  [4] Test C2 / Tor / Metasploit Ports (4444, 9001, 50050)")
        print("  [5] Test Phishing & DNS Anomaly Lookup")
        print("  [6] RUN ALL TESTS (Recommended - Lights up Dashboard!)")
        print("  [0] Exit")
        print("=" * 55)
        
        choice = input("Select an option (0-6): ").strip()
        if choice == "1":
            test_port_scan()
        elif choice == "2":
            test_ssh_brute_force()
        elif choice == "3":
            test_rdp_brute_force()
        elif choice == "4":
            test_suspicious_c2_ports()
        elif choice == "5":
            test_dns_phishing_lookup()
        elif choice == "6":
            run_all_tests()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please enter 0-6.")

if __name__ == "__main__":
    main()
