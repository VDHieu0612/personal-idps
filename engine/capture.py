import sys
import time
import socket
import threading
from typing import Callable, Set, Dict, Any
from .db import log_packet

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(e)

# Reverse DNS Cache to prevent spamming DNS queries
DNS_CACHE: Dict[str, str] = {}

def resolve_domain(ip: str) -> str:
    if ip in DNS_CACHE:
        return DNS_CACHE[ip]
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        DNS_CACHE[ip] = "Internal Local Network"
        return DNS_CACHE[ip]
    try:
        domain = socket.gethostbyaddr(ip)[0]
        DNS_CACHE[ip] = domain
        return domain
    except Exception:
        DNS_CACHE[ip] = "Unknown External Host"
        return DNS_CACHE[ip]

class PacketCapturer:
    def __init__(self, callback: Callable[[dict], None], interface: str = None):
        self.callback = callback
        self.interface = interface
        self.running = False
        self.engine_a_active = False
        self.engine_b_active = False
        self.seen_connections: Set[str] = set()

    def start(self):
        self.running = True

        # Engine A: Socket & Web Connection Monitor (No Npcap required!)
        if PSUTIL_AVAILABLE:
            self.engine_a_active = True
            threading.Thread(target=self._run_socket_engine, daemon=True).start()
            print("[Engine A] Active Socket & Web Connection Inspector initialized (No Npcap required).")
        else:
            print("[Engine A Warning] psutil library not found. Socket Engine disabled.")

        # Engine B: Scapy Raw Packet Inspector (Optional Npcap / Kernel Sniffer)
        if SCAPY_AVAILABLE:
            threading.Thread(target=self._run_scapy_engine, daemon=True).start()
        else:
            print(f"[Engine B Notice] Scapy driver not loaded ({SCAPY_ERROR}). Engine A is covering socket & web inspection.")

    def stop(self):
        self.running = False

    def get_engine_status(self) -> str:
        if self.engine_a_active and self.engine_b_active:
            return "Dual Engine (Socket + Scapy)"
        elif self.engine_a_active:
            return "Socket & Web Engine (No Npcap Required)"
        elif self.engine_b_active:
            return "Scapy Kernel Sniffer"
        else:
            return "Inactive"

    # --- ENGINE A: SOCKET & WEB CONNECTION INSPECTOR ---
    def _run_socket_engine(self):
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                now = time.time()

                for conn in connections:
                    if not conn.raddr:
                        continue

                    src_ip = conn.laddr.ip if conn.laddr else "127.0.0.1"
                    src_port = conn.laddr.port if conn.laddr else 0
                    dst_ip = conn.raddr.ip
                    dst_port = conn.raddr.port

                    # Generate unique connection signature for sliding window
                    conn_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                    if conn_id in self.seen_connections:
                        continue

                    self.seen_connections.add(conn_id)
                    if len(self.seen_connections) > 5000:
                        self.seen_connections.clear()

                    protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    
                    # Inspect Web/HTTPS domain
                    info = ""
                    if dst_port == 443:
                        domain = resolve_domain(dst_ip)
                        info = f"HTTPS Connection [Target Domain: {domain}]"
                    elif dst_port == 80:
                        domain = resolve_domain(dst_ip)
                        info = f"HTTP Web Request [Target Domain: {domain}]"
                    elif dst_port == 53:
                        info = "DNS Query Lookup"
                    else:
                        info = f"Active Connection (PID: {conn.pid or 'System'})"

                    packet_info = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "length": 512,  # estimated stream window
                        "info": info
                    }

                    log_packet(src_ip, dst_ip, src_port, dst_port, protocol, 512, info)
                    self.callback(packet_info)

            except Exception as e:
                pass

            time.sleep(0.5)

    # --- ENGINE B: SCAPY RAW PACKET KERNEL INSPECTOR ---
    def _run_scapy_engine(self):
        try:
            print("[Engine B] Starting Scapy Kernel Packet Capture...")
            sniff(prn=self._handle_scapy_packet, store=0, stop_filter=lambda p: not self.running)
            self.engine_b_active = True
        except Exception as e:
            print(f"[Engine B Notice] Raw packet capture unavailable ({e}). Continuing with Engine A.")

    def _handle_scapy_packet(self, pkt):
        try:
            if not pkt.haslayer(IP):
                return

            self.engine_b_active = True
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = len(pkt)
            protocol = "IP"
            src_port = 0
            dst_port = 0
            info = ""

            if pkt.haslayer(TCP):
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                # Inspect TLS SNI or HTTP payload preview if present
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                        info = payload[:80].decode('utf-8', errors='ignore').replace('\r\n', ' ')
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    protocol = "DNS"
                    info = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"

            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "info": info
            }

            log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, info)
            self.callback(packet_info)
        except Exception:
            pass
