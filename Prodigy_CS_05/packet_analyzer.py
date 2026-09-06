#!/usr/bin/env python3
"""
PRODIGY_CS_05: Network Packet Analyzer
Developed for Prodigy InfoTech Cyber Security Internship Track.

Author: Kaustubh Bangar
Language: Python 3
Dependencies: Standard Library (socket, struct, textwrap, sys, time, threading, queue, tkinter, argparse)
"""

import socket
import struct
import textwrap
import sys
import time
import os
import threading
import queue
import argparse
import random
from typing import Dict, Any, Tuple, Optional, List

# IP Protocol Numbers Mapping (IANA)
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF"
}

# Common Well-Known Port Names
PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS/TLS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

class PacketDecoder:
    """Decodes raw binary network packets into human-readable structured data."""

    @staticmethod
    def format_ipv4(addr_bytes: bytes) -> str:
        """Converts 4 raw bytes into a standard dotted-quad IPv4 string."""
        return ".".join(map(str, addr_bytes))

    @staticmethod
    def format_mac(mac_bytes: bytes) -> str:
        """Converts 6 raw bytes into a colon-separated MAC address."""
        return ":".join(f"{b:02X}" for b in mac_bytes)

    @classmethod
    def decode_ipv4(cls, raw_data: bytes) -> Tuple[Dict[str, Any], bytes]:
        """
        Decodes an IPv4 header (RFC 791).
        Header format: Version & IHL(1B), TOS(1B), TotalLen(2B), ID(2B), Flags/FragOffset(2B),
                       TTL(1B), Protocol(1B), Checksum(2B), SrcIP(4B), DstIP(4B) -> total 20 bytes
        """
        if len(raw_data) < 20:
            return {}, raw_data

        version_ihl, tos, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dst_ip = struct.unpack('! B B H H H B B H 4s 4s', raw_data[:20])

        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4

        flags = flags_offset >> 13
        frag_offset = flags_offset & 0x1FFF
        proto_name = IP_PROTOCOLS.get(proto, f"UNKNOWN({proto})")

        header_info = {
            "version": version,
            "ihl": ihl,
            "tos": tos,
            "total_length": total_length,
            "identification": identification,
            "flags": flags,
            "frag_offset": frag_offset,
            "ttl": ttl,
            "protocol_num": proto,
            "protocol": proto_name,
            "checksum": hex(checksum),
            "src_ip": cls.format_ipv4(src_ip),
            "dst_ip": cls.format_ipv4(dst_ip)
        }

        payload = raw_data[ihl:]
        return header_info, payload

    @classmethod
    def decode_tcp(cls, raw_data: bytes) -> Tuple[Dict[str, Any], bytes]:
        """
        Decodes a TCP header (RFC 793).
        Header format: SrcPort(16b), DstPort(16b), SeqNum(32b), AckNum(32b),
                       Offset/Reserved/Flags(16b), Window(16b), Checksum(16b), UrgPointer(16b)
        """
        if len(raw_data) < 20:
            return {}, raw_data

        src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('! H H L L H H H H', raw_data[:20])

        offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 0x01FF

        flag_urg = bool(flags & 0x0020)
        flag_ack = bool(flags & 0x0010)
        flag_psh = bool(flags & 0x0008)
        flag_rst = bool(flags & 0x0004)
        flag_syn = bool(flags & 0x0002)
        flag_fin = bool(flags & 0x0001)

        active_flags = []
        if flag_syn: active_flags.append("SYN")
        if flag_ack: active_flags.append("ACK")
        if flag_fin: active_flags.append("FIN")
        if flag_rst: active_flags.append("RST")
        if flag_psh: active_flags.append("PSH")
        if flag_urg: active_flags.append("URG")

        src_service = PORT_SERVICES.get(src_port, "")
        dst_service = PORT_SERVICES.get(dst_port, "")

        header_info = {
            "src_port": src_port,
            "dst_port": dst_port,
            "src_service": src_service,
            "dst_service": dst_service,
            "sequence": seq,
            "acknowledgment": ack,
            "data_offset": offset,
            "flags_raw": hex(flags),
            "flags": ",".join(active_flags) if active_flags else "NONE",
            "window_size": window,
            "checksum": hex(checksum),
            "urgent_pointer": urg_ptr
        }

        payload = raw_data[offset:]
        return header_info, payload

    @classmethod
    def decode_udp(cls, raw_data: bytes) -> Tuple[Dict[str, Any], bytes]:
        """
        Decodes a UDP header (RFC 768).
        Header format: SrcPort(16b), DstPort(16b), Length(16b), Checksum(16b)
        """
        if len(raw_data) < 8:
            return {}, raw_data

        src_port, dst_port, length, checksum = struct.unpack('! H H H H', raw_data[:8])

        src_service = PORT_SERVICES.get(src_port, "")
        dst_service = PORT_SERVICES.get(dst_port, "")

        header_info = {
            "src_port": src_port,
            "dst_port": dst_port,
            "src_service": src_service,
            "dst_service": dst_service,
            "length": length,
            "checksum": hex(checksum)
        }

        payload = raw_data[8:]
        return header_info, payload

    @classmethod
    def decode_icmp(cls, raw_data: bytes) -> Tuple[Dict[str, Any], bytes]:
        """
        Decodes an ICMP packet (RFC 792).
        Header format: Type(8b), Code(8b), Checksum(16b), RestOfHeader(32b)
        """
        if len(raw_data) < 8:
            return {}, raw_data

        icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])

        type_names = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request (Ping)",
            11: "Time Exceeded"
        }

        header_info = {
            "type": icmp_type,
            "type_name": type_names.get(icmp_type, f"Type {icmp_type}"),
            "code": code,
            "checksum": hex(checksum)
        }

        payload = raw_data[8:]
        return header_info, payload

    @staticmethod
    def format_hex_ascii_dump(data: bytes, width: int = 16) -> str:
        """Formats byte payload into classic Wireshark-style Hex and ASCII split view."""
        if not data:
            return "    <Empty Payload>"

        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"    {i:04X}   {hex_part:<{width*3}}   {ascii_part}")

        return "\n".join(lines)


class PCAPWriter:
    """Lightweight pure-Python standard PCAP file recorder (RFC 1483/libpcap)."""

    def __init__(self, filename: str):
        self.filename = filename
        self.file = open(filename, "wb")
        # Write Global PCAP Header: Magic(0xa1b2c3d4), Major(2), Minor(4), ThisZone(0), SigFigs(0), SnapLen(65535), LinkType(1=Ethernet / 101=Raw IP)
        self.file.write(struct.pack('! I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        self.file.flush()

    def write_packet(self, raw_data: bytes):
        """Appends a packet record to the PCAP file."""
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1000000)
        length = len(raw_data)
        # Write Packet Record Header: TimestampSec, TimestampMicrosec, SavedLen, ActualLen
        self.file.write(struct.pack('! I I I I', sec, usec, length, length))
        self.file.write(raw_data)
        self.file.flush()

    def close(self):
        """Closes the PCAP file."""
        if self.file and not self.file.closed:
            self.file.close()


class NetworkSniffer:
    """Manages raw socket packet capture with multi-protocol filtering."""

    def __init__(self, interface_ip: Optional[str] = None, filter_proto: str = "ALL", pcap_file: Optional[str] = None):
        self.interface_ip = interface_ip or self.get_default_ip()
        self.filter_proto = filter_proto.upper()
        self.pcap_writer = PCAPWriter(pcap_file) if pcap_file else None
        self.running = False
        self.socket = None
        self.packet_count = 0

    @staticmethod
    def get_default_ip() -> str:
        """Discovers active local IPv4 address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start_capture(self, callback, count: int = 0):
        """Starts real-time packet capture on the raw socket."""
        self.running = True

        # Attempt to create raw socket on Windows (requires admin privileges)
        try:
            if os.name == 'nt':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket.bind((self.interface_ip, 0))
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode in Windows
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print("[!] Permission Denied: Raw socket packet sniffing requires Administrator/Root privileges.")
            print("[*] Automatically falling back to Simulated Packet Capture Engine for safe educational demonstration.\n")
            self._start_simulation(callback, count)
            return
        except Exception as e:
            print(f"[!] Unable to bind raw socket ({e}). Falling back to simulation engine.\n")
            self._start_simulation(callback, count)
            return

        print(f"[*] Sniffing active on IP {self.interface_ip} | Protocol Filter: {self.filter_proto}")
        print("[*] Press Ctrl+C to stop capture.\n")

        try:
            while self.running:
                raw_data, _ = self.socket.recvfrom(65535)
                self.packet_count += 1

                if self.pcap_writer:
                    self.pcap_writer.write_packet(raw_data)

                parsed_pkt = self.parse_packet(raw_data, self.packet_count)
                if parsed_pkt:
                    callback(parsed_pkt)

                if count > 0 and self.packet_count >= count:
                    break

        except KeyboardInterrupt:
            print("\n[*] Stopping packet capture...")
        finally:
            self.stop_capture()

    def _start_simulation(self, callback, count: int = 0):
        """Simulates live realistic network packets for testing and educational environments."""
        print(f"[*] Simulation Engine Activated | Protocol Filter: {self.filter_proto}")
        sample_protocols = ["TCP", "UDP", "ICMP", "HTTP", "DNS"]

        sim_count = 0
        while self.running:
            sim_count += 1
            time.sleep(random.uniform(0.3, 0.9))

            proto = random.choice(sample_protocols)
            src_ip = f"192.168.1.{random.randint(2, 250)}"
            dst_ip = random.choice(["8.8.8.8", "142.250.190.46", "1.1.1.1", "104.244.42.1"])
            src_port = random.randint(49152, 65535)

            if proto == "HTTP":
                dst_port = 80
                payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                transport = {
                    "src_port": src_port, "dst_port": dst_port, "src_service": "", "dst_service": "HTTP",
                    "sequence": 1000 + sim_count, "acknowledgment": 500, "data_offset": 20,
                    "flags": "PSH,ACK", "window_size": 65535, "checksum": "0x4A12", "urgent_pointer": 0
                }
                ip_proto = "TCP"
            elif proto == "DNS":
                dst_port = 53
                payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                transport = {
                    "src_port": src_port, "dst_port": dst_port, "src_service": "", "dst_service": "DNS",
                    "length": len(payload) + 8, "checksum": "0x89EF"
                }
                ip_proto = "UDP"
            elif proto == "TCP":
                dst_port = 443
                payload = b"\x16\x03\x01\x00\xca\x01\x00\x00\xc6\x03\x03" + os.urandom(24)
                transport = {
                    "src_port": src_port, "dst_port": dst_port, "src_service": "", "dst_service": "HTTPS/TLS",
                    "sequence": 5000 + sim_count, "acknowledgment": 0, "data_offset": 20,
                    "flags": "SYN", "window_size": 64240, "checksum": "0x91F2", "urgent_pointer": 0
                }
                ip_proto = "TCP"
            elif proto == "UDP":
                dst_port = 123
                payload = b"\x24" + b"\x00" * 47
                transport = {
                    "src_port": src_port, "dst_port": dst_port, "src_service": "", "dst_service": "NTP",
                    "length": 56, "checksum": "0x12A4"
                }
                ip_proto = "UDP"
            else:  # ICMP
                payload = b"abcdefghijklmnopqrstuvwabcdefghi"
                transport = {"type": 8, "type_name": "Echo Request (Ping)", "code": 0, "checksum": "0x4D2B"}
                ip_proto = "ICMP"

            ip_header = {
                "version": 4, "ihl": 20, "tos": 0, "total_length": 40 + len(payload),
                "identification": 10000 + sim_count, "flags": 2, "frag_offset": 0,
                "ttl": 64, "protocol_num": 6 if ip_proto == "TCP" else (17 if ip_proto == "UDP" else 1),
                "protocol": ip_proto, "checksum": "0xB89A", "src_ip": src_ip, "dst_ip": dst_ip
            }

            if self.filter_proto != "ALL" and self.filter_proto != ip_proto:
                continue

            parsed_pkt = {
                "id": sim_count,
                "timestamp": time.strftime("%H:%M:%S"),
                "ip": ip_header,
                "protocol": ip_proto,
                "transport": transport,
                "payload": payload,
                "hex_dump": PacketDecoder.format_hex_ascii_dump(payload)
            }
            callback(parsed_pkt)

            if count > 0 and sim_count >= count:
                break

    def parse_packet(self, raw_data: bytes, pkt_id: int) -> Optional[Dict[str, Any]]:
        """Parses a raw packet through all layers."""
        ip_header, ip_payload = PacketDecoder.decode_ipv4(raw_data)
        if not ip_header:
            return None

        proto_name = ip_header["protocol"]

        # Apply Protocol Filter
        if self.filter_proto != "ALL" and self.filter_proto != proto_name:
            return None

        transport_header = {}
        app_payload = ip_payload

        if proto_name == "TCP":
            transport_header, app_payload = PacketDecoder.decode_tcp(ip_payload)
        elif proto_name == "UDP":
            transport_header, app_payload = PacketDecoder.decode_udp(ip_payload)
        elif proto_name == "ICMP":
            transport_header, app_payload = PacketDecoder.decode_icmp(ip_payload)

        return {
            "id": pkt_id,
            "timestamp": time.strftime("%H:%M:%S"),
            "ip": ip_header,
            "protocol": proto_name,
            "transport": transport_header,
            "payload": app_payload,
            "hex_dump": PacketDecoder.format_hex_ascii_dump(app_payload)
        }

    def stop_capture(self):
        """Stops live capture and cleans up socket."""
        self.running = False
        if self.socket and os.name == 'nt':
            try:
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        if self.pcap_writer:
            self.pcap_writer.close()


def print_cli_packet(pkt: Dict[str, Any]):
    """Prints formatted packet inspection data to the CLI."""
    ip = pkt["ip"]
    trans = pkt["transport"]
    proto = pkt["protocol"]

    print("=" * 80)
    print(f"[*] Packet #{pkt['id']} | Time: {pkt['timestamp']} | Protocol: [{proto}] | Size: {ip['total_length']} bytes")
    print(f"    Source IP      : {ip['src_ip']:<15} --->  Destination IP: {ip['dst_ip']}")
    print(f"    TTL            : {ip['ttl']:<5} | ID: {ip['identification']:<6} | Checksum: {ip['checksum']}")

    if proto in ("TCP", "UDP"):
        src_svc = f" ({trans['src_service']})" if trans.get("src_service") else ""
        dst_svc = f" ({trans['dst_service']})" if trans.get("dst_service") else ""
        print(f"    Port Mapping   : {trans['src_port']}{src_svc} -> {trans['dst_port']}{dst_svc}")
        if proto == "TCP":
            print(f"    TCP Flags      : [{trans['flags']}] | Seq: {trans['sequence']} | Ack: {trans['acknowledgment']}")
    elif proto == "ICMP":
        print(f"    ICMP Details   : {trans['type_name']} (Code: {trans['code']}) | Checksum: {trans['checksum']}")

    print("    Payload (Hex & ASCII Dump):")
    print(pkt["hex_dump"])
    print("-" * 80)


def launch_gui():
    """Launches the Tkinter Graphical User Interface for the Network Packet Analyzer."""
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, scrolledtext
    except ImportError:
        print("[!] Tkinter is not available in this Python environment.")
        return

    root = tk.Tk()
    root.title("PRODIGY_CS_05 - Network Packet Analyzer")
    root.geometry("980x700")
    root.minsize(850, 550)

    # Style
    style = ttk.Style()
    style.theme_use('clam')

    sniffer_thread = None
    sniffer_instance = None
    captured_packets = []

    # Header
    header_frame = tk.Frame(root, bg="#1E3A8A", height=55)
    header_frame.pack(fill="x")
    title_lbl = tk.Label(header_frame, text="🌐 Network Packet Analyzer (PRODIGY_CS_05)", font=("Helvetica", 16, "bold"), fg="white", bg="#1E3A8A")
    title_lbl.pack(pady=12)

    # Control Bar
    ctrl_frame = tk.Frame(root, padx=10, pady=8)
    ctrl_frame.pack(fill="x")

    proto_lbl = tk.Label(ctrl_frame, text="Filter Protocol:", font=("Helvetica", 10, "bold"))
    proto_lbl.pack(side="left", padx=5)

    proto_combo = ttk.Combobox(ctrl_frame, values=["ALL", "TCP", "UDP", "ICMP"], state="readonly", width=8)
    proto_combo.set("ALL")
    proto_combo.pack(side="left", padx=5)

    mode_lbl = tk.Label(ctrl_frame, text="Mode:", font=("Helvetica", 10, "bold"))
    mode_lbl.pack(side="left", padx=10)

    mode_combo = ttk.Combobox(ctrl_frame, values=["Live Sniff", "Simulation Engine"], state="readonly", width=18)
    mode_combo.set("Simulation Engine")
    mode_combo.pack(side="left", padx=5)

    status_lbl = tk.Label(ctrl_frame, text="● Ready", fg="#059669", font=("Helvetica", 10, "bold"))
    status_lbl.pack(side="right", padx=10)

    # Main Split View: Packet Table (Top) and Detailed Hex Inspector (Bottom)
    paned_window = ttk.PanedWindow(root, orient=tk.VERTICAL)
    paned_window.pack(fill="both", expand=True, padx=10, pady=5)

    # Table Frame
    table_frame = tk.Frame(paned_window)
    paned_window.add(table_frame, weight=3)

    columns = ("No", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Info")
    tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

    tree.heading("No", text="#")
    tree.heading("Time", text="Time")
    tree.heading("Source IP", text="Source IP")
    tree.heading("Destination IP", text="Destination IP")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Length", text="Length")
    tree.heading("Info", text="Summary Details")

    tree.column("No", width=45, anchor="center")
    tree.column("Time", width=75, anchor="center")
    tree.column("Source IP", width=130, anchor="w")
    tree.column("Destination IP", width=130, anchor="w")
    tree.column("Protocol", width=75, anchor="center")
    tree.column("Length", width=65, anchor="center")
    tree.column("Info", width=380, anchor="w")

    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)

    # Detail Inspector Frame
    detail_frame = tk.LabelFrame(paned_window, text=" Packet Details & Payload Hex / ASCII Inspector ", font=("Helvetica", 10, "bold"))
    paned_window.add(detail_frame, weight=2)

    detail_text = scrolledtext.ScrolledText(detail_frame, font=("Consolas", 10), wrap="none", height=10)
    detail_text.pack(fill="both", expand=True, padx=5, pady=5)

    def on_packet_select(event):
        selected_items = tree.selection()
        if not selected_items:
            return
        item_id = selected_items[0]
        idx = int(tree.item(item_id, "values")[0]) - 1

        if 0 <= idx < len(captured_packets):
            pkt = captured_packets[idx]
            ip = pkt["ip"]
            trans = pkt["transport"]
            proto = pkt["protocol"]

            detail_text.delete("1.0", tk.END)
            detail_text.insert(tk.END, f"--- [ PACKET #{pkt['id']} SUMMARY ] ---\n")
            detail_text.insert(tk.END, f"Timestamp      : {pkt['timestamp']}\n")
            detail_text.insert(tk.END, f"Frame Length   : {ip.get('total_length', len(pkt['payload']))} bytes\n\n")

            detail_text.insert(tk.END, "--- [ INTERNET PROTOCOL VERSION 4 (IPv4) ] ---\n")
            detail_text.insert(tk.END, f"Source IP      : {ip['src_ip']}\n")
            detail_text.insert(tk.END, f"Destination IP : {ip['dst_ip']}\n")
            detail_text.insert(tk.END, f"TTL / Protocol : TTL={ip['ttl']} | Protocol={proto} (ID: {ip.get('protocol_num', '-')})\n")
            detail_text.insert(tk.END, f"Header Length  : {ip['ihl']} bytes | Checksum: {ip['checksum']}\n\n")

            if proto in ("TCP", "UDP"):
                detail_text.insert(tk.END, f"--- [ TRANSPORT LAYER ({proto}) ] ---\n")
                detail_text.insert(tk.END, f"Source Port    : {trans['src_port']} {trans.get('src_service', '')}\n")
                detail_text.insert(tk.END, f"Dest Port      : {trans['dst_port']} {trans.get('dst_service', '')}\n")
                if proto == "TCP":
                    detail_text.insert(tk.END, f"Sequence / Ack : Seq={trans['sequence']} | Ack={trans['acknowledgment']}\n")
                    detail_text.insert(tk.END, f"Flags          : [{trans['flags']}] (Window: {trans['window_size']})\n\n")
            elif proto == "ICMP":
                detail_text.insert(tk.END, "--- [ INTERNET CONTROL MESSAGE PROTOCOL (ICMP) ] ---\n")
                detail_text.insert(tk.END, f"Type / Code    : {trans['type_name']} (Code: {trans['code']})\n\n")

            detail_text.insert(tk.END, "--- [ PAYLOAD (HEX & ASCII DUMP) ] ---\n")
            detail_text.insert(tk.END, pkt["hex_dump"] + "\n")

    tree.bind("<<TreeviewSelect>>", on_packet_select)

    def gui_packet_callback(pkt):
        captured_packets.append(pkt)
        ip = pkt["ip"]
        trans = pkt["transport"]
        proto = pkt["protocol"]

        if proto in ("TCP", "UDP"):
            info = f"Port: {trans['src_port']} -> {trans['dst_port']} "
            if proto == "TCP":
                info += f"[{trans['flags']}] Seq={trans['sequence']}"
            else:
                info += f"Len={trans['length']}"
        elif proto == "ICMP":
            info = f"{trans['type_name']} (Code {trans['code']})"
        else:
            info = f"Protocol Data ({len(pkt['payload'])} bytes)"

        # Insert into UI table in main thread
        root.after(0, lambda: tree.insert("", "end", values=(pkt["id"], pkt["timestamp"], ip["src_ip"], ip["dst_ip"], proto, ip.get("total_length", len(pkt["payload"])), info)))

    def start_sniffing():
        nonlocal sniffer_instance, sniffer_thread
        filter_val = proto_combo.get()
        mode_val = mode_combo.get()

        sniffer_instance = NetworkSniffer(filter_proto=filter_val)
        status_lbl.config(text="● Capturing Live...", fg="#DC2626")
        start_btn.config(state="disabled")
        stop_btn.config(state="normal")

        if mode_val == "Simulation Engine":
            sniffer_instance.running = True
            sniffer_thread = threading.Thread(target=sniffer_instance._start_simulation, args=(gui_packet_callback,), daemon=True)
        else:
            sniffer_instance.running = True
            sniffer_thread = threading.Thread(target=sniffer_instance.start_capture, args=(gui_packet_callback,), daemon=True)

        sniffer_thread.start()

    def stop_sniffing():
        nonlocal sniffer_instance
        if sniffer_instance:
            sniffer_instance.stop_capture()
        status_lbl.config(text="● Stopped", fg="#4B5563")
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")

    def clear_packets():
        captured_packets.clear()
        for item in tree.get_children():
            tree.delete(item)
        detail_text.delete("1.0", tk.END)

    # Action Buttons
    btn_frame = tk.Frame(root, pady=10)
    btn_frame.pack(fill="x", padx=10)

    start_btn = tk.Button(btn_frame, text="▶ Start Capture", font=("Helvetica", 10, "bold"), bg="#16A34A", fg="white", command=start_sniffing, padx=12, pady=4)
    start_btn.pack(side="left", padx=5)

    stop_btn = tk.Button(btn_frame, text="⏹ Stop Capture", font=("Helvetica", 10, "bold"), bg="#DC2626", fg="white", state="disabled", command=stop_sniffing, padx=12, pady=4)
    stop_btn.pack(side="left", padx=5)

    clear_btn = tk.Button(btn_frame, text="🗑 Clear", font=("Helvetica", 10), command=clear_packets, padx=10, pady=4)
    clear_btn.pack(side="left", padx=5)

    root.mainloop()


def main():
    parser = argparse.ArgumentParser(description="PRODIGY_CS_05: Network Packet Analyzer")
    parser.add_argument("-p", "--protocol", type=str, default="ALL", choices=["ALL", "TCP", "UDP", "ICMP"], help="Filter by network protocol (default: ALL).")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: 0 for unlimited).")
    parser.add_argument("-w", "--write-pcap", type=str, help="Save captured packets to a standard PCAP file.")
    parser.add_argument("-i", "--interface", type=str, help="IP address of network interface to bind.")
    parser.add_argument("--simulate", action="store_true", help="Run in educational packet simulation mode (no root/admin needed).")
    parser.add_argument("--gui", action="store_true", help="Launch Tkinter Graphical User Interface.")

    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    print("=" * 80)
    print("        PRODIGY INFOTECH - CYBER SECURITY TASK 05")
    print("                NETWORK PACKET ANALYZER")
    print("=" * 80)

    sniffer = NetworkSniffer(
        interface_ip=args.interface,
        filter_proto=args.protocol,
        pcap_file=args.write_pcap
    )

    if args.simulate:
        sniffer.running = True
        sniffer._start_simulation(print_cli_packet, count=args.count)
    else:
        sniffer.start_capture(print_cli_packet, count=args.count)


if __name__ == "__main__":
    main()
