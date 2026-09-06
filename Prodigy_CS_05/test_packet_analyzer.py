#!/usr/bin/env python3
"""
Unit tests for PRODIGY_CS_05 Network Packet Analyzer.
"""

import unittest
import struct
from packet_analyzer import PacketDecoder, PCAPWriter, NetworkSniffer

class TestPacketAnalyzer(unittest.TestCase):

    def test_ipv4_decoder(self):
        # Synthetic 20-byte IPv4 packet header: Version 4, IHL 5 (20 bytes), TOS 0, TotalLen 60, ID 0x1234, TTL 64, Protocol 6 (TCP), Src 192.168.1.10, Dst 8.8.8.8
        src_ip = bytes([192, 168, 1, 10])
        dst_ip = bytes([8, 8, 8, 8])
        raw_ip = struct.pack('! B B H H H B B H 4s 4s', 0x45, 0, 60, 0x1234, 0x4000, 64, 6, 0x5C2A, src_ip, dst_ip)

        header, payload = PacketDecoder.decode_ipv4(raw_ip)
        self.assertEqual(header["version"], 4)
        self.assertEqual(header["ihl"], 20)
        self.assertEqual(header["src_ip"], "192.168.1.10")
        self.assertEqual(header["dst_ip"], "8.8.8.8")
        self.assertEqual(header["protocol"], "TCP")
        self.assertEqual(header["ttl"], 64)

    def test_tcp_decoder(self):
        # Synthetic 20-byte TCP header: SrcPort 443, DstPort 52341, Seq 1000, Ack 2000, Offset 5 (20B), Flags SYN+ACK (0x12)
        raw_tcp = struct.pack('! H H L L H H H H', 443, 52341, 1000, 2000, (5 << 12) | 0x0012, 65535, 0x1A2B, 0)
        header, payload = PacketDecoder.decode_tcp(raw_tcp)

        self.assertEqual(header["src_port"], 443)
        self.assertEqual(header["dst_port"], 52341)
        self.assertEqual(header["dst_service"], "")
        self.assertEqual(header["src_service"], "HTTPS/TLS")
        self.assertIn("SYN", header["flags"])
        self.assertIn("ACK", header["flags"])

    def test_udp_decoder(self):
        # Synthetic 8-byte UDP header: SrcPort 53 (DNS), DstPort 61234, Length 24, Checksum 0x3C4D
        raw_udp = struct.pack('! H H H H', 53, 61234, 24, 0x3C4D)
        header, payload = PacketDecoder.decode_udp(raw_udp)

        self.assertEqual(header["src_port"], 53)
        self.assertEqual(header["dst_port"], 61234)
        self.assertEqual(header["src_service"], "DNS")
        self.assertEqual(header["length"], 24)

    def test_icmp_decoder(self):
        # Synthetic 8-byte ICMP header: Type 8 (Echo Request / Ping), Code 0, Checksum 0x4D2B
        raw_icmp = struct.pack('! B B H I', 8, 0, 0x4D2B, 0)
        header, payload = PacketDecoder.decode_icmp(raw_icmp)

        self.assertEqual(header["type"], 8)
        self.assertEqual(header["type_name"], "Echo Request (Ping)")
        self.assertEqual(header["code"], 0)

    def test_hex_dump_formatting(self):
        sample_bytes = b"Hello, Prodigy!"
        dump = PacketDecoder.format_hex_ascii_dump(sample_bytes)
        self.assertIn("Hello, Prodigy!", dump)
        self.assertIn("48 65 6C 6C 6F", dump)

if __name__ == "__main__":
    unittest.main()
