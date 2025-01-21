# network_parser.py
import scapy.all as scapy
# from scapy.all import *

class NetworkParser:
    def __init__(self):
        pass

    def capture_packets(self, count=100):
        """
        Capture live network packets.
        :param count: Number of packets to capture.
        :return: List of captured packets.
        """
        print(f"[NetworkParser] Capturing {count} packets...")
        packets = scapy.sniff(count=count)
        print(f"[NetworkParser] Captured {len(packets)} packets.")
        return packets

    def load_pcap(self, file_path):
        """
        Load packets from a PCAP file.
        :param file_path: Path to the PCAP file.
        :return: List of packets.
        """
        print(f"[NetworkParser] Loading packets from {file_path}...")
        packets = scapy.rdpcap(file_path)
        print(f"[NetworkParser] Loaded {len(packets)} packets from {file_path}.")
        return packets
    
