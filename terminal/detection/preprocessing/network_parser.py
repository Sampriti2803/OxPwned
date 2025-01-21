import scapy.all as scapy
from .data_cleaner import clean_data

def parse_packet(packet):
    """Extracts relevant fields from a network packet."""
    if scapy.TCP in packet and scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        payload = bytes(packet[scapy.TCP].payload)
        return {"src_ip": src_ip, "dst_ip": dst_ip, "payload": payload}
    return None

def monitor_network(filter="tcp"):
    """Captures and parses packets."""
    packets = scapy.sniff(filter=filter, prn=parse_packet, store=0)
    cleaned_data = [clean_data(packet) for packet in packets if packet]
    return cleaned_data