# data_cleaner.py
class DataCleaner:
    def __init__(self):
        pass

    def clean_packets(self, packets):
        """
        Clean the captured packets by filtering out invalid or irrelevant ones.
        :param packets: List of raw packets.
        :return: List of cleaned packets.
        """
        print("[DataCleaner] Cleaning packets...")
        cleaned_packets = []
        for packet in packets:
            if self.is_valid_packet(packet):
                cleaned_packets.append(packet)
        print(f"[DataCleaner] Cleaned {len(cleaned_packets)} packets out of {len(packets)}.")
        return cleaned_packets

    def is_valid_packet(self, packet):

    # Validate whether a packet is relevant.
    # :param packet: A single packet.
    # :return: Boolean indicating if the packet is valid.

    # Check if the packet has an IP or IPv6 layer and either a TCP or UDP layer
        return (packet.haslayer("IP") or packet.haslayer("IPv6")) and (packet.haslayer("TCP") or packet.haslayer("UDP"))
