# feature_extractor.py
class FeatureExtractor:
    def __init__(self):
        pass

    def extract_features(self, packet):
        """
        Extract relevant features from a cleaned packet.
        :param packet: A single cleaned packet.
        :return: Dictionary of extracted features.
        """
        print("[FeatureExtractor] Extracting features from packet...")
        features = {
            "src_ip": packet["IP"].src if packet.haslayer("IP") else None,
            "dst_ip": packet["IP"].dst if packet.haslayer("IP") else None,
            "src_port": packet["TCP"].sport if packet.haslayer("TCP") else (packet["UDP"].sport if packet.haslayer("UDP") else None),
            "dst_port": packet["TCP"].dport if packet.haslayer("TCP") else (packet["UDP"].dport if packet.haslayer("UDP") else None),
            "payload_size": len(packet["Raw"].load) if packet.haslayer("Raw") else 0
        }
        print(f"[FeatureExtractor] Extracted features: {features}")
        return features
