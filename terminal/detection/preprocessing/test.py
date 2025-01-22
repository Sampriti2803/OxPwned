# test.py
from data_cleaner import DataCleaner
from network_parser import NetworkParser
from feature_extractor import FeatureExtractor

# Initialize NetworkParser and capture packets
parser = NetworkParser()
captured_packets = parser.capture_packets(count=2)

# Initialize DataCleaner and clean the captured packets
cleaner = DataCleaner()
cleaned_packets = cleaner.clean_packets(captured_packets)

# Initialize FeatureExtractor
extractor = FeatureExtractor()

# Extract features from each cleaned packet
extracted_features = []
for packet in cleaned_packets:
    features = extractor.extract_features(packet)
    extracted_features.append(features)

# Print extracted features to verify
print(f"Extracted Features: {extracted_features}")
