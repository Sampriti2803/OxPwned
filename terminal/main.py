from detection.preprocessing.network_parser import monitor_network
from detection.pattern_match.matcher import match_patterns
from output.logger import log_alert

def main():
    packets = monitor_network()
    for packet in packets:
        matches = match_patterns(packet["payload"])
        if matches:
            log_alert(packet, matches)
            # Forward to admin