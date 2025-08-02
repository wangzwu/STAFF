import os
import sys
from scapy.all import rdpcap, wrpcap, TCP, Raw

def should_exclude_payload(payload: bytes, substrings: list) -> bool:
    payload_lower = payload.lower()
    return any(s.encode() in payload_lower for s in substrings)

def filter_pcap_file(filepath, substrings):
    packets = rdpcap(filepath)
    filtered_packets = []

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if b"GET" in payload or b"POST" in payload:
                if should_exclude_payload(payload, substrings):
                    continue
        filtered_packets.append(pkt)

    if len(filtered_packets) != len(packets):
        print(f"Filtered: {filepath} ({len(packets) - len(filtered_packets)} requests removed)")
        wrpcap(filepath, filtered_packets)

def process_pcap_directory(root_dir, substrings):
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".pcap"):
                filepath = os.path.join(dirpath, filename)
                try:
                    filter_pcap_file(filepath, substrings)
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python filter_packets.py <pcap_directory>")
        sys.exit(1)

    pcap_dir = sys.argv[1]
    substrings_to_filter = ['.gif', '.css', '.jpeg', '.jpg', '.png', '.css', '.js', '.ico']

    process_pcap_directory(pcap_dir, substrings_to_filter)
