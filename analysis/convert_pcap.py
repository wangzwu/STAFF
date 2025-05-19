import dpkt
import socket
import os
from collections import defaultdict
import argparse

HTTP_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"]

def convert_pcap_into_single_seed_file(pcap_path, dst_ip, output_raw, region_delimiter):
    requests_with_ts = []

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        sessions = defaultdict(list)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                if len(tcp.data) == 0:
                    continue

                if socket.inet_ntoa(ip.dst) != dst_ip:
                    continue

                session_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                sessions[session_key].append((ts, tcp.seq, bytes(tcp.data)))

            except Exception as e:
                print(f"[DEBUG] Skipping packet due to exception: {e}")
                continue

    for session_key, stream_chunks in sessions.items():
        if not stream_chunks:
            continue
        stream_chunks.sort(key=lambda x: x[1])

        stream_data = b''.join(chunk for _, _, chunk in stream_chunks)

        offsets = []
        current_offset = 0
        for ts, seq, chunk in stream_chunks:
            offsets.append((current_offset, current_offset + len(chunk), ts))
            current_offset += len(chunk)

        i = 0
        while i < len(stream_data):
            for method in HTTP_METHODS:
                if stream_data[i:].startswith(method + b" "):
                    end_of_headers = stream_data.find(b"\r\n\r\n", i)
                    if end_of_headers == -1:
                        break
                    headers = stream_data[i:end_of_headers + 4]
                    content_length = 0
                    for header_line in headers.split(b"\r\n"):
                        if header_line.lower().startswith(b"content-length:"):
                            try:
                                content_length = int(header_line.split(b":")[1].strip())
                            except ValueError:
                                content_length = 0
                    total_len = end_of_headers + 4 + content_length
                    request_data = stream_data[i:total_len]

                    request_start = i
                    request_end = total_len
                    relevant_ts = [ts for start, end, ts in offsets if not (end <= request_start or start >= request_end)]
                    request_ts = min(relevant_ts) if relevant_ts else 0

                    requests_with_ts.append((request_ts, request_data))
                    i = total_len
                    break
            else:
                i += 1

    requests_with_ts.sort(key=lambda x: x[0])

    output_dir = os.path.dirname(output_raw)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_raw, "wb") as f:
        for _, req_data in requests_with_ts:
            f.write(req_data)
            f.write(region_delimiter)

    return [req for _, req in requests_with_ts]


def convert_pcap_into_multiple_seed_files(pcap_path, dst_ip, output_dir, input_filename, region_delimiter):
    requests_with_ts = []

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        sessions = defaultdict(list)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                if len(tcp.data) == 0:
                    continue

                if socket.inet_ntoa(ip.dst) != dst_ip:
                    continue

                session_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                sessions[session_key].append((ts, tcp.seq, bytes(tcp.data)))

            except Exception as e:
                print(f"[DEBUG] Skipping packet due to exception: {e}")
                continue

    os.makedirs(output_dir, exist_ok=True)

    for session_key, stream_chunks in sessions.items():
        if not stream_chunks:
            continue
        stream_chunks.sort(key=lambda x: x[1])

        stream_data = b''.join(chunk for _, _, chunk in stream_chunks)

        offsets = []
        current_offset = 0
        for ts, seq, chunk in stream_chunks:
            offsets.append((current_offset, current_offset + len(chunk), ts))
            current_offset += len(chunk)

        i = 0
        while i < len(stream_data):
            for method in HTTP_METHODS:
                if stream_data[i:].startswith(method + b" "):
                    end_of_headers = stream_data.find(b"\r\n\r\n", i)
                    if end_of_headers == -1:
                        break
                    headers = stream_data[i:end_of_headers + 4]
                    content_length = 0
                    for header_line in headers.split(b"\r\n"):
                        if header_line.lower().startswith(b"content-length:"):
                            try:
                                content_length = int(header_line.split(b":")[1].strip())
                            except ValueError:
                                content_length = 0
                    total_len = end_of_headers + 4 + content_length
                    request_data = stream_data[i:total_len]

                    request_start = i
                    request_end = total_len
                    relevant_ts = [ts for start, end, ts in offsets if not (end <= request_start or start >= request_end)]
                    request_ts = min(relevant_ts) if relevant_ts else 0

                    requests_with_ts.append((request_ts, request_data))
                    i = total_len
                    break
            else:
                i += 1

    requests_with_ts.sort(key=lambda x: x[0])

    for idx, (_, req_data) in enumerate(requests_with_ts):
        output_raw = os.path.join(output_dir, f"{input_filename}_{idx}.seed")
        os.makedirs(os.path.dirname(output_raw), exist_ok=True)
        with open(output_raw, "wb") as f:
            f.write(req_data)
            f.write(region_delimiter)

    return [req for _, req in requests_with_ts]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract HTTP requests from PCAP into seed files.")
    parser.add_argument("pcap_path", help="Path to the PCAP file.")
    parser.add_argument("dst_ip", help="Destination IP to filter for HTTP requests.")
    parser.add_argument("output_path", help="Output file (single mode) or directory (multiple mode).")
    parser.add_argument("--mode", choices=["single", "multiple"], default="single",
                        help="Output mode: 'single' for one file, 'multiple' for one file per request.")
    parser.add_argument("--region-delimiter", default="0a0a0a0a",
                        help="Hex string used to separate requests in output files (default '0a0a0a0a').")

    args = parser.parse_args()

    region_delimiter = bytes.fromhex(args.region_delimiter)

    if args.mode == "single":
        requests = convert_pcap_into_single_seed_file(args.pcap_path, args.dst_ip, args.output_path, region_delimiter)
        print(f"Extracted {len(requests)} HTTP requests into single file '{args.output_path}'.")
    else:
        base_filename = os.path.splitext(os.path.basename(args.pcap_path))[0]
        requests = convert_pcap_into_multiple_seed_files(args.pcap_path, args.dst_ip, args.output_path, base_filename, region_delimiter)
        print(f"Extracted {len(requests)} HTTP requests into directory '{args.output_path}'.")
