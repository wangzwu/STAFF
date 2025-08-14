import struct
import sys

def process_log_file(log_path):
    events = []
    struct_format = "B I I I I B B Q"
    struct_size = struct.calcsize(struct_format)

    with open(log_path, "rb") as f:
        while True:
            data = f.read(struct_size)
            if len(data) < struct_size:
                break

            unpacked = struct.unpack(struct_format, data)
            event = {
                "event": unpacked[0],
                "sink_id": unpacked[1],
                "cov_xxhash": unpacked[2],
                "app_tb_pc": unpacked[3],
                "gpa": unpacked[4],
                "op_name": unpacked[5],
                "value": unpacked[6],
                "inode": unpacked[7]
            }
            events.append(event)

    return events

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    events = process_log_file(log_file)

    i = 30
    flag = False
    for event in events:
        if event["sink_id"] == 10 and event["app_tb_pc"] == 34448:
            flag = True
        
        if flag and i:
            event["value"] = chr(event["value"])
            print(event)
            i -= 1
