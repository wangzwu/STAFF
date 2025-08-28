#!/usr/bin/env python3
import json
import struct
import sys
import pytsk3

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def process_log_file(log_path):
    events = []
    struct_format = "B I I I I B B Q"
    struct_size = struct.calcsize(struct_format)

    with open(log_path, "rb") as f:
        idx = 0
        while True:
            data = f.read(struct_size)
            if len(data) < struct_size:
                break

            unpacked = struct.unpack(struct_format, data)
            event = {
                "index": idx,
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
            idx += 1

    return events

def build_inode_to_path_map(fs_image_path):
    inode_to_path = {}
    img = pytsk3.Img_Info(fs_image_path)
    fs = pytsk3.FS_Info(img)

    def walk_dir(directory, path="/"):
        for entry in directory:
            if not hasattr(entry, "info") or not hasattr(entry.info, "name"):
                continue
            if entry.info.name.name in [b".", b".."]:
                continue
            try:
                inode = entry.info.meta.addr
                name = entry.info.name.name.decode("utf-8", errors="ignore")
                full_path = path + name
                inode_to_path[inode] = full_path
                if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    subdir = fs.open_dir(inode=inode)
                    walk_dir(subdir, full_path + "/")
            except Exception:
                continue

    root_dir = fs.open_dir("/")
    walk_dir(root_dir, "/")
    return inode_to_path

def collect_inode_pc_tuples(events, sink_id, substring_filter):
    inode_pc_with_pos = []
    filtered = [e for e in events if e["sink_id"] == sink_id]

    groups = []
    for op in [0, 1]:
        current_str = []
        current_inodes = set()
        last_gpa = None
        first_event_idx = None

        for e in filtered:
            if e["op_name"] != op:
                continue
            if last_gpa is not None and e["gpa"] != last_gpa + 1:
                if current_str:
                    s = "".join(current_str)
                    if substring_filter in s:
                        groups.append((first_event_idx, set(current_inodes)))
                current_str = []
                current_inodes = set()
                first_event_idx = None

            if first_event_idx is None:
                first_event_idx = e["index"]

            current_str.append(chr(int(e["value"])))
            current_inodes.add(("store" if e["op_name"] else "load",
                                e["inode"], hex(e["app_tb_pc"])))
            last_gpa = e["gpa"]

        if current_str:
            s = "".join(current_str)
            if substring_filter in s:
                groups.append((first_event_idx, set(current_inodes)))

    groups.sort(key=lambda g: g[0])

    position_number = 1
    for _, inode_pc_set in groups:
        for t in inode_pc_set:
            inode_pc_with_pos.append((t[0], t[1], t[2], position_number))
        position_number += 1

    inode_pc_with_pos.sort(key=lambda x: x[3])
    return inode_pc_with_pos

def get_infos_a(data, region_id, start_offset, count):
    try:
        region = data[region_id]
    except IndexError:
        sys.exit(f"Error: region_id {region_id} not found.")

    elements = region[1]
    infos_a_set = set()
    for i in range(start_offset, min(start_offset + count, len(elements))):
        element = elements[i]
        _, _, infos_a, _ = element
        for entry in infos_a:
            if isinstance(entry, list):
                infos_a_set.add(tuple(entry))
    return infos_a_set

def main():
    if len(sys.argv) != 9:
        print(f"Usage: {sys.argv[0]} <log_file> <fs_image> <input_json> <region_id> <offset> <count> <sink_id> <substring>")
        sys.exit(1)

    log_path = sys.argv[1]
    fs_image = sys.argv[2]
    json_file = sys.argv[3]
    region_id = int(sys.argv[4])
    offset = int(sys.argv[5])
    count = int(sys.argv[6])
    sink_id = int(sys.argv[7])
    substring_filter = sys.argv[8]

    with open(json_file, "r") as f:
        data = json.load(f)
    infos_a_set = get_infos_a(data, region_id, offset, count)

    events = process_log_file(log_path)
    inode_map = build_inode_to_path_map(fs_image)
    inode_pc_set = collect_inode_pc_tuples(events, sink_id, substring_filter)

    print("List of (op_name, module_name, pc, position):")
    merged = []

    for op_name, inode, pc, pos in inode_pc_set:
        module_name = inode_map.get(inode, f"<unknown_inode:{inode}>")
        current = (module_name, pc)
        
        if merged and merged[-1]["key"] == current:
            prev_op = merged[-1]["op_name"]
            if prev_op != op_name:
                merged[-1]["op_name"] = f"{prev_op}/{op_name}"
            continue
        
        check_tpl = (inode, int(pc, 16))
        color = GREEN if check_tpl in infos_a_set else RED

        merged.append({
            "op_name": op_name,
            "module_name": module_name,
            "pc": pc,
            "pos": pos,
            "color": color,
            "key": current
        })

    for item in merged:
        print(f"{item['color']}({item['op_name']}, {item['module_name']}, {item['pc']}, {item['pos']}){RESET}")

if __name__ == "__main__":
    main()
