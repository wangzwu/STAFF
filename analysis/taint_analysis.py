import json
import sys
import os
import subprocess
import shutil
from collections import defaultdict, deque
import itertools
from colorama import Fore, Style
from tqdm import tqdm
import bisect
import numpy as np
import matplotlib.pyplot as plt
from scipy.ndimage import gaussian_filter1d
import statistics
import signal
import time
import stat
import warnings
from analysis.convert_pcap import convert_pcap_into_single_seed_file
from typing import List, Tuple, Dict
import socket
import configparser
import struct
import psutil
import csv
import random
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
import pandas



RESET = "\033[0m"
LIGHT_GREY = "\033[90m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
RED = "\033[91m"
ORANGE = "\033[38;5;214m"

qemu_pid = None
subregion_to_find = ""
global_all_app_tb_pcs = None
new_app_tb_pcs = None
global_subregions = {
    "app_tb_pc": [],
    "coverage": []
}
global_subregions_app_tb_pcs = []
global_subregions_covs = []
global_sources = []
global_fs_relations = []
global_regions_dependance = {}
global_regions_affections = {}

error = 0
global_max_len = 50
n_run = 0

# Hyperparams
min_value = 0
max_value = 1
enable_gaussian_filter = True
gaussian_filter_smoothing_sigma = [8, 16, 32]

BRAND_KEYWORDS = {
    "dlink": ["dir", "DIR", "DAP", "dap", "DCH", "dch", "DCS", "dcs", "EBR", "ebr", "DGS", "dgs", "DCS", "dcs", "dhp", "DHP", "dns", "DNS", "DSL", "dsl", "DWR", "dwr", "DWL", "dwl", "DVA", "dva"],
    "netgear": ["R6", "r6", "R8", "r8", "R7", "r7", "WN", "wn", "JWN", "jwn", "EX", "ex", "DM", "dm", "DGN", "dgn", "JNR", "jnr", "DST", "dst", "AC", "ac", "Ac", "AX", "ax", "RBR", "rbr", "rbs", "RBS", "XR5", "xr5", "SRS", "SRR", "srs", "srr", "WPN", "wpn", "WAC", "wac", "WGT", "wgt", "EVG", "evg", "D78", "WAG", "wag", "WAC", "wac", "GS", "gs"],
    "tplink": ["ARCHER", "Archer", "archer", "TL", "tl", "TD", "td", "VR", "vr", "EAP", "eap", "RE", "re", "CPE", "cpe", "WBS", "wbs"],
    "trendnet": ["TEW", "tew", "tv-ip", "fw", "FW"]
}

class Subsequence:
    def __init__(self, region_id: int, offset: int, length: int):
        self.region_id = region_id
        self.offset = offset
        self.length = length
        self.end = offset + length
    
    def __repr__(self):
        return f"Subsequence(region_id={self.region_id}, offset={self.offset}, length={self.length})"

def safe_div(numerator, denominator):
    return numerator / denominator if denominator != 0 else 0

def covers_all_upto_x(entries, X):
    first_elements = {entry[0] for entry in entries}
    return set(range(X+1)).issubset(first_elements)

def set_permissions_recursive(dir_path):
    for root, dirs, files in os.walk(dir_path):
        for d in dirs:
            os.chmod(os.path.join(root, d), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        
        for f in files:
            os.chmod(os.path.join(root, f), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

def send_signal_recursive(target_pid, signal_code):
    try:
        child_pids = subprocess.check_output(["sudo", "-E", "pgrep", "-P", str(target_pid)]).decode('utf-8').splitlines()
        for child_pid in child_pids:
            send_signal_recursive(int(child_pid), signal_code)
    except subprocess.CalledProcessError:
        pass
    finally:
        os.kill(target_pid, signal_code)

def cleanup(firmae_dir, work_dir):
    print("\n[*] Cleanup Procedure..")

    if os.path.exists(os.path.join(work_dir, "debug")):
        shutil.rmtree(os.path.join(work_dir, "debug"), ignore_errors=True)

    subprocess.run(["sudo", "-E", "umount", f"{work_dir}/dev/null"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "-E", "umount", f"{work_dir}/dev/urandom"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "-E", "umount", f"{work_dir}/proc_host/stat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    current_pid = os.getpid()

    parent_pids = set()
    try:
        pid = current_pid
        while pid != 1:
            output = subprocess.check_output(["ps", "-p", str(pid), "-o", "ppid="]).decode().strip()
            ppid = int(output)
            if ppid == pid or ppid == 0:
                break
            parent_pids.add(ppid)
            pid = ppid
    except Exception as e:
        print(f"[!] Error while finding parent processes: {e}")

    try:
        output = subprocess.check_output(["ps", "-e", "-o", "pid=", "-o", "comm="]).decode().splitlines()

        print("\n[*] Running processes before cleanup:")
        for line in output:
            pid_str, *command_parts = line.strip().split()
            pid = int(pid_str)
            command = ' '.join(command_parts)
            print(f"    PID {pid}: {command}")

        print("\n[*] Killing processes:")
        for line in output:
            pid_str, *command_parts = line.strip().split()
            pid = int(pid_str)
            command = ' '.join(command_parts)

            if pid == 1 or pid == current_pid or pid in parent_pids:
                continue

            try:
                os.kill(pid, signal.SIGKILL)
                print(f"    [*] Killed PID {pid} ({command})")
            except ProcessLookupError:
                pass

    except Exception as e:
        print(f"[!] Error during process cleanup: {e}")

    subprocess.run(["sudo", "-E", f"{firmae_dir}/flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sigint_handler(sig, frame):
    if qemu_pid:
        send_signal_recursive(qemu_pid, signal.SIGKILL)
    exit(0)

def auto_find_brand(var):
    for brand, regions in BRAND_KEYWORDS.items():
        if any(region in var for region in regions):
            return brand
    return "NotBrandFound"

def check_firmware(firmware):
    iid = ""
    subprocess.run(["sudo", "-E", "./flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    iid = id_lookup("./scratch/run/", os.path.basename(firmware))

    if iid == "":
        if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", "0.0.0.0", mode], stdout=subprocess.PIPE).returncode == 0:
            if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", "0.0.0.0", mode], stdout=subprocess.PIPE).returncode == 0:
                print("[\033[31m-\033[0m] docker container failed to connect to the hosts' postgresql!")
                exit(1)

        iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, "0.0.0.0", mode]).decode('utf-8').strip()

        if iid == "" or not os.path.exists(os.path.join("scratch", iid)):
            print("\033[32m[+]\033[0m\033[32m[+]\033[0m FirmAE: Creating Firmware Scratch Image")
            subprocess.run(["sudo", "-E", "./run.sh", "-c", os.path.dirname(firmware), firmware, mode, "0.0.0.0"])
            iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, "0.0.0.0", mode]).decode('utf-8').strip()

    return iid

def id_lookup(directory, search_string):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == "name":
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()
                    if content.strip() in search_string and filepath.count("/") == 3:
                        return os.path.basename(root)
    return ""

def collision_analysis(data, cov_field, cov_label):
    cov_to_tuples = defaultdict(set)
    for entry in tqdm(data, desc=f"Calculating collisions on {cov_label}"):
        if entry["event"] == 1:
            cov = entry[cov_field]
            key = (entry["inode"], entry["app_tb_pc"])
            cov_to_tuples[cov].add(key)

    collision_count = sum(len(tuples) > 1 for tuples in cov_to_tuples.values())
    total_count = len(cov_to_tuples)
    print(f"Collisions on '{cov_label}': {collision_count} on {total_count}")

def compute_score_for_combination(regions, combinations, analysis_results):
    combined_analysis_results = {}

    for combination in combinations:
        combined_analysis_results[combination] = []
            
        for i, region in enumerate(regions):
            if len(combined_analysis_results[combination]) <= i:
                combined_analysis_results[combination].append([])

            for j, (byte, _, _) in enumerate(region):
                for metric in combination:
                    if metric == "rarest_app_tb_pc":
                        metric_values = analysis_results["rarest_app_tb_pc"]
                    elif metric == "most_frequent_app_tb_pc":
                        metric_values = analysis_results["most_frequent_app_tb_pc"]
                    elif metric == "rarest_process":
                        metric_values = analysis_results["rarest_process"]
                    elif metric == "most_frequent_process":
                        metric_values = analysis_results["most_frequent_process"]
                    elif metric == "rarest_cov":
                        metric_values = analysis_results["rarest_cov"]
                    elif metric == "most_frequent_cov":
                        metric_values = analysis_results["most_frequent_cov"]
                    elif metric == "number_of_processes":
                        metric_values = analysis_results["number_of_processes"]
                    elif metric == "number_of_app_tb_pcs":
                        metric_values = analysis_results["number_of_app_tb_pcs"]
                    elif metric == "number_of_affected_regions_by_taint":
                        metric_values = analysis_results["number_of_affected_regions_by_taint"]
                    elif metric == "number_of_covs":
                        metric_values = analysis_results["number_of_covs"]
                
                    byte_score = metric_values[i][j]
                    if len(combined_analysis_results[combination][i]) <= j:
                        combined_analysis_results[combination][i].append(byte_score)
                    else:
                        combined_analysis_results[combination][i][j] += byte_score

                combined_analysis_results[combination][i][j] /= len(combination)

    return combined_analysis_results


def plot_normalized_scores(analysis_results, regions, subregion_to_find, smoothing_list, output_filename="analysis_plot"):
    for smoothing in smoothing_list:
        concatenated_regions = []
        subregion_start = -1
        subregion_end = -1

        byte_offset = 0
        for region in regions:
            current_region_str = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in region)
            concatenated_regions.extend([byte for byte in region])
            
            if (subregion_to_find and subregion_to_find != ""):
                sub_idx = current_region_str.find(subregion_to_find)
                if sub_idx != -1:
                    subregion_start = byte_offset + sub_idx
                    subregion_end = subregion_start + len(subregion_to_find)
            
            byte_offset += len(region)

        x_values = np.arange(len(concatenated_regions))

        plt.figure(figsize=(10, 6))

        for analysis_type in analysis_results.keys():
            y_values = []
            for i, region in enumerate(regions):
                y_values.extend(analysis_results[analysis_type][i])
            
            if enable_gaussian_filter and smoothing:
                final_y_values = gaussian_filter1d(y_values, sigma=smoothing)
            else:
                final_y_values = y_values
            plt.plot(x_values, final_y_values, label=analysis_type)

        byte_offset = 0
        for region in regions:
            plt.axvline(x=byte_offset - 0.5, color='black', linestyle='--', linewidth=0.5)
            byte_offset += len(region)

        if subregion_start != -1 and subregion_end != -1:
            plt.axvspan(
                subregion_start - 0.5, 
                subregion_end - 0.5, 
                color='red', 
                alpha=0.2, 
                label="Subregion Highlight"
            )

        plt.xlabel('Byte Position (Concatenated Regions)')
        plt.ylabel('Normalized Score')
        plt.title('Normalized Scores for Each Analysis')
        plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
        
        plt.savefig(output_filename+"_"+str(smoothing)+".png", bbox_inches='tight', pad_inches=0.1)
        plt.close()


def plot_normalized_scores_2(analysis_results, regions, subregion_to_find, smoothing_list, output_filename="analysis_plot_extended"):
    for smoothing in smoothing_list:
        concatenated_regions = []
        hex_labels = []
        subregion_start = -1
        subregion_end = -1

        byte_offset = 0
        for region in regions:
            current_region_str = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in region)
            for byte in region:
                concatenated_regions.append(byte)
                hex_labels.append(chr(byte) if 32 <= byte <= 126 else ".")

            if (subregion_to_find and subregion_to_find != ""):
                sub_idx = current_region_str.find(subregion_to_find)
                if sub_idx != -1:
                    subregion_start = byte_offset + sub_idx
                    subregion_end = subregion_start + len(subregion_to_find)

            byte_offset += len(region)

        x_values = np.arange(len(concatenated_regions))

        plt.figure(figsize=(max(12, len(hex_labels) // 5), 6))
        plt.gcf().set_facecolor('white')

        for analysis_type in analysis_results.keys():
            y_values = []
            for i, region in enumerate(regions):
                y_values.extend(analysis_results[analysis_type][i])
            
            if enable_gaussian_filter and smoothing:
                final_y_values = gaussian_filter1d(y_values, sigma=smoothing)
            else:
                final_y_values = y_values
            plt.plot(x_values, final_y_values, label=analysis_type)

        byte_offset = 0
        for region in regions:
            plt.axvline(x=byte_offset - 0.5, color='black', linestyle='--', linewidth=0.5)
            byte_offset += len(region)

        if subregion_start != -1 and subregion_end != -1:
            plt.axvspan(
                subregion_start - 0.5, 
                subregion_end - 0.5, 
                color='red', 
                alpha=0.2, 
                label="Subregion Highlight"
            )

        plt.xticks(ticks=x_values, labels=hex_labels, rotation=90, fontsize=8)

        plt.xlabel('Byte (Character)')
        plt.ylabel('Normalized Score')
        plt.title('Normalized Scores for Each Analysis')
        plt.legend(loc='upper left', bbox_to_anchor=(1, 1))

        plt.tight_layout()
        plt.savefig(output_filename+"_"+str(smoothing)+".png", bbox_inches='tight', pad_inches=0.1)
        plt.close()


def find_best_regions_for_portion(regions, subregion_to_find, combinations, analysis_results, score_w, contrast_w):
    best_combination = None
    best_score = -1

    combined_analysis_results = compute_score_for_combination(regions, combinations, analysis_results)

    position = (-1, -1)
    for i, region in enumerate(regions):
        current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val, _, _ in region)
        j = current_region_str.find(subregion_to_find)
        if j >= 0:
            position = (i, j)
            break

    if position == (-1, -1):
        raise ValueError("Subregion not found in regions")

    subregion_start = position[1]
    subregion_end = subregion_start + len(subregion_to_find)

    for combination in combinations:
        subregion_score = 0
        contrast_score = 0
        region_scores = combined_analysis_results[combination][position[0]]

        subregion_scores = [
            region_scores[byte_index]
            for byte_index in range(subregion_start, subregion_end)
        ]
        subregion_average = sum(subregion_scores) / len(subregion_scores)

        other_scores = []
        for k, region_scores_for_combination in enumerate(combined_analysis_results[combination]):
            if k == position[0]:
                other_scores.extend(
                    score for idx, score in enumerate(region_scores_for_combination)
                    if idx < subregion_start or idx > subregion_start + len(subregion_to_find) - 1
                )
            else:
                other_scores.extend(region_scores_for_combination)

        other_average = sum(other_scores) / len(other_scores) if other_scores else 0
        contrast_score = abs(subregion_average - other_average)

        combined_score = (score_w * subregion_average) + (contrast_w * contrast_score)

        if combined_score > best_score:
            best_score = combined_score
            best_combination = combination

    return combined_analysis_results, best_combination

def get_intensity_color(value, min_val, max_val):
    if value is None or max_val == min_val:
        return Style.RESET_ALL

    normalized = (value - min_val) / (max_val - min_val)

    # Interpolate color using a rainbow-like spectrum (from red to violet)
    # Colors transition through: Red → Yellow → Green → Cyan → Blue → Magenta
    if normalized <= 0.2:
        r, g, b = 255, int(255 * (normalized / 0.2)), 0
    elif normalized <= 0.4:
        r, g, b = int(255 * (1 - ((normalized - 0.2) / 0.2))), 255, 0
    elif normalized <= 0.6:
        r, g, b = 0, 255, int(255 * ((normalized - 0.4) / 0.2))
    elif normalized <= 0.8:
        r, g, b = 0, int(255 * (1 - ((normalized - 0.6) / 0.2))), 255
    else:
        r, g, b = int(255 * ((normalized - 0.8) / 0.2)), 0, 255

    return f"\033[38;2;{r};{g};{b}m"

def print_color_map_single_line(output_target, min_val, max_val, steps=50):
    output_target.write("Color Map (lightest to darkest): ")

    for step in range(steps + 1):
        value = min_val + step * (max_val - min_val) / steps
        color = get_intensity_color(value, min_val, max_val)
        output_target.write(f"{color}█{Style.RESET_ALL}")
    
    output_target.write("\n")

class TrieNode:
    def __init__(self):
        self.children = {}
        self.positions = []

class MultiSequenceTrie:
    def __init__(self, max_len=-1):
        self.root = TrieNode()
        self.max_len = max_len

    def get_container_memory_limit(self):
        try:
            with open("/sys/fs/cgroup/memory.max", "r") as f:
                val = int(f.read().strip())
                return val if val < (1 << 60) else None
        except Exception:
            return None

    def insert(self, byte_sequence, seq_index):
        length = len(byte_sequence)
        mem_limit = self.get_container_memory_limit()
        process = psutil.Process(os.getpid())

        iteration_check_interval = 2000
        time_check_interval = 1
        last_check_time = time.time()

        for start_pos in range(length):
            current_node = self.root
            end_pos = length if self.max_len == -1 else int(min(length, start_pos + self.max_len))

            for offset, byte in enumerate(byte_sequence[start_pos:end_pos]):
                current_node = current_node.children.setdefault(byte, TrieNode())
                current_node.positions.append((seq_index, start_pos))

                if (offset + start_pos) % iteration_check_interval == 0:
                    now = time.time()
                    if now - last_check_time > time_check_interval:
                        mem_used = process.memory_info().rss

                        if mem_limit and mem_used > mem_limit * 0.9:
                            print(f"[!] Memory limit exceeded: {mem_used} bytes > 90% of {mem_limit} bytes")
                            return False
                        last_check_time = now

        return True

    def find_subsequence(self, subsequence):
        current_node = self.root
        for byte in subsequence:
            if byte in current_node.children:
                current_node = current_node.children[byte]
            else:
                return None
        return list(current_node.positions)

def filter_region_deps(json_path):
    with open(json_path, "r") as f:
        deps = json.load(f)

    MWF = {}
    for r_str, writers in deps.items():
        for w_str, files in writers.items():
            w = int(w_str)
            for f in files:
                if not f:
                    continue
                if f not in MWF or w < MWF[f]:
                    MWF[f] = w

    FW = {}
    for f, w in MWF.items():
        FW.setdefault(w, set()).add(f)

    W = {}
    for r_str, writers in deps.items():
        r = int(r_str)
        W.setdefault(r, set())
        for w_str in writers.keys():
            W[r].add(int(w_str))

    def build_filtered_deps(r, visited=None):
        if visited is None:
            visited = set()
        if r in visited:
            return {}
        visited.add(r)

        acc = {}
        for w in sorted(W.get(r, [])):
            child = build_filtered_deps(w, visited)
            for rr, fileset in child.items():
                acc.setdefault(rr, set()).update(fileset)

            if w in FW:
                acc.setdefault(w, set()).update(FW[w])

        return acc

    filtered_deps = {}
    for r_str in deps.keys():
        r = int(r_str)
        acc = build_filtered_deps(r, visited=set())
        filtered_deps[r_str] = [ w for w, files in sorted(acc.items()) ]

    return filtered_deps


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

def serialize_global_sources(global_sources):
    start = time.perf_counter()

    serialized = []
    for fs_region_ids, region_list in global_sources:
        fs_list = list(fs_region_ids)
        new_region_list = []
        for hex_value, region_ids, app_tb_pcs, coverages in region_list:
            new_region_list.append((
                hex_value,
                list(region_ids),
                list(app_tb_pcs),
                list(coverages)
            ))
        serialized.append((fs_list, new_region_list))

    end = time.perf_counter()
    elapsed_ms = int((end - start) * 1000)
    print(f"\nSerialization ELAPSED: {elapsed_ms} ms\n")

    return serialized

def process_json(sources_hex, taint_data, fs_relations_data, subregion_divisor, min_subregion_len, max_len):
    global global_all_app_tb_pcs
    global new_app_tb_pcs
    global error
    global global_regions_dependance
    global global_regions_affections

    try:
        global global_max_len
    except NameError:
        global_max_len = max_len

    print("\n[\033[34m*\033[0m] max_len:", global_max_len)

    output_dir = "taint_analysis_stats"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    d = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    d3 = {}

    sources = []
    discarded_regions = set()
    last_store_event = None
    current_region_store = [0, []]
    last_load_event = None
    current_region_load = [0, []]
    multi_trie = MultiSequenceTrie(max_len)
    multiples = set()
    multiples2 = set()

    sources_bytes = [bytes(x) for x in sources_hex]

    global_all_set = global_all_app_tb_pcs
    new_app_tb_set = new_app_tb_pcs

    _min = min

    def process_region_matches(region_owner_id, region_list):
        L = len(region_list)
        if L == 0:
            return

        current_value_bytes = bytes(entry[1] for entry in region_list)
        Lb = len(current_value_bytes)

        find_subseq = multi_trie.find_subsequence
        sources_local = sources
        sources_bytes_local = sources_bytes
        global_all_local = global_all_set
        add_new_app_tb = new_app_tb_set.add

        for sub_len in range(Lb, 0, -1):
            if (sub_len < (Lb / subregion_divisor) and sub_len >= min_subregion_len):
                break

            limit = Lb - sub_len + 1
            matched_any = False

            for start_curr in range(limit):
                subslice = current_value_bytes[start_curr:start_curr + sub_len]

                found_positions = find_subseq(subslice)
                if not found_positions:
                    continue

                try:
                    fp_len = len(found_positions)
                except Exception:
                    found_positions = tuple(found_positions)
                    fp_len = len(found_positions)

                if fp_len != 1:
                    continue

                i, start_exist = found_positions[0]

                if region_owner_id < i:
                    continue

                if sources_bytes_local[i][start_exist:start_exist + sub_len] != subslice:
                    continue

                src_region_list = sources_local[i][1]
                for j in range(sub_len):
                    idx = j + start_exist
                    src_entry = src_region_list[idx]

                    deps_set = src_entry[1]
                    inodes_set = src_entry[2]

                    deps_set.add(region_owner_id)

                    inode_pc = region_list[j][2]

                    if inode_pc not in global_all_local:
                        inodes_set.add(inode_pc)
                        add_new_app_tb(inode_pc)

                matched_any = True
                break

            if matched_any:
                break

    previous_sink_id = -1

    fs_relations_lookup = fs_relations_data
    sources_hex_local = sources_hex
    multi_trie_insert = multi_trie.insert

    for event in tqdm(taint_data, desc="Processing sinks"):
        evtype = event.get("event", None)

        if evtype in (0, 1):
            sink_id = event["sink_id"]

            if sink_id > previous_sink_id:
                previous_sink_id = sink_id
                if sink_id >= len(sources_hex_local):
                    error = 1
                    print("Error: sink_id [%d] >= len(sources_hex) [%d]" % (sink_id, len(sources_hex_local)))
                    return None

                fs_rels = set(fs_relations_lookup.get(sink_id, []))
                per_byte = [(b, set(), set(), set()) for b in sources_hex_local[sink_id]]
                sources.append((fs_rels, per_byte))

                ok = multi_trie_insert(sources_hex_local[sink_id], sink_id)
                if not ok:
                    del multi_trie
                    time.sleep(1)
                    proc = psutil.Process(os.getpid())
                    mem_used = proc.memory_info().rss
                    print(f"Current mem_used: {mem_used}")
                    error = 2
                    return None

                global_regions_dependance[sink_id] = []
                global_regions_affections[sink_id] = {}
            elif sink_id == previous_sink_id:
                pass
            else:
                assert False

        if evtype == 1 and event.get("op_name") in (0, 1):
            cov_xxhash = event["cov_xxhash"]
            app_tb_pc = event["app_tb_pc"]
            gpa = event["gpa"]
            op_name = event["op_name"]
            value_hex = event["value"]
            inode = event["inode"]

            if op_name == 1:
                if last_store_event is not None and last_store_event.get("gpa") == gpa - 1:
                    current_region_store[1].append((gpa, value_hex, (inode, app_tb_pc), cov_xxhash))
                else:
                    if last_store_event is not None:
                        process_region_matches(current_region_store[0], current_region_store[1])

                    current_region_store[1] = [(gpa, value_hex, (inode, app_tb_pc), cov_xxhash)]

                current_region_store[0] = sink_id
                last_store_event = event
            else:
                if last_load_event is not None and last_load_event.get("gpa") == gpa - 1:
                    current_region_load[1].append((gpa, value_hex, (inode, app_tb_pc), cov_xxhash))
                else:
                    if last_load_event is not None:
                        process_region_matches(current_region_load[0], current_region_load[1])

                    current_region_load[1] = [(gpa, value_hex, (inode, app_tb_pc), cov_xxhash)]

                current_region_load[0] = sink_id
                last_load_event = event

    if current_region_store[1]:
        process_region_matches(current_region_store[0], current_region_store[1])
    if current_region_load[1]:
        process_region_matches(current_region_load[0], current_region_load[1])

    if len(sources) != len(sources_hex):
        error = 1
        print("Error: len(sources) [%d] != len(sources_hex) [%d]" % (len(sources), len(sources_hex)))
        return None

    return sources

def update_global(sources):
    global global_sources

    start = time.perf_counter()

    if not global_sources:
        global_sources = [
            (fs_ids.copy(), [(hx, ids.copy(), pcs.copy(), cov.copy()) 
                             for hx, ids, pcs, cov in region_list])
            for fs_ids, region_list in sources
        ]
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        print(f"\nELAPSED: {elapsed_ms} ms\n")
        return

    gs = global_sources
    n = min(len(sources), len(gs))

    for i in range(n):
        fs_region_ids, region_list = sources[i]
        g_fs_region_ids, g_region_list = gs[i]

        inter_fs = g_fs_region_ids & fs_region_ids

        m = min(len(region_list), len(g_region_list))
        for j in range(m):
            hex_value, region_ids, app_tb_pcs, coverages = region_list[j]
            g_hex, g_ids, g_pcs, g_covs = g_region_list[j]

            inter_ids = g_ids & region_ids
            inter_pcs = g_pcs & app_tb_pcs
            inter_covs = g_covs & coverages

            g_region_list[j] = (hex_value, inter_ids, inter_pcs, inter_covs)

        gs[i] = (inter_fs, g_region_list)

    global_sources = gs

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    print(f"\nELAPSED: {elapsed_ms} ms\n")

def calculate_delta(global_results, current_results):
    delta = 0
    count = 0

    if global_results:
        for metric in global_results.keys():
            for i, region in enumerate(global_results[metric]):
                for j, score in enumerate(global_results[metric][i]):
                    delta += abs(global_results[metric][i][j] - current_results[metric][i][j])
                    count += 1

        delta /= count
    else:
        delta = 1

    return delta

def check_if_delta_is_little_enough_to_stop(delta, delta_threshold):
    print("THE DELTA IS", delta)
    return delta <= delta_threshold

def calculate_analysis_results():
    global global_subregions_app_tb_pcs
    global global_subregions_covs
    global global_sources

    global_app_tb_pc_frequency = defaultdict(int)
    global_process_frequency = defaultdict(int)
    global_cov_frequency = defaultdict(int)

    unique_processes_per_byte = []
    unique_app_tb_pc_per_byte = []
    unique_region_ids_per_byte = []
    unique_fs_region_ids_per_id = []
    unique_covs_per_byte = []

    for i, (fs_relations, region) in enumerate(global_sources):
        unique_processes_per_byte.append([])
        unique_app_tb_pc_per_byte.append([])
        unique_region_ids_per_byte.append([])
        unique_covs_per_byte.append([])
        unique_fs_region_ids_per_id.append([])

        for affected_region_id in fs_relations:
            unique_fs_region_ids_per_id[i].append(affected_region_id)

        for j, (byte, region_ids, tb_pcs, covs) in enumerate(region):
            unique_processes_per_byte[i].append([])
            unique_app_tb_pc_per_byte[i].append([])
            unique_region_ids_per_byte[i].append([])
            unique_covs_per_byte[i].append([])

            for tb_pc in tb_pcs:
                if tb_pc[0] not in unique_processes_per_byte[i][j]:
                    unique_processes_per_byte[i][j].append(tb_pc[0])
                if tb_pc not in unique_app_tb_pc_per_byte[i][j]:
                    unique_app_tb_pc_per_byte[i][j].append(tb_pc)
                global_app_tb_pc_frequency[tb_pc] += 1
                global_process_frequency[tb_pc[0]] += 1

            for kw_id in region_ids:
                if kw_id not in unique_region_ids_per_byte[i][j]:              
                    unique_region_ids_per_byte[i][j].append(kw_id)

            for cov in covs:
                if cov not in unique_covs_per_byte[i][j]:  
                    unique_covs_per_byte[i][j].append(cov)
                global_cov_frequency[cov] += 1

    max_unique_processes = max((len(processes) for region in unique_processes_per_byte for processes in region), default=0)
    min_unique_processes = min((len(processes) for region in unique_processes_per_byte for processes in region), default=0)
    max_unique_app_tb_pc = max((len(app_tb_pc) for region in unique_app_tb_pc_per_byte for app_tb_pc in region), default=0)
    min_unique_app_tb_pc = min((len(app_tb_pc) for region in unique_app_tb_pc_per_byte for app_tb_pc in region), default=0)
    max_unique_regions = max((len(region_ids) for region in unique_region_ids_per_byte for region_ids in region), default=0)
    min_unique_regions = min((len(region_ids) for region in unique_region_ids_per_byte for region_ids in region), default=0)
    max_unique_fs_regions = max((len(region_ids) for region_ids in unique_fs_region_ids_per_id), default=0)
    min_unique_fs_regions = min((len(region_ids) for region_ids in unique_fs_region_ids_per_id), default=0)
    max_unique_covs = max((len(covs) for region in unique_covs_per_byte for covs in region), default=0)
    min_unique_covs = min((len(covs) for region in unique_covs_per_byte for covs in region), default=0)

    max_frequency_value_app_tb_pc = max(global_app_tb_pc_frequency.values(), default=0)
    min_frequency_value_app_tb_pc = min(global_app_tb_pc_frequency.values(), default=0)
    max_frequency_value_process = max(global_process_frequency.values(), default=0)
    min_frequency_value_process = min(global_process_frequency.values(), default=0)
    max_frequency_value_cov = max(global_cov_frequency.values(), default=0)
    min_frequency_value_cov = min(global_cov_frequency.values(), default=0)

    analysis_results = {}
    metrics = ["rarest_app_tb_pc", "most_frequent_app_tb_pc", "rarest_process", "most_frequent_process", "rarest_cov", "most_frequent_cov", "number_of_processes", "number_of_app_tb_pcs", "number_of_affected_regions_by_taint", "number_of_affected_regions_by_fs", "number_of_covs"]
    for metric in metrics:
        analysis_results[metric] = []

    for i, (_, region) in enumerate(global_sources):
        analysis_results["rarest_app_tb_pc"].append([])
        analysis_results["most_frequent_app_tb_pc"].append([])
        analysis_results["rarest_process"].append([])
        analysis_results["most_frequent_process"].append([])
        analysis_results["rarest_cov"].append([])
        analysis_results["most_frequent_cov"].append([])
        analysis_results["number_of_processes"].append([])
        analysis_results["number_of_app_tb_pcs"].append([])
        analysis_results["number_of_affected_regions_by_taint"].append([])
        analysis_results["number_of_affected_regions_by_fs"].append([])        
        analysis_results["number_of_covs"].append([])

        unique_fs_region_ids = len(unique_fs_region_ids_per_id[i])

        for j, (byte, region_ids, tb_pcs, covs) in enumerate(region):
            tb_pc_counts = [global_app_tb_pc_frequency[tb_pc] for tb_pc in tb_pcs]
            process_counts = [global_process_frequency[tb_pc[0]] for tb_pc in tb_pcs]
            cov_counts = [global_cov_frequency[cov] for cov in covs]

            unique_processes = len(unique_processes_per_byte[i][j])
            unique_app_tb_pc = len(unique_app_tb_pc_per_byte[i][j])
            unique_region_ids = len(unique_region_ids_per_byte[i][j])
            unique_covs = len(unique_covs_per_byte[i][j])

            byte_str = chr(byte) if 32 < byte < 127 else "."

            analysis_results["rarest_app_tb_pc"][-1].append(
                safe_div(
                    max_frequency_value_app_tb_pc - statistics.mean(tb_pc_counts) if tb_pc_counts else 0,
                    max_frequency_value_app_tb_pc - min_frequency_value_app_tb_pc
                )
            )
            analysis_results["most_frequent_app_tb_pc"][-1].append(
                safe_div(
                    statistics.mean(tb_pc_counts) - min_frequency_value_app_tb_pc if tb_pc_counts else 0,
                    max_frequency_value_app_tb_pc - min_frequency_value_app_tb_pc
                )
            )
            analysis_results["rarest_process"][-1].append(
                safe_div(
                    max_frequency_value_process - statistics.mean(process_counts) if process_counts else 0,
                    max_frequency_value_process - min_frequency_value_process
                )
            )
            analysis_results["most_frequent_process"][-1].append(
                safe_div(
                    statistics.mean(process_counts) - min_frequency_value_process if process_counts else 0,
                    max_frequency_value_process - min_frequency_value_process
                )
            )
            analysis_results["rarest_cov"][-1].append(
                safe_div(
                    max_frequency_value_cov - statistics.mean(cov_counts) if cov_counts else 0,
                    max_frequency_value_cov - min_frequency_value_cov
                )
            )
            analysis_results["most_frequent_cov"][-1].append(
                safe_div(
                    statistics.mean(cov_counts) - min_frequency_value_cov if cov_counts else 0,
                    max_frequency_value_cov - min_frequency_value_cov
                )
            )
            analysis_results["number_of_processes"][-1].append(
                safe_div(
                    unique_processes - min_unique_processes,
                    max_unique_processes - min_unique_processes
                )
            )
            analysis_results["number_of_app_tb_pcs"][-1].append(
                safe_div(
                    unique_app_tb_pc - min_unique_app_tb_pc,
                    max_unique_app_tb_pc - min_unique_app_tb_pc
                )
            )
            analysis_results["number_of_affected_regions_by_taint"][-1].append(
                safe_div(
                    unique_region_ids - min_unique_regions,
                    max_unique_regions - min_unique_regions
                )
            )
            analysis_results["number_of_affected_regions_by_fs"][-1].append(
                safe_div(
                    unique_fs_region_ids - min_unique_fs_regions,
                    max_unique_fs_regions - min_unique_fs_regions
                )
            )
            analysis_results["number_of_covs"][-1].append(
                safe_div(
                    unique_covs - min_unique_covs,
                    max_unique_covs - min_unique_covs
                )
            )

    for i, (_, region) in enumerate(global_sources):
        app_tb_pc_set = {}
        coverage_set = {}
        metrics_values_app_tb_pcs = {}
        metrics_values_covs = {}
        count_app_tb_pcs = {}
        count_covs = {}
        offset_app_tb_pcs = {}
        offset_covs = {}
        pcs_app_tb_pcs = {}
        pcs_covs = {}
        affected_regions_app_tb_pcs = {}
        affected_regions_covs = {}

        for j, (hex_value, regions, app_tb_pcs, coverages) in enumerate(region):
            for app_tb_pc in app_tb_pcs:
                if app_tb_pc not in metrics_values_app_tb_pcs:
                    metrics_values_app_tb_pcs[app_tb_pc] = {}
                if app_tb_pc not in count_app_tb_pcs:
                    count_app_tb_pcs[app_tb_pc] = 0
                if app_tb_pc not in app_tb_pc_set:
                    app_tb_pc_set[app_tb_pc] = []
                if app_tb_pc not in offset_app_tb_pcs:
                    offset_app_tb_pcs[app_tb_pc] = j
                if app_tb_pc not in affected_regions_app_tb_pcs:
                    affected_regions_app_tb_pcs[app_tb_pc] = []
                if app_tb_pc not in pcs_app_tb_pcs:
                    pcs_app_tb_pcs[app_tb_pc] = []
                if not metrics_values_app_tb_pcs[app_tb_pc]:
                    for key in analysis_results.keys():
                        metrics_values_app_tb_pcs[app_tb_pc][key] = analysis_results[key][i][j]
                else:
                    for key in analysis_results.keys():
                        metrics_values_app_tb_pcs[app_tb_pc][key] += analysis_results[key][i][j]
                count_app_tb_pcs[app_tb_pc] += 1
                app_tb_pc_set[app_tb_pc].append(hex_value)
                for kw in regions:
                    if kw not in affected_regions_app_tb_pcs[app_tb_pc]:
                        affected_regions_app_tb_pcs[app_tb_pc].append(kw)
                for pc in pcs_app_tb_pcs.keys():
                    if app_tb_pc not in pcs_app_tb_pcs[pc]:
                        pcs_app_tb_pcs[pc].append(app_tb_pc)

            for coverage in coverages:
                if coverage not in metrics_values_covs:
                    metrics_values_covs[coverage] = {}
                if coverage not in count_covs:
                    count_covs[coverage] = 0
                if coverage not in coverage_set:
                    coverage_set[coverage] = []
                if coverage not in offset_covs:
                    offset_covs[coverage] = j
                if coverage not in affected_regions_covs:
                    affected_regions_covs[coverage] = []
                if coverage not in pcs_covs:
                    pcs_covs[coverage] = []
                if not metrics_values_covs[coverage]:
                    for key in analysis_results.keys():
                        metrics_values_covs[coverage][key] = analysis_results[key][i][j]
                else:
                    for key in analysis_results.keys():
                        metrics_values_covs[coverage][key] += analysis_results[key][i][j]
                count_covs[coverage] += 1   
                coverage_set[coverage].append(hex_value)
                for kw in regions:
                    if kw not in affected_regions_covs[coverage]:
                        affected_regions_covs[coverage].append(kw)
                for cov in pcs_covs.keys():
                    if coverage not in pcs_covs[cov]:
                        pcs_covs[cov].append(coverage)

            app_tb_pc_to_del = []
            for app_tb_pc in metrics_values_app_tb_pcs:
                if app_tb_pc not in app_tb_pcs:
                    metrics_values = {metric: metrics_values_app_tb_pcs[app_tb_pc][metric] / count_app_tb_pcs[app_tb_pc] for metric in metrics_values_app_tb_pcs[app_tb_pc]}
                    global_subregions_app_tb_pcs.append((pcs_app_tb_pcs[app_tb_pc], affected_regions_app_tb_pcs[app_tb_pc], app_tb_pc_set[app_tb_pc], ''.join(chr(val) if 32 < val < 127 else '.' for val in app_tb_pc_set[app_tb_pc]), metrics_values, i, offset_app_tb_pcs[app_tb_pc], count_app_tb_pcs[app_tb_pc]))
                    app_tb_pc_to_del.append(app_tb_pc)
            for app_tb_pc in app_tb_pc_to_del:
                del metrics_values_app_tb_pcs[app_tb_pc]
                del count_app_tb_pcs[app_tb_pc]
                del app_tb_pc_set[app_tb_pc]
                del offset_app_tb_pcs[app_tb_pc]
                del affected_regions_app_tb_pcs[app_tb_pc]
                del pcs_app_tb_pcs[app_tb_pc]

            cov_to_del = []
            for cov in metrics_values_covs:
                if cov not in coverages:
                    metrics_values = {metric: metrics_values_covs[cov][metric] / count_covs[cov] for metric in metrics_values_covs[cov]}
                    global_subregions_covs.append((pcs_covs[cov], affected_regions_covs[cov], coverage_set[cov], ''.join(chr(val) if 32 < val < 127 else '.' for val in coverage_set[cov]), metrics_values, i, offset_covs[cov], count_covs[cov]))
                    cov_to_del.append(cov)
            for cov in cov_to_del:
                del metrics_values_covs[cov]
                del count_covs[cov]
                del coverage_set[cov]
                del offset_covs[cov]
                del affected_regions_covs[cov]
                del pcs_covs[cov]

        app_tb_pc_to_del = []
        for app_tb_pc in metrics_values_app_tb_pcs:
            metrics_values = {metric: metrics_values_app_tb_pcs[app_tb_pc][metric] / count_app_tb_pcs[app_tb_pc] for metric in metrics_values_app_tb_pcs[app_tb_pc]}
            global_subregions_app_tb_pcs.append((pcs_app_tb_pcs[app_tb_pc], affected_regions_app_tb_pcs[app_tb_pc], ''.join(chr(val) if 32 < val < 127 else '.' for val in app_tb_pc_set[app_tb_pc]), metrics_values, i, offset_app_tb_pcs[app_tb_pc], count_app_tb_pcs[app_tb_pc]))
            app_tb_pc_to_del.append(app_tb_pc)
        for app_tb_pc in app_tb_pc_to_del:
            del metrics_values_app_tb_pcs[app_tb_pc]
            del count_app_tb_pcs[app_tb_pc]
            del app_tb_pc_set[app_tb_pc]
            del offset_app_tb_pcs[app_tb_pc]
            del affected_regions_app_tb_pcs[app_tb_pc]
            del pcs_app_tb_pcs[app_tb_pc]

        cov_to_del = []
        for cov in metrics_values_covs:
            metrics_values = {metric: metrics_values_covs[cov][metric] / count_covs[cov] for metric in metrics_values_covs[cov]}
            global_subregions_covs.append((pcs_covs[cov], affected_regions_covs[cov], coverage_set[cov], ''.join(chr(val) if 32 < val < 127 else '.' for val in coverage_set[cov]), metrics_values, i, offset_covs[cov], count_covs[cov]))
            cov_to_del.append(cov)
        for cov in cov_to_del:
            del metrics_values_covs[cov]
            del count_covs[cov]
            del coverage_set[cov]
            del offset_covs[cov]
            del affected_regions_covs[cov]
            del pcs_covs[cov]

    return analysis_results

def print_global_results(analysis_results, sources_hex, output_mode="print", output_file_path=None):
    global subregion_to_find

    output_target = sys.stdout if output_mode == "print" else open(output_file_path, "w")
    print_color_map_single_line(output_target, min_value, max_value, steps=50)

    for metric in analysis_results.keys():
        color_analysis_results = []
        for i, region in enumerate(sources_hex):
            color_analysis_results.append("")
            for j, byte_score in enumerate(analysis_results[metric][i]):
                intensity = get_intensity_color(byte_score, min_value, max_value)
                byte_str = chr(region[j]) if 32 < region[j] < 127 else "."
                color_analysis_results[i] += f"{intensity}{byte_str}{Style.RESET_ALL}"

        output_target.write(f"\n{BLUE}{metric}:{Style.RESET_ALL}\n")
        for region in color_analysis_results:
            output_target.write(f"{region}\n")

    output_target.write(f"\n{Style.RESET_ALL}")

def plot_analysis_results(analysis_results, sources_hex, output_dir=None):
    global subregion_to_find

    if output_dir:
        out_png = os.path.join(output_dir, "analysis_plot")
        # out_png_2 = os.path.join(output_dir, "analysis_plot_extended")
        plot_normalized_scores(analysis_results, sources_hex, subregion_to_find, gaussian_filter_smoothing_sigma, out_png)
        # plot_normalized_scores_2(analysis_results, sources_hex, subregion_to_find, gaussian_filter_smoothing_sigma, out_png_2)
    else:
        plot_normalized_scores(analysis_results, sources_hex, subregion_to_find, gaussian_filter_smoothing_sigma)
        # plot_normalized_scores_2(analysis_results, sources_hex, subregion_to_find, gaussian_filter_smoothing_sigma)

def ensure_file_coherence(fs_dir, taint_dir):
    if not os.path.exists(fs_dir):
        if os.path.exists(taint_dir):
            shutil.rmtree(taint_dir)
        return

    if not os.path.exists(taint_dir):
        if os.path.exists(fs_dir):
            shutil.rmtree(fs_dir)
        return

    fs_files = set(f for f in os.listdir(fs_dir) if f.startswith("fs_sink_relations_") and f.endswith(".json"))
    taint_files = set(f for f in os.listdir(taint_dir) if f.startswith("taint_mem_") and f.endswith(".log"))
    
    fs_ids = {f[len("fs_sink_relations_"):].split(".json")[0] for f in fs_files}
    taint_ids = {f[len("taint_mem_"):].split(".log")[0] for f in taint_files}
    
    fs_missing = fs_ids - taint_ids
    taint_missing = taint_ids - fs_ids
    
    for missing_id in fs_missing:
        os.remove(os.path.join(fs_dir, f"fs_sink_relations_{missing_id}.json"))
    
    for missing_id in taint_missing:
        os.remove(os.path.join(taint_dir, f"taint_mem_{missing_id}.log"))

def compare_config(config_path, subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter):
    config = configparser.ConfigParser()
    
    if not config.read(config_path):
        print(f"[-] Error: Config file '{config_path}' not found or unreadable.")
        return 2

    try:
        config_divisor = int(config["PRE-ANALYSIS"]["subregion_divisor"])
        config_len = int(config["PRE-ANALYSIS"]["min_subregion_len"])
        config_threshold = float(config["PRE-ANALYSIS"]["delta_threshold"])
        config_include_libraries = int(config["EMULATION_TRACING"]["include_libraries"])
        config_region_delimiter = bytes.fromhex(config["AFLNET_FUZZING"]["region_delimiter"].replace('\\x', ''))

        if (
            config_divisor == subregion_divisor and
            config_len == min_subregion_len and
            config_threshold == delta_threshold and
            config_include_libraries == include_libraries and
            config_region_delimiter == region_delimiter
        ):
            return 0
        elif config_include_libraries != include_libraries or config_region_delimiter != region_delimiter:
            return 2
        else:
            return 1

    except (KeyError, ValueError) as e:
        print(f"[-] Error reading config {config_path}: {e}")
        return 2

def create_config(config_path, subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter):
    config = configparser.ConfigParser()

    config["PRE-ANALYSIS"] = {
        "subregion_divisor": str(subregion_divisor),
        "min_subregion_len": str(min_subregion_len),
        "delta_threshold": str(delta_threshold),
        "max_len": str(global_max_len)
    }

    config["EMULATION_TRACING"] = {
        "include_libraries": str(include_libraries)
    }

    config["AFLNET_FUZZING"] = {
        "region_delimiter": ''.join(f'\\x{b:02X}' for b in region_delimiter)
    }

    with open(config_path, "w") as configfile:
        config.write(configfile)

    print(f"[+] Config file '{config_path}' created successfully.")

def taint(firmae_dir, taint_dir, work_dir, mode, firmware, sleep, timeout, subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter):
    global global_all_app_tb_pcs
    global new_app_tb_pcs
    global global_subregions_app_tb_pcs
    global global_subregions_covs
    global global_sources
    global global_regions_dependance
    global qemu_pid
    global global_max_len
    global error
    global n_run

    elapsed_seconds = 0
    print("\n[\033[32m+\033[0m] TAINT ANALYSIS of the firmware '%s' (timeout: %d)\n"%(os.path.basename(firmware), timeout))

    all_app_tb_pcs_path = os.path.join(taint_dir, firmware, "all_app_tb_pcs.json")
    if os.path.exists(all_app_tb_pcs_path):
        try:
            with open(all_app_tb_pcs_path, "r") as f:
                loaded = json.load(f)
            global_all_app_tb_pcs = set(tuple(pair) for pair in loaded)
            print(f"[+] Restored global_all_app_tb_pcs ({len(global_all_app_tb_pcs)} entries) from {all_app_tb_pcs_path}")
        except Exception as e:
            print(f"[-] Failed to load {all_app_tb_pcs_path}: {e}; starting with empty set.")
            global_all_app_tb_pcs = set()
    else:
        global_all_app_tb_pcs = set()

    os.environ["EXEC_MODE"] = "RUN"
    os.environ["TAINT"] = "1"
    os.environ["FD_DEPENDENCIES_TRACK"] = "1"
    os.environ["INCLUDE_LIBRARIES"] = str(include_libraries)
    os.environ["REGION_DELIMITER"] = region_delimiter.decode('latin-1')
    # os.environ["DEBUG"] = "1"
    # os.environ["DEBUG_DIR"] = os.path.join(work_dir, "debug", "interaction")

    cleanup(firmae_dir, work_dir)

    pcap_dir = os.path.join("/STAFF/pcap/", firmware)

    if not os.path.exists(pcap_dir):
        print("[-] Directory not found:", pcap_dir)
        exit(1)

    if os.path.exists(os.path.join(work_dir, "webserver_ready")):
        os.remove(os.path.join(work_dir, "webserver_ready"))
    if os.path.exists(os.path.join(work_dir, "source_id")):
        os.remove(os.path.join(work_dir, "source_id"))
    if os.path.exists(os.path.join(work_dir, "pcap_filename")):
        os.remove(os.path.join(work_dir, "pcap_filename"))
    if os.path.exists(os.path.join(work_dir, "proto")):
        os.remove(os.path.join(work_dir, "proto"))

    sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]

    start_fork_executed = False
    a = True
    global_elapsed_seconds = 0
    for proto in sub_dirs:
        print("\n[\033[33m*\033[0m] Protocol: {}".format(proto))
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            elapsed_seconds = 0
            n_run = 0
            new_app_tb_pcs = set()
            start = time.perf_counter()
            required_files = ["config.ini", "taint_plot", "elapsed_time", "analysis_log", "app_tb_pc_subsequences.json", "cov_subsequences.json", "global_analysis_results.json", "region_dependancies.json", "region_affections.json", "fs_relations.json", pcap_file+".seed", pcap_file+".seed_metadata.json"]

            global_subregions_app_tb_pcs = []
            global_subregions_covs = []
            global_sources = []
            global_regions_dependance = {}

            pcap_path = os.path.join(pcap_dir, proto, pcap_file)

            tmp_required_files = required_files + [pcap_file+".seed"]
            missing_files = [file for file in tmp_required_files if not os.path.exists(os.path.join(taint_dir, firmware, proto, pcap_file, file))]
            
            force_run = False
            if missing_files:
                print("The following files are missing under", os.path.join(taint_dir, firmware, proto, pcap_file), ":", ', '.join(missing_files))
                if "config.ini" in missing_files:
                    force_run = True
                else:
                    res = compare_config(os.path.join(taint_dir, firmware, proto, pcap_file, "config.ini"), subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter)
                    if res == 2:
                        print("config.ini file does not match 'include_libraries' or 'region_delimiter'!")
                        force_run = True
                    else:
                        print("config.ini file does not match provided pre-analysis params (not 'include_libraries' or 'region_delimiter')!")                
            else:
                print(f"All required files exist under", os.path.join(taint_dir, firmware, proto, pcap_file))

                res = compare_config(os.path.join(taint_dir, firmware, proto, pcap_file, "config.ini"), subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter)
                if res == 1:
                    print("config.ini file does not match provided pre-analysis params (not 'include_libraries' or 'region_delimiter')!")
                elif res == 2:
                    print("config.ini file does not match 'include_libraries' or 'region_delimiter'!")
                    force_run = True
                else:
                    with open(os.path.join(taint_dir, firmware, proto, pcap_file, "elapsed_time"), "r") as f:
                        read_value = f.read().strip()
                        read_elapsed = int(read_value)
                        global_elapsed_seconds += read_elapsed
                    continue

            print("\n[\033[34m*\033[0m] PCAP #{}".format(pcap_file))
            skip_run = False

            if not force_run:
                taint_json_dir = os.path.join(taint_dir, firmware, proto, pcap_file, "taint_json")
                os.makedirs(taint_json_dir, exist_ok=True)
                set_permissions_recursive(taint_json_dir)

                fs_json_dir = os.path.join(taint_dir, firmware, proto, pcap_file, "fs_sink_relations_json")
                os.makedirs(fs_json_dir, exist_ok=True)
                set_permissions_recursive(fs_json_dir)

                seed_path = os.path.join(taint_dir, firmware, proto, pcap_file, "%s.seed"%(pcap_file))
                sources_hex = convert_pcap_into_single_seed_file(pcap_path, seed_path, region_delimiter)

                ensure_file_coherence(fs_json_dir, taint_json_dir)

                start = time.perf_counter()
                for json_file in sorted(os.listdir(taint_json_dir)):
                    if json_file.startswith("taint_mem_") and json_file.endswith(".log"):
                        json_path = os.path.join(taint_json_dir, json_file)
                        
                        file_id = json_file[len("taint_mem_"):-len(".log")]
                        fs_json_file = f"fs_sink_relations_{file_id}.json"
                        fs_json_path = os.path.join(fs_json_dir, fs_json_file)
                        
                        if not os.path.exists(fs_json_path):
                            os.remove(json_path)
                            print(f"Removed orphaned taint JSON file: {json_path}")
                            continue
                        
                        fs_relations_data = filter_region_deps(fs_json_path)
                        taint_data = process_log_file(json_path)
                        
                        delta_check = False
                        while(True):
                            sources = process_json(sources_hex, taint_data, fs_relations_data, subregion_divisor, min_subregion_len, global_max_len)
                            if sources:
                                delta = update_global(sources)
                                analysis_results = calculate_analysis_results()

                                # if check_if_delta_is_little_enough_to_stop(delta, delta_threshold):
                                if n_run == 0:
                                    skip_run = True
                                    delta_check = True
                                    break
                                else:
                                    n_run += 1
                            else:
                                if error == 2:
                                    if (global_max_len == -1):
                                        global_max_len = 1000
                                    else:
                                        global_max_len /= 2
                                    continue
                                else:
                                    print("Error process_json() (2)")
                                    exit(1)
                                error = 0
                            break

                        if delta_check:
                            break

                end = time.perf_counter()
                elapsed_seconds += int((end - start) * 1000)
            else:
                taint_json_dir = os.path.join(taint_dir, firmware, proto, pcap_file, "taint_json")
                if os.path.exists(taint_json_dir):
                    shutil.rmtree(taint_json_dir)
                os.makedirs(taint_json_dir, exist_ok=True)
                set_permissions_recursive(taint_json_dir)

                fs_json_dir = os.path.join(taint_dir, firmware, proto, pcap_file, "fs_sink_relations_json")
                if os.path.exists(fs_json_dir):
                    shutil.rmtree(fs_json_dir)
                os.makedirs(fs_json_dir, exist_ok=True)
                set_permissions_recursive(fs_json_dir)

                seed_path = os.path.join(taint_dir, firmware, proto, pcap_file, "%s.seed"%(pcap_file))
                sources_hex = convert_pcap_into_single_seed_file(pcap_path, seed_path, region_delimiter)               

            if not skip_run:
                while(1):
                    cleanup(firmae_dir, work_dir)
                    process = subprocess.Popen(
                        ["sudo", "-E", "./run.sh", "-r", os.path.dirname(firmware), firmware, mode, "0.0.0.0"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    qemu_pid = process.pid
                    print("Booting firmware, wait %d seconds..."%(sleep))
                    
                    time.sleep(sleep)

                    start = time.perf_counter()

                    json_dir = "%s/taint/"%(work_dir)

                    while(1):
                        port = None
                        try:
                            port = socket.getservbyname(proto)
                            print(f"The port for {proto.upper()} is {port}.")
                        except OSError:
                            print(f"Protocol {proto.upper()} not found.")
                        command = ["sudo", "-E", "/STAFF/aflnet/client", seed_path, open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(timeout)]
                        
                        print("Current Working Directory:", os.getcwd())
                        process = subprocess.Popen(command)
                        process.wait()
                        if process.returncode == 0:
                            print("\nCommand executed successfully.")
                        elif process.returncode == 1:
                            print("\nCommand finished with errors. Return Code:", process.returncode)
                            exit(1)
                        
                        break

                    print("Sending SIGINT to", qemu_pid)
                    send_signal_recursive(qemu_pid, signal.SIGINT)

                    try:
                        os.waitpid(qemu_pid, 0)
                    except:
                        pass
                    time.sleep(2)
                    
                    taint_json_dir = os.path.join(taint_dir, firmware, proto, pcap_file, "taint_json")
                    os.makedirs(taint_json_dir, exist_ok=True)
                    set_permissions_recursive(taint_json_dir)

                    taint_mem_file = os.path.join(json_dir, "taint_mem.log")
                    if os.path.exists(taint_mem_file):
                        existing_files = [f for f in os.listdir(taint_json_dir) if f.startswith("taint_mem_")]
                        next_index = max(
                            (int(f.split('_')[-1].split('.')[0]) for f in existing_files if f.split('_')[-1].split('.')[0].isdigit()), 
                            default=-1
                        ) + 1

                        taint_target_file = os.path.join(taint_json_dir, f"taint_mem_{next_index}.log")
                        shutil.copy2(taint_mem_file, taint_target_file)
                        print(f"[\033[32m+\033[0m] Stored {taint_mem_file} as {taint_target_file}")

                    fs_json_dir = os.path.join(taint_dir, firmware, proto, pcap_file, "fs_sink_relations_json")
                    os.makedirs(fs_json_dir, exist_ok=True)
                    set_permissions_recursive(fs_json_dir)

                    fs_file = os.path.join(work_dir, "filesystem_sink_relations.json")
                    if os.path.exists(fs_file):
                        existing_files = [f for f in os.listdir(fs_json_dir) if f.startswith("fs_sink_relations_")]
                        next_index = max(
                            (int(f.split('_')[-1].split('.')[0]) for f in existing_files if f.split('_')[-1].split('.')[0].isdigit()), 
                            default=-1
                        ) + 1

                        fs_target_file = os.path.join(fs_json_dir, f"fs_sink_relations_{next_index}.json")
                        shutil.copy2(fs_file, fs_target_file)
                        print(f"[\033[32m+\033[0m] Stored {fs_file} as {fs_target_file}")

                    time.sleep(2)

                    fs_relations_data = filter_region_deps(fs_target_file)
                    taint_data = process_log_file(taint_target_file)

                    delta_check = False
                    while(True):
                        sources = process_json(sources_hex, taint_data, fs_relations_data, subregion_divisor, min_subregion_len, global_max_len)
                        if sources:
                            delta = update_global(sources)
                            analysis_results = calculate_analysis_results()

                            # if check_if_delta_is_little_enough_to_stop(delta, delta_threshold):
                            if n_run == 0:
                                delta_check = True
                                break
                            else:
                                n_run += 1
                        else:
                            if error == 2:
                                if (global_max_len == -1):
                                    global_max_len = 1000
                                else:
                                    global_max_len /= 2
                                continue
                            else:
                                print("Error process_json() (2)")
                                exit(1)
                            error = 0
                        break

                    end = time.perf_counter()
                    elapsed_seconds += int((end - start) * 1000)

                    if delta_check:
                        break
            
            plot_dir_path = os.path.join(taint_dir, firmware, proto, pcap_file, "taint_plot")
            os.makedirs(plot_dir_path, exist_ok=True)
            plot_analysis_results(analysis_results, sources_hex, output_dir=plot_dir_path)
            analysis_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, "analysis_log")
            print_global_results(analysis_results, sources_hex, output_mode="file", output_file_path=analysis_file_path)
            json_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, "app_tb_pc_subsequences.json")
            with open(json_file_path, "w") as f:
                json.dump(global_subregions_app_tb_pcs, f, indent=4)
            json_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, "cov_subsequences.json")
            with open(json_file_path, "w") as f:
                json.dump(global_subregions_covs, f, indent=4)
            json_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, "global_analysis_results.json")
            with open(json_file_path, "w") as f:
                json.dump(analysis_results, f, indent=4)
            json_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, pcap_file + ".seed_metadata.json")
            with open(json_file_path, "w") as f:
                json.dump(serialize_global_sources(global_sources), f, indent=4)
            json_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, "region_dependancies.json")
            with open(json_file_path, "w") as f:
                json.dump(global_regions_dependance, f, indent=4)
            json_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, "region_affections.json")
            with open(json_file_path, "w") as f:
                json.dump(global_regions_affections, f, indent=4)
            json_file_path = os.path.join(taint_dir, firmware, proto, pcap_file, "fs_relations.json")
            with open(json_file_path, "w") as f:
                json.dump(global_fs_relations, f, indent=4)

            for app_tb_pc in new_app_tb_pcs:
                global_all_app_tb_pcs.add(app_tb_pc)
            all_app_tb_pcs_path = os.path.join(taint_dir, firmware, "all_app_tb_pcs.json")
            serializable = [[tb, pc] for (tb, pc) in global_all_app_tb_pcs]
            with open(all_app_tb_pcs_path, "w") as f:
                json.dump(serializable, f, indent=4)
            with open(os.path.join(taint_dir, firmware, proto, pcap_file, "elapsed_time"), "w") as f:
                f.write(f"{elapsed_seconds}")
            global_elapsed_seconds += elapsed_seconds
            with open(os.path.join(taint_dir, firmware, "global_elapsed_time"), "w") as f:
                f.write(f"{global_elapsed_seconds}")
            set_permissions_recursive(taint_json_dir)
            create_config(os.path.join(taint_dir, firmware, proto, pcap_file, "config.ini"), subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter)
            set_permissions_recursive(os.path.join(taint_dir, firmware, proto, pcap_file, "config.ini"))

def compute_f1_vs_ground_truth(run_sets, ground_truth):
    f1_scores = []
    for run_set in run_sets:
        tp = len(run_set & ground_truth)
        fp = len(run_set - ground_truth)
        fn = len(ground_truth - run_set)
        if tp + fp + fn == 0:
            f1_scores.append(1.0)
        else:
            f1_scores.append(2 * tp / (2 * tp + fp + fn))
    return sum(f1_scores) / len(f1_scores) if f1_scores else 0.0

def pre_analysis_exp(db_dir, firmae_dir, work_dir, firmware, proto, include_libraries,
                     region_delimiter, sleep, timeout, taint_analysis_path,
                     pre_analysis_id, stab_upper_runs=10, n_taint_hints_to_eval=10):

    user_interactions_list = os.listdir(os.path.join(taint_analysis_path, firmware, proto))
    available_user_interactions = [u for u in user_interactions_list if "user_interaction_0" not in u]
    if not available_user_interactions:
        return

    os.makedirs(db_dir, exist_ok=True)
    firmware_dir = os.path.join(db_dir, firmware)
    os.makedirs(firmware_dir, exist_ok=True)

    existing_runs = {}
    for entry in os.listdir(firmware_dir):
        if entry.startswith(f"pre_analysis_{pre_analysis_id}_"):
            path = os.path.join(firmware_dir, entry)
            try:
                run_idx = int(entry.split("_")[-1])
            except ValueError:
                continue
            essential_files = ["info.json", "ground_truth.json", "pre_analysis.json"]
            incomplete = any(not os.path.exists(os.path.join(path, f)) for f in essential_files)
            existing_runs[run_idx] = not incomplete

    run_indices = []
    next_run_idx = 0
    while len(run_indices) < n_taint_hints_to_eval:
        if next_run_idx not in existing_runs or existing_runs[next_run_idx] is False:
            run_indices.append(next_run_idx)
        next_run_idx += 1

    for next_run_idx in run_indices:
        chosen_user_interaction = random.choice(available_user_interactions)

        experiment_dir = os.path.join(firmware_dir, f"pre_analysis_{pre_analysis_id}_{next_run_idx}")
        os.makedirs(experiment_dir, exist_ok=True)

        seed_path = os.path.join(taint_analysis_path, firmware, proto,
                                 chosen_user_interaction, chosen_user_interaction + ".seed")
        seed_metadata = os.path.join(taint_analysis_path, firmware, proto,
                                     chosen_user_interaction, chosen_user_interaction + ".seed_metadata.json")
        results_file = os.path.join(taint_analysis_path, firmware, proto,
                                    chosen_user_interaction, "pre_analysis_exp.json")

        shutil.rmtree(os.path.join(work_dir, "debug"), ignore_errors=True)
        os.makedirs(os.path.join(work_dir, "debug"), exist_ok=True)
        shutil.rmtree(os.path.join(work_dir, "outputs"), ignore_errors=True)
        os.makedirs(os.path.join(work_dir, "outputs", "taint_metadata"), exist_ok=True)
        if os.path.exists(seed_metadata):
            shutil.copy(seed_metadata, os.path.join(work_dir, "outputs", "taint_metadata"))

        try:
            port = socket.getservbyname(proto)
        except OSError:
            port = None

        subprocess.run(["sudo", "-E", "/STAFF/aflnet/TaintQueue", seed_path,
                        os.path.join(work_dir, "outputs"), "taint_metrics", "1"], check=False)

        with open(os.path.join(work_dir, "debug", chosen_user_interaction + ".seed_app_tb_pcs_post.json")) as f:
            data = json.load(f)

        elements = data.get("elements", [])
        if not elements:
            continue

        chosen_element_index = random.randrange(len(elements))
        chosen_element = elements[chosen_element_index]

        region = chosen_element.get("index")
        offset = chosen_element.get("offset")
        length = chosen_element.get("count")
        inode_pcs = chosen_element.get("pcs", [])
        affected_regions = chosen_element.get("affected_regions", [])
        region_influences = chosen_element.get("region_influences", [])

        os.environ.update({
            "EXEC_MODE": "RUN",
            "TAINT": "1",
            "FD_DEPENDENCIES_TRACK": "1",
            "INCLUDE_LIBRARIES": str(include_libraries),
            "REGION_DELIMITER": region_delimiter.decode('latin-1') if isinstance(region_delimiter, (bytes, bytearray)) else str(region_delimiter),
            "TARGET_REGION": str(region),
            "TARGET_OFFSET": str(offset),
            "TARGET_LEN": str(length),
            "MEM_OPS": "0",
            "DEBUG": "1"
        })

        json_dir = f"{work_dir}/taint/"
        gt_run_times_ms, taint_runs = [], []
        num_runs, last_inter, first_inter_size, stabilized_gt = 0, None, None, False

        while True:
            try:
                cleanup(firmae_dir, work_dir)
            except: pass

            process = subprocess.Popen(["sudo", "-E", "./run.sh", "-r", os.path.dirname(firmware),
                                        firmware, "run", "0.0.0.0"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            qemu_pid = process.pid
            num_runs += 1
            time.sleep(sleep)

            start_ts = time.time()
            cmd = ["sudo", "-E", "/STAFF/aflnet/client", seed_path,
                   open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(timeout)]
            subprocess.run(cmd)
            try:
                send_signal_recursive(qemu_pid, signal.SIGINT)
            except: pass
            try:
                os.waitpid(qemu_pid, 0)
            except: pass
            time.sleep(2)
            end_ts = time.time()
            gt_run_times_ms.append((end_ts - start_ts) * 1000.0)

            taint_data = process_log_file(os.path.join(json_dir, "taint_mem.log"))
            current_run_set = {(entry["inode"], entry["app_tb_pc"]) for entry in taint_data}
            taint_runs.append(current_run_set)

            if last_inter is None:
                last_inter = current_run_set
                first_inter_size = len(last_inter)
                if num_runs >= stab_upper_runs:
                    break
                continue

            current_inter = last_inter & current_run_set
            if current_inter == last_inter and num_runs > 2:
                stabilized_gt = True
                break
            if num_runs >= stab_upper_runs:
                stabilized_gt = False
                last_inter = current_inter
                break
            last_inter = current_inter

        ground_truth_runs_serializable = [[{"inode": i, "pc": p} for (i, p) in sorted(list(run_set))]
                                          for run_set in taint_runs]
        pre_analysis_list = [{"inode": pc[0], "pc": pc[1]} if isinstance(pc, (list, tuple))
                             else {"inode": pc["inode"], "pc": pc["pc"]} for pc in inode_pcs]

        chosen_taint_index = random.randrange(len(taint_runs)) if taint_runs else None
        taint_run_example = [{"inode": i, "pc": p} for (i, p) in sorted(list(taint_runs[chosen_taint_index]))] \
            if chosen_taint_index is not None else []

        ids = sorted(set([i for i, v in enumerate(affected_regions) if v] +
                         [i for i, v in enumerate(region_influences) if v]))
        ids_arg = ",".join(map(str, ids)) if ids else ""
        os.environ["TARGET_REGION"] = str(ids.index(region)) if ids and region in ids else str(region)
        os.environ["MEM_OPS"] = "0"

        try:
            cleanup(firmae_dir, work_dir)
        except: pass
        process = subprocess.Popen(["sudo", "-E", "./run.sh", "-r", os.path.dirname(firmware),
                                    firmware, "run", "0.0.0.0"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        qemu_pid = process.pid
        time.sleep(sleep)

        start_min_ts = time.time()
        cmd_min = ["sudo", "-E", "/STAFF/aflnet/client", seed_path,
                   open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(timeout)]
        if ids_arg:
            cmd_min.append("--ids=" + ids_arg)
        subprocess.run(cmd_min)
        try:
            send_signal_recursive(qemu_pid, signal.SIGINT)
        except: pass
        try:
            os.waitpid(qemu_pid, 0)
        except: pass
        time.sleep(2)
        end_min_ts = time.time()
        minimized_run_ms = (end_min_ts - start_min_ts) * 1000.0

        taint_data = process_log_file(os.path.join(json_dir, "taint_mem.log"))
        minimized_taint_pcs = {(entry["inode"], entry["app_tb_pc"]) for entry in taint_data}
        minimized_run_example = [{"inode": i, "pc": p} for (i, p) in sorted(list(minimized_taint_pcs))]

        with open(os.path.join(experiment_dir, "times_ms.json"), "w") as tf:
            json.dump({"gt_runs_ms": gt_run_times_ms, "minimized_run_ms": minimized_run_ms}, tf, indent=2)
        with open(os.path.join(experiment_dir, "ground_truth.json"), "w") as gf:
            json.dump(ground_truth_runs_serializable, gf, indent=2)
        with open(os.path.join(experiment_dir, "pre_analysis.json"), "w") as pf:
            json.dump(pre_analysis_list, pf, indent=2)
        with open(os.path.join(experiment_dir, "taint.json"), "w") as tf:
            json.dump(taint_run_example, tf, indent=2)
        with open(os.path.join(experiment_dir, "minimized_taint.json"), "w") as mf:
            json.dump(minimized_run_example, mf, indent=2)

        gt_stability_fraction = 1.0 if stabilized_gt else (len(last_inter) / first_inter_size if first_inter_size else 0.0)

        info = {
            "pre_analysis_id": pre_analysis_id,
            "experiment_index": next_run_idx,
            "user_interaction_id": chosen_user_interaction,
            "taint_hint_id": chosen_element_index,
            "target_region": region,
            "target_offset": offset,
            "target_len": length,
            "kept_region_ids": ids,
            "num_gt_runs": len(taint_runs),
            "stabilized_gt": stabilized_gt,
            "gt_stability": round(gt_stability_fraction, 2)
        }

        with open(os.path.join(experiment_dir, "info.json"), "w") as inf:
            json.dump(info, inf, indent=2)

        results = {"experiment_dir": experiment_dir, "info": info}
        with open(results_file, "w") as rf:
            json.dump(results, rf, indent=4)

def aggregate_pre_analysis_metrics(db_dir, metric_name, output_csv="out.csv"):
    results = []
    for firmware in os.listdir(db_dir):
        firmware_path = os.path.join(db_dir, firmware)
        if not os.path.isdir(firmware_path):
            continue

        metric_values = []
        time_deltas = []

        for run_dir in os.listdir(firmware_path):
            if not run_dir.startswith("pre_analysis_"):
                continue
            run_path = os.path.join(firmware_path, run_dir)

            ground_truth_path = os.path.join(run_path, "ground_truth.json")
            pre_path = os.path.join(run_path, "pre_analysis.json")
            taint_path = os.path.join(run_path, "taint.json")
            min_taint_path = os.path.join(run_path, "minimized_taint.json")
            times_path = os.path.join(run_path, "times_ms.json")

            if not (os.path.exists(ground_truth_path) and os.path.exists(pre_path)):
                continue

            if metric_name.lower() == "time":
                if not os.path.exists(times_path):
                    continue
                with open(times_path) as tf:
                    times = json.load(tf)
                gt_times = times.get("gt_runs_ms", [])
                minimized_time = times.get("minimized_run_ms")
                if gt_times and minimized_time:
                    avg_gt = np.mean(gt_times)
                    delta_pct = ((avg_gt - minimized_time) / avg_gt) * 100.0
                    time_deltas.append(delta_pct)
                continue

            with open(ground_truth_path) as gf:
                gt_runs = json.load(gf)
            with open(pre_path) as pf:
                pre_runs = json.load(pf)

            gt_set = {(e["inode"], e["pc"]) for run in gt_runs for e in run}
            pre_set = {(e["inode"], e["pc"]) for e in pre_runs}

            if not gt_set:
                continue

            y_true = [1 if x in gt_set else 0 for x in sorted(gt_set | pre_set)]
            y_pred = [1 if x in pre_set else 0 for x in sorted(gt_set | pre_set)]

            if metric_name.lower() == "f1":
                value = f1_score(y_true, y_pred, zero_division=0)
            elif metric_name.lower() == "precision":
                value = precision_score(y_true, y_pred, zero_division=0)
            elif metric_name.lower() == "recall":
                value = recall_score(y_true, y_pred, zero_division=0)
            elif metric_name.lower() == "accuracy":
                value = accuracy_score(y_true, y_pred)
            else:
                raise ValueError(f"Unsupported metric: {metric_name}")

            metric_values.append(value)

        if metric_name.lower() == "time":
            avg_value = np.mean(time_deltas) if time_deltas else None
        else:
            avg_value = np.mean(metric_values) if metric_values else None

        if avg_value is not None:
            results.append({"firmware": firmware, metric_name: avg_value})

    df = pd.DataFrame(results)
    df.to_csv(output_csv, index=False)
    return df

def print_usage():
    print("Usage:")
    print("  sudo python3 taint_analysis.py -d <db_dir> -m <metric>")
    print("")
    print("Arguments:")
    print("  -d <db_dir>    Path to the database directory containing pre_analysis experiments")
    print("  -m <metric>    Metric to compute: accuracy, f1, precision, recall, time")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must run with 'root' privilege")
        sys.exit(1)

    db_dir = None
    metric = None

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "-d":
            i += 1
            if i < len(sys.argv):
                db_dir = sys.argv[i]
            else:
                print("[-] Missing value for -d argument.")
                print_usage()
                sys.exit(1)
            i += 1
        elif arg == "-m":
            i += 1
            if i < len(sys.argv):
                metric = sys.argv[i].lower()
            else:
                print("[-] Missing value for -m argument.")
                print_usage()
                sys.exit(1)
            i += 1
        elif arg == "-h":
            print_usage()
            sys.exit(0)
        else:
            print(f"[-] Unknown argument: {arg}")
            print_usage()
            sys.exit(1)

    if not db_dir or not metric:
        print("[-] Both -d and -m arguments are mandatory.")
        print_usage()
        sys.exit(1)

    if not os.path.isdir(db_dir):
        print(f"[-] db_dir '{db_dir}' does not exist or is not a directory")
        sys.exit(1)

    print(f"[+] Aggregating metric '{metric}' over database '{db_dir}'")
    aggregate_pre_analysis_metrics(db_dir, metric)
