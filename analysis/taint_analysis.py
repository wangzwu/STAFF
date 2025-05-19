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

def invert_fs_relations_data(fs_relations):
    inverted_relations = {}
    for outer_key, inner_dict in fs_relations.items():
        for inner_key, file_list in inner_dict.items():
            if inner_key not in inverted_relations:
                inverted_relations[inner_key] = {}
            inverted_relations[inner_key][outer_key] = file_list
    return inverted_relations

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
    def __init__(self):
        self.root = TrieNode()

    def insert(self, byte_sequence, seq_index):
        for start_pos in range(len(byte_sequence)):
            current_node = self.root
            # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in byte_sequence)

            for offset, byte in enumerate(byte_sequence[start_pos:]):
                if byte not in current_node.children:
                    current_node.children[byte] = TrieNode()
                current_node = current_node.children[byte]
                current_node.positions.append((seq_index, start_pos))

    def find_subsequence(self, subsequence):
        current_node = self.root
        # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in subsequence)

        for byte in subsequence:
            if byte in current_node.children:
                current_node = current_node.children[byte]
            else:
                return None
        return list(current_node.positions)

def clean_json_structure(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    file_occurrences = defaultdict(lambda: defaultdict(set))
    for outer_key, inner_dict in data.items():
        for inner_key, file_list in inner_dict.items():
            for file in file_list:
                if file:
                    file_occurrences[file][outer_key].add(inner_key)

    files_to_keep = {
        file
        for file, outer_keys in file_occurrences.items()
        if len(set(inner_key for inner_keys in outer_keys.values() for inner_key in inner_keys)) == 1
    }

    cleaned_data = {}
    for outer_key, inner_dict in data.items():
        cleaned_inner_dict = {}
        for inner_key, file_list in inner_dict.items():
            filtered_files = [file for file in file_list if file in files_to_keep]
            if filtered_files:
                cleaned_inner_dict[inner_key] = filtered_files
        if cleaned_inner_dict:
            cleaned_data[outer_key] = cleaned_inner_dict

    return cleaned_data

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

def process_json(sources_hex, taint_data, inverted_fs_relations_data, subregion_divisor, min_subregion_len):
    global global_regions_dependance
    global global_regions_affections


    output_dir = "taint_analysis_stats"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    d = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    d3 = {}

    sources = []
    # sources_hex = []
    processing_taint_source = False
    discarded_regions = set()
    last_store_event = None
    current_region_store = [0, []]
    last_load_event = None
    current_region_load = [0, []]
    multi_trie = MultiSequenceTrie()
    multiples = set()
    multiples2 = set()

    # output_target = sys.stdout if output_mode == "print" else open(output_file_path, "w")

    previous_sink_id = -1
    for event in tqdm(taint_data, desc="Processing sinks"):
        # if event["event"] != 0 and processing_taint_source:
        #     processing_taint_source = False
        #     multi_trie.insert(sources_hex[-1], len(sources_hex)-1)

        sink_id = -1
        if event["event"] == 1 or event["event"] == 0:
            sink_id = event["sink_id"]

            if sink_id > previous_sink_id:
                previous_sink_id = sink_id
                if sink_id >= len(sources_hex):
                    print("Error: sink_id [%d] >= len(sources_hex) [%d]"%(sink_id, len(sources_hex)))
                    return None
                sources.append(([], [(byte, [], [], []) for byte in sources_hex[sink_id]]))
                multi_trie.insert(sources_hex[sink_id], sink_id)
                global_regions_dependance[sink_id] = []
                global_regions_affections[sink_id] = {}
            elif sink_id == previous_sink_id:
                pass
            else:
                assert(False)   # or continue

        if event["event"] == 1 and (event["op_name"] in {0, 1}):
            cov_xxhash = event["cov_xxhash"]
            app_tb_pc = event["app_tb_pc"]
            gpa = event["gpa"]
            op_name = event["op_name"]
            value_hex = event["value"]
            inode = event["inode"]

            if (op_name == 1):
                if (last_store_event != None):
                    if (last_store_event["gpa"] == gpa-1):
                        current_region_store[1].append((gpa, value_hex, (inode, app_tb_pc), cov_xxhash))
                    else:
                        current_value_hex = bytes([value_hex for _, value_hex, _, _ in current_region_store[1]])
                        # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

                        matched_any = False
                        # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

                        for sub_len in range(len(current_value_hex), 0, -1):
                            if (sub_len < len(current_value_hex)/subregion_divisor and sub_len >= min_subregion_len):
                                break

                            for start_curr in range(len(current_value_hex) - sub_len + 1):
                                found_positions = multi_trie.find_subsequence(current_value_hex[start_curr:start_curr + sub_len])
                                # sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                if found_positions:
                                    if len(found_positions) == 1:
                                        for i, start_exist in found_positions:
                                            if current_region_store[0] >= i and sources_hex[i][start_exist:start_exist + sub_len ] == current_value_hex[start_curr:start_curr + sub_len]:
                                                for j in range(sub_len):
                                                    if i not in global_regions_dependance[current_region_store[0]]:
                                                        global_regions_dependance[current_region_store[0]].append(i)
                                                    if current_region_store[0] not in global_regions_affections[i]:
                                                        sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                                        global_regions_affections[i][current_region_store[0]] = [sub_curr_str]
                                                    else:
                                                        sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                                        if sub_curr_str not in global_regions_affections[i][current_region_store[0]]:
                                                            global_regions_affections[i][current_region_store[0]].append(sub_curr_str)
                                                    if current_region_store[0] not in sources[i][1][j + start_exist][1]:
                                                        sources[i][1][j + start_exist][1].append(current_region_store[0])
                                                    if current_region_store[1][j][2] not in sources[i][1][j + start_exist][2]:
                                                        sources[i][1][j + start_exist][2].append(current_region_store[1][j][2])
                                                    if current_region_store[1][j][3] not in sources[i][1][j + start_exist][3]:
                                                        sources[i][1][j + start_exist][3].append(current_region_store[1][j][3])

                                    matched_any = True
                                    
                                    if matched_any:
                                        break

                            if matched_any:
                                break

                        current_region_store[1] = [(gpa, value_hex, (inode, app_tb_pc), cov_xxhash)]                    
                else:
                    current_region_store[1] = [(gpa, value_hex, (inode, app_tb_pc), cov_xxhash)]
                current_region_store[0] = sink_id
                last_store_event = event
            else:
                if (last_load_event != None):
                    if (last_load_event["gpa"] == gpa-1):
                        current_region_load[1].append((gpa, value_hex, (inode, app_tb_pc), cov_xxhash))
                    else:
                        current_value_hex = bytes([value_hex for _, value_hex, _, _ in current_region_load[1]])
                        # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

                        matched_any = False
                        # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

                        for sub_len in range(len(current_value_hex), 0, -1):
                            if (sub_len < len(current_value_hex)/subregion_divisor and sub_len >= min_subregion_len):
                                break

                            for start_curr in range(len(current_value_hex) - sub_len + 1):
                                found_positions = multi_trie.find_subsequence(current_value_hex[start_curr:start_curr + sub_len])
                                # sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                if found_positions:
                                    if len(found_positions) == 1:           
                                        for i, start_exist in found_positions:
                                            if current_region_load[0] >= i and sources_hex[i][start_exist:start_exist + sub_len ] == current_value_hex[start_curr:start_curr + sub_len]:
                                                for j in range(sub_len):
                                                    if i not in global_regions_dependance[current_region_load[0]]:
                                                        global_regions_dependance[current_region_load[0]].append(i)
                                                    if current_region_load[0] not in global_regions_affections[i]:
                                                        sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                                        global_regions_affections[i][current_region_load[0]] = [sub_curr_str]
                                                    else:
                                                        sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                                        if sub_curr_str not in global_regions_affections[i][current_region_load[0]]:
                                                            global_regions_affections[i][current_region_load[0]].append(sub_curr_str)
                                                    if current_region_load[0] not in sources[i][1][j + start_exist][1]:
                                                        sources[i][1][j + start_exist][1].append(current_region_load[0])
                                                    if current_region_load[1][j][2] not in sources[i][1][j + start_exist][2]:
                                                        sources[i][1][j + start_exist][2].append(current_region_load[1][j][2])
                                                    if current_region_load[1][j][3] not in sources[i][1][j + start_exist][3]:
                                                        sources[i][1][j + start_exist][3].append(current_region_load[1][j][3])

                                    matched_any = True

                                    if matched_any:
                                        break

                            if matched_any:
                                break

                        current_region_load[1] = [(gpa, value_hex, (inode, app_tb_pc), cov_xxhash)]
                else:
                    current_region_load[1] = [(gpa, value_hex, (inode, app_tb_pc), cov_xxhash)]
                current_region_load[0] = sink_id
                last_load_event = event

    if (len(sources) != len(sources_hex)):
        print("Error: len(sources) [%d] != len(sources_hex) [%d]"%(len(sources), len(sources_hex)))
        return None

    current_value_hex = bytes([value_hex for _, value_hex, _, _ in current_region_store[1]])
    # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

    matched_any = False
    # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

    for sub_len in range(len(current_value_hex), 0, -1):
        if (sub_len < len(current_value_hex)/subregion_divisor and sub_len >= min_subregion_len):
            break

        for start_curr in range(len(current_value_hex) - sub_len + 1):
            found_positions = multi_trie.find_subsequence(current_value_hex[start_curr:start_curr + sub_len])
            # sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
            if found_positions:
                if len(found_positions) == 1:
                    for i, start_exist in found_positions:
                        if current_region_store[0] >= i and sources_hex[i][start_exist:start_exist + sub_len ] == current_value_hex[start_curr:start_curr + sub_len]:
                            for j in range(sub_len):
                                if i not in global_regions_dependance[current_region_store[0]]:
                                    global_regions_dependance[current_region_store[0]].append(i)
                                if current_region_store[0] not in global_regions_affections[i]:
                                    sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                    global_regions_affections[i][current_region_store[0]] = [sub_curr_str]
                                else:
                                    sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                    if sub_curr_str not in global_regions_affections[i][current_region_store[0]]:
                                        global_regions_affections[i][current_region_store[0]].append(sub_curr_str)
                                if current_region_store[0] not in sources[i][1][j + start_exist][1]:
                                    sources[i][1][j + start_exist][1].append(current_region_store[0])
                                if current_region_store[1][j][2] not in sources[i][1][j + start_exist][2]:
                                    sources[i][1][j + start_exist][2].append(current_region_store[1][j][2])
                                if current_region_store[1][j][3] not in sources[i][1][j + start_exist][3]:
                                    sources[i][1][j + start_exist][3].append(current_region_store[1][j][3])

                matched_any = True

                if matched_any:
                    break

        if matched_any:
            break

    current_value_hex = bytes([value_hex for _, value_hex, _, _ in current_region_load[1]])
    # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

    matched_any = False
    # current_region_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex)

    for sub_len in range(len(current_value_hex), 0, -1):
        if (sub_len < len(current_value_hex)/subregion_divisor and sub_len >= min_subregion_len):
            break

        for start_curr in range(len(current_value_hex) - sub_len + 1):
            found_positions = multi_trie.find_subsequence(current_value_hex[start_curr:start_curr + sub_len])
            # sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
            if found_positions:
                if len(found_positions) == 1:
                    for i, start_exist in found_positions:
                        if current_region_load[0] >= i and sources_hex[i][start_exist:start_exist + sub_len ] == current_value_hex[start_curr:start_curr + sub_len]:
                            for j in range(sub_len):
                                if i not in global_regions_dependance[current_region_load[0]]:
                                    global_regions_dependance[current_region_load[0]].append(i)
                                if current_region_load[0] not in global_regions_affections[i]:
                                    sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                    global_regions_affections[i][current_region_load[0]] = [sub_curr_str]
                                else:
                                    sub_curr_str = "".join(chr(val) if 32 < val < 127 else "." for val in current_value_hex[start_curr:start_curr + sub_len])
                                    if sub_curr_str not in global_regions_affections[i][current_region_load[0]]:
                                        global_regions_affections[i][current_region_load[0]].append(sub_curr_str)
                                if current_region_load[0] not in sources[i][1][j + start_exist][1]:
                                    sources[i][1][j + start_exist][1].append(current_region_load[0])
                                if current_region_load[1][j][2] not in sources[i][1][j + start_exist][2]:
                                    sources[i][1][j + start_exist][2].append(current_region_load[1][j][2])
                                if current_region_load[1][j][3] not in sources[i][1][j + start_exist][3]:
                                    sources[i][1][j + start_exist][3].append(current_region_load[1][j][3])

                    matched_any = True

                    if matched_any:
                        break

            if matched_any:
                break    

    # collision_analysis(taint_data, "cov_orig", "ORIG")
    # collision_analysis(taint_data, "cov_xxhash", "xxHash")
    # collision_analysis(taint_data, "cov_sha1", "SHA1")

    return sources

def update_global(sources):
    global global_sources
    delta = 0.0
    count = 0

    if global_sources:
        for i, (fs_region_ids, region_list) in enumerate(sources):
            global_fs_region_ids, global_region_list = global_sources[i]

            new_fs_regions = len(set(fs_region_ids) - set(global_fs_region_ids))
            merged_fs_regions = list(set(global_fs_region_ids) & set(fs_region_ids))
            delta += new_fs_regions / max(len(merged_fs_regions), 1)
            global_fs_region_ids = merged_fs_regions
            count += 1

            for j, (hex_value, region_ids, app_tb_pcs, coverages) in enumerate(region_list):
                global_hex, global_ids, global_pcs, global_covs = global_region_list[j]

                new_ids = len(set(region_ids) - set(global_ids))
                merged_ids = list(set(global_ids) | set(region_ids))
                delta += new_ids / max(len(merged_ids), 1)

                new_pcs = len(set(app_tb_pcs) - set(global_pcs))
                merged_pcs = list(set(global_pcs) | set(app_tb_pcs))
                delta += new_pcs / max(len(merged_pcs), 1)

                new_covs = len(set(coverages) - set(global_covs))
                merged_covs = list(set(global_covs) | set(coverages))
                delta += new_covs / max(len(merged_covs), 1)

                global_region_list[j] = (hex_value, merged_ids, merged_pcs, merged_covs)
                count += 3

            global_sources[i] = (global_fs_region_ids, global_region_list)

        delta /= max(count, 1)
    else:
        global_sources = sources
        delta = 1.0

    return delta

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
        "delta_threshold": str(delta_threshold)
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

def taint(work_dir, mode, firmware, sleep, timeout, subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter):
    global global_subregions_app_tb_pcs
    global global_subregions_covs
    global global_sources
    global global_regions_dependance
    global qemu_pid

    print("\n[\033[32m+\033[0m] TAINT ANALYSIS of the firmware '%s' (timeout: %d)\n"%(os.path.basename(firmware), timeout))

    os.environ["EXEC_MODE"] = "RUN"
    os.environ["TAINT"] = "1"
    os.environ["FD_DEPENDENCIES_TRACK"] = "1"
    os.environ["INCLUDE_LIBRARIES"] = str(include_libraries)
    os.environ["REGION_DELIMITER"] = region_delimiter.decode('latin-1')
    os.environ["DEBUG"] = "1"
    os.environ["DEBUG_DIR"] = os.path.join(work_dir, "debug", "interaction")

    subprocess.run(["sudo", "-E", "/STAFF/FirmAE/flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
    for proto in sub_dirs:
        print("\n[\033[33m*\033[0m] Protocol: {}".format(proto))
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            required_files = ["config.ini", "taint_plot", "analysis_log", "app_tb_pc_subsequences.json", "cov_subsequences.json", "global_analysis_results.json", "region_dependancies.json", "region_affections.json", "fs_relations.json", pcap_file+".seed", pcap_file+".seed_metadata.json"]

            global_subregions_app_tb_pcs = []
            global_subregions_covs = []
            global_sources = []
            global_regions_dependance = {}

            pcap_path = os.path.join(pcap_dir, proto, pcap_file)

            tmp_required_files = required_files + [pcap_file+".seed"]
            missing_files = [file for file in tmp_required_files if not os.path.exists(os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, file))]
            
            force_run = False
            if missing_files:
                print("The following files are missing under", os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file), ":", ', '.join(missing_files))
                if "config.ini" in missing_files:
                    force_run = True
                else:
                    res = compare_config(os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "config.ini"), subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter)
                    if res == 2:
                        print("config.ini file does not match 'include_libraries' or 'region_delimiter'!")
                        force_run = True
                    else:
                        print("config.ini file does not match provided pre-analysis params (not 'include_libraries' or 'region_delimiter')!")                
            else:
                print(f"All required files exist under", os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file))

                res = compare_config(os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "config.ini"), subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter)
                if res == 1:
                    print("config.ini file does not match provided pre-analysis params (not 'include_libraries' or 'region_delimiter')!")
                elif res == 2:
                    print("config.ini file does not match 'include_libraries' or 'region_delimiter'!")
                    force_run = True
                # else:
                #     continue

            print("\n[\033[34m*\033[0m] PCAP #{}".format(pcap_file))
            skip_run = False

            if not force_run:
                taint_json_dir = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "taint_json")
                os.makedirs(taint_json_dir, exist_ok=True)
                set_permissions_recursive(taint_json_dir)

                fs_json_dir = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "fs_sink_relations_json")
                os.makedirs(fs_json_dir, exist_ok=True)
                set_permissions_recursive(fs_json_dir)

                seed_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "%s.seed"%(pcap_file))
                sources_hex = convert_pcap_into_single_seed_file(pcap_path, open(os.path.join(work_dir, "ip")).read().strip(), seed_path, region_delimiter)

                ensure_file_coherence(fs_json_dir, taint_json_dir)

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
                        
                        fs_relations_data = clean_json_structure(fs_json_path)
                        taint_data = process_log_file(json_path)
                        
                        sources = process_json(sources_hex, taint_data, invert_fs_relations_data(fs_relations_data), subregion_divisor, min_subregion_len)
                        if sources:
                            delta = update_global(sources)
                            analysis_results = calculate_analysis_results()

                            if check_if_delta_is_little_enough_to_stop(delta, delta_threshold):
                                skip_run = True
                                break
                        else:
                            print("Error process_json() (2)")
                            exit(1)
            else:
                taint_json_dir = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "taint_json")
                if os.path.exists(taint_json_dir):
                    shutil.rmtree(taint_json_dir)
                os.makedirs(taint_json_dir, exist_ok=True)
                set_permissions_recursive(taint_json_dir)

                fs_json_dir = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "fs_sink_relations_json")
                if os.path.exists(fs_json_dir):
                    shutil.rmtree(fs_json_dir)
                os.makedirs(fs_json_dir, exist_ok=True)
                set_permissions_recursive(fs_json_dir)

                seed_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "%s.seed"%(pcap_file))
                sources_hex = convert_pcap_into_single_seed_file(pcap_path, open(os.path.join(work_dir, "ip")).read().strip(), seed_path, region_delimiter)               

            if not skip_run:
                while(1):
                    subprocess.run(["sudo", "-E", "/STAFF/FirmAE/flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    process = subprocess.Popen(
                        ["sudo", "-E", "./run.sh", "-r", os.path.dirname(firmware), firmware, mode, "0.0.0.0"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    qemu_pid = process.pid
                    print("Booting firmware, wait %d seconds..."%(sleep))
                    
                    time.sleep(sleep)

                    json_dir = "%s/taint/"%(work_dir)

                    while(1):
                        port = None
                        try:
                            port = socket.getservbyname(proto)
                            print(f"The port for {proto.upper()} is {port}.")
                        except OSError:
                            print(f"Protocol {proto.upper()} not found.")
                        command = ["sudo", "-E", "/STAFF/aflnet/client", seed_path, os.path.join("/STAFF/FirmAE", work_dir, "qemu.final.serial.log"), open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(timeout)]
                        
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
                    
                    taint_json_dir = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "taint_json")
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

                    fs_json_dir = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "fs_sink_relations_json")
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

                    fs_relations_data = clean_json_structure(fs_target_file)
                    taint_data = process_log_file(taint_target_file)

                    sources = process_json(sources_hex, taint_data, invert_fs_relations_data(fs_relations_data), subregion_divisor, min_subregion_len)
                    if sources:
                        delta = update_global(sources)
                        analysis_results = calculate_analysis_results()

                        if check_if_delta_is_little_enough_to_stop(delta, delta_threshold):
                            break
                    else:
                        print("Error process_json() (1)")
                        exit(1)

            plot_dir_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "taint_plot")
            os.makedirs(plot_dir_path, exist_ok=True)
            plot_analysis_results(analysis_results, sources_hex, output_dir=plot_dir_path)
            analysis_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "analysis_log")
            print_global_results(analysis_results, sources_hex, output_mode="file", output_file_path=analysis_file_path)
            json_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "app_tb_pc_subsequences.json")
            with open(json_file_path, "w") as f:
                json.dump(global_subregions_app_tb_pcs, f, indent=4)
            json_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "cov_subsequences.json")
            with open(json_file_path, "w") as f:
                json.dump(global_subregions_covs, f, indent=4)
            json_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "global_analysis_results.json")
            with open(json_file_path, "w") as f:
                json.dump(analysis_results, f, indent=4)
            json_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, pcap_file+".seed_metadata.json")
            with open(json_file_path, "w") as f:
                json.dump(global_sources, f, indent=4)
            json_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "region_dependancies.json")
            with open(json_file_path, "w") as f:
                json.dump(global_regions_dependance, f, indent=4)
            json_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "region_affections.json")
            with open(json_file_path, "w") as f:
                json.dump(global_regions_affections, f, indent=4)
            json_file_path = os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "fs_relations.json")
            with open(json_file_path, "w") as f:
                json.dump(global_fs_relations, f, indent=4)
            set_permissions_recursive(taint_json_dir)
            create_config(os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "config.ini"), subregion_divisor, min_subregion_len, delta_threshold, include_libraries, region_delimiter)
            set_permissions_recursive(os.path.join("/STAFF/taint_analysis", firmware, proto, pcap_file, "config.ini"))

def start(firmware, timeout):
    subregion_divisor = 10
    min_subregion_len = 3
    delta_threshold = 0.15

    os.environ["NO_PSQL"] = "1"

    os.chdir(os.path.join("FirmAE"))

    if firmware != "all":
        iid = check_firmware(firmware)
    else:
        try:
            for entry in search_recursive("../firmwares"):
                print("Checking %s"%entry)
                check_firmware(entry)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            exit(0)

    work_dir = os.path.join("scratch", mode, iid)

    if os.path.exists(os.path.join(work_dir, "debug")):
        shutil.rmtree(os.path.join(work_dir, "debug"))

    if "true" in open(os.path.join(work_dir, "web_check")).read():
        with open("%s/time_web"%work_dir, 'r') as file:
            sleep = file.read().strip()
        taint(work_dir, "run", os.path.basename(firmware), sleep, timeout, subregion_divisor, min_subregion_len, delta_threshold)

    elif not subprocess.run(["sudo", "-E", "egrep", "-sqi", "false", "ping"]).returncode:
        print("WEB is FALSE and PING IS TRUE")
        return
    else:
        print("WEB and PING ARE FALSE")
        return


if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    signal.signal(signal.SIGINT, sigint_handler)

    if len(sys.argv) == 1 or sys.argv[1] == "-h":
        print_usage()
        sys.exit(1)

    if os.geteuid() != 0:
        print("[-] This script must run with 'root' privilege")
        sys.exit(1)

    mode = ""
    analysis_type = ""
    analysis_args = []
    firmware = ""

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "-i":
            i += 1
            firmware = sys.argv[i]
            i += 1
        elif arg == "-t":
            i += 1
            timeout = sys.argv[i]
            i += 1
        else:
            i += 1

    if not firmware:
        print("The -i argument is mandatory.")
        print_usage()
        sys.exit(1)

    brand = auto_find_brand(firmware)
    iid = 0

    if firmware != "all":
        first_character = firmware[0]
        if not first_character == "/":
            firmware = "../{}".format(firmware)

    start(firmware, timeout)
