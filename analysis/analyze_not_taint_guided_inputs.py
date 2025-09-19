#!/usr/bin/env python3
import os
import re
import argparse
from collections import defaultdict
from typing import Dict, Set, Optional, List, Tuple
import configparser


def parse_filename_info(filename: str) -> Optional[Dict]:
    taint_match = re.search(r'id&(\d+)', filename)
    if not taint_match:
        return None
    taint_flag = int(taint_match.group(1))
    
    id_match = re.search(r'id&\d+(?:\[[^\]]+\])?:(\d+)', filename)
    if not id_match:
        return None
    input_id = id_match.group(1)
    
    src_match = re.search(r'src:(\d+)', filename)
    src_id = src_match.group(1) if src_match else None
    
    return {
        'input_id': input_id,
        'taint_flag': taint_flag,
        'src_id': src_id,
        'filename': filename
    }


def build_genealogy_tree(crash_files: List[str]) -> Dict[str, Dict]:
    genealogy = {}
    
    for filename in crash_files:
        info = parse_filename_info(filename)
        if info is None:
            continue
            
        input_id = info['input_id']
        genealogy[input_id] = info
    
    return genealogy


def trace_genealogy_chain(input_id: str, genealogy: Dict[str, Dict], 
                         visited: Set[str] = None) -> List[Tuple[str, int]]:
    if visited is None:
        visited = set()
    
    chain = []
    current_id = input_id
    
    while current_id is not None:
        if current_id in visited:
            break
        
        visited.add(current_id)
        
        if current_id not in genealogy:
            break
        
        info = genealogy[current_id]
        chain.append((current_id, info['taint_flag']))
        
        current_id = info['src_id']
    
    return chain


def analyze_experiments_with_queue(experiments_dir: str):
    if not os.path.isdir(experiments_dir):
        print(f"[ERROR] Experiments directory not found: {experiments_dir}")
        return
    
    for exp_dir in sorted(os.listdir(experiments_dir)):
        if not exp_dir.startswith("exp_"):
            continue
            
        exp_path = os.path.join(experiments_dir, exp_dir)
        if not os.path.isdir(exp_path):
            continue
        
        config_path = os.path.join(exp_path, "outputs", "config.ini")
        if not os.path.isfile(config_path):
            continue
            
        config = configparser.ConfigParser()
        try:
            config.read(config_path)
            method = config.get("GENERAL", "mode")
            firmware_path = config.get("GENERAL", "firmware")
            firmware = os.path.basename(firmware_path)
        except Exception as e:
            print(f"[WARN] Could not read config for {exp_dir}: {e}")
            continue
        
        if method != "staff_state_aware":
            continue
        
        print(f"\n=== {exp_dir} - {firmware} ({method}) ===")
        
        queue_dir = os.path.join(exp_path, "outputs", "queue")
        if not os.path.isdir(queue_dir):
            print(f"[WARN] No queue directory found: {queue_dir}")
            continue
        
        queue_files = []
        for entry in sorted(os.listdir(queue_dir)):
            queue_path = os.path.join(queue_dir, entry)
            if os.path.isfile(queue_path):
                queue_files.append(entry)
        
        if not queue_files:
            print(f"[WARN] No queue files found in {queue_dir}")
            continue
        
        queue_genealogy = build_genealogy_tree(queue_files)
        print(f"[INFO] Built genealogy with {len(queue_genealogy)} inputs from queue")
        
        crash_files = []
        exp_crashes_dir = os.path.join(exp_path, "outputs", "crashes")
        if os.path.isdir(exp_crashes_dir):
            for entry in sorted(os.listdir(exp_crashes_dir)):
                if os.path.isfile(os.path.join(exp_crashes_dir, entry)):
                    crash_files.append(entry)
        
        if not crash_files:
            print(f"[WARN] No crash files found for {exp_dir}")
            continue
        
        print(f"[INFO] Found {len(crash_files)} crash files")
        
        zero_crashes_found = False
        filtered_crashes_found = False
        for crash_file in sorted(crash_files):
            crash_info = parse_filename_info(crash_file)
            if not crash_info:
                continue
            
            if crash_info['taint_flag'] != 0:
                continue
            
            zero_crashes_found = True
            input_id = crash_info['input_id']
            
            crash_chain = [(input_id, crash_info['taint_flag'])]
            
            src_id = crash_info['src_id']
            if src_id:
                queue_chain = trace_genealogy_chain(src_id, queue_genealogy)
                crash_chain.extend(queue_chain)
            
            has_taint_one = any(cflag == 1 for _, cflag in crash_chain[1:])
            
            should_print = True
            if hasattr(analyze_experiments_with_queue, 'filter_no_taint') and analyze_experiments_with_queue.filter_no_taint:
                should_print = not has_taint_one
            elif hasattr(analyze_experiments_with_queue, 'filter_has_taint') and analyze_experiments_with_queue.filter_has_taint:
                should_print = has_taint_one
            
            if not should_print:
                continue
                
            filtered_crashes_found = True
            
            if len(crash_chain) == 1:
                print(f"{input_id}&{crash_info['taint_flag']} --> [no source genealogy found]")
                continue
            
            chain_str = " --> ".join([f"{cid}&{cflag}" for cid, cflag in crash_chain])
            print(f"{chain_str}")
        
        if not zero_crashes_found:
            print("[INFO] No &0 crashes found in this experiment")
        elif not filtered_crashes_found:
            filter_type = ""
            if hasattr(analyze_experiments_with_queue, 'filter_no_taint') and analyze_experiments_with_queue.filter_no_taint:
                filter_type = " (with no &1 in history)"
            elif hasattr(analyze_experiments_with_queue, 'filter_has_taint') and analyze_experiments_with_queue.filter_has_taint:
                filter_type = " (with &1 in history)"
            print(f"[INFO] No &0 crashes matching filter criteria found{filter_type}")


def main():
    parser = argparse.ArgumentParser(description="Trace genealogy of &0 valued crashes")
    parser.add_argument("experiments_dir", nargs='?',
                       help="Path to experiments directory containing exp_* subdirectories")
    parser.add_argument("--filter-no-taint", action="store_true",
                       help="Show only &0 crashes with NO &1 inputs in their history")
    parser.add_argument("--filter-has-taint", action="store_true",
                       help="Show only &0 crashes with at least one &1 input in their history")
    
    args = parser.parse_args()
    
    if args.filter_no_taint and args.filter_has_taint:
        print("[ERROR] Cannot use both --filter-no-taint and --filter-has-taint at the same time")
        return
    
    if args.filter_no_taint:
        analyze_experiments_with_queue.filter_no_taint = True
        print("[FILTER] Showing only &0 crashes with NO &1 inputs in their history\n")
    elif args.filter_has_taint:
        analyze_experiments_with_queue.filter_has_taint = True
        print("[FILTER] Showing only &0 crashes with at least one &1 input in their history\n")
    
    if args.experiments_dir:
        print(f"Analyzing experiments with queue genealogy:")
        print(f"  Experiments dir: {args.experiments_dir}")
        print("Note: This will show complete genealogy by reading queue files\n")
        analyze_experiments_with_queue(args.experiments_dir)


if __name__ == "__main__":
    main()