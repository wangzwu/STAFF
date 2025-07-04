#!/usr/bin/env python3
import os
import glob
import configparser
import sys

BASE_DIRS = ["experiments_done/baseline", "experiments_done/staff_state_aware_0_taint_edge"]
TOOLS = ["aflnet_base", "aflnet_state_aware", "staff_base", "staff_state_aware", "triforce"]

def usage():
    print(f"Usage: {sys.argv[0]} <tool> <firmware>")
    print(f"  <tool>: one of {', '.join(TOOLS)}")
    print(f"  <firmware>: firmware identifier as 'brand/firmware_name'")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()

    tool = sys.argv[1]
    firmware = sys.argv[2]

    if tool not in TOOLS:
        print(f"Error: Unknown tool '{tool}'. Expected one of {', '.join(TOOLS)}")
        sys.exit(1)

    matching_dirs = []

    all_exp_dirs = []
    for base in BASE_DIRS:
        all_exp_dirs.extend(glob.glob(os.path.join(base, "exp_*")))

    for exp_dir in sorted(all_exp_dirs):
        cfg_path = os.path.join(exp_dir, "outputs", "config.ini")
        stats_path = os.path.join(exp_dir, "outputs", "fuzzer_stats")

        if not os.path.isfile(cfg_path) or not os.path.isfile(stats_path):
            continue

        cfg = configparser.ConfigParser()
        cfg.read(cfg_path)

        if "GENERAL" not in cfg or "firmware" not in cfg["GENERAL"] or "mode" not in cfg["GENERAL"]:
            continue

        exp_firmware = cfg["GENERAL"]["firmware"]
        exp_mode = cfg["GENERAL"]["mode"]

        if exp_mode != tool or exp_firmware != firmware:
            continue

        matching_dirs.append(exp_dir)

    for d in matching_dirs:
        print(d)

if __name__ == "__main__":
    main()
