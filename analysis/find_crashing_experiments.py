#!/usr/bin/env python3
import os
import glob
import configparser

BASE_DIRS = [
    "experiments_done/baseline",
    "experiments_done/staff_state_aware_0_taint_edge"
]

def has_crashes(exp_dir):
    """
    Returns True if crash_traces or crashes directory exists and is non-empty
    """
    crash_dirs = ["crash_traces", "crashes"]
    for d in crash_dirs:
        full_path = os.path.join(exp_dir, "outputs", d)
        if os.path.isdir(full_path) and os.listdir(full_path):
            return True
    return False

def read_config_info(exp_dir):
    config_path = os.path.join(exp_dir, "outputs", "config.ini")
    firmware = "(unknown_firmware)"
    tool = "(unknown_tool)"
    if os.path.isfile(config_path):
        config = configparser.ConfigParser()
        config.read(config_path)
        try:
            firmware_path = config.get("GENERAL", "firmware")
            firmware = os.path.basename(firmware_path)
        except Exception:
            pass
        try:
            tool = config.get("GENERAL", "mode")
        except Exception:
            pass
    return firmware, tool

def find_crashing_experiments():
    crashing = []
    for base in BASE_DIRS:
        for exp_dir in sorted(glob.glob(os.path.join(base, "exp_*"))):
            if has_crashes(exp_dir):
                firmware, tool = read_config_info(exp_dir)
                crashing.append((exp_dir, firmware, tool))
    return crashing

if __name__ == "__main__":
    crashing_experiments = find_crashing_experiments()
    for exp_dir, firmware, tool in crashing_experiments:
        print(f"{exp_dir} {firmware} {tool}")
