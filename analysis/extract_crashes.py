#!/usr/bin/env python3
import os
import glob
import configparser
import shutil

BASE_DIRS = [
    "experiments"
]

DEST_DIR = "extracted_crash_outputs"

def has_crashes(exp_dir):
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

def copy_dir(src_dir, dest_dir):
    if not os.path.isdir(src_dir):
        return
    os.makedirs(dest_dir, exist_ok=True)
    for item in os.listdir(src_dir):
        s = os.path.join(src_dir, item)
        d = os.path.join(dest_dir, item)
        if os.path.isfile(s):
            shutil.copy2(s, d)
        elif os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True)

def copy_crash_and_crash_traces(exp_dir, firmware, tool):
    base_dest = os.path.join(DEST_DIR, firmware, tool, os.path.basename(exp_dir))
    copy_dir(os.path.join(exp_dir, "outputs", "crash_traces"), os.path.join(base_dest, "crash_traces"))
    copy_dir(os.path.join(exp_dir, "outputs", "crashes"), os.path.join(base_dest, "crashes"))

def find_and_copy_crashes():
    for base in BASE_DIRS:
        for exp_dir in sorted(glob.glob(os.path.join(base, "exp_*"))):
            if has_crashes(exp_dir):
                firmware, tool = read_config_info(exp_dir)
                copy_crash_and_crash_traces(exp_dir, firmware, tool)

if __name__ == "__main__":
    find_and_copy_crashes()
