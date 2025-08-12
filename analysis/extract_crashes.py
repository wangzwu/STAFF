#!/usr/bin/env python3
import os
import glob
import configparser
import shutil
import re

def rename_crash_files(root_dir):
    for firmware_name in os.listdir(root_dir):
        firmware_path = os.path.join(root_dir, firmware_name)
        if not os.path.isdir(firmware_path):
            continue

        for mode_name in os.listdir(firmware_path):
            mode_path = os.path.join(firmware_path, mode_name)
            if not os.path.isdir(mode_path):
                continue

            for exp_name in os.listdir(mode_path):
                exp_path = os.path.join(mode_path, exp_name)
                if not os.path.isdir(exp_path):
                    continue

                traces_dir = os.path.join(exp_path, "crash_traces")
                crashes_dir = os.path.join(exp_path, "crashes")

                if not (os.path.isdir(traces_dir) and os.path.isdir(crashes_dir)):
                    continue

                for trace_file in os.listdir(traces_dir):
                    m = re.search(r":([^,]+),", trace_file)
                    if not m:
                        continue
                    crash_id = m.group(1)

                    crash_file = None
                    for f in os.listdir(crashes_dir):
                        if f":{crash_id}," in f:
                            crash_file = f
                            break

                    if crash_file:
                        old_path = os.path.join(crashes_dir, crash_file)
                        new_path = os.path.join(crashes_dir, trace_file)
                        os.rename(old_path, new_path)

def chmod_recursive(path, mode=0o777):
    for root, dirs, files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), mode)
        for f in files:
            os.chmod(os.path.join(root, f), mode)
    os.chmod(path, mode)

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

def copy_crash_and_crash_traces(exp_dir, firmware, tool, dest_dir):
    base_dest = os.path.join(dest_dir, firmware, tool, os.path.basename(exp_dir))
    copy_dir(os.path.join(exp_dir, "outputs", "crash_traces"), os.path.join(base_dest, "crash_traces"))
    copy_dir(os.path.join(exp_dir, "outputs", "crashes"), os.path.join(base_dest, "crashes"))

def find_and_copy_crashes(base_dir, dest_dir="extracted_crashes_outputs"):
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir, ignore_errors=True)
    for exp_dir in sorted(glob.glob(os.path.join(base_dir, "exp_*"))):
        if has_crashes(exp_dir):
            firmware, tool = read_config_info(exp_dir)
            copy_crash_and_crash_traces(exp_dir, firmware, tool, dest_dir)
    chmod_recursive(dest_dir, 0o777)

def extract_crash_id(filename):
    try:
        after_colon = filename.split(":", 1)[1]
        crash_id = after_colon.split(",", 1)[0]
        return crash_id
    except IndexError:
        return None

def substitute_extracted_crashes(exp_dir, extracted_root="extracted_crashes_outputs"):
    if not os.path.isdir(exp_dir):
        return

    for sub_exp in sorted(os.listdir(exp_dir)):
        sub_path = os.path.join(exp_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        config_path = os.path.join(sub_path, "outputs", "config.ini")
        if not os.path.isfile(config_path):
            continue

        config = configparser.ConfigParser()
        config.read(config_path)

        try:
            mode = config.get("GENERAL", "mode")
            firmware_path = config.get("GENERAL", "firmware")
        except Exception as e:
            continue

        extracted_dir = os.path.join(extracted_root, firmware_path.split("/")[1], mode)
        if not os.path.isdir(extracted_dir):
            continue

        orig_crashes_dir = os.path.join(sub_path, "outputs", "crashes")
        orig_traces_dir  = os.path.join(sub_path, "outputs", "crash_traces")

        if not os.path.isdir(orig_crashes_dir):
            os.makedirs(orig_crashes_dir)
        if not os.path.isdir(orig_traces_dir):
            os.makedirs(orig_traces_dir)

        crashes_copied = 0
        traces_copied = 0

        for exp in os.listdir(extracted_dir):
            exp_path = os.path.join(extracted_dir, exp)
            if not os.path.isdir(exp_path) or exp != sub_exp:
                continue

            for ftype in {"crashes", "crash_traces"}:
                src_folder = os.path.join(exp_path, ftype)
                if not os.path.isdir(src_folder):
                    continue
                dst_folder = orig_traces_dir if ftype == "crash_traces" else orig_crashes_dir

                for file in os.listdir(src_folder):
                    src_file = os.path.join(src_folder, file)
                    if not os.path.isfile(src_file):
                        continue

                    crash_id = extract_crash_id(file)
                    if crash_id is None:
                        # print(f"[WARN] Cannot extract crash id from {file}, skipping")
                        continue

                    for existing_file in os.listdir(dst_folder):
                        if extract_crash_id(existing_file) == crash_id:
                            existing_path = os.path.join(dst_folder, existing_file)
                            os.remove(existing_path)

                    dst_file = os.path.join(dst_folder, file)
                    shutil.copy2(src_file, dst_file)

                    if ftype == "crash_traces":
                        traces_copied += 1
                    else:
                        crashes_copied += 1


if __name__ == "__main__":
    find_and_copy_crashes("experiments")
