import os
import shutil
import configparser
import re
import argparse

BASELINE_MODES = {"aflnet_base", "aflnet_state_aware", "triforce"}

def get_next_available_exp_name(dest_dir):
    used = set()
    pattern = re.compile(r'^exp_(\d+)$')
    for entry in os.listdir(dest_dir):
        match = pattern.match(entry)
        if match:
            used.add(int(match.group(1)))
    n = 0
    while True:
        if n not in used:
            return f"exp_{n}"
        n += 1

def determine_destination(mode, taint, coverage):
    if mode in BASELINE_MODES:
        return "experiments_done/baseline"
    elif mode == "staff_state_aware":
        return f"experiments_done/staff_state_aware_{taint}_{coverage}"
    elif mode == "staff_base":
        return f"experiments_done/staff_base_{taint}_{coverage}"
    else:
        return None

def move_experiment(exp_path, mode, taint, coverage):
    dest_subdir = determine_destination(mode, taint, coverage)
    if dest_subdir is None:
        print(f"Skipping unknown mode '{mode}' in {exp_path}")
        return

    os.makedirs(dest_subdir, exist_ok=True)
    new_name = get_next_available_exp_name(dest_subdir)
    dst_path = os.path.join(dest_subdir, new_name)

    print(f"Moving {os.path.basename(exp_path)} -> {dest_subdir}/{new_name}")
    shutil.move(exp_path, dst_path)

def process_experiment_dir(exp_dir):
    config_path = os.path.join(exp_dir, "outputs", "config.ini")
    if not os.path.isfile(config_path):
        print(f"Warning: config.ini not found in {exp_dir}. Skipping.")
        return

    config = configparser.ConfigParser()
    config.read(config_path)

    try:
        mode = config.get("GENERAL", "mode").strip()
        taint = config.get("AFLNET_FUZZING", "taint_hints_all_at_once").strip()
        coverage = config.get("EXTRA_FUZZING", "coverage_tracing").strip()
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"Invalid config in {exp_dir}: {e}. Skipping.")
        return

    move_experiment(exp_dir, mode, taint, coverage)

def main():
    parser = argparse.ArgumentParser(description="Organize experiment folders based on config.ini content.")
    parser.add_argument("--input-dir", required=True, help="Root directory containing experiment folders (e.g., 0,1,2...)")
    args = parser.parse_args()

    for entry in os.listdir(args.input_dir):
        exp_path = os.path.join(args.input_dir, entry)
        if os.path.isdir(exp_path):
            process_experiment_dir(exp_path)

if __name__ == "__main__":
    main()
