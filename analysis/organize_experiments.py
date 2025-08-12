import os
import shutil
import configparser
import re
import argparse
import csv

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
    if mode == "aflnet_base":
        return f"experiments_done/aflnet_base_{taint}_{coverage}"
    elif mode == "aflnet_state_aware":
        return f"experiments_done/aflnet_state_aware_{taint}_{coverage}"
    elif mode == "triforce":
        return f"experiments_done/triforce_{taint}_{coverage}"
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
        taint = config.get("STAFF_FUZZING", "taint_hints_all_at_once").strip()
        coverage = config.get("EXTRA_FUZZING", "coverage_tracing").strip()
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"Invalid config in {exp_dir}: {e}. Skipping.")
        return

    move_experiment(exp_dir, mode, taint, coverage)

def main():
    parser = argparse.ArgumentParser(description="Organize experiment folders based on config.ini content, optionally filtered by a CSV.")
    parser.add_argument("--input-dir", required=True,
                        help="Root directory containing experiment folders (e.g., 0,1,2...)")
    parser.add_argument("--input-csv", required=False,
                        help="Optional CSV file listing experiments and their statuses.")
    args = parser.parse_args()

    succeeded_exps = None
    rows = []
    fieldnames = []
    group_header = None
    if args.input_csv:
        with open(args.input_csv, 'r', newline='') as csvfile:
            group_header = csvfile.readline()
            reader = csv.DictReader(csvfile)
            fieldnames = reader.fieldnames
            rows = list(reader)
        succeeded_exps = [row['exp_name'].strip() for row in rows if row.get('status', '').strip().lower() == 'succeeded']

    for entry in os.listdir(args.input_dir):
        exp_path = os.path.join(args.input_dir, entry)
        if not os.path.isdir(exp_path):
            continue
        if succeeded_exps is not None and entry not in succeeded_exps:
            continue
        process_experiment_dir(exp_path)

    if succeeded_exps is not None:
        remaining = [row for row in rows if row['exp_name'].strip() not in succeeded_exps]
        with open(args.input_csv, 'w', newline='') as csvfile:
            if group_header is not None:
                csvfile.write(group_header)
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(remaining)

if __name__ == "__main__":
    main()
