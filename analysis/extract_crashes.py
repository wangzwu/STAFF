#!/usr/bin/env python3
import os
import configparser
import shutil
import re
import argparse
from typing import List, Tuple
import pandas as pd

def extract_crash_id(filename: str):
    try:
        after_colon = filename.split(":", 1)[1]
        crash_id = after_colon.split(",", 1)[0]
        return crash_id
    except IndexError:
        return None

def read_start_time(fuzzer_stats_path: str):
    if not os.path.isfile(fuzzer_stats_path):
        return None
    with open(fuzzer_stats_path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if ln.startswith("start_time"):
                parts = ln.split(":", 1)
                if len(parts) == 2:
                    try:
                        return int(parts[1].strip())
                    except ValueError:
                        return None
    return None

def parse_plot_changes(plot_path: str) -> List[Tuple[int,int,int]]:
    events = []
    if not os.path.isfile(plot_path):
        return events
    prev = None
    with open(plot_path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = [p.strip() for p in ln.split(",")]
            if len(parts) < 9:
                continue
            try:
                unix_time = int(parts[0])
                unique_crashes = int(parts[8])
            except ValueError:
                continue
            if prev is None:
                prev = unique_crashes
                continue
            if unique_crashes != prev:
                events.append((unix_time, prev, unique_crashes))
                prev = unique_crashes
            else:
                prev = unique_crashes
    return events

def safe_rename(src: str, dst: str, overwrite: bool=True):
    if os.path.abspath(src) == os.path.abspath(dst):
        return
    if os.path.exists(dst):
        if overwrite:
            os.remove(dst)
        else:
            raise FileExistsError(dst)
    os.rename(src, dst)

def make_tte_suffix(filename: str, tte: int) -> str:
    if re.search(r'\$\d+$', filename):
        return re.sub(r'\$\d+$', f'${tte}', filename)
    else:
        return filename + f'${tte}'

def unify_crash_and_trace_filenames(extracted_root="extracted_crashes_outputs", verbose=True):
    if not os.path.isdir(extracted_root):
        if verbose:
            print(f"[ERROR] extracted_root does not exist: {extracted_root}")
        return

    for firmware in sorted(os.listdir(extracted_root)):
        firmware_path = os.path.join(extracted_root, firmware)
        if not os.path.isdir(firmware_path):
            continue

        for mode in sorted(os.listdir(firmware_path)):
            mode_path = os.path.join(firmware_path, mode)
            if not os.path.isdir(mode_path):
                continue

            for sub_exp in sorted(os.listdir(mode_path)):
                exp_path = os.path.join(mode_path, sub_exp)
                if not os.path.isdir(exp_path):
                    continue

                crashes_dir = os.path.join(exp_path, "crashes")
                traces_dir = os.path.join(exp_path, "crash_traces")
                if not (os.path.isdir(crashes_dir) and os.path.isdir(traces_dir)):
                    continue

                crash_map = {}

                for f in os.listdir(crashes_dir):
                    fpath = os.path.join(crashes_dir, f)

                    if os.path.isfile(fpath):
                        cid = extract_crash_id(f)
                        if cid:
                            crash_map[cid] = fpath

                    elif os.path.isdir(fpath):
                        for subf in os.listdir(fpath):
                            subpath = os.path.join(fpath, subf)
                            if os.path.isfile(subpath):
                                cid = extract_crash_id(subf)
                                if cid:
                                    crash_map[cid] = subpath


                trace_map = {}

                for f in os.listdir(traces_dir):
                    fpath = os.path.join(traces_dir, f)

                    if os.path.isfile(fpath):
                        cid = extract_crash_id(f)
                        if cid:
                            trace_map[cid] = fpath

                    elif os.path.isdir(fpath):
                        for subf in os.listdir(fpath):
                            subpath = os.path.join(fpath, subf)
                            if os.path.isfile(subpath):
                                cid = extract_crash_id(subf)
                                if cid:
                                    trace_map[cid] = subpath

                for cid in sorted(set(crash_map.keys()) | set(trace_map.keys())):
                    cfile = crash_map.get(cid)
                    tfile = trace_map.get(cid)

                    if not (cfile and tfile):
                        continue

                    cbase = os.path.basename(cfile)
                    tbase = os.path.basename(tfile)

                    if len(cbase) > len(tbase):
                        suffix = tbase.split("$")[-1] if "$" in tbase else ""
                        new_name = f"{cbase.split('$')[0]}${suffix}" if suffix else cbase.split('$')[0]
                        new_path = os.path.join(traces_dir, new_name)

                        if new_path != tfile and not os.path.exists(new_path):
                            if verbose:
                                print(f"[RENAME] crash_trace: {tfile} -> {new_path}")
                            os.rename(tfile, new_path)

                    elif len(tbase) > len(cbase):
                        suffix = cbase.split("$")[-1] if "$" in cbase else ""
                        new_name = f"{tbase.split('$')[0]}${suffix}" if suffix else tbase.split('$')[0]
                        new_path = os.path.join(crashes_dir, new_name)

                        if new_path != cfile and not os.path.exists(new_path):
                            if verbose:
                                print(f"[RENAME] crash: {cfile} -> {new_path}")
                            os.rename(cfile, new_path)


def update_extracted_root_from_experiments(experiments_dir, extracted_root="extracted_crashes_outputs", verbose=True):
    if not os.path.isdir(experiments_dir):
        if verbose:
            print(f"[ERROR] experiments_dir does not exist: {experiments_dir}")
        return

    for sub_exp in sorted(os.listdir(experiments_dir)):
        sub_path = os.path.join(experiments_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        config_path = os.path.join(sub_path, "outputs", "config.ini")
        if not os.path.isfile(config_path):
            if verbose:
                print(f"[INFO] skipping {sub_path}: no config.ini")
            continue

        config = configparser.ConfigParser()
        config.read(config_path)
        try:
            mode = config.get("GENERAL", "mode")
            firmware_path = config.get("GENERAL", "firmware")
        except Exception as e:
            if verbose:
                print(f"[WARN] couldn't read mode/firmware in {config_path}: {e}")
            continue

        firmware_basename = os.path.basename(firmware_path)
        target_exp_dir = os.path.join(extracted_root, firmware_basename, mode, sub_exp)

        for ftype in ("crashes", "crash_traces"):
            os.makedirs(os.path.join(target_exp_dir, ftype), exist_ok=True)

        copied_counts = {"crashes": 0, "crash_traces": 0}

        for ftype in ("crashes", "crash_traces"):
            src_folder = os.path.join(sub_path, "outputs", ftype)
            dst_folder = os.path.join(target_exp_dir, ftype)

            if not os.path.isdir(src_folder):
                if verbose:
                    print(f"[INFO] no {ftype} in {sub_path}, skipping {ftype}")
                continue

            for file in sorted(os.listdir(src_folder)):
                src_file = os.path.join(src_folder, file)
                if not os.path.isfile(src_file):
                    continue

                crash_id = extract_crash_id(file)
                if crash_id is None:
                    if verbose:
                        print(f"[WARN] cannot extract crash id from '{file}', skipping")
                    continue

                already_exists = False
                for existing_file in os.listdir(dst_folder):
                    existing_path = os.path.join(dst_folder, existing_file)
                    if not os.path.isfile(existing_path):
                        continue
                    if extract_crash_id(existing_file) == crash_id:
                        already_exists = True
                        break

                if already_exists:
                    if verbose:
                        print(f"[SKIP] {ftype}: crash_id {crash_id} already exists in extracted_root")
                    continue

                dst_file = os.path.join(dst_folder, file)
                shutil.copy2(src_file, dst_file)
                if verbose:
                    print(f"Copied NEW to extracted_root: {src_file} -> {dst_file}")
                copied_counts[ftype] += 1

        if verbose:
            print(f"[RESULT] {sub_exp} -> firmware='{firmware_basename}', mode='{mode}': "
                  f"crashes_copied={copied_counts['crashes']}, "
                  f"traces_copied={copied_counts['crash_traces']}")

def annotate_extracted_with_tte(experiments_dir, extracted_root="extracted_crashes_outputs", verbose=True):
    if not os.path.isdir(experiments_dir):
        if verbose:
            print(f"[ERROR] experiments_dir does not exist: {experiments_dir}")
        return

    for sub_exp in sorted(os.listdir(experiments_dir)):
        sub_path = os.path.join(experiments_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        config_path = os.path.join(sub_path, "outputs", "config.ini")
        if not os.path.isfile(config_path):
            if verbose:
                print(f"[INFO] skipping {sub_path}: no config.ini")
            continue

        config = configparser.ConfigParser()
        config.read(config_path)
        try:
            mode = config.get("GENERAL", "mode")
            firmware_path = config.get("GENERAL", "firmware")
        except Exception as e:
            if verbose:
                print(f"[WARN] couldn't read mode/firmware in {config_path}: {e}")
            continue

        firmware_basename = os.path.basename(firmware_path)
        target_exp_dir = os.path.join(extracted_root, firmware_basename, mode, sub_exp)

        if not os.path.isdir(target_exp_dir):
            if verbose:
                print(f"[INFO] no extracted dir for {sub_exp} at {target_exp_dir}, skipping")
            continue

        fuzzer_stats_path = os.path.join(sub_path, "outputs", "fuzzer_stats")
        start_time = read_start_time(fuzzer_stats_path)
        if start_time is None:
            if verbose:
                print(f"[WARN] no start_time found in {fuzzer_stats_path}, skipping {sub_exp}")
            continue

        plot_candidates = [
            os.path.join(sub_path, "plot_data"),
            os.path.join(sub_path, "outputs", "plot_data"),
        ]
        plot_path = None
        for p in plot_candidates:
            if os.path.isfile(p):
                plot_path = p
                break
        if plot_path is None:
            if verbose:
                print(f"[INFO] no plot_data for {sub_exp}, skipping TTE annotation")
            continue

        events = parse_plot_changes(plot_path)
        if not events:
            if verbose:
                print(f"[INFO] no unique_crashes changes detected in {plot_path}")
            continue

        crash_times = {}
        prev_u = 0
        try:
            with open(plot_path, "r") as pf:
                for ln in pf:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    parts = [p.strip() for p in ln.split(",")]
                    if len(parts) < 9:
                        continue
                    try:
                        unix_time = int(parts[0])
                        unique_crashes = int(parts[8])
                    except ValueError:
                        continue
                    if unique_crashes > prev_u:
                        for k in range(prev_u + 1, unique_crashes + 1):
                            if k not in crash_times:
                                crash_times[k] = unix_time
                    prev_u = unique_crashes
        except Exception:
            crash_times = {}

        crashes_folder = os.path.join(target_exp_dir, "crashes")
        crash_entries = {}
        crash_real_mtime = {}
        if os.path.isdir(crashes_folder):
            for fname in sorted(os.listdir(crashes_folder)):
                fpath = os.path.join(crashes_folder, fname)
                if not os.path.isfile(fpath):
                    continue
                cid = extract_crash_id(fname)
                if cid is None:
                    cid = f"__fname__::{fname}"
                crash_entries.setdefault(cid, []).append(fname)
                try:
                    crash_real_mtime[cid] = int(os.path.getmtime(fpath))
                except Exception:
                    crash_real_mtime.setdefault(cid, None)

        def cid_sort_key(cid):
            if cid.startswith("__fname__::"):
                return (1, cid)
            try:
                return (0, int(cid))
            except Exception:
                return (1, cid)

        ordered_cids = sorted(list(crash_entries.keys()), key=cid_sort_key)

        cid_to_mtime = {}
        for idx, cid in enumerate(ordered_cids, start=1):
            vmtime = crash_times.get(idx)
            if vmtime is None:
                vmtime = crash_real_mtime.get(cid)
            cid_to_mtime[cid] = vmtime

        files_map = []
        for cid, fnames in crash_entries.items():
            for fname in fnames:
                fpath = os.path.join(crashes_folder, fname)
                if not os.path.isfile(fpath):
                    continue
                mtime = cid_to_mtime.get(cid)
                files_map.append((fpath, "crashes", mtime-start_time))

        traces_folder = os.path.join(target_exp_dir, "crash_traces")
        if os.path.isdir(traces_folder):
            for tname in sorted(os.listdir(traces_folder)):
                tpath = os.path.join(traces_folder, tname)
                if not os.path.isfile(tpath):
                    continue
                tcid = extract_crash_id(tname)
                if tcid is None:
                    tcid = f"__fname__::{tname}"
                tm = cid_to_mtime.get(tcid)
                if tm is None:
                    try:
                        tm = int(os.path.getmtime(tpath))
                    except Exception:
                        tm = None
                files_map.append((tpath, "crash_traces", tm-start_time))

        matched_any = False

        for fpath, ftype, tte in files_map:
            dirname = os.path.dirname(fpath)
            fname = os.path.basename(fpath)
            new_fname = make_tte_suffix(fname, tte)
            new_path = os.path.join(dirname, new_fname)
            if verbose:
                print(f"[RENAME] {ftype}: {fpath} -> {new_path}", tte, start_time, unix_time)

            safe_rename(fpath, new_path, overwrite=True)

            matched_any = True

        if not matched_any and verbose:
            print(f"[WARN] no extracted crash file matched unix_time={unix_time} for {sub_exp}")

def extract_crashID(fname: str):
    match = re.search(r"£(\d+)", fname)
    if match:
        return match.group(1)
    return None

def summarize_crash_occurrences(extracted_root="extracted_crashes_outputs", verbose=True):
    methods = ["triforce", "aflnet_state_aware", "staff_state_aware", "aflnet_base"]
    table = {}

    for firmware in sorted(os.listdir(extracted_root)):
        firmware_path = os.path.join(extracted_root, firmware)
        if not os.path.isdir(firmware_path):
            continue

        for method in methods:
            method_path = os.path.join(firmware_path, method)
            if not os.path.isdir(method_path):
                continue

            for exp in sorted(os.listdir(method_path)):
                exp_path = os.path.join(method_path, exp)
                crashes_dir = os.path.join(exp_path, "crashes")
                if not os.path.isdir(crashes_dir):
                    continue

                exp_crashID_min_tte = {}

                for fname in os.listdir(crashes_dir):
                    fpath = os.path.join(crashes_dir, fname)
                    if not os.path.isfile(fpath):
                        continue
                    if "£" not in fname:
                        continue

                    crashID = extract_crashID(fname)
                    if crashID is None:
                        continue
                    
                    tte = None
                    if "$" in fname:
                        try:
                            tte = int(fname.split("$")[-1])
                        except Exception:
                            tte = None

                    if tte is not None:
                        if crashID not in exp_crashID_min_tte:
                            exp_crashID_min_tte[crashID] = tte
                        else:
                            exp_crashID_min_tte[crashID] = min(exp_crashID_min_tte[crashID], tte)

                for crashID, tte in exp_crashID_min_tte.items():
                    table.setdefault(crashID, {}).setdefault(method, {"count": 0, "ttes": []})
                    table[crashID][method]["count"] += 1
                    table[crashID][method]["ttes"].append(tte)

    rows = []
    for crashID, methods_data in table.items():
        row = {"crashID": crashID}
        for method in methods:
            data = methods_data.get(method, {"count": 0, "ttes": []})
            row[f"{method}_count"] = data["count"]
            ttes = data["ttes"]
            if ttes:
                row[f"{method}_avg_tte"] = sum(ttes) / len(ttes)
            else:
                row[f"{method}_avg_tte"] = None
        rows.append(row)

    df = pd.DataFrame(rows)
    if "crashID" in df.columns:
        df = df.sort_values("crashID")
    else:
        print("[WARN] crashID column missing. Columns available:", df.columns)
    print(df.to_string(index=False))
    return df

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Copy crashes from experiments_dir to extracted_root, then annotate files with $<tte> based on plot_data/fuzzer_stats.")
    parser.add_argument("experiments_dir", help="Path to directory containing exp_* directories.")
    parser.add_argument("--extracted_root", default="extracted_crashes_outputs", help="Destination root to update/annotate.")
    parser.add_argument("--update", action="store_true", help="Do not copy crashes into extracted_root; operate only on existing extracted_root.")
    parser.add_argument("--annotate", action="store_true", help="Do not run TTE annotation after copying.")
    parser.add_argument("--quiet", action="store_true", help="Reduce verbosity.")
    args = parser.parse_args()

    verbose = not args.quiet

    unify_crash_and_trace_filenames()

    if args.update:
        update_extracted_root_from_experiments(args.experiments_dir, extracted_root=args.extracted_root, verbose=verbose)
    else:
        if verbose:
            print("[INFO] skipping copy step")

    if args.annotate:
        annotate_extracted_with_tte(args.experiments_dir, extracted_root=args.extracted_root, verbose=verbose)
    else:
        if verbose:
            print("[INFO] skipping annotation step")

    summarize_crash_occurrences()
