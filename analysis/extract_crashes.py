#!/usr/bin/env python3
import os
import configparser
import shutil
import re
import argparse
from typing import List, Tuple
import pandas as pd

SKIP_MODULES = {("dap2310_v1.00_o772.bin", "any", "ethlink"), ("dap2310_v1.00_o772.bin", "any", "aparraymsg"),
                ("dir300_v1.03_7c.bin", "any", "ethlink"), ("dir300_v1.03_7c.bin", "any", "aparraymsg"), 
                ("FW_RT_N10U_B1_30043763754.zip", "any", "u2ec"), ("DGND3300_Firmware_Version_1.1.00.22__North_America_.zip", "any", "potcounter"),
                ("DGND3300_Firmware_Version_1.1.00.22__North_America_.zip", "any", "busybox"), ("FW_RE1000_1.0.02.001_US_20120214_SHIPPING.bin", "any", "upnp"),
                ("FW_WRT320N_1.0.05.002_20110331.bin", "any", "upnp"), ("TL-WPA8630_US__V2_171011.zip", "any", "wifiSched"),
                ("JNR3210_Firmware_Version_1.1.0.14.zip", "any", "busybox"), ("DGND3300_Firmware_Version_1.1.00.22__North_America_.zip", "any", "unknown"),
                ("FW_RT_N53_30043763754.zip", "any", "rc"), ("FW_TV-IP651WI_V1_1.07.01.zip", "aflnet_base", "alphapd"),
                ("FW_TV-IP651WI_V1_1.07.01.zip", "aflnet_state_aware", "alphapd"), ("JNR3210_Firmware_Version_1.1.0.14.zip", "any", "rc")}

DEFAULT_METHODS = ["triforce", "aflnet_state_aware", "staff_state_aware", "aflnet_base"]

PC_RANGES = {
    # "DGN3500-V1.1.00.30_NA.zip": {
    #     "setup.cgi": {
    #         "FUN_A": (0x000115d0, 0x00018f34),
    #     },
    # },
    # # other firmwares...
}

GROUPS = []

import csv
import re
import os
import textwrap
from collections import defaultdict
from typing import Dict, Tuple

def _parse_num_token(tok: str):
    if tok is None:
        raise ValueError("Empty token")
    s = str(tok).strip().lower()
    if not s:
        raise ValueError("Empty token")

    try:
        return int(s, 0)
    except Exception:
        pass
    m = re.search(r'([0-9a-fA-F]+)', s)
    if m:
        try:
            return int(m.group(1), 16)
        except Exception:
            pass
    raise ValueError(f"Cannot parse numeric token: {tok!r}")

def load_pc_ranges_from_csv(csv_path: str = "crashes.csv",
                            output_py: str = "pc_ranges_generated.py",
                            verbose: bool = True) -> Dict[str, Dict[str, Dict[str, Tuple[int,int]]]]:
    pc_ranges = defaultdict(lambda: defaultdict(dict))

    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    if verbose:
        print(f"[INFO] reading PC ranges from: {csv_path}")

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        row_no = 0
        for raw in reader:
            row_no += 1
            if not raw or all(not (c and c.strip()) for c in raw):
                continue
            first = raw[0].strip() if raw else ""
            if first.startswith("#"):
                continue

            cols = [c.strip() for c in raw if c is not None]

            if len(cols) < 4:
                if verbose:
                    print(f"[WARN] row {row_no}: not enough columns -> {cols}")
                continue

            firmware = cols[0]
            module = cols[1]
            start_tok = cols[2]
            end_tok = cols[3]

            func_tok = None
            if len(cols) >= 5:
                func_tok = cols[4]
            else:
                m = re.search(r'\(([^)]+)\)', cols[3])
                if m:
                    func_tok = m.group(0)

            func_name = None
            if func_tok is not None:
                fn = str(func_tok).strip()
                fn = fn.strip().lstrip(",").strip()
                if fn.startswith("(") and fn.endswith(")"):
                    fn = fn[1:-1].strip()
                fn = fn.strip("'\" ")
                if fn:
                    func_name = fn

            if func_name is None:
                func_name = f"range_{start_tok}_{end_tok}"

            try:
                s_int = _parse_num_token(start_tok)
                e_int = _parse_num_token(end_tok)
            except Exception as ex:
                if verbose:
                    print(f"[ERROR] row {row_no}: cannot parse ({start_tok},{end_tok}) -> {ex}; skipping")
                continue

            if s_int > e_int:
                if verbose:
                    print(f"[WARN] row {row_no}: start > end, swapping: {hex(s_int)} > {hex(e_int)}")
                s_int, e_int = e_int, s_int

            if func_name in pc_ranges[firmware][module]:
                if verbose:
                    old = pc_ranges[firmware][module][func_name]
                    print(f"[WARN] row {row_no}: duplicate function '{func_name}' for {firmware}/{module}; "
                          f"old={hex(old[0])}-{hex(old[1])} -> new={hex(s_int)}-{hex(e_int)} (overwriting)")

            pc_ranges[firmware][module][func_name] = (s_int, e_int)
            if verbose:
                print(f"[ROW {row_no}] {firmware} / {module} -> {func_name}: 0x{s_int:08x}-0x{e_int:08x}")

    pc_ranges = {fw: {mod: dict(funcs) for mod, funcs in mods.items()} for fw, mods in pc_ranges.items()}

    lines = []
    lines.append("# Auto-generated PC_RANGES from " + os.path.basename(csv_path))
    lines.append("PC_RANGES = {")
    for fw, mods in sorted(pc_ranges.items()):
        lines.append(f"    {fw!r}: {{")
        for mod, funcs in sorted(mods.items()):
            lines.append(f"        {mod!r}: {{")
            for fname, (s, e) in sorted(funcs.items()):
                lines.append(f"            {fname!r}: (0x{s:08x}, 0x{e:08x}),")
            lines.append("        },")
        lines.append("    },")
    lines.append("}")
    content = "\n".join(lines) + "\n"

    try:
        with open(output_py, "w", encoding="utf-8") as ofh:
            ofh.write(content)
        if verbose:
            print(f"[WRITE] PC_RANGES python literal -> {output_py}")
    except Exception as ex:
        if verbose:
            print(f"[ERROR] cannot write {output_py}: {ex}")

    return pc_ranges

def chmod_recursive(path, mode):
    for root, dirs, files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), mode)
        for f in files:
            os.chmod(os.path.join(root, f), mode)

    os.chmod(path, mode)

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


import os
import shutil
import configparser

def update_extracted_root_from_experiments(experiments_dir, extracted_root="extracted_crashes_outputs", verbose=True):
    """
    Copy crashes/crash_traces from experiment outputs into a structured extracted_root.
    Special handling for 'triforce': filenames are renamed using the timestamp after '$' (ts//1000).
    """
    def extract_ts_from_name(filename):
        """
        Extract timestamp after `$` in filename.
        Returns integer timestamp // 1000 or None if not found.
        """
        if "$" not in filename:
            return None
        try:
            ts_str = filename.split("$")[-1]
            ts = int(ts_str)
            return ts // 1000
        except Exception:
            return None

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

        # skip if both crashes and crash_traces exist but empty
        if (os.path.isdir(os.path.join(sub_path, "outputs", "crash_traces")) and not os.listdir(os.path.join(sub_path, "outputs", "crash_traces"))
            and os.path.isdir(os.path.join(sub_path, "outputs", "crashes")) and not os.listdir(os.path.join(sub_path, "outputs", "crashes"))):
            continue

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

                # --- special handling for triforce ---
                if mode == "triforce":
                    ts = extract_ts_from_name(file)
                    if ts is not None:
                        if "$" in file:
                            prefix, _ = file.rsplit("$", 1)
                            dst_file = os.path.join(dst_folder, f"{prefix}${ts}")

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
                if "sig" in fname:
                    continue
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
                if "sig" not in tname:
                    continue
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
            if "triforce" in fpath:
                continue
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

import os
import re
from collections import defaultdict

def _parse_first_frame_pc_module(trace_path):
    """
    Parse a crash_trace file and return (pc, module) from the first trace block first frame.
    Returns (pc_str, module_str) or (None, None) if not found.
    """
    pc = None
    module = None
    in_trace = False
    try:
        with open(trace_path, "r", errors="ignore") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                if ln.startswith("=== Trace"):
                    in_trace = True
                    continue
                if in_trace:
                    if ln.startswith("Process:"):
                        continue
                    # first frame line, e.g.:
                    # [00] inode: 24715, pc: 0x000034e0, module: udhcpd
                    m_pc = re.search(r"pc:\s*(0x[0-9A-Fa-f]+)", ln)
                    m_mod = re.search(r"module:\s*([^\s,]+)", ln)
                    if m_pc:
                        pc = m_pc.group(1)
                    if m_mod:
                        module = m_mod.group(1)
                    # return after processing the first frame-like line
                    if ln.startswith("["):
                        return (pc, module)
    except Exception:
        return (None, None)
    return (None, None)


def _latex_escape(s: str) -> str:
    """Escape characters that are special in LaTeX tables."""
    if s is None:
        return ""
    s = str(s)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    for k, v in replacements.items():
        s = s.replace(k, v)
    return s

def _write_csv_rows(headers, rows, out_csv, verbose=True):
    """Write CSV deterministically; always write header even if rows empty."""
    try:
        with open(out_csv, "w", newline='', encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=headers)
            writer.writeheader()
            for r in rows:
                # ensure serializable simple values
                serial = {}
                for h in headers:
                    v = r.get(h, "")
                    if v is None:
                        v = ""
                    # convert floats/int to str or keep number (csv will stringify)
                    serial[h] = v
                writer.writerow(serial)
        if verbose:
            print(f"[WRITE] CSV -> {out_csv}")
    except Exception as e:
        if verbose:
            print(f"[ERROR] writing CSV {out_csv}: {e}")


def _write_tex_table(headers, rows, out_tex, verbose=True):
    """Write a simple LaTeX tabular wrapped in table*; truncate firmware to 13 chars."""
    try:
        with open(out_tex, "w", encoding="utf-8") as fh:
            fh.write("\\begin{table*}[ht]\n\\centering\n")
            fh.write("\\begin{tabular}{%s}\n" % ("l" * len(headers)))
            fh.write(" & ".join(_latex_escape(h) for h in headers) + " \\\\\n")
            fh.write("\\hline\n")
            for r in rows:
                vals = []
                for h in headers:
                    v = r.get(h, "")
                    if v is None:
                        v = ""
                    # truncate firmware column
                    if h.lower() == "firmware":
                        v = str(v)[:13]
                    vals.append(_latex_escape(v))
                fh.write(" & ".join(vals) + " \\\\\n")
            fh.write("\\end{tabular}\n")
            fh.write("\\end{table*}\n")
        if verbose:
            print(f"[WRITE] LaTeX -> {out_tex}")
    except Exception as e:
        if verbose:
            print(f"[ERROR] writing LaTeX {out_tex}: {e}")


def _write_tex_table_count_tte(headers, rows, methods, out_tex, verbose=True):
    """
    Write a LaTeX tabular with two-level headers wrapped in table*:
    - First row: method names (merged over two columns each)
    - Second row: 'Count' and 'TTE' subcolumns for each method
    - Truncate firmware to 13 chars.
    """
    try:
        with open(out_tex, "w", encoding="utf-8") as fh:
            n_fixed = 3  # firmware, module, pc
            n_cols = n_fixed + 2 * len(methods)
            col_spec = "l" * n_cols
            fh.write("\\begin{table*}[ht]\n\\centering\n")
            fh.write("\\begin{tabular}{%s}\n" % col_spec)

            # First header row
            first_row = ["Firmware", "Module", "PC"]
            for m in methods:
                first_row.append("\\multicolumn{2}{c}{%s}" % _latex_escape(m))
            fh.write(" & ".join(first_row) + " \\\\\n")

            # Second header row: Count / TTE
            second_row = [""] * n_fixed
            for _ in methods:
                second_row.extend(["Count", "TTE"])
            fh.write(" & ".join(second_row) + " \\\\\n")

            fh.write("\\hline\n")

            # Data rows
            for r in rows:
                vals = []
                for h in headers:
                    v = r.get(h, "")
                    if v is None:
                        v = ""
                    # truncate firmware column
                    if h.lower() == "firmware":
                        v = str(v)[:13]
                    vals.append(_latex_escape(v))
                fh.write(" & ".join(vals) + " \\\\\n")

            fh.write("\\end{tabular}\n")
            fh.write("\\end{table*}\n")

        if verbose:
            print(f"[WRITE] LaTeX -> {out_tex}")
    except Exception as e:
        if verbose:
            print(f"[ERROR] writing LaTeX {out_tex}: {e}")


def build_agg_from_extracted(extracted_root="extracted_crashes_outputs", methods=None, verbose=False):
    member_to_group = {}
    for group in GROUPS:
        if not group:
            continue
        rep = group[0]
        for member in group:
            member_to_group[member] = rep

    # normalized_skip = set((fw, mode, mod.lower()) for fw, mode, mod in SKIP_MODULES)

    if methods is None:
        methods = DEFAULT_METHODS

    agg = defaultdict(lambda: defaultdict(dict))

    def collect_trace_files(traces_dir):
        files = []
        if not os.path.isdir(traces_dir):
            return files
        for entry in sorted(os.listdir(traces_dir)):
            epath = os.path.join(traces_dir, entry)
            if os.path.isfile(epath):
                files.append(epath)
            elif os.path.isdir(epath):
                for subf in sorted(os.listdir(epath)):
                    subp = os.path.join(epath, subf)
                    if os.path.isfile(subp):
                        files.append(subp)
        return files

    for firmware in sorted(os.listdir(extracted_root)):
        fw_path = os.path.join(extracted_root, firmware)
        if not os.path.isdir(fw_path):
            continue

        for method in methods:
            method_path = os.path.join(fw_path, method)
            if not os.path.isdir(method_path):
                continue
            for exp in sorted(os.listdir(method_path)):
                exp_path = os.path.join(method_path, exp)
                if not os.path.isdir(exp_path):
                    continue
                traces_dir = os.path.join(exp_path, "crash_traces")
                if not os.path.isdir(traces_dir):
                    continue

                files = collect_trace_files(traces_dir)
                if not files:
                    continue

                per_exp_min_tte = {}
                for tf in files:
                    pc, module = _parse_first_frame_pc_module(tf)
                    if pc is None and module is None:
                        if verbose:
                            print(f"[SKIP] cannot parse first frame from {tf}")
                        continue

                    module_norm = (module or "(unknown_module)")
                    # if (firmware, mode, module_norm.lower()) in normalized_skip:
                    #     if verbose:
                    #         print(f"[SKIP] (fw,mode,module) in SKIP_MODULES: ({firmware},{mode},{module_norm}) -> {tf}")
                    #     continue

                    pc_norm = pc or "(unknown_pc)"
                    raw_key = (firmware, module_norm, pc_norm)
                    group_key = member_to_group.get(raw_key, raw_key)

                    bname = os.path.basename(tf)
                    tte_val = None
                    if "$" in bname:
                        suf = bname.rsplit("$", 1)[1]
                        try:
                            tte_val = int(suf)
                        except Exception:
                            tte_val = None

                    prev = per_exp_min_tte.get(group_key)
                    if prev is None:
                        per_exp_min_tte[group_key] = tte_val
                    else:
                        if prev is None:
                            per_exp_min_tte[group_key] = tte_val
                        elif tte_val is None:
                            pass
                        else:
                            per_exp_min_tte[group_key] = min(prev, tte_val)

                for key, min_tte in per_exp_min_tte.items():
                    agg[key][method][exp] = min_tte

    return agg

def build_three_tables_and_write_consistent(
        extracted_root="extracted_crashes_outputs",
        methods=None,
        out1_csv="out1.csv", out1_tex="out1.tex",
        out2_csv="out2.csv", out2_tex="out2.tex",
        out3_csv="out3.csv", out3_tex="out3.tex",
        firmwares_csv="analysis/fw_names.csv",
        verbose=True):
    """
    Build tables and write CSV+LaTeX with three tables:
    - Table1: Number of crashes
    - Table2: TTE crashes
    - Table3: Rare crashes (staff_state_aware only)
    Columns: brand, firmware, version, module, function (for Table2+3)
    """
    import re
    from collections import defaultdict
    import csv

    if methods is None:
        methods = DEFAULT_METHODS

    # Method abbreviations for headers
    METHOD_ABBR = {
        "aflnet_base": "AB",
        "aflnet_state_aware": "ASA",
        "triforce": "TRI",
        "staff_state_aware": "STAFF"
    }

    # Load firmware -> (brand, name, version)
    def load_firmware_map_triplet(path):
        mapping = {}
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                fw_file = row["firmware"].strip()
                brand = row.get("brand", "").strip()
                name = row.get("name", "").strip()
                version = row.get("version", "").strip()
                mapping[fw_file] = (brand, name, version)
        return mapping

    fw_map = load_firmware_map_triplet(firmwares_csv)

    # Build raw aggregation
    agg_raw = build_agg_from_extracted(extracted_root=extracted_root, methods=methods, verbose=verbose)

    # Flatten GROUPS mapping
    member_to_group = {}
    for group in GROUPS:
        if not group:
            continue
        rep = group[0]
        for member in group:
            member_to_group[member] = rep

    # Helper: convert pc string to int
    def pc_to_int(pc_str):
        if pc_str is None:
            return None
        s = str(pc_str).strip()
        try:
            return int(s, 0)
        except:
            m = re.search(r"(0x[0-9a-fA-F]+)", s)
            if m:
                return int(m.group(1), 16)
            m2 = re.search(r"(\d+)", s)
            if m2:
                return int(m2.group(1), 10)
        return None

    # Map raw key into function ranges / GROUPS
    def map_key_by_range_and_groups_debug(fw, module, pc_str):
        raw = (fw, module, pc_str)
        pc_int = pc_to_int(pc_str)
        if raw in member_to_group:
            return member_to_group[raw]
        if pc_int is not None:
            norm_pc = f"0x{pc_int:08x}"
            alt = (fw, module, norm_pc)
            if alt in member_to_group:
                return member_to_group[alt]
        for fw_key, modmap in PC_RANGES.items():
            if fw_key.lower() != fw.lower() and fw_key not in fw and fw not in fw_key:
                continue
            ranges = modmap.get(module) or modmap.get(module.lower())
            if not ranges:
                continue
            if pc_int is None:
                pc_int = pc_to_int(pc_str)
                if pc_int is None:
                    continue
            for fun_name, (start, end) in ranges.items():
                try:
                    s = int(start)
                    e = int(end)
                except:
                    continue
                if s <= pc_int <= e:
                    return (fw, module, fun_name)
        return raw

    def should_skip(fw, method, module):
        return (fw, method, module) in SKIP_MODULES or (fw, "any", module) in SKIP_MODULES

    # Remap agg_raw into agg applying ranges/groups
    agg = defaultdict(lambda: defaultdict(dict))
    for (fw, module, pc_key), method_dict in agg_raw.items():
        mapped_key = map_key_by_range_and_groups_debug(fw, module, pc_key)
        for method_name, exp_map in method_dict.items():
            if should_skip(fw, method_name, module):
                continue
            for exp, tte in exp_map.items():
                prev = agg[mapped_key][method_name].get(exp)
                if prev is None:
                    agg[mapped_key][method_name][exp] = tte
                elif prev is not None and tte is not None:
                    agg[mapped_key][method_name][exp] = min(prev, tte)

    competitor_names = ["aflnet_base", "aflnet_state_aware", "triforce"]

    # ---------- Table1: Number of crashes ----------
    firmware_set = sorted({k[0] for k in agg.keys()})
    table1_rows = []
    for fw in firmware_set:
        brand, name, version = fw_map.get(fw, ("", fw, ""))
        row = {"brand": brand, "firmware": name, "version": version}
        for m in methods:
            per_run_crashes = defaultdict(set)
            for (f, module, pc), method_dict in agg.items():
                if f != fw:
                    continue
                for exp, tte in method_dict.get(m, {}).items():
                    if tte is not None:
                        per_run_crashes[exp].add((f, module, pc))
            mean_crashes = (sum(len(s) for s in per_run_crashes.values()) / len(per_run_crashes)) if per_run_crashes else 0.0
            row[f"{METHOD_ABBR.get(m, m)}_mean_cnt"] = round(mean_crashes, 3)
        rare_cnt = 0
        for (f, module, pc), method_dict in agg.items():
            if f != fw:
                continue
            staff_found = "staff_state_aware" in method_dict and len(method_dict["staff_state_aware"]) > 0
            competitor_found = any(len(method_dict.get(c, {})) > 0 for c in competitor_names)
            if staff_found and not competitor_found:
                rare_cnt += 1
        row["rare_crashes"] = rare_cnt
        table1_rows.append(row)

    headers1 = ["brand", "firmware", "version"] + [f"{METHOD_ABBR.get(m, m)}_mean_cnt" for m in methods] + ["rare_crashes"]

    # ---------- Table2: TTE crashes and Table3: rare crashes ----------
    def format_time_hm(seconds: float) -> str:
        if seconds is None:
            return ""
        seconds = int(seconds)
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h{m}m"

    table23_rows = []
    table3_rows = []

    for (fw, module, pc), method_dict in sorted(agg.items(), key=lambda x: (x[0][0], x[0][1], str(x[0][2]))):
        brand, name, version = fw_map.get(fw, ("", fw, ""))
        row = {"brand": brand, "firmware": name, "version": version, "module": module, "function": pc}
        for m in methods:
            cnt = len(method_dict.get(m, {}))
            row[f"{METHOD_ABBR.get(m, m)}_cnt"] = cnt
            ttes = [v for v in method_dict.get(m, {}).values() if v is not None]
            avg_tte = (sum(ttes) / len(ttes)) if ttes else None
            row[f"{METHOD_ABBR.get(m, m)}_avg_tte"] = format_time_hm(avg_tte) if avg_tte is not None else ""
        table23_rows.append(row)

        # Rare crashes only
        staff_found = "staff_state_aware" in method_dict and len(method_dict["staff_state_aware"]) > 0
        competitor_found = any(len(method_dict.get(c, {})) > 0 for c in competitor_names)
        if staff_found and not competitor_found:
            rare_row = {"brand": brand, "firmware": name, "version": version, "module": module, "function": pc}
            table3_rows.append(rare_row)

    headers23 = ["brand", "firmware", "version", "module", "function"]
    for m in methods:
        headers23.append(f"{METHOD_ABBR.get(m, m)}_cnt")
        headers23.append(f"{METHOD_ABBR.get(m, m)}_avg_tte")
    headers3 = ["brand", "firmware", "version", "module", "function"]

    # ---------- Write CSV + LaTeX ----------
def build_three_tables_and_write_consistent(
        extracted_root="extracted_crashes_outputs",
        methods=None,
        out1_csv="out1.csv", out1_tex="out1.tex",
        out2_csv="out2.csv", out2_tex="out2.tex",
        out3_csv="out3.csv", out3_tex="out3.tex",
        firmwares_csv="analysis/fw_names.csv",
        verbose=True):
    """
    Build tables and write CSV+LaTeX with three tables:
    - Table1: Number of crashes
    - Table2: TTE crashes
    - Table3: Rare crashes (staff_state_aware only)
    Columns: brand, firmware, version, module, function (for Table2+3)
    """
    import re
    from collections import defaultdict
    import csv

    if methods is None:
        methods = DEFAULT_METHODS

    # Method abbreviations for headers
    METHOD_ABBR = {
        "aflnet_base": "AB",
        "aflnet_state_aware": "ASA",
        "triforce": "TRI",
        "staff_state_aware": "STAFF"
    }

    # Load firmware -> (brand, name, version)
    def load_firmware_map_triplet(path):
        mapping = {}
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                fw_file = row["firmware"].strip()
                brand = row.get("brand", "").strip()
                name = row.get("name", "").strip()
                version = row.get("version", "").strip()
                mapping[fw_file] = (brand, name, version)
        return mapping

    fw_map = load_firmware_map_triplet(firmwares_csv)

    # Build raw aggregation
    agg_raw = build_agg_from_extracted(extracted_root=extracted_root, methods=methods, verbose=verbose)

    # Flatten GROUPS mapping
    member_to_group = {}
    for group in GROUPS:
        if not group:
            continue
        rep = group[0]
        for member in group:
            member_to_group[member] = rep

    # Helper: convert pc string to int
    def pc_to_int(pc_str):
        if pc_str is None:
            return None
        s = str(pc_str).strip()
        try:
            return int(s, 0)
        except:
            m = re.search(r"(0x[0-9a-fA-F]+)", s)
            if m:
                return int(m.group(1), 16)
            m2 = re.search(r"(\d+)", s)
            if m2:
                return int(m2.group(1), 10)
        return None

    # Map raw key into function ranges / GROUPS
    def map_key_by_range_and_groups_debug(fw, module, pc_str):
        raw = (fw, module, pc_str)
        pc_int = pc_to_int(pc_str)
        if raw in member_to_group:
            return member_to_group[raw]
        if pc_int is not None:
            norm_pc = f"0x{pc_int:08x}"
            alt = (fw, module, norm_pc)
            if alt in member_to_group:
                return member_to_group[alt]
        for fw_key, modmap in PC_RANGES.items():
            if fw_key.lower() != fw.lower() and fw_key not in fw and fw not in fw_key:
                continue
            ranges = modmap.get(module) or modmap.get(module.lower())
            if not ranges:
                continue
            if pc_int is None:
                pc_int = pc_to_int(pc_str)
                if pc_int is None:
                    continue
            for fun_name, (start, end) in ranges.items():
                try:
                    s = int(start)
                    e = int(end)
                except:
                    continue
                if s <= pc_int <= e:
                    return (fw, module, fun_name)
        return raw

    def should_skip(fw, method, module):
        return (fw, method, module) in SKIP_MODULES or (fw, "any", module) in SKIP_MODULES

    # Remap agg_raw into agg applying ranges/groups
    agg = defaultdict(lambda: defaultdict(dict))
    for (fw, module, pc_key), method_dict in agg_raw.items():
        mapped_key = map_key_by_range_and_groups_debug(fw, module, pc_key)
        for method_name, exp_map in method_dict.items():
            if should_skip(fw, method_name, module):
                continue
            for exp, tte in exp_map.items():
                prev = agg[mapped_key][method_name].get(exp)
                if prev is None:
                    agg[mapped_key][method_name][exp] = tte
                elif prev is not None and tte is not None:
                    agg[mapped_key][method_name][exp] = min(prev, tte)

    competitor_names = ["aflnet_base", "aflnet_state_aware", "triforce"]

    # ---------- Table1: Number of crashes ----------
    firmware_set = sorted({k[0] for k in agg.keys()})
    table1_rows = []

    for fw in firmware_set:
        brand, name, version = fw_map.get(fw, ("", fw, ""))
        row = {"brand": brand, "firmware": name, "version": version}

        # Compute mean crashes per method
        for m in methods:
            per_run_crashes = defaultdict(set)
            for (f, module, pc), method_dict in agg.items():
                if f != fw:
                    continue
                for exp, tte in method_dict.get(m, {}).items():
                    if tte is not None:
                        per_run_crashes[exp].add((f, module, pc))
            mean_crashes = (
                sum(len(s) for s in per_run_crashes.values()) / len(per_run_crashes)
                if per_run_crashes else 0.0
            )
            # Use abbreviation for the column name
            col_name = f"{METHOD_ABBR.get(m, m)}_mean_cnt"
            row[col_name] = round(mean_crashes, 3)

        # Compute "rare crashes"
        rare_cnt = 0
        for (f, module, pc), method_dict in agg.items():
            if f != fw:
                continue
            staff_found = "staff_state_aware" in method_dict and len(method_dict["staff_state_aware"]) > 0
            competitor_found = any(len(method_dict.get(c, {})) > 0 for c in competitor_names)
            if staff_found and not competitor_found:
                rare_cnt += 1
        row["rare_crashes"] = rare_cnt
        table1_rows.append(row)

    # Table headers using abbreviations
    headers1 = ["brand", "firmware", "version"] + [f"{METHOD_ABBR.get(m, m)}_mean_cnt" for m in methods] + ["rare_crashes"]

    # ---------- Table2: TTE crashes and Table3: rare crashes ----------
    def format_time_hm(seconds: float) -> str:
        if seconds is None:
            return ""
        seconds = int(seconds)
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h{m}m"

    table23_rows = []
    table3_rows = []

    for (fw, module, pc), method_dict in sorted(agg.items(), key=lambda x: (x[0][0], x[0][1], str(x[0][2]))):
        brand, name, version = fw_map.get(fw, ("", fw, ""))
        # row = {"brand": brand, "firmware": name, "version": version, "module": module, "function": pc}
        row = {"firmware": name, "module": module, "function": pc}
        for m in methods:
            cnt = len(method_dict.get(m, {}))
            row[f"{METHOD_ABBR.get(m, m)}_cnt"] = cnt
            ttes = [v for v in method_dict.get(m, {}).values() if v is not None]
            avg_tte = (sum(ttes) / len(ttes)) if ttes else None
            row[f"{METHOD_ABBR.get(m, m)}_avg_tte"] = format_time_hm(avg_tte) if avg_tte is not None else ""
        table23_rows.append(row)

        # Rare crashes only
        staff_found = "staff_state_aware" in method_dict and len(method_dict["staff_state_aware"]) > 0
        competitor_found = any(len(method_dict.get(c, {})) > 0 for c in competitor_names)
        if staff_found and not competitor_found:
            rare_row = {"brand": brand, "firmware": name, "version": version, "module": module, "function": pc}
            table3_rows.append(rare_row)

    # headers23 = ["brand", "firmware", "version", "module", "function"]
    headers23 = ["firmware", "module", "function"]
    for m in methods:
        headers23.append(f"{METHOD_ABBR.get(m, m)}_cnt")
        headers23.append(f"{METHOD_ABBR.get(m, m)}_avg_tte")
    headers3 = ["brand", "firmware", "version", "module", "function"]

    # ---------- Write CSV + LaTeX ----------
    def write_pair(headers, rows, csv_path, tex_path, caption="", count_tte_table=False):
        import pandas as pd
        pd = pd if "pd" in globals() else None

        def latex_escape(s):
            if s is None:
                return ""
            s = str(s).replace("_", "\\_")
            s = s.replace("mean\\_", "\\(\\mu\\)")
            s = s.replace("avg\\_", "\\(\\mu\\)")
            return s

        if pd is not None and rows:
            df = pd.DataFrame(rows)
            for h in headers:
                if h not in df.columns:
                    df[h] = None
            df = df[headers]
            df.to_csv(csv_path, index=False, encoding="utf-8")

            with open(tex_path, "w", encoding="utf-8") as fh:
                fh.write("\\begin{table*}[ht]\n\\centering\n")
                col_format = "l" * len(headers) if not count_tte_table else "l" * 3 + "cc" * len(methods)
                fh.write(f"\\begin{{tabular}}{{{col_format}}}\n")

                if count_tte_table:
                    first_row = ["firmware", "module", "function"]
                    for m in methods:
                        abbr = METHOD_ABBR.get(m, m)
                        first_row.append(f"\\multicolumn{{2}}{{c}}{{{latex_escape(abbr)}}}")
                    fh.write(" & ".join(first_row) + " \\\\\n")
                    second_row = [""] * 3
                    for _ in methods:
                        second_row.append("cnt")
                        second_row.append("TTE")
                    fh.write(" & ".join(second_row) + " \\\\\n\\hline\n")
                else:
                    fh.write(" & ".join(latex_escape(h) for h in headers) + " \\\\\n\\hline\n")

                # --- Write rows ---
                for row in rows:
                    if count_tte_table:
                        values = [latex_escape(row.get(h, "")) for h in ["firmware","module","function"]]
                        for m in methods:
                            abbr = METHOD_ABBR.get(m, m)
                            values.append(str(row.get(f"{abbr}_cnt", "")))
                            values.append(str(row.get(f"{abbr}_avg_tte", "")))
                    else:
                        values = [latex_escape(row.get(h, "")) for h in headers]
                    fh.write(" & ".join(values) + " \\\\\n")

                fh.write("\\end{tabular}\n")
                if caption:
                    fh.write(f"\\caption{{{latex_escape(caption)}}}\n")
                fh.write("\\end{table*}\n")

            if pd is not None:
                print(f"[WRITE] CSV -> {csv_path} ; LaTeX -> {tex_path}")

    write_pair(headers1, table1_rows, out1_csv, out1_tex, caption="Number of crashes")
    write_pair(headers23, table23_rows, out2_csv, out2_tex, caption="TTE crashes", count_tte_table=True)
    write_pair(headers3, table3_rows, out3_csv, out3_tex, caption="Rare crashes")

    return (table1_rows, table23_rows, table3_rows), agg


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Copy crashes from experiments_dir to extracted_root, then annotate files with $<tte> based on plot_data/fuzzer_stats."
    )
    parser.add_argument("experiments_dir", help="Path to directory containing exp_* directories.")
    parser.add_argument("--extracted_root", default="extracted_crashes_outputs",
                        help="Destination root to update/annotate.")
    parser.add_argument("--update", action="store_true",
                        help="Do not copy crashes into extracted_root; operate only on existing extracted_root.")
    parser.add_argument("--annotate", action="store_true",
                        help="Do not run TTE annotation after copying.")
    parser.add_argument("--quiet", action="store_true", help="Reduce verbosity.")
    parser.add_argument("--crashes-csv", default="crashes.csv",
                        help="CSV file containing PC ranges / function mapping (default: crashes.csv)")
    parser.add_argument("--pc-ranges-py", default="pc_ranges_generated.py",
                        help="Output Python file to write PC_RANGES literal to (default: pc_ranges_generated.py)")

    args = parser.parse_args()
    verbose = not args.quiet

    # load/generate PC_RANGES from the provided CSV
    try:
        PC_RANGES = load_pc_ranges_from_csv(args.crashes_csv, output_py=args.pc_ranges_py, verbose=verbose)
    except Exception as e:
        print(f"[ERROR] cannot load PC ranges from '{args.crashes_csv}': {e}")
        raise SystemExit(1)

    # debug: show loaded ranges (pause if you still want to inspect)
    print("Loaded PC_RANGES (top-level keys):", list(PC_RANGES.keys()))
    # print full mapping if you need:
    if verbose:
        import pprint
        pprint.pprint(PC_RANGES)
    # input("PC_RANGES loaded — press Enter to continue...")
    
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

    build_three_tables_and_write_consistent(
        extracted_root="extracted_crashes_outputs",
        methods=None,
        out1_csv="out1.csv", out1_tex="out1.tex",
        out2_csv="out2.csv", out2_tex="out2.tex",
        out3_csv="out3.csv", out3_tex="out3.tex",
        verbose=True
    )

    chmod_recursive(args.extracted_root, 0o777)
