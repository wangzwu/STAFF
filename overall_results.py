#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd

BASE_DIR = "experiments"
OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

TOOLS = ["aflnet_base", "aflnet_state_aware", "staff_base", "staff_state_aware", "triforce"]
TOOL_RANK = {
    "aflnet_base": -1,
    "aflnet_state_aware": -2,
    "triforce": -3,
    "staff_base": 1,
    "staff_state_aware": 2,
}

METRICS = ["bitmap_cvg", "unique_crashes", "unique_hangs", "paths_total", "paths_favored", "execs_done"]
BASELINE_EXPERIMENTS = "0,1,2,5,6,7,10,11,12,15,16,17,20,21,22,25,26,27,"
STAFF_EDGE = "3,4,8,9,13,14,18,19,23,24,28,29"
STAFF_TAINT_BLOCK = "42-53"
INCLUDE_EXPERIMENTS = BASELINE_EXPERIMENTS+STAFF_TAINT_BLOCK

def parse_range_list(skip_str):
    include_set = set()
    for part in skip_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            include_set.update(range(start, end + 1))
        else:
            include_set.add(int(part))
    return include_set

def parse_fuzzer_stats(path, fallback_path=None, force_time_fallback=False):
    data = {}
    start_time = None
    last_update = None

    def load_times_from(path):
        nonlocal start_time, last_update
        with open(path) as f:
            for line in f:
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                key = key.strip()
                val = val.strip().rstrip('%')
                if key == "start_time":
                    try:
                        start_time = int(val)
                    except ValueError:
                        pass
                elif key == "last_update":
                    try:
                        last_update = int(val)
                    except ValueError:
                        pass

    with open(path) as f:
        for line in f:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip().rstrip('%')
            try:
                if key == "start_time":
                    start_time = int(val)
                elif key == "last_update":
                    last_update = int(val)
                elif key in METRICS:
                    data[key] = float(val)
            except ValueError:
                pass

    if force_time_fallback and fallback_path:
        load_times_from(fallback_path)

    if start_time and last_update:
        data["run_time"] = float(last_update - start_time)
    else:
        data["run_time"] = 0.0

    return data

agg = defaultdict(lambda: defaultdict(list))
valid_experiments = 0
firmwares = set()
include_set = parse_range_list(INCLUDE_EXPERIMENTS)

for exp_dir in sorted(glob.glob(os.path.join(BASE_DIR, "exp_*"))):
    exp_name = os.path.basename(exp_dir)
    try:
        exp_id = int(exp_name.split("_")[1])
        if exp_id not in include_set:
            continue
    except (IndexError, ValueError):
        continue

    cfg_path = os.path.join(exp_dir, "outputs", "config.ini")
    stats_path = os.path.join(exp_dir, "outputs", "fuzzer_stats")

    if not os.path.isfile(cfg_path) or not os.path.isfile(stats_path):
        continue

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)
    if "GENERAL" not in cfg or "firmware" not in cfg["GENERAL"] or "mode" not in cfg["GENERAL"]:
        continue

    firmware = cfg["GENERAL"]["firmware"]
    mode = cfg["GENERAL"]["mode"]

    if mode not in TOOLS:
        continue

    old_stats_path = os.path.join(exp_dir, "outputs", "old_fuzzer_stats") if mode == "triforce" else None
    stats = parse_fuzzer_stats(stats_path, fallback_path=old_stats_path, force_time_fallback=(mode == "triforce"))
    if stats.get("execs_done", 0.0) <= 0:
        continue

    valid_experiments += 1
    firmwares.add(firmware)
    key = (firmware, mode)
    for m in METRICS + ["run_time"]:
        agg[key][m].append(stats.get(m, 0.0))

if not valid_experiments:
    exit(1)

rows = []

empty_template = {"winner": "", "Firmware": "", "Mode": ""}
empty_template.update({f"{m}_avg": "" for m in METRICS})
empty_template["run_time_avg"] = ""
rows.append(empty_template)

for firmware in sorted(firmwares):
    tool_rows = {}
    for tool in TOOLS:
        key = (firmware, tool)
        row = {"Firmware": firmware, "Mode": tool}

        if key in agg:
            metrics = agg[key]
            for m in METRICS:
                vals = metrics[m]
                avg_val = sum(vals) / len(vals) if vals else 0.0
                row[f"{m}_avg"] = round(avg_val, 4) if m == "bitmap_cvg" else int(round(avg_val))
            row["run_time_avg"] = int(round(sum(metrics["run_time"]) / len(metrics["run_time"])))
        else:
            for m in METRICS:
                row[f"{m}_avg"] = 0 if m != "bitmap_cvg" else 0.0
            row["run_time_avg"] = 0

        tool_rows[tool] = row

    def score(tool):
        r = tool_rows[tool]
        return (
            r["unique_crashes_avg"],
            r["bitmap_cvg_avg"],
            TOOL_RANK[tool]
        )

    scores = {tool: score(tool) for tool in TOOLS}
    max_crashes = max(s[0] for s in scores.values())
    tied_on_crashes = [t for t, s in scores.items() if s[0] == max_crashes]

    max_bitmap = max(scores[t][1] for t in tied_on_crashes)
    tied_finalists = [t for t in tied_on_crashes if scores[t][1] == max_bitmap]

    legacy = ["triforce", "aflnet_base", "aflnet_state_aware"]
    staff = ["staff_base", "staff_state_aware"]

    best_legacy = max((tool_rows[t] for t in legacy), key=lambda r: r["bitmap_cvg_avg"])
    best_staff = max((tool_rows[t] for t in staff), key=lambda r: r["bitmap_cvg_avg"])

    abs_diff = abs(best_legacy["bitmap_cvg_avg"] - best_staff["bitmap_cvg_avg"])
    rel_diff = abs_diff / max(best_legacy["bitmap_cvg_avg"], 1e-6)

    legacy_crashes = max(tool_rows[t]["unique_crashes_avg"] for t in legacy)
    staff_crashes = max(tool_rows[t]["unique_crashes_avg"] for t in staff)

    # if legacy_crashes == staff_crashes and (abs_diff < 1.0 or rel_diff < 0.05):
    if legacy_crashes == staff_crashes and (rel_diff < 0.05):
        winner_rank = 0
    elif len(tied_finalists) > 1 and any(TOOL_RANK[t] > 0 for t in tied_finalists) and any(TOOL_RANK[t] < 0 for t in tied_finalists):
        winner_rank = 0
    else:
        winner_tool = max(tied_finalists, key=lambda t: TOOL_RANK[t])
        winner_rank = TOOL_RANK[winner_tool]

    for tool in TOOLS:
        row = tool_rows[tool]
        row["winner"] = winner_rank
        reordered = {"winner": row["winner"], "Firmware": row["Firmware"], "Mode": row["Mode"]}
        reordered.update({k: v for k, v in row.items() if k not in reordered})
        rows.append(reordered)

    rows.append({k: "" for k in rows[-1].keys()})

df_fw_mode = pd.DataFrame(rows)

out1 = os.path.join(OUTPUT_DIR, "per_firmware_mode.csv")
df_fw_mode.to_csv(out1, index=False)

rows = []
for mode, group in df_fw_mode[df_fw_mode["Firmware"] != ""].groupby("Mode"):
    row = {"Mode": mode}
    for m in METRICS:
        if m == "bitmap_cvg":
            row[f"{m}_avg"] = round(group[f"{m}_avg"].astype(float).mean(), 4)
        else:
            row[f"{m}_sum"] = int(group[f"{m}_avg"].astype(float).sum())
    row["run_time_avg"] = int(round(group["run_time_avg"].astype(float).mean()))
    rows.append(row)

df_mode = pd.DataFrame(rows).sort_values("Mode")
out2 = os.path.join(OUTPUT_DIR, "per_mode_aggregate.csv")
df_mode.to_csv(out2, index=False)

print("\nPer-Firmware/Mode Averages:")
print(df_fw_mode)

print("\nPer-Mode Aggregated Totals:")
print(df_mode)
