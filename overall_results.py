#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd

BASE_DIR = "experiments"
OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

METRICS = ["bitmap_cvg", "unique_crashes", "unique_hangs", "paths_total", "paths_favored"]
WEIGHT = "execs_done"

def parse_fuzzer_stats(path):
    data = {}
    with open(path) as f:
        for line in f:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip().rstrip('%')
            if key in METRICS + [WEIGHT]:
                try:
                    data[key] = float(val)
                except ValueError:
                    data[key] = 0.0
    return data

agg = defaultdict(lambda: {w: 0.0 for w in METRICS + [WEIGHT]})
valid_experiments = 0

for exp_dir in sorted(glob.glob(os.path.join(BASE_DIR, "exp_*"))):
    print(f"\nChecking {exp_dir}")
    cfg_path = os.path.join(exp_dir, "outputs", "config.ini")
    stats_path = os.path.join(exp_dir, "outputs", "fuzzer_stats")

    if not os.path.isfile(cfg_path):
        print("  -> MISSING config.ini")
        continue
    if not os.path.isfile(stats_path):
        print("  -> MISSING fuzzer_stats")
        continue

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)
    if "GENERAL" not in cfg or "firmware" not in cfg["GENERAL"] or "mode" not in cfg["GENERAL"]:
        print("  -> INVALID config.ini")
        continue

    firmware = cfg["GENERAL"]["firmware"]
    mode = cfg["GENERAL"]["mode"]

    stats = parse_fuzzer_stats(stats_path)
    w = stats.get(WEIGHT, 0.0)
    if w <= 0:
        print("  -> ZERO execs_done")
        continue

    print("  -> OK ✅")
    valid_experiments += 1

    key = (firmware, mode)
    agg[key][WEIGHT] += w
    for m in METRICS:
        agg[key][m] += stats.get(m, 0.0) * w

if not valid_experiments:
    print("\nNo valid experiments found.")
    exit(1)

rows = []
for (firmware, mode), vals in agg.items():
    total_w = vals[WEIGHT]
    row = {
        "Firmware": firmware,
        "Mode": mode,
        f"{WEIGHT}_sum": int(total_w),
    }
    for m in METRICS:
        if m == "bitmap_cvg":
            row[f"{m}_avg"] = round(vals[m] / total_w, 4) if total_w > 0 else 0.0
        else:
            row[f"{m}_sum"] = int(round(vals[m]))
    rows.append(row)

df_fw_mode = pd.DataFrame(rows).sort_values(["Firmware", "Mode"])
out1 = os.path.join(OUTPUT_DIR, "per_firmware_mode.csv")
df_fw_mode.to_csv(out1, index=False)
print(f"\n-> saved per-firmware/mode table to {out1}")

rows = []
for mode, group in df_fw_mode.groupby("Mode"):
    row = {"Mode": mode}
    total_w = group[f"{WEIGHT}_sum"].sum()
    row[f"{WEIGHT}_sum"] = int(total_w)
    for m in METRICS:
        if m == "bitmap_cvg":
            val = (group[f"{m}_avg"] * group[f"{WEIGHT}_sum"]).sum() / total_w
            row[f"{m}_avg"] = round(val, 4)
        else:
            row[f"{m}_sum"] = int(group[f"{m}_sum"].sum())
    rows.append(row)

df_mode = pd.DataFrame(rows).sort_values("Mode")
out2 = os.path.join(OUTPUT_DIR, "per_mode_aggregate.csv")
df_mode.to_csv(out2, index=False)
print(f"-> saved per-mode aggregate table to {out2}")

print("\nPer-Firmware/Mode weighted results:")
try:
    print(df_fw_mode.to_markdown(index=False))
except ImportError:
    print(df_fw_mode)

print("\nPer-Mode aggregate results:")
try:
    print(df_mode.to_markdown(index=False))
except ImportError:
    print(df_mode)
