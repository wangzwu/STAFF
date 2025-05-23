#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd

BASE_DIR = "experiments"
OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

METRICS = ["bitmap_cvg", "unique_crashes", "unique_hangs", "paths_total", "paths_favored", "execs_done"]

def parse_fuzzer_stats(path):
    data = {}
    with open(path) as f:
        for line in f:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip().rstrip('%')
            if key in METRICS:
                try:
                    data[key] = float(val)
                except ValueError:
                    data[key] = 0.0
    return data

agg = defaultdict(lambda: defaultdict(list))
valid_experiments = 0

for exp_dir in sorted(glob.glob(os.path.join(BASE_DIR, "exp_*"))):
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

    stats = parse_fuzzer_stats(stats_path)
    if stats.get("execs_done", 0.0) <= 0:
        continue

    valid_experiments += 1
    key = (firmware, mode)
    for m in METRICS:
        agg[key][m].append(stats.get(m, 0.0))

if not valid_experiments:
    exit(1)

rows = []
for (firmware, mode), metrics in agg.items():
    row = {"Firmware": firmware, "Mode": mode}
    for m in METRICS:
        vals = metrics[m]
        if m == "bitmap_cvg":
            row[f"{m}_avg"] = round(sum(vals) / len(vals), 4)
        else:
            row[f"{m}_avg"] = int(round(sum(vals) / len(vals)))
    rows.append(row)

df_fw_mode = pd.DataFrame(rows).sort_values(["Firmware", "Mode"])
out1 = os.path.join(OUTPUT_DIR, "per_firmware_mode.csv")
df_fw_mode.to_csv(out1, index=False)

rows = []
for mode, group in df_fw_mode.groupby("Mode"):
    row = {"Mode": mode}
    for m in METRICS:
        if m == "bitmap_cvg":
            row[f"{m}_avg"] = round(group[f"{m}_avg"].mean(), 4)
        else:
            row[f"{m}_sum"] = int(group[f"{m}_avg"].sum())
    rows.append(row)

df_mode = pd.DataFrame(rows).sort_values("Mode")
out2 = os.path.join(OUTPUT_DIR, "per_mode_aggregate.csv")
df_mode.to_csv(out2, index=False)

print("\nPer-Firmware/Mode Averages:")
print(df_fw_mode)

print("\nPer-Mode Aggregated Totals:")
print(df_mode)
