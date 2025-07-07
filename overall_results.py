#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd
from scipy.stats import mannwhitneyu
import re

BLACKBOX = ["neaps_array", "ethlink", "aparraymsg"]

BASE_DIRS = [
    "experiments_done/baseline",
    "experiments_done/staff_state_aware_0_block"
]
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

METRICS = [
    "bitmap_cvg", "unique_crashes_direct", "unique_crashes_indirect",
    "unique_crashes_none", "unique_crashes_total", "unique_hangs", "paths_total",
    "paths_favored", "execs_done"
]
BASELINE_TOOLS = ["aflnet_base", "aflnet_state_aware", "triforce"]
STAFF_TOOLS    = ["staff_base", "staff_state_aware"]

INCLUDE_EXPERIMENTS = None

A12_LOWER_THRESHOLD = 0.44
A12_UPPER_THRESHOLD = 0.56

def effect_size_a12(x, y):
    n_x, n_y = len(x), len(y)
    ranks = pd.Series(x + y).rank()
    r_x = ranks.iloc[:n_x].sum()
    return (r_x / n_x - (n_x + 1) / 2) / n_y

def parse_range_list(rng):
    if not rng:
        return None
    s = set()
    for part in rng.split(","):
        if "-" in part:
            a,b = map(int, part.split("-"))
            s.update(range(a,b+1))
        elif part.strip():
            s.add(int(part))
    return s

def parse_fuzzer_stats(path, fallback_path=None, force_time_fallback=False):
    data, start, last = {}, None, None
    def load_times(p):
        nonlocal start, last
        if not os.path.exists(p): return 1
        for ln in open(p):
            if ":" not in ln: continue
            k,v = ln.split(":",1); k,v=k.strip(),v.strip().rstrip('%')
            if k=="start_time":
                try: start=int(v)
                except: pass
            elif k=="last_update":
                try: last=int(v)
                except: pass
        return 0
    for ln in open(path):
        if ":" not in ln: continue
        k,v = ln.split(":",1); k,v=k.strip(),v.strip().rstrip('%')
        try:
            if k=="start_time":     start=int(v)
            elif k=="last_update":  last=int(v)
            elif k in METRICS:      data[k]=float(v)
        except: pass
    if force_time_fallback and fallback_path and load_times(fallback_path):
        return None
    data["run_time"] = float((last or 0) - (start or 0))
    return data

def count_crashes_from_traces(exp_dir):
    traces_dir = os.path.join(exp_dir, "outputs", "crash_traces")
    queue_dir  = os.path.join(exp_dir, "outputs", "queue")
    if not os.path.isdir(traces_dir):
        return 0.0, 0.0, 0.0

    id_to_queue = {}
    for fn in os.listdir(queue_dir):
        parts = fn.split(":",1)
        if len(parts)<2: 
            continue
        after = parts[1]
        m = re.match(r"([0-9]+)&[01]", after)
        if m:
            _id = m.group(1)
            id_to_queue[_id] = os.path.join(queue_dir, fn)

    def is_indirect_trace(txt, visited):
        for sid in re.findall(r"src:([0-9]+)", txt):
            if sid in visited:
                continue
            visited.add(sid)
            qpath = id_to_queue.get(sid)
            if not qpath:
                continue
            if "&1" in os.path.basename(qpath):
                return True
            try:
                subtxt = open(qpath, "r", errors="ignore").read()
            except:
                continue
            if is_indirect_trace(subtxt, visited):
                return True
        return False

    direct_cr = indirect_cr = none_cr = 0.0

    for tf in os.listdir(traces_dir):
        tp = os.path.join(traces_dir, tf)
        if not os.path.isfile(tp):
            continue
        txt = open(tp, "r", errors="ignore").read()
        crash_count = txt.count("Process: ")

        if "&1" in tf:
            direct_cr += crash_count
        else:
            if is_indirect_trace(txt, visited=set()):
                indirect_cr += crash_count
            else:
                none_cr += crash_count

    return direct_cr, indirect_cr, none_cr

def read_config(exp_dir):
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(exp_dir,"outputs","config.ini"))
    return cfg.get("GENERAL","firmware"), cfg.get("GENERAL","mode")

agg_ids = defaultdict(list)
agg = defaultdict(lambda: defaultdict(list))
include_set = parse_range_list(INCLUDE_EXPERIMENTS)
valid = 0
firmwares = set()

for base in BASE_DIRS:
    for exp in sorted(glob.glob(os.path.join(base,"exp_*"))):
        nm = os.path.basename(exp)
        try:
            eid = int(nm.split("_",1)[1])
            if include_set and eid not in include_set:
                continue
        except: pass

        cfgp = os.path.join(exp,"outputs","config.ini")
        statp= os.path.join(exp,"outputs","fuzzer_stats")
        if not os.path.isfile(cfgp) or not os.path.isfile(statp):
            continue

        fw, mode = read_config(exp)
        if mode not in TOOLS:
            continue

        stats = parse_fuzzer_stats(
            statp,
            fallback_path=os.path.join(exp,"outputs","old_fuzzer_stats") if mode=="triforce" else None,
            force_time_fallback=(mode=="triforce")
        )
        if not stats:
            continue

        agg_ids[(fw, mode)].append(eid)

        direct_cr, indirect_cr, none_cr = count_crashes_from_traces(exp)
        total_cr = direct_cr + indirect_cr + none_cr

        valid += 1
        firmwares.add(fw)
        key = (fw, mode)

        agg[key]["unique_crashes_direct"].append(direct_cr)
        agg[key]["unique_crashes_indirect"].append(indirect_cr)
        agg[key]["unique_crashes_none"].append(none_cr)
        agg[key]["unique_crashes_total"].append(total_cr)

        for m in [x for x in METRICS if not x.startswith("unique_crashes")]:
            agg[key][m].append(stats.get(m, 0.0))
        agg[key]["run_time"].append(stats["run_time"])

if valid == 0:
    exit(1)

summary = {}
for (fw, mode), vals in agg.items():
    n = len(vals["run_time"])
    row = {"num_experiments": n}
    for m in METRICS + ["run_time"]:
        col = f"{m}_avg"
        if vals[m]:
            avg = sum(vals[m]) / n
        else:
            avg = 0.0
        row[col] = round(avg,4) if m=="bitmap_cvg" else int(round(avg))
    summary[(fw,mode)] = row

results = []
columns = [
    "winner", "Firmware", "Mode", "num_experiments",
    *[f"{m}_avg" for m in METRICS],
    "run_time_avg", "best_baseline",
    "bitmap_cvg_p_value_with_best", "bitmap_cvg_A12_with_best",
    "unique_crashes_direct_p_value_with_best", "unique_crashes_direct_A12_with_best"
]

for fw in sorted(firmwares):
    results.append({col: "" for col in columns})

    base_modes = [
        mode for mode in TOOLS
        if mode in BASELINE_TOOLS
           and summary.get((fw, mode), {}).get("num_experiments", 0) > 0
    ]
    if not base_modes:
        chosen = None
        winner = 0
        best_base = ""
        best_base_cr = best_base_cvg = []
    else:
        base_modes.sort(
            key=lambda t: (
                summary[(fw,t)]["unique_crashes_total_avg"],
                summary[(fw,t)]["bitmap_cvg_avg"]
            ),
            reverse=True
        )
        best_base     = base_modes[0]
        best_base_cr  = agg[(fw,best_base)]["unique_crashes_direct"]
        best_base_cvg = agg[(fw,best_base)]["bitmap_cvg"]

        staff_modes = [m for m in TOOLS if m in STAFF_TOOLS]
        has_staff = any(
            summary.get((fw,s),{}).get("num_experiments",0)>0
            for s in staff_modes
        )
        if not has_staff:
            chosen = best_base
            winner = TOOL_RANK[best_base]
            best_staff_cr = best_staff_cvg = []
        else:
            staff_modes = [
                s for s in staff_modes
                if summary.get((fw,s),{}).get("num_experiments",0)>0
            ]
            staff_modes.sort(
                key=lambda t: (
                    summary[(fw,t)]["unique_crashes_total_avg"],
                    summary[(fw,t)]["bitmap_cvg_avg"]
                ),
                reverse=True
            )
            best_staff     = staff_modes[0]
            best_staff_cr  = agg[(fw,best_staff)]["unique_crashes_direct"]
            best_staff_cvg = agg[(fw,best_staff)]["bitmap_cvg"]

            a12_cr = effect_size_a12(best_staff_cr, best_base_cr)
            if A12_LOWER_THRESHOLD <= a12_cr <= A12_UPPER_THRESHOLD:
                a12 = effect_size_a12(best_staff_cvg, best_base_cvg)
            else:
                a12 = a12_cr

            if   a12 <  A12_LOWER_THRESHOLD:
                chosen = best_base
            elif a12 >  A12_UPPER_THRESHOLD:
                chosen = best_staff
            else:
                chosen = None
            winner = TOOL_RANK[chosen] if chosen else 0

    for mode in TOOLS:
        run_count = len( agg.get((fw,mode),{}).get("bitmap_cvg", []) )
        out = {
            "winner": winner,
            "Firmware": fw,
            "Mode": mode,
            "num_experiments": run_count,
            "best_baseline": best_base
        }

        for m in METRICS:
            out[f"{m}_avg"] = summary.get((fw,mode),{}).get(f"{m}_avg", "")
        out["run_time_avg"] = summary.get((fw,mode),{}).get("run_time_avg", "")

        vals_c = agg.get((fw,mode),{}).get("bitmap_cvg",[])
        vals_cr = agg.get((fw,mode),{}).get("unique_crashes_direct",[])
        if vals_c and best_base_cvg:
            out["bitmap_cvg_p_value_with_best"] = round(mannwhitneyu(vals_c, best_base_cvg).pvalue,4)
            out["bitmap_cvg_A12_with_best"]     = round(effect_size_a12(vals_c, best_base_cvg),4)
        else:
            out["bitmap_cvg_p_value_with_best"] = ""
            out["bitmap_cvg_A12_with_best"]     = ""
        if vals_cr and best_base_cr:
            out["unique_crashes_direct_p_value_with_best"] = round(mannwhitneyu(vals_cr, best_base_cr).pvalue,4)
            out["unique_crashes_direct_A12_with_best"]     = round(effect_size_a12(vals_cr, best_base_cr),4)
        else:
            out["unique_crashes_direct_p_value_with_best"] = ""
            out["unique_crashes_direct_A12_with_best"]     = ""

        results.append(out)

final_df = pd.DataFrame(results)
final_df.to_csv(os.path.join(OUTPUT_DIR,"per_firmware_mode.csv"), index=False)

print("\nPer-Firmware/Mode Averages:")
print(final_df)
