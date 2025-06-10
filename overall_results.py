#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd
from itertools import combinations
from math import log
from scipy.stats import mannwhitneyu, chi2

BASE_DIR   = "experiments"
OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

TOOLS = ["aflnet_base","aflnet_state_aware","staff_base","staff_state_aware","triforce"]
TOOL_RANK = {"aflnet_base":-1,"aflnet_state_aware":-2,"triforce":-3,
             "staff_base":1,"staff_state_aware":2}

METRICS = ["unique_crashes","unique_hangs","paths_total","paths_favored","execs_done"]
INCLUDE_EXPERIMENTS = None

def parse_range_list(spec):
    if not spec: return None
    s = set()
    for part in spec.split(","):
        if not part: continue
        if "-" in part:
            a,b = map(int, part.split("-"))
            s.update(range(a,b+1))
        else:
            s.add(int(part))
    return s

def parse_fuzzer_stats(path, fallback_path=None, force_time_fallback=False):
    data = {}
    start = last = None

    def _parse_file(p):
        nonlocal start, last
        with open(p) as f:
            for line in f:
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                key = key.strip()
                val = val.strip().rstrip('%')

                if key == "start_time":
                    try:
                        start = int(val)
                    except ValueError:
                        pass
                    continue
                if key == "last_update":
                    try:
                        last = int(val)
                    except ValueError:
                        pass
                    continue

                if key in METRICS:
                    try:
                        data[key] = float(val)
                    except ValueError:
                        pass

    _parse_file(path)

    if force_time_fallback and fallback_path and os.path.isfile(fallback_path):
        _parse_file(fallback_path)

    if start is not None and last is not None:
        data["run_time"] = float(last - start)
    else:
        data["run_time"] = 0.0

    return data

agg_stats = defaultdict(lambda: defaultdict(list))
agg_plot  = defaultdict(list)
firmwares = set()
include    = parse_range_list(INCLUDE_EXPERIMENTS)
valid=0

for d in sorted(glob.glob(os.path.join(BASE_DIR,"exp_*"))):
    try:
        eid = int(os.path.basename(d).split("_")[1])
        if include and eid not in include: continue
    except: continue

    outdir = os.path.join(d,"outputs")
    statf  = os.path.join(outdir,"fuzzer_stats")
    plotf  = os.path.join(outdir,"plot_data")
    cfgf   = os.path.join(outdir,"config.ini")
    if not all(os.path.isfile(p) for p in (statf, plotf, cfgf)):
        continue

    cfg = configparser.ConfigParser()
    cfg.read(cfgf)
    if "GENERAL" not in cfg or "firmware" not in cfg["GENERAL"] or "mode" not in cfg["GENERAL"]:
        continue

    fw   = cfg["GENERAL"]["firmware"]
    mode = cfg["GENERAL"]["mode"]
    if mode not in TOOLS:
        continue

    oldf = os.path.join(outdir,"old_fuzzer_stats") if mode=="triforce" else None
    stats = parse_fuzzer_stats(statf, fallback_path=oldf, force_time_fallback=(mode=="triforce"))
    if stats.get("execs_done",0) <= 0:
        continue
    
    if (mode == "triforce"):
        dfp = pd.read_csv(plotf, comment="#", 
                        names=["unix_time","paths_total","map_size","unique_crashes",
                        "unique_hangs","stability","n_calibration"])
    else:
        dfp = pd.read_csv(plotf, comment="#", 
                        names=["unix_time","cycles_done","execs_done","cur_path",
                                "paths_total","pending_total","pending_favs",
                                "map_size","unique_crashes","unique_hangs",
                                "max_depth","execs_per_sec","stability",
                                "n_fetched_random_hints","n_fetched_state_hints",
                                "n_fetched_taint_hints","n_calibration"])

    dfp["map_size"] = dfp["map_size"].str.rstrip("%").astype(float)
    series = dfp["map_size"].tolist()

    valid += 1
    firmwares.add(fw)
    key = (fw, mode)

    for m in METRICS + ["run_time"]:
        agg_stats[key][m].append(stats.get(m,0.0))
    agg_plot[key].append(series)

if valid==0:
    print("exit(1)")
    exit(1)

rows = []

hdr = {"winner":"","Firmware":"","Mode":"","num_experiments":""}
hdr.update({f"{m}_avg":"" for m in METRICS})
hdr["run_time_avg"] = ""
hdr["bitmap_cvg_p_consistency"] = ""
rows.append(hdr)

for fw in sorted(firmwares):
    tool_rows = {}

    for t in TOOLS:
        key = (fw,t)
        row = {"Firmware":fw,"Mode":t}
        if key in agg_stats:
            vals = agg_stats[key]
            for m in METRICS:
                avg = sum(vals[m])/len(vals[m]) if vals[m] else 0.0
                row[f"{m}_avg"] = int(round(avg))
            row["run_time_avg"] = int(round(sum(vals["run_time"])/len(vals["run_time"])))
            row["num_experiments"] = len(vals[METRICS[0]])
        else:
            for m in METRICS:
                row[f"{m}_avg"] = 0
            row["run_time_avg"] = 0
            row["num_experiments"] = 0
        tool_rows[t] = row

    for t in TOOLS:
        series_list = agg_plot.get((fw,t), [])
        pvals = []

        for s1, s2 in combinations(series_list, 2):
            L = min(len(s1), len(s2))
            if L<1:
                continue
            a = s1[:L]; b = s2[:L]
            _, p = mannwhitneyu(a, b, alternative="two-sided")
            pvals.append(max(min(p,1.0),0.0))

        if pvals:
            chi2_stat = -2 * sum(log(p) for p in pvals if p>0)
            df        = 2*len(pvals)
            combined  = chi2.sf(chi2_stat, df)
            row_p     = round(combined,4)
        else:
            row_p = float("nan")

        tool_rows[t]["bitmap_cvg_p_consistency"] = row_p

    def score(t):
        r = tool_rows[t]
        return (r["unique_crashes_avg"], r["paths_total_avg"], TOOL_RANK[t])
    sc = {t:score(t) for t in TOOLS}
    max_cr = max(sc[t][0] for t in TOOLS)
    tied  = [t for t in TOOLS if sc[t][0]==max_cr]
    max_cv = max(sc[t][1] for t in tied)
    finalists = [t for t in tied if sc[t][1]==max_cv]
    legacy = ["triforce","aflnet_base","aflnet_state_aware"]
    staff  = ["staff_base","staff_state_aware"]
    bl = max(tool_rows[t]["paths_total_avg"] for t in legacy)
    bs = max(tool_rows[t]["paths_total_avg"] for t in staff)
    rel=abs(bl-bs)/max(bl,1e-6)
    cl=max(tool_rows[t]["unique_crashes_avg"] for t in legacy)
    cs=max(tool_rows[t]["unique_crashes_avg"] for t in staff)

    if cl==cs and rel<0.05:
        wr=0
    elif (len(finalists)>1 and any(TOOL_RANK[t]>0 for t in finalists)
                         and any(TOOL_RANK[t]<0 for t in finalists)):
        wr=0
    else:
        wr=TOOL_RANK[max(finalists, key=lambda t:TOOL_RANK[t])]

    for t in TOOLS:
        rr = tool_rows[t]
        rr["winner"] = wr
        out = {
            "winner": rr["winner"],
            "Firmware": rr["Firmware"],
            "Mode": rr["Mode"],
            "num_experiments": rr["num_experiments"],
            "bitmap_cvg_p_consistency": rr["bitmap_cvg_p_consistency"],
        }
        out.update({k:v for k,v in rr.items() if k not in out})
        rows.append(out)
    rows.append({k:"" for k in rows[-1]})

df_fw = pd.DataFrame(rows)
df_fw.to_csv(os.path.join(OUTPUT_DIR,"per_firmware_mode.csv"),index=False)

print("\nPer-Firmware/Mode Averages + Consistency p-values:")
print(df_fw)
