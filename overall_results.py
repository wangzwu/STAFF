#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd
from scipy.stats import mannwhitneyu

BLACKBOX = [
    "neaps_array",
    "ethlink",
    "aparraymsg"
]

BASE_DIRS = [
    "experiments_done/baseline",
    "experiments_done/staff_state_aware_0_taint_block"
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

METRICS = ["bitmap_cvg", "unique_crashes", "unique_hangs", "paths_total", "paths_favored", "execs_done"]
BASELINE_TOOLS = ["aflnet_base", "aflnet_state_aware", "triforce"]

BASELINE_EXPERIMENTS = "0,1,2,5,6,7,10,11,12,15,16,17,20,21,22,25,26,27,"
STAFF_EDGE = "3,4,8,9,13,14,18,19,23,24,28,29"
STAFF_TAINT_BLOCK = "42-53"
INCLUDE_EXPERIMENTS = None


def effect_size_a12(x, y):
    n_x, n_y = len(x), len(y)
    ranks = pd.Series(x + y).rank()
    r_x = ranks.iloc[:n_x].sum()
    return (r_x / n_x - (n_x + 1) / 2) / n_y


def parse_range_list(range_str):
    include_set = set()
    for part in range_str.split(","):
        if "-" in part:
            a, b = map(int, part.split("-"))
            include_set.update(range(a, b + 1))
        elif part.strip():
            include_set.add(int(part))
    return include_set


def parse_fuzzer_stats(path, fallback_path=None, force_time_fallback=False):
    data = {}
    start_time = last_update = None
    def load_times(p):
        nonlocal start_time, last_update
        if not os.path.exists(p): return 1
        for ln in open(p):
            if ":" not in ln: continue
            k, v = ln.split(":",1)
            k, v = k.strip(), v.strip().rstrip('%')
            if k == "start_time":
                try: start_time = int(v)
                except: pass
            elif k == "last_update":
                try: last_update = int(v)
                except: pass
        return 0
    for ln in open(path):
        if ":" not in ln: continue
        k, v = ln.split(":",1)
        k, v = k.strip(), v.strip().rstrip('%')
        try:
            if k == "start_time": start_time = int(v)
            elif k == "last_update": last_update = int(v)
            elif k in METRICS and k != "unique_crashes":
                data[k] = float(v)
        except: pass
    if force_time_fallback and fallback_path:
        if load_times(fallback_path): return None
    data["run_time"] = float((last_update or 0) - (start_time or 0))
    return data


def count_crashes_from_traces(exp_dir, debug=False):
    ct = os.path.join(exp_dir, "outputs", "crash_traces")
    if not os.path.isdir(ct): return 0
    total = 0
    for f in os.listdir(ct):
        p = os.path.join(ct, f)
        if not os.path.isfile(p): continue
        txt = open(p, 'r', errors='ignore').read()
        c = txt.count("Process: ") + 1
        for pat in BLACKBOX:
            if pat in txt: c -= 1
        if debug:
            print(f"DEBUG [{exp_dir}]: file={f}, base_count={txt.count('Process: ')+1}, after_blackbox={c}")
        total += max(c, 0)
    if debug:
        print(f"DEBUG [{exp_dir}]: total_crashes={total}")
    return total


def read_config(exp_dir):
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(exp_dir, "outputs", "config.ini"))
    return cfg.get("GENERAL","firmware"), cfg.get("GENERAL","mode")

agg = defaultdict(lambda: defaultdict(list))
valid = 0
firmwares = set()
include_set = parse_range_list(INCLUDE_EXPERIMENTS) if INCLUDE_EXPERIMENTS else None
all_dirs = []
for b in BASE_DIRS:
    all_dirs += glob.glob(os.path.join(b, "exp_*"))
for exp in sorted(all_dirs):
    nm = os.path.basename(exp)
    try:
        eid = int(nm.split("_")[1])
        if include_set and eid not in include_set: continue
    except: pass
    cfgp = os.path.join(exp, "outputs", "config.ini")
    statp = os.path.join(exp, "outputs", "fuzzer_stats")
    plotp = os.path.join(exp, "outputs", "plot_data")
    if not os.path.isfile(cfgp) or not os.path.isfile(statp): continue
    fw, mode = read_config(exp)
    if mode not in TOOLS: continue
    stats = parse_fuzzer_stats(statp, 
        fallback_path=os.path.join(exp, "outputs", "old_fuzzer_stats") if mode=="triforce" else None,
        force_time_fallback=(mode=="triforce"))
    if not stats: continue
    cc = count_crashes_from_traces(exp)
    # if cc <= 0: continue

    cols = (["unix_time","paths_total","map_size","unique_crashes","unique_hangs","stability","n_calibration"]
            if mode=="triforce" else
            ["unix_time","cycles_done","execs_done","cur_path","paths_total",
             "pending_total","pending_favs","map_size","unique_crashes",
             "unique_hangs","max_depth","execs_per_sec","stability",
             "n_fetched_random_hints","n_fetched_state_hints",
             "n_fetched_taint_hints","n_calibration"])
    dfp = pd.read_csv(plotp, comment="#", names=cols)
    dfp["map_size"] = dfp["map_size"].str.rstrip("%").astype(float)

    valid += 1
    firmwares.add(fw)
    key = (fw,mode)
    agg[key]["bitmap_cvg"].append(dfp["map_size"].tolist())
    agg[key]["run_time"].append(stats["run_time"])
    agg[key]["unique_crashes"].append(cc)
    for m in METRICS:
        if m not in ("bitmap_cvg","unique_crashes"):
            agg[key][m].append(stats.get(m,0.0))
if valid == 0: exit(1)


rows = []
headers = ["winner","Firmware","Mode","num_experiments"] + [f"{m}_avg" for m in METRICS] + ["run_time_avg"]
for fw in sorted(firmwares):
    rows.append({h:"" for h in headers})
    tool_rows = {}
    baseline_scores = []

    for t in TOOLS:
        k=(fw,t)
        mets = agg.get(k,{})
        count_list = mets.get("unique_crashes",[])
        row={"Firmware":fw, "Mode":t, "num_experiments":len(count_list)}

        for m in METRICS:
            vals = mets.get(m,[])
            if not vals:
                row[f"{m}_avg"] = 0
            else:
                if m=="bitmap_cvg":
                    flat=[x for sub in vals for x in (sub if isinstance(sub,list) else [sub])]
                    row[f"{m}_avg"]=round(sum(flat)/len(flat),4)
                else:
                    row[f"{m}_avg"]=int(round(sum(vals)/len(vals)))
        row["run_time_avg"]=int(round(sum(mets.get("run_time",[]))/len(mets.get("run_time",[1]))))
        tool_rows[t]=row
        if t in BASELINE_TOOLS:
            baseline_scores.append((t,row["unique_crashes_avg"],row["bitmap_cvg_avg"]))
    if not baseline_scores: continue

    baseline_scores.sort(key=lambda x:(x[1],x[2]),reverse=True)
    best_base=baseline_scores[0][0]
    best_vals_cvg=agg[(fw,best_base)]["bitmap_cvg"]
    best_vals_cr=agg[(fw,best_base)]["unique_crashes"]

    def score(tool): return (
        tool_rows[tool]["unique_crashes_avg"],
        tool_rows[tool]["bitmap_cvg_avg"],
        TOOL_RANK.get(tool,0)
    )
    scores={t:score(t) for t in tool_rows}
    max_cr=max(s[0] for s in scores.values())
    tied_cr=[t for t,s in scores.items() if s[0]==max_cr]
    max_bm=max(scores[t][1] for t in tied_cr)
    tied_final=[t for t in tied_cr if scores[t][1]==max_bm]

    legacy=[t for t in BASELINE_TOOLS if t in tool_rows]
    staff=[t for t in ["staff_base","staff_state_aware"] if t in tool_rows]
    best_leg=max((tool_rows[t] for t in legacy),key=lambda r:r["bitmap_cvg_avg"],default=None)
    best_st=max((tool_rows[t] for t in staff),key=lambda r:r["bitmap_cvg_avg"],default=None)
    abs_diff=abs(best_leg["bitmap_cvg_avg"]-best_st["bitmap_cvg_avg"]) if best_leg and best_st else 0
    rel_diff=abs_diff/max(best_leg["bitmap_cvg_avg"],1e-6)
    leg_cr=max((tool_rows[t]["unique_crashes_avg"] for t in legacy),default=0)
    st_cr=max((tool_rows[t]["unique_crashes_avg"] for t in staff),default=0)
    if leg_cr==st_cr and rel_diff<0.05:
        winner=0
    elif len(tied_final)>1 and any(TOOL_RANK[t]>0 for t in tied_final) and any(TOOL_RANK[t]<0 for t in tied_final):
        winner=0
    else:
        winner=TOOL_RANK.get(max(tied_final,key=lambda t:TOOL_RANK[t]),0)

    for t,r in tool_rows.items():
        r["winner"]=winner
        r["best_baseline"]=best_base

        vals=agg[(fw,t)]["bitmap_cvg"]
        if vals and best_vals_cvg:
            flat_t=[x for sub in vals for x in (sub if isinstance(sub,list) else [sub])]
            flat_b=[x for sub in best_vals_cvg for x in (sub if isinstance(sub,list) else [sub])]
            r["bitmap_cvg_p_value_with_best"]=round(mannwhitneyu(flat_t,flat_b).pvalue,4)
            r["bitmap_cvg_A12_with_best"]=round(effect_size_a12(flat_t,flat_b),4)
        else:
            r["bitmap_cvg_p_value_with_best"]=None
            r["bitmap_cvg_A12_with_best"]=None
        vals_cr=agg[(fw,t)]["unique_crashes"]
        if vals_cr and best_vals_cr:
            r["unique_crashes_p_value_with_best"]=round(mannwhitneyu(vals_cr,best_vals_cr).pvalue,4)
            r["unique_crashes_A12_with_best"]=round(effect_size_a12(vals_cr,best_vals_cr),4)
        else:
            r["unique_crashes_p_value_with_best"]=None
            r["unique_crashes_A12_with_best"]=None

        base = {"winner":r["winner"],"Firmware":r["Firmware"],"Mode":r["Mode"],
                "num_experiments":r["num_experiments"],"best_baseline":r["best_baseline"],
                "bitmap_cvg_p_value_with_best":r["bitmap_cvg_p_value_with_best"],
                "bitmap_cvg_A12_with_best":r["bitmap_cvg_A12_with_best"],
                "unique_crashes_p_value_with_best":r["unique_crashes_p_value_with_best"],
                "unique_crashes_A12_with_best":r["unique_crashes_A12_with_best"]}
        base.update(r)
        rows.append(base)

df = pd.DataFrame(rows)
df.to_csv(os.path.join(OUTPUT_DIR,"per_firmware_mode.csv"),index=False)
mode_rows=[]
for mo,grp in df[df["Firmware"]!=""].groupby("Mode"):
    mr={"Mode":mo}
    for m in METRICS:
        if m=="bitmap_cvg": mr[f"{m}_avg"]=round(grp[f"{m}_avg"].astype(float).mean(),4)
        else: mr[f"{m}_sum"]=int(grp[f"{m}_avg"].astype(float).sum())
    mr["run_time_avg"]=int(round(grp["run_time_avg"].astype(float).mean()))
    mr["total_experiments"]=int(grp["num_experiments"].astype(int).sum())
    mode_rows.append(mr)
df2=pd.DataFrame(mode_rows).sort_values("Mode")
df2.to_csv(os.path.join(OUTPUT_DIR,"per_mode_aggregate.csv"),index=False)

print("\nPer-Firmware/Mode Averages:")
print(df)
print("\nPer-Mode Aggregated Totals:")
print(df2)
