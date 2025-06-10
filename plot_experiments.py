import os
import configparser
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
from itertools import combinations
import venn
from scipy.stats import mannwhitneyu, chi2
from math import log

TRIM_LINES = False
# INCLUDE_EXPERIMENTS = "0-82"
INCLUDE_EXPERIMENTS = None

def parse_range_list(skip_str):
    include_set = set()
    for part in skip_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            include_set.update(range(start, end + 1))
        else:
            include_set.add(int(part))
    return include_set

def get_bitmap_data(bitmap_path):
    bitmap_data = set()
    with open(bitmap_path, 'rb') as file:
        content = file.read(65536)
        for i in range(len(content)):
            if content[i] != 255:
                bitmap_data.add(i)
    return bitmap_data

def parse_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)
    return {s: dict(config.items(s)) for s in config.sections()}

def parse_plot_data(exp_path):
    dfs = []
    for fn in sorted(os.listdir(exp_path)):
        if not fn.startswith("plot_data"):
            continue

        full = os.path.join(exp_path, fn)

        with open(full, 'r') as f:
            first = ""
            while True:
                line = f.readline()
                if not line:
                    break
                first = line.strip()
                if first:
                    break

        if first.startswith("# unix_time, paths_total, map_size"):
            names = [
                "unix_time",
                "paths_total",
                "map_size",
                "unique_crashes",
                "unique_hangs",
                "stability",
                "n_calibration",
            ]
        else:
            names = [
                "unix_time", "cycles_done", "execs_done", "cur_path",
                "paths_total", "pending_total", "pending_favs", "map_size",
                "unique_crashes", "unique_hangs", "max_depth",
                "execs_per_sec", "stability",
                "n_fetched_random_hints", "n_fetched_state_hints",
                "n_fetched_taint_hints", "n_calibration",
            ]

        df_part = pd.read_csv(full, comment="#", names=names, header=None)
        dfs.append(df_part)

    if not dfs:
        return None, []

    df = pd.concat(dfs, ignore_index=True)
    df['map_size']  = df['map_size'].astype(str).str.rstrip('%').astype(float)
    df['stability'] = df['stability'].astype(str).str.rstrip('%').astype(float)
    df['unix_time'] = df['unix_time'] - df['unix_time'].iloc[0]

    resume_path = os.path.join(exp_path, "resume_ts")
    resume_ts = []
    if os.path.exists(resume_path):
        with open(resume_path, 'r') as f:
            for line in f:
                try:
                    ts = float(line.strip()) - df['unix_time'].iloc[0]
                    resume_ts.append(ts)
                except ValueError:
                    continue

    return df, resume_ts

def read_params(param_file):
    config = configparser.ConfigParser()
    config.read(param_file)
    
    fixed_params = {}
    var_params = []
    
    if 'fixed_params' in config.sections():
        for key, value in config.items('fixed_params'):
            section, param = key.split('.', 1)
            if (section.upper(), param) != ('GENERAL_FUZZING', 'fuzz_tmout'):
                fixed_params[(section.upper(), param)] = value
    
    if 'var_params' in config.sections():
        for key, value in config.items('var_params'):
            section, param = key.split('.', 1)
            var_params.append((section.upper(), param))
    
    return var_params, fixed_params

def find_matching_experiments(base_dir, var_params, fixed_params):
    experiments = defaultdict(list)
    include_set = None
    
    if INCLUDE_EXPERIMENTS:
        include_set = parse_range_list(INCLUDE_EXPERIMENTS)

    for exp_id in os.listdir(base_dir):
        try:
            exp_n = int(exp_id.split('_')[1])
        except (ValueError, IndexError):
            continue

        if include_set and exp_n not in include_set:
            continue
        
        exp_path = os.path.join(base_dir, exp_id, 'outputs')
        config_path = os.path.join(exp_path, 'config.ini')
        if not os.path.exists(config_path):
            continue
        
        config = parse_config(config_path)
        
        match = all(config[section].get(param) == val 
                    for (section, param), val in fixed_params.items() if section in config and param in config[section])
        
        if match:
            key = tuple(config[s].get(p, 'NA') for s, p in var_params)
            experiments[key].append(exp_id)
    
    return experiments

def merge_experiment_data(experiments, base_dir):
    merged_data = {}
    resume_markers = defaultdict(list)
    experiment_counts = {}
    _map_size_series_raw = {}

    expected_cols = [
        'map_size', 'unique_crashes', 'unique_hangs', 'paths_total',
        'execs_per_sec', 'cycles_done', 'execs_done', 'stability',
        'n_fetched_random_hints', 'n_fetched_state_hints',
        'n_fetched_taint_hints', 'n_calibration'
    ]

    for key, exp_list in experiments.items():
        all_dfs = []
        map_size_series = []
        min_time, max_time = float('inf'), 0.0

        for exp_id in exp_list:
            exp_path = os.path.join(base_dir, exp_id, 'outputs')
            df, resume_ts = parse_plot_data(exp_path)
            if df is None or 'map_size' not in df.columns:
                continue

            all_dfs.append(df)
            map_size_series.append(df['map_size'].dropna().values)
            min_time = min(min_time, df['unix_time'].min())
            max_time = max(max_time, df['unix_time'].max())
            resume_markers[key].extend(resume_ts)

        if not all_dfs:
            continue

        experiment_counts[key] = len(all_dfs)
        _map_size_series_raw[key] = map_size_series

        common_times = np.linspace(min_time, max_time, num=100)
        interpolated_dfs = []

        for df in all_dfs:
            interp_df = pd.DataFrame({'unix_time': common_times})
            for col in expected_cols:
                if col in df.columns:
                    interp_df[col] = np.interp(common_times, df['unix_time'], df[col],
                                               left=np.nan, right=np.nan)
                else:
                    interp_df[col] = np.nan
            interpolated_dfs.append(interp_df)

        if TRIM_LINES:
            start_t = max(df['unix_time'].min() for df in all_dfs)
            end_t = min(df['unix_time'].max() for df in all_dfs)
            merged_df = pd.concat(interpolated_dfs)
            merged_df = merged_df[
                (merged_df['unix_time'] >= start_t) &
                (merged_df['unix_time'] <= end_t)
            ]
        else:
            merged_df = pd.concat(interpolated_dfs)

        merged_data[key] = merged_df

    pvals = {}
    for key, series_list in _map_size_series_raw.items():
        pair_p = []
        for a, b in combinations(series_list, 2):
            a, b = np.array(a), np.array(b)
            L = min(len(a), len(b))
            if L < 1:
                continue
            _, p = mannwhitneyu(a[:L], b[:L], alternative="two-sided")
            pair_p.append(max(min(p, 1.0), 0.0))

        if pair_p:
            chi2_stat = -2 * sum(log(p) for p in pair_p if p > 0)
            df = 2 * len(pair_p)
            combined_p = chi2.sf(chi2_stat, df)
            pvals[key] = round(combined_p, 4)
        else:
            pvals[key] = float('nan')

    return merged_data, resume_markers, experiment_counts, pvals

def plot_metric(merged_data, metric, ylabel, title, output_path,
                resume_markers, experiment_counts, pvals, var_params):
    plt.figure(figsize=(10, 6))

    for key, df in merged_data.items():
        label = ", ".join(f"{p}={v}" for (section, p), v in zip(var_params, key))
        n_exp = experiment_counts.get(key, '?')
        p_val = pvals.get(key, float('nan'))

        if np.isnan(p_val):
            label += f" (n={n_exp})"
        else:
            label += f" (n={n_exp}, p={p_val})"

        mean_vals = df.groupby('unix_time')[metric].mean()
        std_vals  = df.groupby('unix_time')[metric].std()

        plt.plot(mean_vals.index, mean_vals, label=label)
        plt.fill_between(mean_vals.index,
                         mean_vals - std_vals,
                         mean_vals + std_vals,
                         alpha=0.2)

        for ts in resume_markers.get(key, []):
            if mean_vals.index.min() <= ts <= mean_vals.index.max():
                plt.axvline(ts, linestyle='--', color='gray', alpha=0.3)

    plt.xlabel("Time (s)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_experiments(merged_data, resume_markers, experiment_counts, pvals, output_dir, var_params):
    os.makedirs(output_dir, exist_ok=True)

    metrics_to_plot = [
        ('map_size',       "Coverage (%)",                     "Coverage over Time with Confidence Bands"),
        ('unique_crashes', "Unique Crashes",                   "Crashes over Time with Confidence Bands"),
        ('unique_hangs',   "Unique Hangs",                     "Hangs over Time with Confidence Bands"),
        ('paths_total',    "Total Paths",                      "Total Paths over Time with Confidence Bands"),
        ('execs_per_sec',  "Executions per Second",            "Executions per Second over Time with Confidence Bands"),
        ('cycles_done',    "Cycles Done",                      "Fuzzing Cycles Done over Time with Confidence Bands"),
        ('stability',      "Stability (%)",                    "Fuzzing Stability over Time with Confidence Bands"),
        ('execs_done',     "Total Executions Done",            "Total Executions Done over Time"),
        ('n_calibration',  "Calibration Runs",                 "Calibration Runs Done over Time"),
    ]

    for metric, ylabel, title in metrics_to_plot:
        filename = f"{metric}_plot.png"

        plot_metric(
            merged_data=merged_data,
            metric=metric,
            ylabel=ylabel,
            title=title,
            output_path=os.path.join(output_dir, filename),
            resume_markers=resume_markers,
            experiment_counts=experiment_counts,
            pvals=pvals,
            var_params=var_params
        )

def plot_venn(experiments, base_dir, output_dir):
    def collect_sets(suffix):
        fuzz_sets = {}
        for key, exp_list in experiments.items():
            combined_set = set()
            for exp_id in exp_list:
                exp_path = os.path.join(base_dir, exp_id, 'outputs')
                bitmap_path = os.path.join(exp_path, suffix)
                if os.path.exists(bitmap_path):
                    combined_set |= get_bitmap_data(bitmap_path)
            fuzz_sets[key] = combined_set
        return fuzz_sets

    def plot_fuzz_sets(fuzz_sets, title, filename):
        keys = list(fuzz_sets.keys())
        plt.figure(figsize=(6, 6))
        if len(keys) == 2:
            venn.venn({keys[0][0]: fuzz_sets[keys[0]], keys[1][0]: fuzz_sets[keys[1]]})
        elif len(keys) == 3:
            venn.venn({keys[0][0]: fuzz_sets[keys[0]], keys[1][0]: fuzz_sets[keys[1]], keys[2][0]: fuzz_sets[keys[2]]})
        elif len(keys) == 4:
            venn.venn({keys[0][0]: fuzz_sets[keys[0]], keys[1][0]: fuzz_sets[keys[1]],
                       keys[2][0]: fuzz_sets[keys[2]], keys[3][0]: fuzz_sets[keys[3]]})
        elif len(keys) == 5:
            venn.venn({keys[0][0]: fuzz_sets[keys[0]], keys[1][0]: fuzz_sets[keys[1]],
                       keys[2][0]: fuzz_sets[keys[2]], keys[3][0]: fuzz_sets[keys[3]], keys[4][0]: fuzz_sets[keys[4]]})
        else:
            print(f"Too many fuzz sets ({len(keys)}), cannot create Venn diagram.")
            return
        plt.title(title)
        plt.savefig(os.path.join(output_dir, filename))
        plt.close()

    fuzz_sets = collect_sets('fuzz_bitmap')
    plot_fuzz_sets(fuzz_sets, "Venn Diagram of Fuzz Bitmap Coverage", "venn_fuzz_bitmap.png")


if __name__ == "__main__":
    base_dir    = "experiments"
    output_dir  = "exp_out"
    param_file  = "plot_params.ini"

    var_params, fixed_params = read_params(param_file)

    experiments = find_matching_experiments(base_dir, var_params, fixed_params)
    merged_data, resume_markers, experiment_counts, pvals = merge_experiment_data(experiments, base_dir)

    plot_experiments(
        merged_data,
        resume_markers,
        experiment_counts,
        pvals,
        output_dir,
        var_params
    )

    plot_venn(experiments, base_dir, output_dir)
