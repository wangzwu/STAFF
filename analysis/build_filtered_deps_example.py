#!/usr/bin/env python3
import json
import os
from pprint import pprint
from typing import Dict, Any, Union, Tuple

def filter_region_deps(json_path_or_deps: Union[str, os.PathLike, Dict[str, Any]]) -> Tuple[Dict[str, list], Dict[str, Dict[int, list]]]:
    if isinstance(json_path_or_deps, (str, bytes, os.PathLike)):
        with open(json_path_or_deps, "r") as f:
            deps = json.load(f)
    elif isinstance(json_path_or_deps, dict):
        deps = json_path_or_deps
    else:
        raise TypeError("filter_region_deps expects a path or a dict")

    MWF: Dict[str, int] = {}
    for r_str, writers in deps.items():
        for w_str, files in writers.items():
            w = int(w_str)
            for f in files:
                if not f:
                    continue
                if f not in MWF or w < MWF[f]:
                    MWF[f] = w

    FW: Dict[int, set] = {}
    for f, w in MWF.items():
        FW.setdefault(w, set()).add(f)

    W: Dict[int, set] = {}
    for r_str, writers in deps.items():
        r = int(r_str)
        W.setdefault(r, set())
        for w_str in writers.keys():
            W[r].add(int(w_str))

    def build_filtered_deps(r: int, visited=None):
        if visited is None:
            visited = set()
        if r in visited:
            return {}
        visited.add(r)

        acc: Dict[int, set] = {}
        for w in sorted(W.get(r, [])):
            child = build_filtered_deps(w, visited)
            for rr, fileset in child.items():
                acc.setdefault(rr, set()).update(fileset)

            if w in FW:
                acc.setdefault(w, set()).update(FW[w])

        return acc

    filtered_deps: Dict[str, list] = {}
    filtered_deps_with_files: Dict[str, Dict[int, list]] = {}
    for r_str in deps.keys():
        r = int(r_str)
        acc = build_filtered_deps(r, visited=set())
        filtered_deps[r_str] = [ w for w, files in sorted(acc.items()) ]
        filtered_deps_with_files[r_str] = { w: sorted(list(files)) for w, files in sorted(acc.items()) }

    return filtered_deps, filtered_deps_with_files

demo_instance = {
    "4": {
        "3": ["file_6", "file_3", ""],
    },
    "3": {
        "2": ["file_3", "file_4", "file_6"]
    },
    "2": {
        "1": ["file_1", "file_3", "file_2"]
    },
    "1": {
        "0": ["file_0", "file_1", "file_2"]
    },
    "0": {
    }
}

if __name__ == "__main__":
    filtered_list, filtered_with_files = filter_region_deps(demo_instance)

    print("\n--- filtered (writers only) ---")
    pprint(filtered_list)

    print("\n--- filtered (writers with files) ---")
    pprint(filtered_with_files)

    compact_mapping = {}
    for region_str in sorted(filtered_with_files.keys(), key=int):
        compact_mapping[region_str] = filtered_with_files.get(region_str, {})

    print("\n--- COMPACT mapping: region -> { writer: [files...] } ---")
    pprint(compact_mapping)

    print("\nCompact JSON-friendly output:")
    print(json.dumps(compact_mapping, indent=2, sort_keys=True))

    with open("demo_compact_with_files.json", "w") as f:
        json.dump(compact_mapping, f, indent=2, sort_keys=True)

    print("\nSaved demo_compact_with_files.json")
