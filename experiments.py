#!/usr/bin/python3 -u

import os
import sys
import subprocess
import fcntl
import random
import docker
import csv
from configparser import ConfigParser
from collections import defaultdict
from time import sleep
import re
import shutil

EXPERIMENTS_DIR = "experiments"
SCHEDULE_CSV = "schedule.csv"

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
N_CPU_MIN = 0
N_CPU_MAX = int(os.cpu_count())
logical_to_pair = {}
pair_to_logical = defaultdict(list)
CPUS_WHITELIST = None
CPUS_WHITELIST = [0,56,4,60,64,8,12,68,10,66,6,62,2,58,16,72,20,76,24,80,26,82,22,78,18,74,14,70,28,84,32,88,36,92,40,96,38,94,34,90,30,86,100,44,104,48,108,52,110,54,106,50,1,57,5,61,65,9,13,69,11,67]
reset_firmware_images = 1

def usage():
    print("python3 experiments.py")
    sys.exit(1)

def get_sibling_logical_ids(logical_id):
    global logical_to_pair
    global pair_to_logical

    pair = logical_to_pair[logical_id]
    return pair_to_logical[pair]

def get_running_containers():
    running_containers = {}
    try:
        containers = docker.from_env().containers.list()
        for container in containers:
            cpus = container.attrs['HostConfig']['CpusetCpus'].split(",")
            name = container.name
            for c in cpus:
                if int(c) < N_CPU_MAX:
                    running_containers[int(c)] = name
    except Exception as e:
        print(e)
        sys.exit(1)
    return running_containers

def remove_container_if_exists(container_name):
    try:
        container_id = subprocess.check_output(
            ["docker", "ps", "-a", "-q", "--filter", f"name={container_name}"], stderr=subprocess.PIPE
        ).decode().strip()
        if container_id:
            print(f"Container {container_name} already exists. Removing it...")
            subprocess.check_call(["docker", "rm", "-f", container_name])
    except subprocess.CalledProcessError as e:
        print(f"Error while checking/removing container {container_name}: {e}")
        sys.exit(1)

def wait_for_container_init(file_path="wait_for_container_init"):
    while os.path.exists(file_path):
        print(f"Waiting for {file_path} to be removed...")
        sleep(1)
    print(f"{file_path} removed, continuing execution.")

def start_routine(exp_name, container_name, cpus, replay):
    global reset_firmware_images

    remove_container_if_exists(container_name)

    os.makedirs("docker", exist_ok=True)

    log_filename = f"docker/{container_name}.log"
    if os.path.exists(log_filename):
        os.remove(log_filename)

    command = f"python3 start.py --reset_firmware_images {reset_firmware_images} --replay_exp {replay} --keep_config 0 --output {os.path.join(EXPERIMENTS_DIR, exp_name)} --container_name {container_name}; "
    reset_firmware_images = 0
    
    print(command)
    with open("command", 'w') as file:
        file.write(command)

    print("Running " + container_name)
    print(f"./docker.sh run_exp {container_name} {cpus}")

    with open("wait_for_container_init", "w") as f:
        f.write("")

    subprocess.check_output(f"./docker.sh run_exp {container_name} {cpus}", shell=True)

    wait_for_container_init()

def run_experiment(exp_name, container_name, n_cores, replay):
    if n_cores < 1 or n_cores > N_CPU_MAX:
        print(f"Invalid n_cores: {n_cores}")
        usage()

    if len(container_name) < 3:
        print("Insert a valid container name")
        usage()

    running = get_running_containers()

    lock = open(SCRIPT_DIR + '/affinity.lock', 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    affinity_file = SCRIPT_DIR + '/affinity.dat'
    affinity = {}

    if os.path.exists(affinity_file):
        with open(affinity_file, 'r') as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                
                tokens = line.split(",")
                if len(tokens) != 2:
                    print(f"Invalid line in affinity.dat: {line}")
                    continue

                try:
                    cpu_id, name = int(tokens[0]), tokens[1]
                except ValueError:
                    print(f"Error parsing line in affinity.dat: {line}")
                    continue

                if cpu_id < N_CPU_MIN or cpu_id > N_CPU_MAX:
                    print("Invalid cpu_id:", cpu_id)
                    sys.exit(1)
                if cpu_id in running and name != running[cpu_id]:
                    print("Mismatch in status names")
                affinity[cpu_id] = running.get(cpu_id, "none")
    else:
        affinity = {i: "none" for i in range(N_CPU_MAX)}

    for i in range(N_CPU_MAX):
        if i not in affinity:
            affinity[i] = "none"

    free_cpus = [i for i in range(N_CPU_MAX) if affinity[i] == "none" and (CPUS_WHITELIST is None or i in CPUS_WHITELIST)]
    if len(free_cpus) < n_cores:
        print(f"ERROR: too few CPUs available: {len(free_cpus)}")
        fcntl.lockf(lock, fcntl.LOCK_UN)
        sys.exit(1)

    assigned = []
    random.shuffle(free_cpus)
    j = 0
    for i in free_cpus:
        logical_ids = get_sibling_logical_ids(i)
        for logical_id in logical_ids:
            assigned.append(str(logical_id))
            affinity[logical_id] = container_name

            print(f"Assigning CPU #{logical_id} => {container_name}")

        if len(assigned)/len(logical_ids) == n_cores:
            break

    cpuset = ",".join(assigned)
    start_routine(exp_name, container_name, cpuset, replay)

    with open(affinity_file, 'w') as fp:
        for i in range(N_CPU_MAX):
            fp.write(f"{i},{affinity[i]}\n")

    print(','.join(assigned))
    fcntl.lockf(lock, fcntl.LOCK_UN)

def parse_affinity(affinity_file, mode=None):
    mode_map = {}
    used_numbers = set()

    running = get_running_containers()

    affinity_file = SCRIPT_DIR + '/affinity.dat'
    affinity = {}

    lock = open(SCRIPT_DIR + '/affinity.lock', 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    if os.path.exists(affinity_file):
        with open(affinity_file, 'r') as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                
                tokens = line.split(",")
                if len(tokens) != 2:
                    print(f"Invalid line in affinity.dat: {line}")
                    continue

                try:
                    cpu_id, name = int(tokens[0]), tokens[1]
                except ValueError:
                    print(f"Error parsing line in affinity.dat: {line}")
                    continue

                if cpu_id < N_CPU_MIN or cpu_id > N_CPU_MAX:
                    print("Invalid cpu_id:", cpu_id)
                    sys.exit(1)
                if cpu_id in running and name != running[cpu_id]:
                    print("Mismatch in status names")
                affinity[cpu_id] = running.get(cpu_id, "none")
    else:
        affinity = {i: "none" for i in range(N_CPU_MAX)}

    for i in range(N_CPU_MAX):
        if i not in affinity:
            affinity[i] = "none"

    with open(affinity_file, 'w') as fp:
        for i in range(N_CPU_MAX):
            fp.write(f"{i},{affinity[i]}\n")

    with open(affinity_file, "r") as infile:
        for line in infile:
            parts = line.strip().split(",")
            if len(parts) != 2:
                continue
            
            num, container = parts
            num = int(num)
            
            if container != "none":
                match = re.match(r"(.+)_(\d+)", container)
                if match:
                    container_mode, container_num = match.groups()
                    container_num = int(container_num)
                    
                    if mode is None or container_mode == mode:
                        if container_mode not in mode_map:
                            mode_map[container_mode] = set()
                        mode_map[container_mode].add(container_num)
                        used_numbers.add(container_num)

    fcntl.lockf(lock, fcntl.LOCK_UN)

    return mode_map, used_numbers

def get_first_available_name(existing, base_name):
    num = 0
    while f"{base_name}_{num}" in existing:
        num += 1
    return f"{base_name}_{num}"

def get_next_available_exp_name(out_dir):
    used = set()
    pattern = re.compile(r'^exp_(\d+)$')
    for entry in os.listdir(out_dir):
        match = pattern.match(entry)
        if match:
            used.add(int(match.group(1)))

    n = 1
    while True:
        if n not in used:
            return f"exp_{n}"
        n += 1

def ensure_experiment_consistency(csv_file, exp_dir, affinity_file="affinity.dat", done_dir="experiments_done"):
    lock = open(SCRIPT_DIR + '/schedule.lock', 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    os.makedirs(done_dir, exist_ok=True)

    existing_experiments = set(os.listdir(exp_dir)) if os.path.exists(exp_dir) else set()
    done_experiments = set(os.listdir(done_dir)) if os.path.exists(done_dir) else set()

    mode_map, used_numbers = parse_affinity(affinity_file, None)

    rows_to_keep = []
    rows_to_remove = []

    with open(csv_file, "r") as infile:
        reader = csv.reader(infile)

        try:
            header1 = next(reader)
            header2 = next(reader)
        except StopIteration:
            print("CSV file is empty or missing headers. Exiting...")
            return

        rows_to_keep.append(header1)
        rows_to_keep.append(header2)

        status_idx = header2.index("status")
        exp_name_idx = header2.index("exp_name")
        container_name_idx = header2.index("container_name")

        for row in reader:
            if len(row) > 1:
                status = row[status_idx]
                exp_name = row[exp_name_idx]
                container_name = row[container_name_idx]
                num_cores = row[3]

                if os.path.exists(exp_dir) and exp_name not in existing_experiments and exp_name != "":
                    continue
                elif (status == "" or exp_name == "" or container_name == "") and \
                        not (status == "" and exp_name == "" and container_name == ""):
                    continue
                elif not os.path.exists(exp_dir) and exp_name != "":
                    continue

                container_in_affinity = False
                match = re.match(r"(.+)_(\d+)", container_name)
                if match:
                    container_num = int(match.groups()[1])
                    if container_num in used_numbers:
                        container_in_affinity = True

                if status and not container_in_affinity and status == "running":
                    row[status_idx] = "stopped"

                rows_to_keep.append(row)

    with open(csv_file, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(rows_to_keep)
        print("Schedule CSV has been cleaned.")

    if os.path.exists(exp_dir):
        for exp_dir_name in existing_experiments:
            exp_dir_path = os.path.join(exp_dir, exp_dir_name)
            if os.path.isdir(exp_dir_path) and not os.listdir(exp_dir_path):
                print(f"Removing orphan empty experiment directory: {exp_dir_path}")
                os.rmdir(exp_dir_path)

                for row in rows_to_keep:
                    if row[exp_name_idx] == exp_dir_name:
                        rows_to_remove.append(row)

        with open(csv_file, "r") as infile:
            rows = list(csv.reader(infile))

        with open(csv_file, "w", newline="") as outfile:
            writer = csv.writer(outfile)
            for row in rows:
                if row not in rows_to_remove:
                    writer.writerow(row)

    fcntl.lockf(lock, fcntl.LOCK_UN)
    print("Orphan experiment directories have been cleaned.")

def assign_names(csv_file, idx, num_cores, config_data):
    mode = config_data["GENERAL"]["mode"]
    
    affinity_file = "affinity.dat"

    if num_cores < 1 or num_cores > N_CPU_MAX:
        print(f"Invalid num_cores: {num_cores}")
        usage()

    running = get_running_containers()

    lock = open(SCRIPT_DIR + '/affinity.lock', 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    affinity = {}

    if os.path.exists(affinity_file):
        with open(affinity_file, 'r') as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                
                tokens = line.split(",")
                if len(tokens) != 2:
                    print(f"Invalid line in affinity.dat: {line}")
                    continue

                try:
                    cpu_id, name = int(tokens[0]), tokens[1]
                except ValueError:
                    print(f"Error parsing line in affinity.dat: {line}")
                    continue

                if cpu_id < N_CPU_MIN or cpu_id > N_CPU_MAX:
                    print("Invalid cpu_id:", cpu_id)
                    sys.exit(1)
                if cpu_id in running and name != running[cpu_id]:
                    print("Mismatch in status names")
                affinity[cpu_id] = running.get(cpu_id, "none")
    else:
        affinity = {i: "none" for i in range(N_CPU_MAX)}

    for i in range(N_CPU_MAX):
        if i not in affinity:
            affinity[i] = "none"

    free_cpus = [i for i in range(N_CPU_MAX) if affinity[i] == "none" and (CPUS_WHITELIST is None or i in CPUS_WHITELIST)]
    if len(free_cpus) < num_cores:
        print(f"ERROR: too few CPUs available: {len(free_cpus)}")
        fcntl.lockf(lock, fcntl.LOCK_UN)
        return None, None

    with open(affinity_file, 'w') as fp:
        for i in range(N_CPU_MAX):
            fp.write(f"{i},{affinity[i]}\n")

    fcntl.lockf(lock, fcntl.LOCK_UN)

    mode_map, used_numbers = parse_affinity(affinity_file, mode)

    existing_containers = mode_map.get(mode, set())

    assigned_containers = existing_containers.copy()
    for section, values in config_data.items():
        for key, value in values.items():
            if key == "container_name" and value.startswith(f"{mode}_"):
                container_num = int(value.split("_")[-1])
                assigned_containers.add(container_num)

    available_container_num = None
    for i in range(0, N_CPU_MAX + 1):
        if i not in assigned_containers and i not in used_numbers:
            available_container_num = i
            break

    if available_container_num is None:
        max_container_num = max(assigned_containers) if assigned_containers else -1
        available_container_num = max_container_num + 1

    container_name = f"{mode}_{available_container_num}"

    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)
    
    existing_experiments = {name for name in os.listdir(EXPERIMENTS_DIR) if name.startswith("exp_")}
    exp_name = get_first_available_name(existing_experiments, "exp")

    if not os.path.exists(os.path.join(EXPERIMENTS_DIR, exp_name)):
        os.makedirs(os.path.join(EXPERIMENTS_DIR, exp_name))

    lock = open(SCRIPT_DIR + '/schedule.lock', 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    with open(csv_file, "r") as infile:
        rows = list(csv.reader(infile))

    headers = rows[1]
    required_headers = {"status", "exp_name", "container_name"}
    existing_headers = set(headers)

    missing_headers = required_headers - existing_headers
    if missing_headers:
        headers.extend(missing_headers)

    container_name_idx = headers.index("container_name")
    status_idx = headers.index("status")
    exp_name_idx = headers.index("exp_name")

    rows_to_stop = []

    for i, row in enumerate(rows[2:], start=2):
        while len(row) < len(headers):
            row.append("")
        
        if row[container_name_idx] == container_name and row[status_idx] == "running":
            rows_to_stop.append(i)

    if idx < len(rows) - 2:
        row = rows[idx + 2]
        row[status_idx] = "running"
        row[exp_name_idx] = exp_name
        row[container_name_idx] = container_name

    for i in rows_to_stop:
        rows[i][status_idx] = "stopped"

    with open(csv_file, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(rows)

    fcntl.lockf(lock, fcntl.LOCK_UN)

    return exp_name, container_name

def clean_param_name(param):
    return re.sub(r"\s*\(.*?\)", "", param).strip()

def parse_schedule(csv_file):
    lock = open(SCRIPT_DIR + '/schedule.lock', 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    experiments = []

    with open(csv_file, "r") as infile:
        reader = csv.reader(infile)
        try:
            headers = next(reader)
            params = next(reader)
        except StopIteration:
            print("CSV file is empty or missing headers. Exiting...")
            return None
        
        params = [clean_param_name(param) for param in params]

        section_map = {}
        current_section = None
        
        for i, header in enumerate(headers):
            if header:
                current_section = header.strip()
            section_map[i] = current_section

        for values in reader:
            config_data = {}
            num_cores = None
            valid_row = True

            for i, value in enumerate(values):
                section = section_map.get(i, "")
                param_name = params[i]
                param_value = value.strip()

                if param_name == "status":
                    status = param_value
                elif param_name == "exp_name":
                    exp_name = param_value
                elif param_name == "container_name":
                    container_name = param_value
                elif param_name == "num_cores":
                    num_cores = param_value
                elif section and param_name:
                    if section not in config_data:
                        config_data[section] = {}

                    if param_value:
                        config_data[section][param_name] = param_value
                    else:
                        valid_row = False
                        break
            
            if (not valid_row):
                continue

            experiments.append((status, exp_name, container_name, num_cores, config_data))

    fcntl.lockf(lock, fcntl.LOCK_UN)

    return experiments

def create_config_file(config_data, index):
    config = ConfigParser()
    
    for section, values in config_data.items():
        config[section] = values
    
    os.makedirs("docker", exist_ok=True)
    config_path = f"config.ini"
    
    with open(config_path, "w") as configfile:
        config.write(configfile)
    
    return config_path

if __name__ == "__main__":
    ensure_experiment_consistency(SCHEDULE_CSV, EXPERIMENTS_DIR)
    experiments = parse_schedule(SCHEDULE_CSV)

    with open("cpu_ids.csv") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cpu_id = int(row["CPU ID"])
            physical_id = int(row["Physical ID"])
            logical_id = int(row["Logical ID"])
            pair = (cpu_id, physical_id)

            logical_to_pair[logical_id] = pair
            pair_to_logical[pair].append(logical_id)

    if experiments:
        for idx, (status, exp_name, container_name, num_cores, config_data) in enumerate(experiments):
            if status == "":
                    exp_name, container_name = assign_names(SCHEDULE_CSV, idx, int(num_cores), config_data)

                    if exp_name and container_name:
                        config_file_path = create_config_file(config_data, idx)
                        print(f"Config file created: {config_file_path} (num_cores: {num_cores})")
                        run_experiment(exp_name, container_name, int(num_cores), 0)
            elif status == "replay":
                if exp_name and container_name:
                    config_data["GENERAL"]["status"] = ""
                    config_data["GENERAL"]["mode"] = container_name

                    if exp_name and container_name:
                        config_file_path = create_config_file(config_data, idx)
                        print(f"Config file created: {config_file_path} (num_cores: {num_cores})")
                        run_experiment(exp_name, container_name, int(num_cores), 1)
                else:
                    assert(exp_name and container_name)
