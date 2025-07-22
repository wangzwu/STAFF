import os
import subprocess
import signal
import shutil
import re
import fcntl
import time
import pyshark
import socket
import argparse
import configparser
from analysis.convert_pcap import convert_pcap_into_single_seed_file, convert_pcap_into_multiple_seed_files
from analysis.taint_analysis import taint
import csv
import stat
import glob
import tempfile
import angr
import tarfile
from FirmAE.sources.extractor.extractor import Extractor
from typing import Dict, Optional

patterns = [
    "FirmAE/scratch/staff*",
    "FirmAE/scratch/aflnet*",
    "FirmAE/scratch/triforce*",
    "FirmAE/images/staff*",
    "FirmAE/images/aflnet*",
    "FirmAE/images/triforce*",
    "FirmAE/firm_db_aflnet*",
    "FirmAE/firm_db_staff*",
    "FirmAE/firm_db_triforce*"
]

DEFAULT_CONFIG = {
    "GENERAL": {
        "mode": ("run", str),
        "firmware": ("dlink/dap2310_v1.00_o772.bin", str)
    },
    "CAPTURE": {
        "whitelist_keywords": ("POST/PUT/.php/.cgi/.xml", str),
        "blacklist_keywords": (".gif/.jpg/.png/.css/.js/.ico/.htm/.html", str)
    },
    "PRE-ANALYSIS": {
        "subregion_divisor": (10, int),
        "min_subregion_len": (3, int),
        "delta_threshold": (0.15, float)
    },
    "EMULATION_TRACING": {
        "include_libraries": (1, int)
    },
    "GENERAL_FUZZING": {
        "fuzz_tmout": (86400, int),
        "timeout": (120, int),
        "afl_no_arith": (1, int),
        "afl_no_bitflip": (0, int),
        "afl_no_interest": (1, int),
        "afl_no_user_extras": (1, int),
        "afl_no_extras": (1, int),
        "afl_calibration": (1, int),
        "afl_shuffle_queue": (1, int)
    },
    "AFLNET_FUZZING": {
        "region_delimiter": ("\x1A\x1A\x1A\x1A", bytes),
        "proto": ("http", str),
        "region_level_mutation": (1, int)
    },
    "STAFF_FUZZING": {
        "taint_hints_all_at_once": (0, int),
        "sequence_minimization": (1, int),
        "taint_metrics": ("rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes", str),
        "checkpoint_strategy": (1, int)
    },    
    "EXTRA_FUZZING": {
        "coverage_tracing": ("taint_block", str),
        "stage_max": (1, int)
    }
}

STAFF_DIR = os.getcwd()
CRASH_DIR = os.path.join(STAFF_DIR, "extracted_crash_outputs")
FIRMAE_DIR = os.path.join(STAFF_DIR, "FirmAE")
PCAP_DIR = os.path.join(STAFF_DIR, "pcap")
TAINT_DIR = os.path.join(STAFF_DIR, "taint_analysis")
FIRMWARE_DIR = os.path.join(STAFF_DIR, "firmwares")
ANALYSIS_DIR = os.path.join(STAFF_DIR, "analysis")
CONFIG_INI_PATH=os.path.join(STAFF_DIR, "config.ini")
SCHEDULE_CSV_PATH=os.path.join(STAFF_DIR, "schedule.csv")
EXP_DONE_PATH=os.path.join(STAFF_DIR, "experiments_done")

captured_pcap_path = None
PSQL_IP = None
config = None

def set_permissions_recursive(dir_path):
    for root, dirs, files in os.walk(dir_path):
        for d in dirs:
            os.chmod(os.path.join(root, d), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        
        for f in files:
            os.chmod(os.path.join(root, f), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

def update_schedule_status(schedule_csv_path, status, exp_name):
    lock = open(os.path.join(os.path.dirname(schedule_csv_path), "schedule.lock"), 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    updated_rows = []
    with open(schedule_csv_path, "r") as infile:
        reader = csv.reader(infile)
        
        try:
            header1 = next(reader)
            header2 = next(reader)
        except StopIteration:
            print("CSV file is empty or missing headers. Exiting...")
            return

        updated_rows.append(header1)
        updated_rows.append(header2)

        status_idx = header2.index("status")
        exp_name_idx = header2.index("exp_name")
        container_name_idx = header2.index("container_name")

        for row in reader:
            if len(row) > 1:
                if row[exp_name_idx] == exp_name:
                    row[status_idx] = status
                updated_rows.append(row)

    with open(schedule_csv_path, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(updated_rows)

    fcntl.lockf(lock, fcntl.LOCK_UN)

def get_pcap_application_layer_protocol(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    fourth_layers = []

    for packet in capture:
        layers = packet.layers

        if len(layers) >= 4:
            fourth_layer = layers[3].layer_name
            fourth_layers.append(fourth_layer)

    filtered_layers = [layer for layer in fourth_layers if layer != "DATA"]

    if filtered_layers:
        if all(layer == filtered_layers[0] for layer in filtered_layers):
            return filtered_layers[0]
        else:
            return "mixed"
    else:
        return "none"

def cleanup(work_dir):
    print("\n[*] Cleanup Procedure..")

    if os.path.exists(os.path.join(work_dir, "debug")):
        shutil.rmtree(os.path.join(work_dir, "debug"), ignore_errors=True)

    subprocess.run(["sudo", "-E", "umount", f"{work_dir}/dev/null"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "-E", "umount", f"{work_dir}/dev/urandom"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "-E", "umount", f"{work_dir}/proc_host/stat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    current_pid = os.getpid()

    parent_pids = set()
    try:
        pid = current_pid
        while pid != 1:
            output = subprocess.check_output(["ps", "-p", str(pid), "-o", "ppid="]).decode().strip()
            ppid = int(output)
            if ppid == pid or ppid == 0:
                break
            parent_pids.add(ppid)
            pid = ppid
    except Exception as e:
        print(f"[!] Error while finding parent processes: {e}")

    try:
        output = subprocess.check_output(["ps", "-e", "-o", "pid=", "-o", "comm="]).decode().splitlines()

        print("\n[*] Running processes before cleanup:")
        for line in output:
            pid_str, *command_parts = line.strip().split()
            pid = int(pid_str)
            command = ' '.join(command_parts)
            print(f"    PID {pid}: {command}")

        print("\n[*] Killing processes:")
        for line in output:
            pid_str, *command_parts = line.strip().split()
            pid = int(pid_str)
            command = ' '.join(command_parts)

            if pid == 1 or pid == current_pid or pid in parent_pids:
                continue

            try:
                os.kill(pid, signal.SIGKILL)
                print(f"    [*] Killed PID {pid} ({command})")
            except ProcessLookupError:
                pass

    except Exception as e:
        print(f"[!] Error during process cleanup: {e}")

    subprocess.run(["sudo", "-E", f"{FIRMAE_DIR}/flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def cleanup_and_exit(work_dir):
    cleanup(work_dir)
    print("[+] ..End")
    exit(0)

def send_signal_recursive(target_pid, signal_code):
    try:
        child_pids = subprocess.check_output(["sudo", "-E", "pgrep", "-P", str(target_pid)]).decode('utf-8').splitlines()
        for child_pid in child_pids:
            send_signal_recursive(int(child_pid), signal_code)
    except subprocess.CalledProcessError:
        pass
    finally:
        os.kill(target_pid, signal_code)

def get_next_filename(directory_path, word):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        os.chmod(directory_path, 0o777)

    pattern = "{}_([0-9]+).*".format(word)

    highest_i = -1
    for filename in os.listdir(directory_path):
        match = re.match(pattern, filename)
        if match:
            i = int(match.group(1))
            if i > highest_i:
                highest_i = i

    next_i = highest_i + 1
    return "{}_{}".format(word, next_i)

def run_capture_signal_handler(signum, frame):
    global config
    global captured_pcap_path

    if config["GENERAL"]["mode"] == "run_capture":
        time.sleep(1)

        dst_dir = os.path.join(PCAP_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]), get_pcap_application_layer_protocol(captured_pcap_path))

        if not os.path.exists(dst_dir):
            os.makedirs(dst_dir)
        try:
            next_pcap_name = get_next_filename(dst_dir, "user_interaction")
            final_pcap_path = os.path.join(dst_dir, "{}.pcap".format(next_pcap_name))
            shutil.move(captured_pcap_path, final_pcap_path)
            print(f"[INFO] File moved to {final_pcap_path}")
        except Exception as e:
            print(f"[ERROR] Failed to move file: {e}")
        
        set_permissions_recursive(PCAP_DIR)

    exit(0)

def copy_file(src_path, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    filename = os.path.basename(src_path)
    dest_path = os.path.join(dest_dir, filename)
    shutil.copy2(src_path, dest_path)

def fast_copytree(source, destination):
    os.makedirs(destination, exist_ok=True)
    subprocess.run(["rsync", "-a", "--info=progress2", source + "/", destination], check=True)

def replace_pattern_in_file(file_path, pattern, replacement):
    with open(file_path, 'r') as file:
        content = file.read()

    content = re.sub(pattern, replacement, content)

    with open(file_path, 'w') as file:
        file.write(content)

def copy_image(dst_mode, firmware):
    src_iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, PSQL_IP, "run"]).decode('utf-8').strip()

    if not src_iid or not os.path.exists(os.path.join(FIRMAE_DIR, "scratch", "run", src_iid)):
        return False

    mode = "run"
    source_csv = os.path.join(FIRMAE_DIR, f"firm_db_{mode}.csv")
    dst_csv = os.path.join(FIRMAE_DIR, f"firm_db_{dst_mode}.csv")
    os.makedirs(os.path.dirname(dst_csv), exist_ok=True)

    if not os.path.exists(dst_csv):
        with open(dst_csv, mode='w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['id', 'firmware', 'brand', 'arch', 'result'])

    row_to_copy = None
    with open(source_csv, mode='r', newline='', encoding='utf-8') as src_file:
        reader = csv.reader(src_file)
        next(reader)
        for row in reader:
            if row[0] == src_iid:
                row_to_copy = row
                break

    if not row_to_copy:
        return False

    existing_ids = set()
    existing_id = None
    with open(dst_csv, mode='r', newline='', encoding='utf-8') as dst_file:
        reader = csv.reader(dst_file)
        next(reader, None)
        for row in reader:
            if row[0].isdigit():
                existing_ids.add(int(row[0]))
            if row[1] == os.path.basename(firmware):
                existing_id = row[0]

    dst_iid = existing_id if existing_id else str(max(existing_ids) + 1 if existing_ids else 1)

    row_to_copy[0] = dst_iid
    with open(dst_csv, mode='a', newline='', encoding='utf-8') as dst_file:
        writer = csv.writer(dst_file)
        writer.writerow(row_to_copy)

    source_img = os.path.join(FIRMAE_DIR, "scratch", "run", src_iid)
    dest_img = os.path.join(FIRMAE_DIR, "scratch", dst_mode, dst_iid)

    fast_copytree(source_img, dest_img)

    run_file = os.path.join(dest_img, "run.sh")
    if not os.path.islink(run_file.replace(".sh", "_%s.sh" % dst_mode)):
        os.symlink(run_file, run_file.replace(".sh", "_%s.sh" % dst_mode))

    replace_pattern_in_file(run_file, f'IID={src_iid}', f'IID={dst_iid}')

    if "staff_base" in dst_mode:
        suffix = dst_mode.split("staff_base", 1)[1]
        dst_abbr_mode = f"sb{suffix}"
    elif "staff_state_aware" in dst_mode:
        suffix = dst_mode.split("staff_state_aware", 1)[1]
        dst_abbr_mode = f"ss{suffix}"
    elif "triforce" in dst_mode:
        suffix = dst_mode.split("triforce", 1)[1]
        dst_abbr_mode = f"t{suffix}"
    elif "aflnet_base" in dst_mode:
        suffix = dst_mode.split("aflnet_base", 1)[1]
        dst_abbr_mode = f"ab{suffix}"
    elif "aflnet_state_aware" in dst_mode:
        suffix = dst_mode.split("aflnet_state_aware", 1)[1]
        dst_abbr_mode = f"as{suffix}"
    else:
        assert(0)

    replace_pattern_in_file(run_file, '_run_', f'_{dst_abbr_mode}_')
    replace_pattern_in_file(run_file, f'_{src_iid}', f'_{dst_iid}')
    
    prev_dir = os.getcwd()
    os.chdir(STAFF_DIR)
    subprocess.run(["sudo", "-E", "python3", os.path.join(STAFF_DIR, "update_executables.py"), dst_mode])
    os.chdir(prev_dir)

    return True

def check_firmware(firmware, mode):
    iid = ""
    subprocess.run(["sudo", "-E", "./flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", PSQL_IP, mode], stdout=subprocess.PIPE).returncode == 0:
        if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", PSQL_IP, mode], stdout=subprocess.PIPE).returncode == 0:
            print("[\033[31m-\033[0m] docker container failed to connect to the hosts' postgresql!")
            exit(1)

    iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, PSQL_IP, mode]).decode('utf-8').strip()

    if iid == "" or not os.path.exists(os.path.join(FIRMAE_DIR, "scratch", mode, iid)):
        copy_image(mode, firmware)

    print("\033[32m[+]\033[0m\033[32m[+]\033[0m FirmAE: Creating Firmware Scratch Image")
    subprocess.run(["sudo", "-E", "./run.sh", "-c", os.path.basename(os.path.dirname(firmware)), os.path.join(FIRMWARE_DIR, firmware), mode, PSQL_IP])
    iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, PSQL_IP, mode]).decode('utf-8').strip()

    return iid

def search_recursive(directory):
    for root, _, files in os.walk(directory):
        for filename in files:
            if any(filename.endswith(extension) for extension in ('.zip', '.tar.gz', '.ZIP')):
                yield os.path.abspath(os.path.join(root, filename))

def check(mode):
    global config

    if config["GENERAL"]["firmware"] != "all":
        return check_firmware(config["GENERAL"]["firmware"], mode)
    else:
        main_files = []
        subdir_files = []
        subdirs = []
        for root, dirs, files in os.walk(FIRMWARE_DIR):
            if root == FIRMWARE_DIR:
                main_files.extend([os.path.join(root, f) for f in files])
                subdirs = [os.path.join(root, d) for d in dirs]
            else:
                subdir_files.extend([os.path.join(root, f) for f in files])

        subdir_groups = {}

        for subdir in subdirs:
            subdir_groups[subdir] = [
                os.path.join(root, f)
                for root, _, files in os.walk(subdir)
                for f in files
            ]

        if not subdir_groups:
            return

        max_files = max(len(files) for files in subdir_groups.values())

        for i in range(max_files):
            for subdir in subdirs:
                if i < len(subdir_groups[subdir]):
                    file = subdir_groups[subdir][i]
                    print("Checking %s" % file)
                    check_firmware(file, mode)

        return 0

def load_config(file_path="config.ini"):
    global config

    config = configparser.ConfigParser()
    config.read(file_path)

    final_config = {}

    for section, options in DEFAULT_CONFIG.items():
        final_config[section] = {}

        if not config.has_section(section):
            config.add_section(section)

        for key, default_info in options.items():
            if isinstance(default_info, tuple) and len(default_info) == 2:
                default_value, data_type = default_info
            else:
                print(f"Warning: Invalid default entry for {section}.{key}, skipping.")
                continue

            if config.has_option(section, key):
                value = config.get(section, key)
                try:
                    if data_type == int:
                        value = int(value)
                    elif data_type == float:
                        value = float(value)
                    elif data_type == str:
                        value = str(value)
                    elif data_type == bytes:
                        value = bytes.fromhex(value.replace('\\x', ''))
                    else:
                        assert(0)
                except ValueError:
                    print(f"Warning: Invalid type for {section}.{key}, using default value.")
                    value = default_value
            else:
                value = default_value

            final_config[section][key] = value

    return final_config

def replay_firmware(firmware, work_dir, crash_analysis=False, crash_seed=None, target_procname=None):
    global config

    os.environ["EXEC_MODE"] = "RUN"
    os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')    
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])

    if crash_analysis:
        os.environ["CRASH_ANALYSIS"] = "1"
        os.environ["TRACE_LEN"] = "300"
        os.environ["TARGET_PROCNAME"] = target_procname
        os.environ["DEBUG"] = "1"
        os.environ["DEBUG_DIR"] = os.path.join(work_dir, "debug", "interaction")
    else:
        os.environ["TAINT"] = "1"
        os.environ["FD_DEPENDENCIES_TRACK"] = "1"
        os.environ["DEBUG"] = "1"
        os.environ["DEBUG_DIR"] = os.path.join(work_dir, "debug", "interaction")

    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep = file.read().strip()
    sleep=int(float(sleep))

    if (crash_analysis):
        print(f"\n[\033[32m+\033[0m] Crash mode (seed: {crash_seed})")

        seed_path = crash_seed
        process = subprocess.Popen(
            ["sudo", "-E", "./run.sh", "-r", os.path.basename(os.path.dirname(firmware)), os.path.join(FIRMWARE_DIR, firmware), "run", PSQL_IP],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        qemu_pid = process.pid
        print("Booting firmware, wait %d seconds..."%(sleep))
        time.sleep(sleep)

        port = 80
        command = ["sudo", "-E", os.path.join(STAFF_DIR, "aflnet", "client"), seed_path, os.path.join(work_dir, "qemu.final.serial.log"), open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(config["GENERAL_FUZZING"]["timeout"])]    
        print(" ".join(command))
        subprocess.run(command)

        send_signal_recursive(qemu_pid, signal.SIGINT)
    else:
        pcap_dir = os.path.join(PCAP_DIR, firmware)
                    
        print("\n[\033[32m+\033[0m] Replay mode")

        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]
        start_fork_executed = False
        for proto in sub_dirs:
            print("\n[\033[33m*\033[0m] Protocol: {}".format(proto))
            for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
                pcap_path = os.path.join(pcap_dir, proto, pcap_file)
                print("\n[\033[34m*\033[0m] PCAP #{}".format(pcap_file))

                seed_path = os.path.join(work_dir, "inputs", "%s.seed"%(pcap_file))
                sources_hex = convert_pcap_into_single_seed_file(pcap_path, seed_path, config["AFLNET_FUZZING"]["region_delimiter"])

                process = subprocess.Popen(
                    ["sudo", "-E", "./run.sh", "-r", os.path.basename(os.path.dirname(firmware)), os.path.join(FIRMWARE_DIR, firmware), "run", PSQL_IP],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                qemu_pid = process.pid
                print("Booting firmware, wait %d seconds..."%(sleep))
                time.sleep(sleep)

                port = None
                try:
                    port = socket.getservbyname(proto)
                    print(f"The port for {proto.upper()} is {port}.")
                except OSError:
                    print(f"Protocol {proto.upper()} not found.")
                command = ["sudo", "-E", os.path.join(STAFF_DIR, "aflnet", "client"), seed_path, os.path.join(work_dir, "qemu.final.serial.log"), open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(config["GENERAL_FUZZING"]["timeout"])]    
                print(" ".join(command))
                subprocess.run(command)

                send_signal_recursive(qemu_pid, signal.SIGINT)
                try:
                    os.waitpid(qemu_pid, 0)
                except:
                    pass
                time.sleep(2)


####################################################################

def replay():
    global config

    if config["GENERAL"]["firmware"] != "all":
        iid = str(check("run"))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

        if "true" in open(os.path.join(work_dir, "web_check")).read():
            replay_firmware(config["GENERAL"]["firmware"], work_dir)
    else:
        firmware_brands = {}
        
        for brand in os.listdir(PCAP_DIR):
            brand_path = os.path.join(PCAP_DIR, brand)
            if os.path.isdir(brand_path):
                firmware_brands[brand] = {}
                for device in os.listdir(brand_path):
                    device_path = os.path.join(brand_path, device)
                    if os.path.isdir(device_path):
                        firmware_brands[brand][device] = [
                            os.path.join(root, f)
                            for root, _, files in os.walk(device_path)
                            for f in files
                        ]

        if not firmware_brands:
            return

        for brand, devices in firmware_brands.items():
            for device, files in devices.items():
                print(f"Replaying {os.path.basename(brand)}/{os.path.basename(device)}")
                iid = str(check_firmware(os.path.join(os.path.basename(brand), os.path.basename(device)), "run"))
                work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

                if "true" in open(os.path.join(work_dir, "web_check")).read():
                    replay_firmware(os.path.join(os.path.basename(brand), os.path.basename(device)), work_dir)

def run(capture, crash_analysis, crash_dir=None):
    global config
    global captured_pcap_path

    iid = str(check("run"))
    work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

    if "true" not in open(os.path.join(work_dir, "web_check")).read():
        return

    if os.path.exists(os.path.join(work_dir, "debug")):
        shutil.rmtree(os.path.join(work_dir, "debug"), ignore_errors=True)

    os.environ["EXEC_MODE"] = "RUN"
    # os.environ["CALLSTACK_TRACE"] = "1"
    # os.environ["INCLUDE_LIBRARIES"] = "1"
    # os.environ["DEBUG"] = "1"
    # os.environ["TAINT"] = "1"
    
    signal.signal(signal.SIGINT, run_capture_signal_handler)

    if os.path.exists(os.path.join(work_dir, "webserver_ready")):
        os.remove(os.path.join(work_dir, "webserver_ready"))

    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep = file.read().strip()
    sleep=int(float(sleep))

    process = subprocess.Popen(
        ["sudo", "-E", "./run.sh", "-r", os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.join(FIRMWARE_DIR, config["GENERAL"]["firmware"]), "run", PSQL_IP],

    )
    qemu_pid = process.pid

    print(f"Sleeping for {sleep} seconds...")
    time.sleep(sleep)
    
    print("[\033[32m+\033[0m] Web service READY!\n")

    if capture:
        blacklist_keywords = config["CAPTURE"]["blacklist_keywords"].split('/')
        whitelist_keywords = config["CAPTURE"]["whitelist_keywords"].split('/')

        pcap_dir = os.path.join(
            work_dir,
            PCAP_DIR,
            os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])),
            os.path.basename(config["GENERAL"]["firmware"])
        )

        os.makedirs(pcap_dir, exist_ok=True)

        captured_pcap_path = os.path.join(pcap_dir, "user_interaction.pcap")

        interface = f"tap_run_{iid}_0"
        target_ip = open(os.path.join(work_dir, "ip")).read().strip()

        subprocess.run([
            "sudo", "-E", "python3", os.path.join(ANALYSIS_DIR, "capture_packets.py"),
            interface,
            target_ip,
            captured_pcap_path,
            " ".join(blacklist_keywords),
            " ".join(whitelist_keywords)
        ])

        os.kill(qemu_pid, signal.SIGINT)

    os.waitpid(qemu_pid, 0)


def fuzz(out_dir, container_name, replay_exp):
    global config

    mode = container_name if container_name else config["GENERAL"]["mode"]

    if "staff" in mode:
        tmp_iid = str(check("run"))
        tmp_work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", tmp_iid)
        if "true" not in open(os.path.join(tmp_work_dir, "web_check")).read():
            return
        if os.path.exists(os.path.join(tmp_work_dir, "mem_file")):
            os.remove(os.path.join(tmp_work_dir, "mem_file"))
        with open(os.path.join(tmp_work_dir, "time_web"), 'r') as file:
            sleep = file.read().strip()
        sleep=int(float(sleep))
        taint(tmp_work_dir, "run", config["GENERAL"]["firmware"], sleep, config["GENERAL_FUZZING"]["timeout"], config["PRE-ANALYSIS"]["subregion_divisor"], config["PRE-ANALYSIS"]["min_subregion_len"], config["PRE-ANALYSIS"]["delta_threshold"], config["EMULATION_TRACING"]["include_libraries"], config["AFLNET_FUZZING"]["region_delimiter"])

    iid = str(check(mode))
    work_dir = os.path.join(FIRMAE_DIR, "scratch", mode, iid)

    if "true" not in open(os.path.join(work_dir, "web_check")).read():
        return
    if os.path.exists(os.path.join(work_dir, "mem_file")):
        os.remove(os.path.join(work_dir, "mem_file"))
    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep = file.read().strip()

    os.environ["TAINT"] = "0"
    os.environ["FD_DEPENDENCIES_TRACK"] = "0"
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])
    os.environ["COVERAGE_TRACING"] = str(config["EXTRA_FUZZING"]["coverage_tracing"])
    os.environ["STAGE_MAX"] = str(config["EXTRA_FUZZING"]["stage_max"])
    os.environ["AFL_NO_ARITH"] = str(config["GENERAL_FUZZING"]["afl_no_arith"])
    os.environ["AFL_NO_BITFLIP"] = str(config["GENERAL_FUZZING"]["afl_no_bitflip"])
    os.environ["AFL_NO_INTEREST"] = str(config["GENERAL_FUZZING"]["afl_no_interest"])
    os.environ["AFL_NO_USER_EXTRAS"] = str(config["GENERAL_FUZZING"]["afl_no_user_extras"])
    os.environ["AFL_NO_EXTRAS"] = str(config["GENERAL_FUZZING"]["afl_no_extras"])
    os.environ["AFL_CALIBRATION"] = str(config["GENERAL_FUZZING"]["afl_calibration"])
    os.environ["AFL_SHUFFLE_QUEUE"] = str(config["GENERAL_FUZZING"]["afl_shuffle_queue"])
    # os.environ["DEBUG_FUZZ"] = "1"
    # os.environ["DEBUG"] = "1"

    if "aflnet" in mode or "staff" in mode or replay_exp:
        os.environ["EXEC_MODE"] = "AFLNET"
        os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')   
    elif "triforce" in mode:
        os.environ["EXEC_MODE"] = "TRIFORCE"
    else:
        assert(0)

    with open("/proc/self/status") as file:
        status_content = file.read()

    cpu_to_bind = re.search(r"Cpus_allowed_list:\s*([0-9]+)", status_content)

    if cpu_to_bind:
        cpu_to_bind_value = cpu_to_bind.group(1)
        print("CPU_TO_BIND:", cpu_to_bind_value)
    else:
        print("CPU_TO_BIND not found in /proc/self/status")

    if os.path.exists(os.path.join(work_dir, "outputs")):
        shutil.rmtree(os.path.join(work_dir, "outputs"), ignore_errors=True)
    
    os.makedirs(os.path.join(work_dir, "outputs"))

    if "staff" in mode:
        if out_dir:
            os.makedirs(os.path.join(out_dir, "outputs", "taint_metadata"))
        else:
            os.makedirs(os.path.join(work_dir, "outputs", "taint_metadata"))

    if os.path.exists(os.path.join(work_dir, "inputs")):
        shutil.rmtree(os.path.join(work_dir, "inputs"), ignore_errors=True)
    
    os.makedirs(os.path.join(work_dir, "inputs"))

    filename = os.path.join(work_dir, "ip")
    ip = ""
    try:
        with open(filename, 'r') as file:
            ip = file.read().strip()
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        exit(1)

    proto = config["AFLNET_FUZZING"]["proto"]
    port = None
    try:
        port = socket.getservbyname(proto)
        print(f"The port for {proto.upper()} is {port}.")
    except OSError:
        print(f"Protocol {proto.upper()} not found.")
        exit(1)

    if "staff" in mode:
        os.environ["SEQUENCE_MINIMIZATION"] = str(config["STAFF_FUZZING"]["sequence_minimization"])

        inputs = os.path.join(work_dir, "inputs")
        pcap_dir = os.path.join(TAINT_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]))
        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            pcap_path = os.path.join(pcap_dir, proto, pcap_file)
            pcap_file = os.path.join(pcap_path, "%s.seed"%(pcap_file))
            taint_metadata_file = os.path.join(pcap_path, "%s_metadata.json"%(pcap_file))
            shutil.copy(pcap_file, inputs)

            if out_dir:
                shutil.copy(taint_metadata_file, os.path.join(out_dir, "outputs", "taint_metadata"))
            else:
                shutil.copy(taint_metadata_file, os.path.join(work_dir, "outputs", "taint_metadata"))

    elif "aflnet" in mode:
        inputs = os.path.join(work_dir, "inputs")
        pcap_dir = os.path.join(PCAP_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]))
        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            seed_path = os.path.join(inputs, "%s.seed"%(pcap_file))
            pcap_path = os.path.join(pcap_dir, proto, pcap_file)
            convert_pcap_into_single_seed_file(pcap_path, seed_path, config["AFLNET_FUZZING"]["region_delimiter"])        
    elif "triforce" in mode:
        inputs = os.path.join(work_dir, "inputs")
        os.makedirs(inputs, exist_ok=True)
        seed_path = os.path.join(work_dir, "seed")

        pcap_dir = os.path.join(PCAP_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]))
        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]

        first_seed_written = False
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            pcap_path = os.path.join(pcap_dir, proto, pcap_file)
            generated = convert_pcap_into_multiple_seed_files(
                pcap_path,
                inputs,
                pcap_file,
                config["AFLNET_FUZZING"]["region_delimiter"]
            )

            if not first_seed_written and generated:
                seed_files = sorted(
                    [f for f in os.listdir(inputs) if f.startswith(pcap_file)],
                    key=lambda name: int(name.split("_")[-1].split(".")[0])
                )
                if seed_files:
                    src = os.path.join(inputs, seed_files[0])
                    dst = os.path.join(seed_path)
                    shutil.copy(src, dst)
                    first_seed_written = True
    else:
        assert(0)

    subprocess.run(["sudo", "-E", "./run.sh", "-f", os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.join(FIRMWARE_DIR, config["GENERAL"]["firmware"]), mode, PSQL_IP])

    filename = os.path.join(work_dir, "afl-qemu-system-trace_cmd")
    afl_qemu_system_trace_cmd = ""
    try:
        with open(filename, 'r') as file:
            afl_qemu_system_trace_cmd = file.read()
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        exit(1)

    filename = os.path.join(work_dir, "afl-qemu-system-trace_cmd_append")
    afl_qemu_system_trace_cmd_append = ""
    try:
        with open(filename, 'r') as file:
            afl_qemu_system_trace_cmd_append = file.read()
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        exit(1)

    subprocess.run(["sudo", "-E", "tee", "/proc/sys/kernel/core_pattern"], input=b"core\n", check=True)

    env = os.environ.copy()
    env["AFL_SKIP_CPUFREQ"] = "1"

    prev_dir = os.getcwd()
    os.chdir(work_dir)

    command = ["sudo", "-E"]
    # command += ["gdb", "--args"]
    command += ["./afl-fuzz"]
    command += ["-t", "8000000+"]
    command += ["-w", str(config["GENERAL_FUZZING"]["timeout"])]
    command += ["-b", cpu_to_bind_value]
    command += ["-y", str(config["GENERAL_FUZZING"]["fuzz_tmout"])]
    command += ["-m", "none"]
    command += ["-i", inputs]
    if out_dir:
        command += ["-o", os.path.join(out_dir, "outputs")]
    else:
        command += ["-o", "outputs"]
    command += ["-x", "keywords"]
    command += ["-D", str(sleep)]
    if "staff" in mode or "aflnet" in mode:
        command += ["-N", f"tcp://{ip}/{port}"]
        command += ["-P", proto.upper()]
        if config["AFLNET_FUZZING"]["region_level_mutation"]:
            command += ["-R"]
        if config["STAFF_FUZZING"]["checkpoint_strategy"]:
            command += ["-X"]
    if "staff" in mode:
        command += ["-H"]
        with open(os.path.join(work_dir, "taint_metrics"), 'w') as file:
            file.write(config["STAFF_FUZZING"]["taint_metrics"])
        with open(os.path.join(TAINT_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]), "global_elapsed_time"), "r") as f:
            global_elapsed_time_ms = f.read().strip()
        command += ["-A", global_elapsed_time_ms]
        if config["STAFF_FUZZING"]["taint_hints_all_at_once"]:
            command += ["-O"]
    if "state_aware" in mode:
        command += ["-E"]

    replay_cmd = list(command)
    replay_cmd += ["-N", f"tcp://{ip}/{port}"]
    replay_cmd += ["-P", proto.upper()]
    if config["AFLNET_FUZZING"]["region_level_mutation"]:
        replay_cmd += ["-R"]
    if config["STAFF_FUZZING"]["checkpoint_strategy"]:
        replay_cmd += ["-X"]

    command += ["-QQ"]
    command += ["--"]

    for arg in afl_qemu_system_trace_cmd.split(" "):
        if arg != '':
            command.append(arg.strip())

    command.append("-append")

    command.append(afl_qemu_system_trace_cmd_append.strip())

    command.append("--aflFile")
    command.append("@@")

    if not replay_exp:
        ret = 1
        try:
            print(" ".join(command))
            subprocess.run(
                command,
                env=env,
                check=True
            )
            ret = 0
        except subprocess.CalledProcessError as e:
            print(f"Command failed with error: {e}")
            ret = 1

    if "triforce" in mode or replay_exp:
        os.chdir(prev_dir)
        cleanup(work_dir)
        subprocess.run(["sudo", "-E", "./run.sh", "-f", os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.join(FIRMWARE_DIR, config["GENERAL"]["firmware"]), mode, PSQL_IP])
        os.chdir(work_dir)

        if out_dir:
            os.rename(os.path.join(out_dir, "outputs", "plot_data"), os.path.join(out_dir, "outputs", "old_plot_data"))
            os.rename(os.path.join(out_dir, "outputs", "fuzzer_stats"), os.path.join(out_dir, "outputs", "old_fuzzer_stats"))
        else:
            os.rename(os.path.join("outputs", "plot_data"), os.path.join("outputs", "old_plot_data"))
            os.rename(os.path.join("outputs", "fuzzer_stats"), os.path.join("outputs", "old_fuzzer_stats"))

        os.environ["EXEC_MODE"] = "AFLNET"
        os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')
        os.environ["AFL_SKIP_CPUFREQ"] = "1"
        env = os.environ.copy()

        command = ["sudo", "-E"]
        command += ["./afl-fuzz-net" if x == "./afl-fuzz" else x for x in replay_cmd[2:]]
        command += ["-Y"]
        command += ["-QQ"]
        command += ["--"]

        for arg in afl_qemu_system_trace_cmd.split(" "):
            if arg != '':
                command.append(arg.strip())

        command.append("-append")

        command.append(afl_qemu_system_trace_cmd_append.strip())

        command.append("--aflFile")
        command.append("@@")

        try:
            print(" ".join(command))
            subprocess.run(
                command,
                env=env,
                check=True
            )
            ret = 0
        except subprocess.CalledProcessError as e:
            print(f"Command failed with error: {e}")
            ret = 1

    os.chdir(prev_dir)

    if out_dir:
        if ret:
            update_schedule_status(SCHEDULE_CSV_PATH, "failed", os.path.basename(out_dir))
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir, ignore_errors=True)
        else:
            update_schedule_status(SCHEDULE_CSV_PATH, "succeeded", os.path.basename(out_dir))

            # if os.path.isdir(out_dir):
            #     os.makedirs(EXP_DONE_PATH, exist_ok=True)

            #     def get_next_available_exp_name(out_dir):
            #         used = set()
            #         pattern = re.compile(r'^exp_(\d+)$')
            #         for entry in os.listdir(out_dir):
            #             match = pattern.match(entry)
            #             if match:
            #                 used.add(int(match.group(1)))
            #         n = 1
            #         while True:
            #             if n not in used:
            #                 return f"exp_{n}"
            #             n += 1

            #     new_exp_name = get_next_available_exp_name(EXP_DONE_PATH)
            #     dst_path = os.path.join(EXP_DONE_PATH, new_exp_name)
            #     print(f"Moving succeeded experiment {os.path.basename(out_dir)} -> {new_exp_name}")
            #     shutil.move(out_dir, dst_path)

    return ret

def pre_analysis():
    global config

    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])

    if (config["GENERAL"]["firmware"] != "all"):
        iid = str(check("run"))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

        if "true" in open(os.path.join(work_dir, "web_check")).read():
            with open(os.path.join(work_dir, "time_web"), 'r') as file:
                sleep = file.read().strip()
            sleep=int(float(sleep))

            taint(work_dir, "run", config["GENERAL"]["firmware"], sleep, config["GENERAL_FUZZING"]["timeout"], config["PRE-ANALYSIS"]["subregion_divisor"], config["PRE-ANALYSIS"]["min_subregion_len"], config["PRE-ANALYSIS"]["delta_threshold"], config["EMULATION_TRACING"]["include_libraries"], config["AFLNET_FUZZING"]["region_delimiter"])
    else:
        firmware_brands = {}
        
        for brand in os.listdir(PCAP_DIR):
            brand_path = os.path.join(PCAP_DIR, brand)
            if os.path.isdir(brand_path):
                firmware_brands[brand] = {}
                for device in os.listdir(brand_path):
                    device_path = os.path.join(brand_path, device)
                    if os.path.isdir(device_path):
                        firmware_brands[brand][device] = [
                            os.path.join(root, f)
                            for root, _, files in os.walk(device_path)
                            for f in files
                        ]

        if not firmware_brands:
            return

        for brand, devices in firmware_brands.items():
            for device, files in devices.items():
                print(f"Pre-analyzing {os.path.basename(brand)}/{os.path.basename(device)}")
                iid = str(check_firmware(os.path.join(os.path.basename(brand), os.path.basename(device)), "run"))
                work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

                if "true" in open(os.path.join(work_dir, "web_check")).read():
                    with open(os.path.join(work_dir, "time_web"), 'r') as file:
                        sleep = file.read().strip()
                    sleep=int(float(sleep))

                    taint(work_dir, "run", os.path.join(os.path.basename(brand), os.path.basename(device)), sleep, config["GENERAL_FUZZING"]["timeout"], config["PRE-ANALYSIS"]["subregion_divisor"], config["PRE-ANALYSIS"]["min_subregion_len"], config["PRE-ANALYSIS"]["delta_threshold"], config["EMULATION_TRACING"]["include_libraries"], config["AFLNET_FUZZING"]["region_delimiter"])

def crash_analysis(_=None):
    global config

    PROCESS_RE = re.compile(r".*Process:\s*(\S+)")
    MODULE_RE  = re.compile(r".*module:\s*(\S+)")
    PC_RE      = re.compile(r"pc:\s*(0x[0-9A-Fa-f]+)")
    SYMBOL_TAG = ", symbol:"

    module_cache: Dict[str, angr.Project] = {}

    def set_permissions_recursive(path: str, mode: int = 0o777) -> None:
        for root, dirs, files in os.walk(path):
            os.chmod(root, mode)
            for f in files:
                os.chmod(os.path.join(root, f), mode)

    def run_extractor(fw_path: str, extract_dir: str) -> None:
        env = os.environ.copy()
        env["NO_PSQL"] = "1"
        subprocess.run(
            [
                "./sources/extractor/extractor.py",
                "-t", "run",
                "-b", "unknown",
                "-sql", "0.0.0.0",
                "-np",
                "-nk",
                fw_path,
                extract_dir
            ],
            env=env,
            check=True
        )

    def build_fw_index(root: str) -> Dict[str, str]:
        idx: Dict[str, str] = {}
        for d, _, files in os.walk(root):
            for fn in files:
                idx[os.path.basename(fn)] = os.path.join(d, fn)
        return idx

    def find_module_path(extract_dir: str, module_name: str) -> Optional[str]:
        for d, _, files in os.walk(extract_dir):
            if module_name in files:
                return os.path.join(d, module_name)
        return None

    def lookup_symbol(module_path: str, addr: int) -> Optional[str]:
        proj = module_cache.get(module_path)
        if proj is None:
            proj = angr.Project(module_path, auto_load_libs=False)
            module_cache[module_path] = proj

        sym = proj.loader.find_symbol(addr)
        if sym and sym.name:
            return sym.name

        mobj = proj.loader.main_object
        base = getattr(mobj, "rebased_addr", None) \
             or getattr(mobj, "mapped_base", None) \
             or getattr(mobj, "linked_base", 0)
        for f in mobj.symbols:
            if f.is_function:
                start = f.rebased_addr - base
                end   = start + (f.size or 1)
                if start <= addr < end:
                    return f.name
        return None

    def annotate_log_file(path: str, extract_dir: str) -> None:
        with open(path, "r") as f:
            lines = f.readlines()

        out: list[str] = []
        for line in lines:
            if SYMBOL_TAG in line:
                out.append(line)
                continue

            m_mod = MODULE_RE.match(line)
            m_pc  = PC_RE.search(line)
            if not (m_mod and m_pc):
                out.append(line)
                continue

            module_name = m_mod.group(1)
            addr        = int(m_pc.group(1), 16)
            module_path = find_module_path(extract_dir, module_name)
            if not module_path:
                out.append(line)
                continue

            sym = lookup_symbol(module_path, addr)
            if sym:
                out.append(line.rstrip("\n") + f"{SYMBOL_TAG} {sym}\n")
            else:
                out.append(line)

        with open(path, "w") as f:
            f.writelines(out)
        os.chmod(path, 0o777)
        print(f"[INFO] Annotated symbols in {path}")

    def move_dir_contents(src_dir: str, dest_dir: str) -> None:
        if not os.path.isdir(src_dir):
            raise ValueError(f"Source {src_dir!r} is not a directory")

        if os.path.exists(dest_dir) and not os.path.isdir(dest_dir):
            shutil.move(dest_dir, dest_dir.replace(os.path.basename(dest_dir), "seed"))
            os.makedirs(dest_dir, exist_ok=True)
            shutil.move(dest_dir.replace(os.path.basename(dest_dir), "seed"), dest_dir)

        for name in os.listdir(src_dir):
            s = os.path.join(src_dir, name)
            d = os.path.join(dest_dir, name)
            if os.path.exists(d):
                if os.path.isdir(d):
                    shutil.rmtree(d)
                else:
                    os.remove(d)
            shutil.move(s, d)

    base_fw    = os.path.basename(config["GENERAL"]["firmware"])
    crash_root = os.path.join(CRASH_DIR, base_fw)
    fw_index   = build_fw_index(FIRMWARE_DIR)

    for root, dirs, files in os.walk(crash_root):
        if os.path.basename(root) != "crashes":
            continue

        extract_dir = tempfile.mkdtemp(prefix="extracted_")
        try:
            fw_file = fw_index.get(base_fw)
            if not fw_file:
                print(f"[WARN] Firmware '{base_fw}' not found under {FIRMWARE_DIR}")
                continue

            run_extractor(fw_file, extract_dir)
            set_permissions_recursive(extract_dir)

            tars = glob.glob(os.path.join(extract_dir, "*.tar.gz"))
            if not tars:
                raise FileNotFoundError("No .tar.gz in extracted/")
            latest = max(tars, key=os.path.getmtime)
            with tarfile.open(latest, "r:gz") as tar:
                tar.extractall(path=extract_dir)

            for crash_file in files:
                crash_file_path = os.path.join(root, crash_file)

                if os.path.isdir(crash_file_path) or "README" in crash_file:
                    continue

                if (os.path.isfile(crash_file_path.replace("crashes", "crash_traces"))):
                    crash_trace = crash_file_path.replace("crashes", "crash_traces")
                else:
                    crash_trace = os.path.join(crash_file_path.replace("crashes", "crash_traces"), "seed")

                with open(crash_trace) as tf:
                    for line in tf:
                        m = PROCESS_RE.match(line)
                        if not m:
                            continue
                        iid = str(check_firmware(
                            os.path.join(os.path.dirname(config["GENERAL"]["firmware"]), base_fw),
                            "run"
                        ))
                        work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)
                        if "true" in open(os.path.join(work_dir, "web_check")).read():
                            replay_firmware(
                                os.path.join(os.path.dirname(config["GENERAL"]["firmware"]), base_fw),
                                work_dir, True,
                                crash_file_path,
                                m.group(1)
                            )
                            dest = os.path.join(crash_file_path.replace("crashes", "crash_traces"))

                            existing = set(os.listdir(dest)) if os.path.isdir(dest) else set()
                            move_dir_contents(os.path.join(work_dir, "crash_analysis"), dest)
                            shutil.copy(os.path.join(work_dir, "qemu.final.serial.log"), dest)
                            new_files = set(os.listdir(dest)) - existing

                            for fn in new_files:
                                if "qemu" not in fn:
                                    annotate_log_file(os.path.join(dest, fn), extract_dir)

        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

def start(keep_config, reset_firmware_images, replay_exp, out_dir, container_name, crash_dir=None):
    global PSQL_IP, config

    PSQL_IP = "0.0.0.0"
    os.environ["NO_PSQL"] = "1"

    if reset_firmware_images:
        for pattern in patterns:
            for path in glob.glob(pattern):
                if os.path.isdir(path):
                    print(f"Removing directory: {path}")
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    print(f"Removing file: {path}")
                    os.remove(path)

    config = load_config(CONFIG_INI_PATH)

    if not keep_config:
        if any(x in config["GENERAL"]["mode"] for x in ["aflnet_base", "aflnet_state_aware", "triforce", "staff_base", "staff_state_aware"]):
            if out_dir:
                copy_file(CONFIG_INI_PATH, os.path.join(out_dir, "outputs"))
            else:
                os.remove(CONFIG_INI_PATH)
        else:
            os.remove(CONFIG_INI_PATH)

    prev_dir = os.getcwd()
    os.chdir(FIRMAE_DIR)

    mode = config["GENERAL"]["mode"]
    if mode == "run":
        run(False, False)
    elif mode == "run_capture":
        run(True, False)
    elif mode == "replay":
        replay()
    elif mode == "crash_analysis":
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        crash_analysis(CRASH_DIR)
    elif mode == "check":
        check("run")
    elif mode == "pre_analysis":
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        pre_analysis()
    elif any(x in mode for x in ["aflnet_base", "aflnet_state_aware", "triforce", "staff_base", "staff_state_aware"]) or replay_exp:
        fuzz(out_dir, container_name, replay_exp)
    else:
        assert False, f"Unknown mode: {mode}"

    os.chdir(prev_dir)

if __name__ == "__main__":
    os.umask(0o000)
    parser = argparse.ArgumentParser(description="Process some arguments.")
    parser.add_argument("--keep_config", type=int, help="Keep config file", default=1)
    parser.add_argument("--reset_firmware_images", type=int, help="Reset firmware images", default=0)
    parser.add_argument("--replay_exp", type=int, help="Replay an experiment (triforce)", default=0)
    parser.add_argument("--output", type=str, help="Output dir", default=None)
    parser.add_argument("--container_name", type=str, help="Container name", default=None)
    parser.add_argument("--crash_dir", type=str, help="Directory of crash outputs for crash_analysis mode", default=None)

    args = parser.parse_args()

    start(
        args.keep_config,
        args.reset_firmware_images,
        args.replay_exp,
        os.path.abspath(args.output) if args.output else None,
        args.container_name if args.container_name else None,
        args.crash_dir
    )