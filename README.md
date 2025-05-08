
# STAFF  
_Stateful Taint‑Assisted Full‑system Firmware Fuzzer_

## Introduction & Motivation  
**STAFF** is a stateful, taint‑based, full‑system firmware fuzzing tool that combines ideas from protocol fuzzers and whole-system taint analyzers to uncover deep-state bugs in embedded systems. It builds on three pillars:

1. **AFLNET**: a greybox fuzzer for network protocols that uses state-feedback (e.g., HTTP response codes) alongside coverage feedback to guide mutations of message sequences.
2. **DECAF++**: a whole-system dynamic taint analysis framework that is twice as fast as its predecessor and imposes minimal overhead when inputs are untainted.
3. **FirmAE**: a large-scale firmware emulation framework that boosts firmware execution success from 16 % to ≈79 % through automated configuration and emulation heuristics.

STAFF targets firmware exposing **Protocol-based services**, applying fuzzing over sequences of protocol-level messages (called “regions”).

## Overview

![System Architecture Diagram](img/workflow.png)

### Exploration Phase
An initial *exploration phase* where the user interact with the target firmware and all requests are captured and recorded into a pcap files which are then used as initial corpus for the subsequent testing.

### Taint-Assisted pre-analysis

(TODO. Describe the "subsequences matching algorithm" from **“metadata map”** is obtained.)

Before fuzzing begins, STAFF performs a **taint-assisted pre-analysis** of sample interactions to extract **per-byte scores** that indicate the importance of each input byte with respect to various behavioral aspects of the system, such as:

- **Execution flow**: how many and which Translation Blocks (TBs) a byte can influence.
- **Process scope**: how many and which processes are affected by data derived from that byte.
- **Cross-region interaction**: whether that byte impacts subsequent regions in the same sequence (e.g., through control/data dependencies).
- **Persistence and reuse**: whether the byte is stored and later accessed via the filesystem (e.g., in session tokens, credentials, or temporary files).

STAFF uses these metrics on the **“metadata map”** of the initial interactions, resulting into a **taint-based priority queue** of mutation targets. Each entry in the queue includes the region, offset, and length to mutate—enabling **precise and effective mutation strategies**.

To further improve efficiency, STAFF enforces **input sequence minimization**. When a specific region is selected for mutation at a given offset, STAFF identifies and selects only the subset of regions from the original input sequence that are **relevant to the behavior influenced by that mutation**. This includes:

- **Prefix regions**: earlier regions that affect the chosen region (e.g., they initialize session state or write files later read by the target region).
- **Suffix regions**: later regions that are affected by the mutation in the chosen region (e.g., they read or rely on modified data through shared memory or persistent storage).

This minimization is achieved by combining **taint-tracking** and a **filesystem tracking mechanism** that detects dependencies such as files involved in login sessions or inter-region communication. By replaying only the **essential subset** of the original sequence, STAFF significantly reduces execution time while preserving semantic correctness and state dependencies.
To avoid re‑executing the same prefix for every mutation of a region, STAFF enforces a **checkpoint stragegy** by executing the unmodified prefix once, then takes a VM snapshot via a secondary forkserver. For each variant, it forks from that snapshot, applies the mutated region and reattaches the original suffix, resuming execution from the saved state. This reuse of the prefix snapshot drastically reduces redundant computation when exploring multiple mutations of the same region.


### Emulation/Fuzzing Phase
TODO (coverage tracing strategy, execution trace instability/variability, VM snapshot/forking strategy, crash deduplication strategy, ...)

## Experimental Assessment

### Methods comparison
In this experimental assessment **STAFF** will be compared with the main state-of-the-art fuzzing methods which could be applied into a stateful full-system context:

- **AFLNet "base"**. It behaves similarly to classic greybox fuzzers like AFL, but adapted for network protocols. It mutates sequences of protocol messages extracted from packet captures (PCAPs), blindly exploring the input space without awareness of the protocol’s state transitions or server responses.

- **AFLNet "state-aware"**. It enhances fuzzing effectiveness by learning a protocol state machine on the fly. It uses server responses to build an intermediate protocol state model (IPSM), identifies target states (especially rarely fuzzed ones), and prioritizes mutations that exercise unexplored transitions or improve coverage.

- **DECAF++ TriforceAFL (from FirmAFL)**. It is a system-mode fork of AFL designed for full-system fuzzing. Unlike classical QEMU user-mode fuzzers, it runs a parallel full-system QEMU VM and injects test cases into the guest via a syscall buffer. This enables extensive fuzzing of firmware in a multi-process environment. However, it does not track state changes or support multi-step testcases, making it less suited for deeply stateful protocol interactions.

- **STAFF "base"**. It enforces into an hybrid-way the method of **AFLNet "base"** strengthening with *taint hints* obtained from the *pre-analysis phase*. 

- **STAFF "state-aware"**. It enforces into an hybrid-way the method of **AFLNet "state-aware"** strengthening with *taint hints* obtained from the *pre-analysis phase*. 

### Experimental parameters

The parameters used into this experimental evaluation are divided in several categories which are described below.

#### PRE-ANALYSIS parameters

**subregion_divisor**
   - *Definition:* A parameter that dynamically limits the maximum size of candidate subregions (subsequences) to be matched against known inputs. It ensures that the subregion length is less than a fraction (typically 1/subregion_divisor) of the total region size.

   - *Purpose:* To avoid overfitting or matching overly large regions that are unlikely to provide meaningful or unique insights.

   - *Example:* If the region is 20 bytes long and subregion_divisor = 2, then only subregions of size <10 will be considered for matching (unless overridden by min_subregion_len).

**min_subregion_len**
   - *Definition:* The minimum allowable length for a subregion to be considered a valid match during taint propagation analysis.

   - *Purpose:* To filter out small, non-informative matches that may occur frequently by chance (e.g., common ASCII characters or short patterns), reducing false positives.

   - *Example:* If min_subregion_len = 4, then subsequences shorter than 4 bytes are ignored even if they match known input bytes.

**delta_threshold**
   - *Definition:* A (typically optional) parameter representing a numerical limit used to quantify acceptable differences between matched regions—for example, in content, length, or offset.

   - *Purpose:* To allow some tolerance when comparing regions, especially in heuristic or approximate matching scenarios (e.g., when detecting slightly modified or shifted data).

   - *Example:* If delta_threshold = 2, then two subsequences may be considered equivalent even if they differ by up to 2 bytes or are shifted by 2 positions.


#### EMULATION_TRACING parameters

**include_libraries**. When enabled, the coverage/tracing bitmap collects PCs from all translation blocks—including those in dynamically‑linked or emulated libraries—rather than restricting to PCs in the main firmware binaries alone.

#### GENERAL_FUZZING parameters

**fuzz_tmout**. A global watchdog timeout for the whole fuzzing run (often in seconds or minutes). When the entire campaign exceeds this, it cleanly shuts down.

**timeout**. The per‑input (or region) execution timeout (in milliseconds) that the fuzzer applies when running your target under QEMU. Inputs taking longer are killed and counted as “hangs.”

**afl_no_arith**. Disable AFL’s built‑in integer‑arithmetic mutations. No “add/subtract constant” operations will be applied.

**afl_no_bitflip**.	Disable AFL’s single‑bit and multi‑bit flip mutations.

**afl_no_interest**. Turn off AFL’s “interest” heuristic: normally AFL skips mutations on bytes it deems uninteresting; with this flag, every byte is equally likely to be mutated.

**afl_no_user_extras**. Disable any user‑supplied extra testcases (via ‑‑extras_dir) from being injected into the mutation queue.

**afl_no_extras**. Disable all extra (dictionary‑ or user‑provided) tokens—only blind mutations and seeds will be used.

**afl_calibration**. Enable AFL’s calibration stage on each new seed: test it multiple times to measure stability (counts of hangs/crashes) before adding it to the queue.

**afl_shuffle_queue**. Randomize the order in which AFL pulls seeds from its queue for mutation, rather than strictly FIFO. This can help avoid starvation of late‑discovered seeds.

#### AFLNET_FUZZING parameters

**region_delimiter**. A special marker byte or sequence that AFLNet treats as the boundary between protocol “regions” (e.g. between messages).

**proto**. The name of the protocol under test (e.g. FTP, RTSP); used to pick the correct parser and state‑machine learner. At the moment, only HTTP is supported.

**region_level_mutation**. Enables higher‑level, message‑or “region”‑granular mutations (only for non-STAFF mutations). When turned on, AFLNet may apply any of these four operators:
   - Replace the current region with a random region drawn from another seed.
   - Insert a random region from another seed at the beginning of the current region.
   - Insert a random region from another seed at the end of the current region.
   - Duplicate the current region, appending a copy immediately after it.

#### STAFF_FUZZING parameters

**sequence_minimization**. Selected an interesting message sequence, this toggles whether to run a reducer that tries to drop extraneous regions while preserving the new coverage or state‑transition. *(See [Overview](#Overview))*

**taint_metric**. A per‑byte score from pre‑analyzed interactions that combines its influence on code flow, process scope, cross‑region dependencies, and persistence. These scores drive a priority queue of (region, offset, length) mutation targets. *(See [Overview](#Overview))*

**checkpoint_strategy**. Specifies that STAFF first executes the unmodified prefix up to the mutation point a single time, takes a VM snapshot via a secondary forkserver, then for each variant forks from that snapshot, applies the mutated region and reattaches the original suffix—thereby avoiding repeated execution of the unchanged prefix. *(See [Overview](#Overview))*

#### EXTRA_FUZZING parameters

**coverage_tracing**. Selects the coverage feedback mode: classic edge‑ or block‑coverage, or taint‑focused variants that report only edges or blocks involving taint‑related loads/stores.

**stage_max**. The maximum number of sequential mutations of the same type to apply to each seed in one go. For example, if *stage_max = 32*, the fuzzer may apply and run up to 32 bit‑flips (or 32 consecutive arithmetic ops, etc.).

## Getting Started

### Prerequisites
Make sure the following are installed on your system:
- [Docker](https://docs.docker.com/get-docker/)

---

### Setup & Build

1. **Clone the repository and build the Docker image:**
   ```bash
   git clone https://github.com/alessioizzillo/STAFF.git
   cd STAFF
   ./docker.sh build
   ```

2. **Run the Docker container and set up the environment:**
   ```bash
   ./docker.sh run STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```

3. **Inside the container**, run:
   ```bash
   ./install.sh
   make
   ```

4. **Detach from the container** by pressing:
   ```
   Ctrl-A + D
   ```

5. **Save the current container state** by running:
   ```bash
   docker commit STAFF staff
   ```
6. (Optional) **Remove the container**  by running:
   ```bash
   docker rm -f STAFF
   ```

---

### Create FirmAE Images

To generate the FirmAE image for your firmware:

1. Be sure your firmware is under the directory `firmware/<brand>`

2. Create a docker container with a **bridge network** and attach it:
   ```bash
   ./docker.sh run_bridge STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```

3. Edit the `config.ini` file based on the firmware you want to process:
   ```ini
   [GENERAL]
   mode = check
   firmware = dlink/dap2310_v1.00_o772.bin
   ```

   Use `all` to generate images for the entire dataset:
   ```ini
   [GENERAL]
   mode = check
   firmware = all
   ```

4. Launch the `start.py` script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
   ```

5. (Optional) **Remove the container**  by running:
   ```bash
   docker rm -f STAFF
   ```

---

### Capture a new interaction

To capture an interaction for your firmware:

1. Edit the `config.ini` file based on the firmware you want to process and the whitelist/blacklist keywords which will filter in/out some requests (*note*: whitelist has higher priority than blacklist):
   ```ini
   [GENERAL]
   mode = run_capture
   firmware = dlink/dap2310_v1.00_o772.bin

   [CAPTURE]
   whitelist_keywords = POST/PUT/.php/.cgi/.xml
   blacklist_keywords = .gif/.jpg/.png/.css/.js/.ico/.htm/.html
   ```

2. Create a docker container with **host network** and attach it:
   ```bash
   ./docker.sh run STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```

3. Launch the `start.py` script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
   ```

4. Wait for firmware booting up, and use a browser or something else to reach the webserver at the indicated IP.

5. All your actions will be recorded into a pcap file.

6. (Optional) **Remove the container**  by running:
   ```bash
   docker rm -f STAFF
   ```

---

### Start an experiment

To generate the FirmAE image for your firmware:

1. Edit the `config.ini` file based on the firmware you want to process:
   ```ini
   [GENERAL]
   mode = staff_base     # The available tools are: staff_base/staff_state_aware/aflnet_base/aflnet_state_aware/triforce
   firmware = dlink/dap2310_v1.00_o772.bin

   # Change this params how you want
   [PRE-ANALYSIS]
   subregion_divisor = 10
   min_subregion_len = 3
   delta_threshold = 1.0

   [EMULATION_TRACING]
   include_libraries = 1

   [GENERAL_FUZZING]
   fuzz_tmout = 14400
   timeout = 120
   afl_no_arith = 1
   afl_no_bitflip = 0
   afl_no_interest = 1
   afl_no_user_extras = 1
   afl_no_extras = 1
   afl_calibration = 1
   afl_shuffle_queue = 1

   [AFLNET_FUZZING]
   region_delimiter = \x1A\x1A\x1A\x1A
   proto = http
   region_level_mutation = 1

   [STAFF_FUZZING]
   sequence_minimization = 1
   taint_metrics = rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes
   checkpoint_strategy = 1

   [EXTRA_FUZZING]
   coverage_tracing = taint_block
   stage_max = 1

   ```

2. Launch the image generation script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
   ```

3. You will find the results under `STAFF/FirmAE/scratch/<image_id>/outputs`

---

### Start a bunch of experiments

You can use `schedule.csv` to start one or more experiments parallely on different docker container. The structure is the following:

<table style="border-collapse: collapse; width: 100%; color: inherit; border-color: inherit;">
  <tr>
    <th colspan="4"></th>
    <th colspan="2" style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">GENERAL</th>
    <th colspan="2" style="border-right: 1px solid currentColor;">PRE-ANALYSIS</th>
    <th style="border-right: 1px solid currentColor;">EMULATION_TRACING</th>
    <th style="border-right: 1px solid currentColor;">GENERAL_FUZZING</th>
    <th colspan="6"></th>
    <th colspan="2" style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">AFLNET_FUZZING</th>
    <th colspan="2" style="border-right: 1px solid currentColor;">STAFF_FUZZING</th>
    <th style="border-right: 1px solid currentColor;">EXTRA_FUZZING</th>
    <th colspan="6"></th>
  </tr>
  <tr>
    <th style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">status</th>
    <th style="border-right: 1px solid currentColor;">exp_name</th>
    <th style="border-right: 1px solid currentColor;">container_name</th>
    <th style="border-right: 1px solid currentColor;">num_cores</th>
    <th style="border-right: 1px solid currentColor;">mode (M)</th>
    <th style="border-right: 1px solid currentColor;">firmware (F)</th>
    <th style="border-right: 1px solid currentColor;">subregion_divisor (SD)</th>
    <th style="border-right: 1px solid currentColor;">min_subregion_len (MSL)</th>
    <th style="border-right: 1px solid currentColor;">delta_threshold (DT)</th>
    <th style="border-right: 1px solid currentColor;">include_libraries (IL)</th>
    <th style="border-right: 1px solid currentColor;">fuzz_tmout (FT)</th>
    <th style="border-right: 1px solid currentColor;">timeout (T)</th>
    <th style="border-right: 1px solid currentColor;">afl_no_arith (ANA)</th>
    <th style="border-right: 1px solid currentColor;">afl_no_bitflip (ANB)</th>
    <th style="border-right: 1px solid currentColor;">afl_no_interest (ANI)</th>
    <th style="border-right: 1px solid currentColor;">afl_no_user_extras (ANU)</th>
    <th style="border-right: 1px solid currentColor;">afl_no_extras (ANE)</th>
    <th style="border-right: 1px solid currentColor;">afl_calibration (AC)</th>
    <th style="border-right: 1px solid currentColor;">afl_shuffle_queue (ASQ)</th>
    <th style="border-right: 1px solid currentColor;">region_delimiter (RD)</th>
    <th style="border-right: 1px solid currentColor;">proto (P)</th>
    <th style="border-right: 1px solid currentColor;">region_level_mutation (RLM)</th>
    <th style="border-right: 1px solid currentColor;">sequence_minimization (SM)</th>
    <th style="border-right: 1px solid currentColor;">taint_metrics (TM)</th>
    <th style="border-right: 1px solid currentColor;">checkpoint_strategy (CS)</th>
    <th style="border-right: 1px solid currentColor;">coverage_tracing (CT)</th>
    <th style="border-right: 1px solid currentColor;">stage_max (SMA)</th>
  </tr>
  <!-- Data Row 1 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">staff_base</td>
    <td style="border-right: 1px solid currentColor;">dlink/dap2310_v1.00_o772.bin</td>
    <td style="border-right: 1px solid currentColor;">10</td>
    <td style="border-right: 1px solid currentColor;">3</td>
    <td style="border-right: 1px solid currentColor;">1.0</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">14400</td>
    <td style="border-right: 1px solid currentColor;">120</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">0</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">\x1A\x1A\x1A\x1A</td>
    <td style="border-right: 1px solid currentColor;">http</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">taint_block</td>
    <td style="border-right: 1px solid currentColor;">1</td>
  </tr>
  <!-- Data Row 2 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">staff_state_aware</td>
    <td style="border-right: 1px solid currentColor;">dlink/dap2310_v1.00_o772.bin</td>
    <td style="border-right: 1px solid currentColor;">10</td>
    <td style="border-right: 1px solid currentColor;">3</td>
    <td style="border-right: 1px solid currentColor;">1.0</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">14400</td>
    <td style="border-right: 1px solid currentColor;">120</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">0</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">\x1A\x1A\x1A\x1A</td>
    <td style="border-right: 1px solid currentColor;">http</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes</td>
    <td style="border-right: 1px solid currentColor;">1</td>
    <td style="border-right: 1px solid currentColor;">taint_block</td>
    <td style="border-right: 1px solid currentColor;">1</td>
  </tr>
  <!-- Data Row 3 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;"></td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
    <td style="border-right: 1px solid currentColor;">...</td>
  </tr>
  <tr>
    <td colspan="27" style="border-top: 1px solid currentColor;"></td>
  </tr>
</table>

The first three lines must be left empty because they will be automatically filled. They stand respectively for the status of the experiment (running/stopped/succeeded/failed), the experiment name and the name of the docker container where the experiment is running.

To run the experiments into `schedule.csv`:

1. Get the core mapping into `cpu_ids.csv` by launching the following command:
   ```bash
   echo "CPU ID,Physical ID,Logical ID" > cpu_ids.csv; lscpu -p=NODE,CORE,CPU | grep -v '^#' | sort -t',' -k1,1n -k2,2n -k3,3n >> cpu_ids.csv;
   ```

2. Launch the `experiments.py` script:
   ```bash
   python3 experiments.py
   ```

To finally plot the experiments, you need to edit the `plot_params.ini` whose structure is:

   ```ini
   [fixed_params]
   GENERAL.firmware = dlink/dap2310_v1.00_o772.bin
   PRE-ANALYSIS.subregion_divisor = 10
   PRE-ANALYSIS.min_subregion_len = 3
   PRE-ANALYSIS.delta_threshold = 1.0
   EMULATION_TRACING.include_libraries = 1
   GENERAL_FUZZING.fuzz_tmout = 14400
   GENERAL_FUZZING.timeout = 120
   GENERAL_FUZZING.afl_no_arith = 1
   GENERAL_FUZZING.afl_no_bitflip = 0
   GENERAL_FUZZING.afl_no_interest = 1
   GENERAL_FUZZING.afl_no_user_extras = 1
   GENERAL_FUZZING.afl_no_extras = 1
   GENERAL_FUZZING.afl_calibration = 1
   GENERAL_FUZZING.afl_shuffle_queue = 1
   AFLNET_FUZZING.region_delimiter = \x1A\x1A\x1A\x1A
   AFLNET_FUZZING.proto = http
   AFLNET_FUZZING.region_level_mutation = 1
   STAFF_FUZZING.sequence_minimization = 1
   STAFF_FUZZING.taint_metrics = rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes
   STAFF_FUZZING.checkpoint_strategy = 1
   EXTRA_FUZZING.coverage_tracing = taint_block
   EXTRA_FUZZING.stage_max = 1

   [var_params]
   GENERAL.mode = 

   ```

So, you need to:

1. Set all the fixed parameters and leave blank the parameter you want it to be variable. In the case above, we left blank *mode* which corresponds to the tool name in order to compare results among the other state-of-the-art methods.

2. You can finally (or while running) plot the experiments by launching:
   ```bash
   python3 experiments.py
   ```
3. You will find plots into `exp_out` directory.