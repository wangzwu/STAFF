
# STAFF  
_Stateful Taint‑Assisted Full‑system Firmware Fuzzer_

# Table of Contents

- [Introduction & Motivation](#introduction--motivation)

- [Overview](#overview)  
  - [Exploration Phase](#exploration-phase)  
  - [Taint-Assisted Pre-analysis](#taint-assisted-pre-analysis)  
  - [Emulation/Fuzzing Phase](#emulationfuzzing-phase)

- [Experimental Assessment](#experimental-assessment)  
  - [Methods Comparison](#methods-comparison)  
  - [Experimental Parameters](#experimental-parameters)  
  - [Dataset](#dataset)

- [Getting Started](#getting-started)  
  - [Prerequisites](#prerequisites)  
  - [Setup & Build](#setup--build)  
  - [Create FirmAE Images](#create-firmae-images)  
  - [Capture a New Interaction](#capture-a-new-interaction)  
  - [Perform a Pre-analysis](#perform-a-pre-analysis)  
  - [Start an Experiment](#start-an-experiment)  
  - [Start a Bunch of Experiments](#start-a-bunch-of-experiments)

## Introduction & Motivation  
**STAFF** is a stateful, taint‑based, full‑system firmware fuzzing tool that combines ideas from protocol fuzzers and whole-system taint analyzers to uncover deep-state bugs in embedded systems. It builds on three pillars:

1. **AFLNET**: a greybox fuzzer for network protocols that uses state-feedback (e.g., HTTP response codes) alongside coverage feedback to guide mutations of message sequences.
2. **DECAF++**: a whole-system dynamic taint analysis framework that is twice as fast as its predecessor and imposes minimal overhead when inputs are untainted.
3. **FirmAE**: a large-scale firmware emulation framework that boosts firmware execution success from 16 % to ≈79 % through automated configuration and emulation heuristics.

STAFF targets firmware exposing **Protocol-based services**, applying fuzzing over sequences of protocol-level messages (called “regions”).

## Overview

![System Architecture Diagram](img/staff_overall.svg)

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

#### Algorithm: Build Taint‐Interaction Metadata via Subsequence Matching

This module performs dependency inference between tainted memory regions by:
1. Building a trie of all possible subsequences (with optional length limits) from sink regions.
2. Parsing taint events into contiguous memory blocks.
3. Matching each block's subregions against the trie to identify dependencies.
4. Recording byte-level dependencies between memory regions.

---

The goal is to infer potential **dataflow or taint propagation** relationships between regions of memory during binary execution, based on taint traces and subsequence similarity.

---

```python
Inputs:
  - sources_hex: List of byte‐arrays, one per sink region index
  - log_path: Path to the binary taint log file
  - inverted_fs: File‐system relations (not used in subsequence logic)
  - subregion_divisor ∈ ℕ⁺: Controls minimal subregion size
  - min_sub_len ∈ ℕ⁺: Minimum subsequence length
  - max_len ∈ ℤ (≥–1): Upper bound on subsequence length (–1 → unbounded)

Globals to populate:
  - global_regions_dependance: map sink_id → list of dependent sink_ids
  - global_regions_affections: map sink_id → map other_sink_id → list of matching substrings

Output:
  - sources: List of length N = len(sources_hex), each entry
      ( fs_relations: list,
        region_info: list of tuples ( byte, [taint_sources], [app_tb_pcs], [coverages] ) )

Steps:

1. ─── Parse Taint Log ───
   1.1. Let struct_fmt ← "B I I I I B B Q"
   1.2. Read entire log_path in record‐sized chunks:
         for each record: unpack into fields
           event, sink_id, cov, pc, gpa, op_name, value, inode
         append each event‐dict to `events`

2. ─── Initialize Data Structures ───
   2.1. sources ← empty list
   2.2. previous_sink_id ← –1
   2.3. last_store_event ← null ; current_store_block ← (–1, empty list)
   2.4. last_load_event  ← null ; current_load_block  ← (–1, empty list)
   2.5. multi_trie ← new MultiSequenceTrie(max_len)
   2.6. Clear global_regions_dependance, global_regions_affections

3. ─── Process Each Event ───
   For event in events in chronological order:
     
     if event.event ∉ {0,1}:
       continue   // ignore non‐sink events

     sink_id ← event.sink_id

     // 3A. New sink region encountered?
     if sink_id > previous_sink_id:
       previous_sink_id ← sink_id
       if sink_id ≥ len(sources_hex): error and abort
       // Initialize `sources[sink_id]`
       byte_seq ← sources_hex[sink_id]
       region_info ← [ (b, [], [], []) for each b in byte_seq ]
       append ( [], region_info ) to `sources`

       // Insert the full region into trie
       if not multi_trie.insert(byte_seq, sink_id):
         error ← memory‐limit; abort

       global_regions_dependance[sink_id] ← []
       global_regions_affections[sink_id] ← {}

     // 3B. Collect consecutive store/load blocks
     if event.event == 1 and event.op_name ∈ {0,1}:
       mode ← (event.op_name == 1) ? "store" : "load"
       (last_evt, current_block) ←
         mode=="store" ? (last_store_event, current_store_block)
                        : (last_load_event,  current_load_block)

       if last_evt ≠ null and event.gpa == last_evt.gpa + 1:
         append (gpa, value, (inode, pc), cov) to current_block.entries
       else:
         if last_evt ≠ null:
           ProcessBlock(current_block, mode)
         current_block ← (sink_id, [ (gpa, value, (inode, pc), cov) ])

       if mode == "store":
         last_store_event ← event; current_store_block ← current_block
       else:
         last_load_event  ← event; current_load_block  ← current_block

4. ─── Final Block Flush ───
   if last_store_event  ≠ null: ProcessBlock(current_store_block, "store")
   if last_load_event   ≠ null: ProcessBlock(current_load_block,  "load")

5. ─── Return `sources` ───
   if len(sources) ≠ len(sources_hex): error and abort
   return sources

────────────────────────────────────────────────────────────────────────────────

Subroutine: ProcessBlock(block, mode)
Inputs:
  - block = ( region_id, entries )
      where entries = list of tuples (gpa, value, (inode,pc), cov)
  - mode ∈ {"store","load"}

Steps:

1. Extract byte_sequence:
   byte_seq ← [ value for each (_, value, _, _) in entries ]
   L ← length(byte_seq)

2. Enumerate candidate subsequence lengths:
   for sub_len from L down to 1:
     if sub_len < L/subregion_divisor AND sub_len ≥ min_sub_len:
       break   // too small relative to divisor

     // Slide window of size sub_len
     for start_pos in 0 … (L – sub_len):
       subseq ← byte_seq[start_pos : start_pos + sub_len]
       positions ← multi_trie.find_subsequence(subseq)
       if positions is null:
         continue
       if positions.size == 1:
         (other_id, other_start) ← positions[0]
         // Verify monotonic and exact match
         if region_id ≥ other_id AND
            sources_hex[other_id][other_start : other_start+sub_len] == subseq:
           
           RecordDependencyAndAffection(
             from_id=region_id,
             to_id=other_id,
             subseq=subseq,
             start_offset=other_start,
             entries=entries
           )
       goto EndOfBlock  // stop after first successful match

EndOfBlock:

────────────────────────────────────────────────────────────────────────────────

Subroutine: RecordDependencyAndAffection(from_id, to_id, subseq, start_offset, entries)

1. // Dependency
   if to_id not in global_regions_dependance[from_id]:
     append to_id

2. // Affection
   substr_str ← make_printable(subseq)
   A ← global_regions_affections[to_id]
   if from_id not in A: A[from_id] ← [substr_str]
   else if substr_str not in A[from_id]: append substr_str

3. // Annotate `sources[to_id].region_info`
   for j in 0 … length(subseq)-1:
     (_, taint_list, pc_list, cov_list) ← sources[to_id][1][start_offset + j]
     append from_id       to taint_list
     append entries[j].(inode,pc) to pc_list
     append entries[j].cov to cov_list

────────────────────────────────────────────────────────────────────────────────

Class MultiSequenceTrie
  Fields:
    root      ← new TrieNode()
    max_len   ← maximum sequence length per subsequence (−1 if unbounded)

  Method insert(sequence, seq_id)
    for i from 0 to length(sequence) − 1 do
      node ← root
      for j from i to min(i + max_len, length(sequence)) do
        byte ← sequence[j]
        if byte not in node.children:
          node.children[byte] ← new TrieNode()
        node ← node.children[byte]
        append (seq_id, i) to node.positions

  Method find_subsequence(subseq)
    node ← root
    for byte in subseq do
      if byte not in node.children:
        return null
      node ← node.children[byte]
    return node.positions

Class TrieNode
  Fields:
    children  ← map from byte to TrieNode
    positions ← list of (seq_id, start_offset)

```

Below is a summary of the **time** and **space complexities** of the entire subsequence‐extraction and matching algorithm, expressed in terms of:

**S** = number of sink regions (≈ len(sources_hex))

**L** = average length of each region’s byte sequence

**M** = max_len (if set ≥ 0, otherwise M ≈ L)

**E** = total number of taint events (≈ total memory operations logged)

Breakdown of the **time complexity** for each major phase of the algorithm:

1. **Trie construction (O(S · L · M))**  
   We insert all length-bounded subsequences of each sink region (S regions, each of length L, up to maximum subsequence length M) into the `MultiSequenceTrie`. Each start position (L) can extend up to M steps, yielding O(L·M) per region, and O(S·L·M) overall.

2. **Event grouping (O(E) or O(E log E))**  
   We scan and optionally sort the total E taint events by physical address (`gpa`) to form contiguous blocks. If events arrive pre-sorted, this is O(E); otherwise sorting adds an O(E log E) factor.

3. **Subsequence matching (O(S · L² · M))**  
   For each sink region block (at most S blocks of average length ≤ L), we try sliding windows of all lengths from L down to a lower bound. Each window (≈L of them) calls `find_subsequence()` which traverses up to M trie levels. That yields O(L × L × M) = O(L²·M) per region, or O(S·L²·M) total.

4. **Recording metadata (O(S · M))**  
   On each successful match (one per block, ≤S matches), we update per-byte lists of length up to M. This is O(M) per region, or O(S·M) overall.

| Step                    | Complexity             |
|------------------------|------------------------|
| Trie construction      | O(S · L · M)           |
| Event grouping         | O(E) (or O(E log E))   |
| Subsequence matching   | O(S · L² · M)          |
| Recording metadata     | O(S · M)               |
| **Overall**            | **O(S · L² · M)**      |

---

Below is a breakdown of the **space requirements** of the data structures used:

1. **Trie nodes & positions (O(S · L · M))**  
   Each inserted subsequence prefix creates or reuses a trie node. In the worst case (no shared prefixes), there are O(L·M) nodes per region, each holding a list of positions—total O(S·L·M).

2. **Sources per-byte info (O(S · L))**  
   We maintain for each byte of each sink region (S regions, L bytes each) lists of taint origins, PCs, and coverage hashes. This requires O(S·L) space.

3. **Dependency map (O(S²))**  
   In the worst case, every sink region might depend on every other, yielding an O(S²) sized map for `global_regions_dependance`.

| Component                 | Complexity              |
|--------------------------|-------------------------|
| Trie nodes & positions   | O(S · L · M)            |
| Sources per-byte info    | O(S · L)                |
| Dependency map           | O(S²)                   |
| **Total**                | **O(S · L · M + S²)**   |


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

### Dataset

The dataset is a curated subset of firmware images originally sourced from the larger [FirmAE](https://github.com/pr0v3rbs/FirmAE) project. It includes firmware for various brands of routers and IP cameras. The selection was performed by analyzing a wide range of images and filtering in only those firmwares that met the following criteria:

- The embedded web server is reachable and explorable.
- The firmware emulates correctly, without critical sections being broken or failing to initialize.
- The interface supports fast and responsive user interactions.
- A valid and simple web session can be captured and replayed using a PCAP trace.
- The web server does not selectively respond only to specific browser clients or reject automated/non-standard user agents.
- The firmware does not require an encrypted or obfuscated login session procedure that prevents reproducible interaction or taint tracing.
- Web authentication must result in actual, replayable HTTP requests (e.g., not just browser pop-ups that don’t produce usable credentialed traffic).
- Firmware was excluded if the embedded web server only presents an informational landing page with static content or external links (e.g., to the vendor's website), without exposing the actual device management interface.

The corresponding firmware images are located in the `firmwares` directory, and the per-firmware user interaction traces can be found in the `pcap` directory. Below is a table summarizing the dataset.

<table style="border-collapse: collapse; width: 100%; color: inherit; border-color: inherit;">
  <tr>
    <td colspan="27" style="border-bottom: 1px solid currentColor;"></td>
  </tr>
  <tr>
    <th style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Brand</th>
    <th style="border-right: 1px solid currentColor;">Firmware Name</th>
    <th style="border-right: 1px solid currentColor;">Device Type</th>
    <th style="border-right: 1px solid currentColor;">Number of PCAPs</th>    
  </tr>
  <!-- Data Row 1 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">ASUS</td>
    <td style="border-right: 1px solid currentColor;">FW_RT_N10U_B1_30043763754.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 2 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">ASUS</td>
    <td style="border-right: 1px solid currentColor;">FW_RT_N53_30043763754.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 3 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">D-Link</td>
    <td style="border-right: 1px solid currentColor;">dap2310_v1.00_o772.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 4 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">D-Link</td>
    <td style="border-right: 1px solid currentColor;">dir300_v1.03_7c.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 5 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">D-Link</td>
    <td style="border-right: 1px solid currentColor;">DIR815A1_FW104b03.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">5</td>
  </tr>
  <!-- Data Row 6 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Linksys</td>
    <td style="border-right: 1px solid currentColor;">FW_RE1000_1.0.02.001_US_20120214_SHIPPING.bin</td>
    <td style="border-right: 1px solid currentColor;">Range Extender</td>
    <td style="border-right: 1px solid currentColor;">2</td>
  </tr>
  <!-- Data Row 7 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Linksys</td>
    <td style="border-right: 1px solid currentColor;">FW_WRT320N_1.0.05.002_20110331.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 8 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Netgear</td>
    <td style="border-right: 1px solid currentColor;">DGN3500-V1.1.00.30_NA.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">5</td>
  </tr>
  <!-- Data Row 9 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Netgear</td>
    <td style="border-right: 1px solid currentColor;">DGND3300_Firmware_Version_1.1.00.22__North_America_.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">5</td>
  </tr>
  <!-- Data Row 10 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Netgear</td>
    <td style="border-right: 1px solid currentColor;">JNR3210_Firmware_Version_1.1.0.14.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 11 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TP-Link</td>
    <td style="border-right: 1px solid currentColor;">Archer_C2_US__v1_160128.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 12 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TP-Link</td>
    <td style="border-right: 1px solid currentColor;">TL-WPA8630_US__V2_171011.zip</td>
    <td style="border-right: 1px solid currentColor;">Range Extender</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 13 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TRENDnet</td>
    <td style="border-right: 1px solid currentColor;">FW_TV-IP121WN_1.2.2.zip</td>
    <td style="border-right: 1px solid currentColor;">IP Camera</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 14 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TRENDnet</td>
    <td style="border-right: 1px solid currentColor;">FW_TV-IP651WI_V1_1.07.01.zip</td>
    <td style="border-right: 1px solid currentColor;">IP Camera</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 15 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TRENDnet</td>
    <td style="border-right: 1px solid currentColor;">TEW-652BRU_1.00b12.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <tr>
    <td colspan="27" style="border-top: 1px solid currentColor;"></td>
  </tr>
</table>

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

### Perform a pre-analysis

To capture an interaction for your firmware:

1. Be sure in `pcap/<brand>/<firmware_name>` there are some pcap files containing an interaction.

2. Edit the `config.ini` file based on the firmware you want to process and the whitelist/blacklist keywords which will filter in/out some requests (*note*: whitelist has higher priority than blacklist):
   ```ini
   [GENERAL]
   mode = pre_analysis
   firmware = dlink/dap2310_v1.00_o772.bin

   [CAPTURE]
   whitelist_keywords = POST/PUT/.php/.cgi/.xml
   blacklist_keywords = .gif/.jpg/.png/.css/.js/.ico/.htm/.html
   ```

2. Create a docker container with **bridge network** and attach it:
   ```bash
   ./docker.sh run_bridge STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```
   If the process will be "Killed", it means it exceeded the memory limit during the process. You can modify the script `docker.sh` by increasing the memory limit.

3. Launch the `start.py` script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
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