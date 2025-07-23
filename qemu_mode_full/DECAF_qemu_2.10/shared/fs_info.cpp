#include "shared/elfio/elfio.hpp"
#include "shared/DECAF_fileio.h"
#include "extern_vars.h"
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <iostream>
#include <fstream>
#include <sstream>
#include <functional>
#include <memory>
#include <fcntl.h>
#include <xxhash.h>

int debug_var = 0;
using namespace ELFIO;

struct FunctionIndex {
    Elf_Xword start_offset;
    Elf_Xword end_offset;
    std::string function_name;
};

struct TextSectionInfo {
    Elf_Xword start_offset;
    Elf_Xword size;
    std::vector<std::pair<Elf_Xword, FunctionIndex>> function_map;
};

struct FileInfo {
    TextSectionInfo text_section;
};

std::vector<std::pair<TSK_INUM_T, FileInfo>> file_info_vec;
std::unordered_map<int, std::vector<std::pair<TSK_INUM_T, std::tuple<uintptr_t, std::string>>>> base_address_map;
std::unordered_map<int, std::pair<TSK_INUM_T, uintptr_t>> pid_cache;

int add_base_addr(int pid, uint64_t inode_num, uintptr_t base_addr, const std::string &module_name) {
    auto &vec = base_address_map[pid];

    auto it = std::find_if(vec.begin(), vec.end(), [&](const auto &entry) {
        const auto &existing_inode = entry.first;
        const auto &existing_tup   = entry.second;
        return existing_inode == inode_num
            || std::get<0>(existing_tup) == base_addr;
    });

    if (it == vec.end()) {
        vec.emplace_back(inode_num, std::make_tuple(base_addr, module_name));
    } else {
        it->first  = inode_num;
        it->second = std::make_tuple(base_addr, module_name);
    }

    return 0;
}

int get_pc_text_info(int pid, uintptr_t pc, int &adjusted_pc, TSK_INUM_T &inode_num) {
    auto pid_it = base_address_map.find(pid);
    if (pid_it == base_address_map.end()) return 0;

    for (const auto &[inode, base_tuple] : pid_it->second) {
        const auto &[base_address, _] = base_tuple;
        uintptr_t adj_pc = pc - base_address;

        auto file_it = std::find_if(file_info_vec.begin(), file_info_vec.end(),
            [inode](const std::pair<TSK_INUM_T, FileInfo> &entry) -> bool {
                return entry.first == inode;
            });

        if (file_it == file_info_vec.end()) continue;

        const auto &text_section = file_it->second.text_section;
        if (adj_pc < text_section.start_offset || adj_pc >= text_section.start_offset + text_section.size) continue;

        adjusted_pc = static_cast<int>(adj_pc);
        inode_num = inode;
        return 1;
    }

    adjusted_pc = 0;
    inode_num = 0;
    return 0;
}

int get_module_name_from_inode(int pid, uint64_t inode, char name_buf[MAX_MODULE_NAME_LENGTH]) {
    auto it = base_address_map.find(pid);
    if (it == base_address_map.end()) return 0;

    for (const auto &[cur_inode, base_tuple] : it->second) {
        if (cur_inode == inode) {
            const auto &module_name = std::get<1>(base_tuple);
            strncpy(reinterpret_cast<char *>(name_buf), module_name.c_str(), MAX_MODULE_NAME_LENGTH - 1);
            name_buf[MAX_MODULE_NAME_LENGTH - 1] = '\0';
            return 1;
        }
    }

    return 0;
}

static TSK_WALK_RET_ENUM write_action(TSK_FS_FILE *fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr) {
    if (size == 0)
        return TSK_WALK_CONT;

    std::string *sp = static_cast<std::string *>(ptr);
    sp->append(buf, size);

    return TSK_WALK_CONT;
}

TSK_WALK_RET_ENUM inode_callback(TSK_FS_FILE *fs_file, const char *path, void *ptr) {
    if (!fs_file || !fs_file->meta) {
        return TSK_WALK_CONT;
    }

    TSK_INUM_T inode_number = fs_file->meta->addr;

    if (fs_file->meta->type == TSK_FS_META_TYPE_REG) {
        std::string local_copy;
        if (tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_NONE, write_action, &local_copy) != TSK_OK) {
            return TSK_WALK_CONT;
        }

        std::istringstream is(local_copy);
        elfio reader;
        if (!reader.load(is)) {
            return TSK_WALK_CONT;
        }

        uintptr_t base_address = 0;
        const segment *text_segment = nullptr;
        for (size_t i = 0; i < reader.segments.size(); ++i) {
            const segment *seg = reader.segments[i];
            if (seg->get_type() == PT_LOAD && (seg->get_flags() & PF_X)) {
                base_address = seg->get_virtual_address();
                text_segment = seg;
                break;
            }
        }

        if (!text_segment) {
            return TSK_WALK_CONT;
        }

        TextSectionInfo text_section;
        for (size_t i = 0; i < reader.sections.size(); ++i) {
            const section *psec = reader.sections[i];
            std::string name = psec->get_name();

            if (name == ".text") {
                text_section.start_offset = psec->get_address() - base_address;
                text_section.size = psec->get_size();
            }

            if (psec->get_type() == SHT_SYMTAB || psec->get_type() == SHT_DYNSYM) {
                const symbol_section_accessor symbols(reader, psec);
                for (size_t j = 0; j < symbols.get_symbols_num(); ++j) {
                    std::string func_name;
                    Elf64_Addr value;
                    Elf_Xword size;
                    unsigned char bind, type, other;
                    Elf_Half section_index;

                    symbols.get_symbol(j, func_name, value, size, bind, type, section_index, other);
                    if (type == STT_FUNC) {
                        FunctionIndex func_info = {
                            value - base_address,
                            value - base_address + size,
                            func_name
                        };

                        text_section.function_map.emplace_back(func_info.start_offset, func_info);
                    }
                }
            }
        }

        auto it = std::find_if(file_info_vec.begin(), file_info_vec.end(),
            [inode_number](const std::pair<TSK_INUM_T, FileInfo> &entry) -> bool {
                return entry.first == inode_number;
            });

        if (it == file_info_vec.end()) {
            file_info_vec.emplace_back(inode_number, FileInfo{text_section});
        } else {
            it->second.text_section = text_section;
        }
    }

    return TSK_WALK_CONT;
}

void process_fs_info(TSK_FS_INFO *fs, int debug) {
    debug_var = debug;
    if (tsk_fs_dir_walk(fs, fs->root_inum, TSK_FS_DIR_WALK_FLAG_RECURSE, inode_callback, NULL) != TSK_OK) {
        // fprintf(stderr, "Error: Directory walk failed.\n");
        tsk_error_print(stderr);
    }
}

struct DataStorage {
    std::vector<std::vector<std::tuple<std::string, std::tuple<int, int>>>> coverage_vec;
    std::vector<std::vector<std::pair<std::string, int>>> syscall_vec;
    std::vector<std::vector<int>> accept_fd_vec;
    std::vector<std::deque<std::tuple<uint64_t, uint32_t, uint8_t>>> inode_pc_trace_vec;

    std::unordered_map<int, std::string> pid_to_procname;
    std::unordered_map<int, std::vector<int>> pid_relationships;
};

DataStorage storage;

void set_procname(int pid, const std::string &name) {
    storage.pid_to_procname[pid] = name;
}

std::string get_procname(int pid) {
    auto it = storage.pid_to_procname.find(pid);
    return it != storage.pid_to_procname.end() ? it->second : std::string();
}

void add_pid_relationship(int parent_pid, int child_pid) {
    storage.pid_relationships[parent_pid].push_back(child_pid);
}

std::vector<int> get_child_pids(int parent_pid) {
    auto it = storage.pid_relationships.find(parent_pid);
    return it != storage.pid_relationships.end() ? it->second : std::vector<int>();
}

void remove_pid_relationship(int parent_pid, int child_pid) {
    auto it = storage.pid_relationships.find(parent_pid);
    if (it == storage.pid_relationships.end()) return;
    auto &vec = it->second;
    vec.erase(std::remove(vec.begin(), vec.end(), child_pid), vec.end());
    if (vec.empty())
        storage.pid_relationships.erase(parent_pid);
}

void register_process(int pid, const std::string &procname, int parent_pid = -1) {
    set_procname(pid, procname);
    if (parent_pid >= 0) {
        add_pid_relationship(parent_pid, pid);
    }
}

void unregister_process(int pid) {
    storage.pid_to_procname.erase(pid);

    std::vector<int> parents;
    parents.reserve(storage.pid_relationships.size());
    for (const auto &entry : storage.pid_relationships) {
        parents.push_back(entry.first);
    }
    for (int parent_pid : parents) {
        remove_pid_relationship(parent_pid, pid);
    }

    storage.pid_relationships.erase(pid);
}

void insert_coverage_value(int pid, const char *cov_name, int value, int index) {
    if (pid >= (int)storage.coverage_vec.size())
        storage.coverage_vec.resize(pid + 1);

    auto &cov_map = storage.coverage_vec[pid];
    auto it = std::find_if(cov_map.begin(), cov_map.end(),
        [&cov_name](auto &entry){ return std::get<0>(entry) == cov_name; });

    if (it == cov_map.end()) {
        cov_map.emplace_back(cov_name, std::make_tuple(0,0));
        it = cov_map.end() - 1;
    }

    if (index == 0)
        std::get<0>(std::get<1>(*it)) = value;
    else
        std::get<1>(std::get<1>(*it)) = value;
}

int get_coverage_value(int pid, const char *cov_name, int index) {
    if (pid < (int)storage.coverage_vec.size()) {
        const auto &cov_map = storage.coverage_vec[pid];
        auto it = std::find_if(cov_map.begin(), cov_map.end(),
            [&cov_name](auto &entry){ return std::get<0>(entry) == cov_name; });
        if (it != cov_map.end())
            return index==0
                ? std::get<0>(std::get<1>(*it))
                : std::get<1>(std::get<1>(*it));
    }
    return 0;
}

void remove_coverage_by_pid(int pid) {
    if (pid < (int)storage.coverage_vec.size())
        storage.coverage_vec[pid].clear();
}

void insert_syscall_value(int pid, const char *var_name, int value) {
    if (pid >= (int)storage.syscall_vec.size())
        storage.syscall_vec.resize(pid + 1);

    auto &syscall_map = storage.syscall_vec[pid];
    auto it = std::find_if(syscall_map.begin(), syscall_map.end(),
        [&var_name](auto &entry){ return entry.first == var_name; });

    if (it == syscall_map.end())
        syscall_map.emplace_back(var_name, value);
    else
        it->second = value;
}

int get_syscall_value(int pid, const char *var_name) {
    if (pid < (int)storage.syscall_vec.size()) {
        const auto &syscall_map = storage.syscall_vec[pid];
        auto it = std::find_if(syscall_map.begin(), syscall_map.end(),
            [&var_name](auto &entry){ return entry.first == var_name; });
        if (it != syscall_map.end())
            return it->second;
    }
    return 0;
}

void remove_syscall_by_pid(int pid) {
    if (pid < (int)storage.syscall_vec.size())
        storage.syscall_vec[pid].clear();
}

void insert_accept_fd(int pid, int fd) {
    if (pid >= (int)storage.accept_fd_vec.size())
        storage.accept_fd_vec.resize(pid + 1);

    auto &fd_set = storage.accept_fd_vec[pid];
    if (std::find(fd_set.begin(), fd_set.end(), fd) == fd_set.end())
        fd_set.push_back(fd);
}

void copy_accept_fds(int src_pid, int dst_pid) {
    if (src_pid >= (int)storage.accept_fd_vec.size())
        return;
    const auto &src = storage.accept_fd_vec[src_pid];
    if (dst_pid >= (int)storage.accept_fd_vec.size())
        storage.accept_fd_vec.resize(dst_pid + 1);
    auto &dst = storage.accept_fd_vec[dst_pid];
    for (int fd : src)
        if (std::find(dst.begin(), dst.end(), fd) == dst.end())
            dst.push_back(fd);
}

int is_accept_fd_open(int pid, int fd) {
    if (pid < (int)storage.accept_fd_vec.size())
        return std::find(
            storage.accept_fd_vec[pid].begin(),
            storage.accept_fd_vec[pid].end(), fd
        ) != storage.accept_fd_vec[pid].end();
    return 0;
}

void remove_accept_fd(int pid, int fd) {
    if (pid < (int)storage.accept_fd_vec.size()) {
        auto &fd_set = storage.accept_fd_vec[pid];
        fd_set.erase(
            std::remove(fd_set.begin(), fd_set.end(), fd),
            fd_set.end()
        );
    }
}

void remove_all_accept_fds(int pid) {
    if (pid < (int)storage.accept_fd_vec.size())
        storage.accept_fd_vec[pid].clear();
}

void insert_inode_pc_trace(int pid, uint64_t inode, uint32_t pc, int trace_len, uint8_t is_lib) {
    if (pid >= (int)storage.inode_pc_trace_vec.size())
        storage.inode_pc_trace_vec.resize(pid + 1);

    auto &trace = storage.inode_pc_trace_vec[pid];

    if (is_lib && !trace.empty()) {
        const auto &last = trace.back();
        if (std::get<2>(last)) { 
            return;
        }
    }

    trace.emplace_back(inode, pc, is_lib);

    if ((int)trace.size() > trace_len)
        trace.pop_front();
}

void remove_inode_pc_trace_by_pid(int pid) {
    if (pid < (int)storage.inode_pc_trace_vec.size())
        storage.inode_pc_trace_vec[pid].clear();
}

void copy_inode_trace_to_shmem(int pid, char proc_name[MAX_PROCESS_NAME_LENGTH], trace_t *cur_crashes) {
    if (pid >= storage.inode_pc_trace_vec.size()) return;

    int free_index = -1;
    for (int i = 0; i < NUM_TRACES; ++i) {
        if (cur_crashes[i].procname[0] == '\0') {
            free_index = i;
            break;
        }
    }

    if (free_index == -1) return;

    trace_t &target = cur_crashes[free_index];
    strncpy(reinterpret_cast<char *>(target.procname), proc_name, MAX_PROCESS_NAME_LENGTH - 1);
    target.procname[MAX_PROCESS_NAME_LENGTH - 1] = '\0';

    const auto &trace_vec = storage.inode_pc_trace_vec[pid];
    int count = 0;

    for (auto it = trace_vec.rbegin(); it != trace_vec.rend(); ++it) {
        if (count >= TRACE_LEN) break;

        const auto &[inode, pc, is_lib] = *it;

        trace_element_t &el = target.trace[count];
        el.inode = inode;
        el.pc = pc;

        char name_buf[MAX_MODULE_NAME_LENGTH] = {0};
        if (!get_module_name_from_inode(pid, inode, name_buf)) {
            strncpy(name_buf, "unknown", MAX_MODULE_NAME_LENGTH - 1);
        }
        memcpy(el.modname, name_buf, MAX_MODULE_NAME_LENGTH);

        ++count;
    }
}

static void dump_trace(FILE *f, int tid, const char *header) {
    fprintf(f, "--- %s PID %d Trace ---\n", header, tid);

    const auto &tvec = storage.inode_pc_trace_vec[tid];
    int total = (int)tvec.size();
    int cnt = 0;

    for (auto it = tvec.rbegin(); it != tvec.rend(); ++it) {
        const auto &[inode, pc, is_lib] = *it;
        char buf[MAX_MODULE_NAME_LENGTH] = {0};

        if (!get_module_name_from_inode(tid, inode, buf))
            strncpy(buf, "unknown", MAX_MODULE_NAME_LENGTH - 1);

        fprintf(f, "  [%03d] inode: %lu, pc: 0x%08lx, module: %s\n",
                cnt++, inode, (unsigned long)pc, buf);
    }

    fprintf(f, "Total %s trace elements: %d\n\n", header, total);
}

void dump_pid_trace_to_file(int pid) {
    if (pid < 0 || pid >= (int)storage.inode_pc_trace_vec.size()) {
        fprintf(stderr, "Invalid pid %d for trace dump\n", pid);
        return;
    }

    char path_buf[256];
    snprintf(path_buf, sizeof(path_buf), "crash_analysis/%d.log", pid);

    FILE *f = fopen(path_buf, "w");
    if (!f) {
        perror("fopen (pid trace dump)");
        return;
    }

    fprintf(f, "=== Trace for PID %d ===\n", pid);
    auto pname = get_procname(pid);
    fprintf(f, "Process: %s\n\n", pname.empty() ? "<unknown>" : pname.c_str());

    dump_trace(f, pid, "Self");

    std::vector<int> stack = { pid }, visited;
    visited.reserve(16);
    while (!stack.empty()) {
        int cur = stack.back(); stack.pop_back();
        visited.push_back(cur);

        for (auto &entry : storage.pid_relationships) {
            int parent = entry.first;
            const auto &children = entry.second;
            if (std::find(children.begin(), children.end(), cur) != children.end()
                && std::find(visited.begin(), visited.end(), parent) == visited.end()) {
                dump_trace(f, parent, "Parent");
                stack.push_back(parent);
            }
        }
    }

    auto children = get_child_pids(pid);
    if (!children.empty()) {
        fprintf(f, "Children: ");
        for (int c : children) {
            auto cn = get_procname(c);
            fprintf(f, "%d(%s) ", c, cn.empty() ? "<unknown>" : cn.c_str());
        }
        fprintf(f, "\n\n");
    }

    fclose(f);
}

void remove_pid(int pid) {
    remove_coverage_by_pid(pid);
    remove_syscall_by_pid(pid);
    remove_all_accept_fds(pid);
    remove_inode_pc_trace_by_pid(pid);
    unregister_process(pid);
}

void clear_storage() {
    for (auto &c : storage.coverage_vec)     c.clear();
    for (auto &s : storage.syscall_vec)      s.clear();
    for (auto &f : storage.accept_fd_vec)    f.clear();
    for (auto &t : storage.inode_pc_trace_vec) t.clear();
    storage.pid_to_procname.clear();
    storage.pid_relationships.clear();
}

// FS Tracking

struct FsNode {
    std::string name;
    int sink_id;
    bool deleted = false;
    FsNode* parent = nullptr;
    std::unordered_map<std::string, std::unique_ptr<FsNode>> children;
};

struct {
    FsNode root;
    std::unordered_map<int, std::unordered_map<int, FsNode*>> fd_map;
    std::unordered_map<int, std::unordered_map<int, std::vector<std::string>>> sink_relations;
} fs_tracker;

std::unordered_map<int, FsNode*> current_working_dirs;
std::unordered_map<int, FsNode*> root_dirs;

std::string reconstruct_filepath(FsNode* node) {
    std::vector<std::string> path_parts;
    FsNode* current_node = node;

    while (current_node != &fs_tracker.root) {
        path_parts.push_back(current_node->name);
        current_node = current_node->parent;  // Use parent pointer
    }

    std::reverse(path_parts.begin(), path_parts.end());

    std::string full_path = "/";
    for (const auto& part : path_parts) {
        full_path += part + "/";
    }
    full_path.pop_back();

    return full_path;
}

//_______________________________________________________________________
void write_debug_log(const std::string &filename, const std::string &data) {
    if (!debug_var) return;

    FILE* file = fopen(filename.c_str(), "w");
    if (file) {
        fprintf(file, "%s", data.c_str());
        fclose(file);
    }
}

void dump_fd_map_state() {
    if (debug_var) {
        std::string fd_map_data;

        for (const auto& pid_entry : fs_tracker.fd_map) {
            for (const auto& fd_entry : pid_entry.second) {
                fd_map_data += "PID: " + std::to_string(pid_entry.first) +
                               ", FD: " + std::to_string(fd_entry.first) +
                               ", Path: " + reconstruct_filepath(fd_entry.second) + "\n";
            }
        }

        write_debug_log("debug/fd_map_debug.log", fd_map_data);
    }
}

void capture_node_state(const FsNode &node, std::string &state_data, const std::string &indent = "", bool is_last = true) {
    state_data += indent + (is_last ? "└── " : "├── ") + node.name +
                  " (sink_id: " + std::to_string(node.sink_id) +
                  (node.deleted ? ", deleted: true" : "") + ")\n";

    std::string new_indent = indent + (is_last ? "    " : "│   ");

    auto it = node.children.begin();
    while (it != node.children.end()) {
        bool is_child_last = (std::next(it) == node.children.end());
        capture_node_state(*it->second, state_data, new_indent, is_child_last);
        ++it;
    }
}

void dump_fs_tree_state() {
    if (debug_var) {
        std::string fs_tree_data;

        for (const auto& entry : fs_tracker.root.children) {
            capture_node_state(*entry.second, fs_tree_data);
        }

        write_debug_log("debug/fs_tree_debug.log", fs_tree_data);
    }
}

void dump_sink_relations_state() {
    if (debug_var) {
        std::string sink_relations_data;

        for (const auto& affected_entry : fs_tracker.sink_relations) {
            int affected_sink_id = affected_entry.first;

            sink_relations_data += "Affected Sink ID: " + std::to_string(affected_sink_id) + "\n";

            const auto& affectors_map = affected_entry.second;
            auto affector_it = affectors_map.begin();
            while (affector_it != affectors_map.end()) {
                int affector_sink_id = affector_it->first;
                const auto& paths_list = affector_it->second;

                bool is_last_affector = std::next(affector_it) == affectors_map.end();

                sink_relations_data += (is_last_affector ? "  └── " : "  ├── ") +
                                       std::string("Affector Sink ID: ") +
                                       std::to_string(affector_sink_id) + "\n";

                for (size_t i = 0; i < paths_list.size(); ++i) {
                    sink_relations_data += std::string("      ") +
                                           (i == paths_list.size() - 1 ? "└── " : "├── ") +
                                           paths_list[i] + "\n";
                }

                ++affector_it;
            }
        }

        write_debug_log("debug/sink_relations_debug.log", sink_relations_data);
    }
}

//_____________________________________________________________________

void mark_node_deleted(FsNode &node) {
    node.deleted = true;

    for (auto &child_entry : node.children) {
        mark_node_deleted(*child_entry.second);
    }
}

std::string resolve_relative_path(const std::string& base_path, const std::string& relative_path) {
    std::vector<std::string> path_parts;
    std::istringstream path_stream(base_path);
    std::string part;

    while (std::getline(path_stream, part, '/')) {
        if (!part.empty()) {
            path_parts.push_back(part);
        }
    }

    std::istringstream relative_stream(relative_path);
    while (std::getline(relative_stream, part, '/')) {
        if (part == "." || part.empty()) {
            continue;
        }
        else if (part == "..") {
            if (!path_parts.empty()) {
                path_parts.pop_back();
            }
        }
        else {
            path_parts.push_back(part);
        }
    }

    std::ostringstream full_path;
    for (const auto& p : path_parts) {
        full_path << "/" << p;
    }

    return full_path.str();
}

std::string get_full_path(int pid, const char *path) {
    if (path[0] == '/') {
        return std::string(path);
    }

    auto cwd_it = current_working_dirs.find(pid);
    if (cwd_it != current_working_dirs.end()) {
        std::string cwd_path = reconstruct_filepath(cwd_it->second);
        return resolve_relative_path(cwd_path, path);
    }

    auto root_it = root_dirs.find(pid);
    if (root_it != root_dirs.end()) {
        std::string root_path = reconstruct_filepath(root_it->second);
        return resolve_relative_path(root_path, path);
    }

    return resolve_relative_path("/", path);
}

void reset_node_deleted(FsNode &node) {
    node.deleted = false;
}

void output_sink_relations_to_json(const char* output_file) {
    if (!output_file || std::strlen(output_file) == 0) {
        std::fprintf(stderr, "Error: Invalid output file path.\n");
        return;
    }

    FILE* file = std::fopen(output_file, "w");
    if (!file) {
        std::fprintf(stderr, "Error: Could not open file for writing: %s\n", output_file);
        return;
    }

    std::fprintf(file, "{\n");

    bool first_affected = true;
    for (const auto& affected_entry : fs_tracker.sink_relations) {
        if (!first_affected) {
            std::fprintf(file, ",\n");
        }
        first_affected = false;

        int affected_sink_id = affected_entry.first;
        const auto& affectors_map = affected_entry.second;

        std::fprintf(file, "  \"%d\": {\n", affected_sink_id);

        bool first_affector = true;
        for (const auto& affector_entry : affectors_map) {
            if (!first_affector) {
                std::fprintf(file, ",\n");
            }
            first_affector = false;

            int affector_sink_id = affector_entry.first;
            const auto& paths_list = affector_entry.second;

            std::fprintf(file, "    \"%d\": [", affector_sink_id);

            bool first_path = true;
            for (const auto& path : paths_list) {
                if (!first_path) {
                    std::fprintf(file, ", ");
                }
                first_path = false;

                std::fprintf(file, "\"%s\"", path.c_str());
            }

            std::fprintf(file, "]");
        }

        std::fprintf(file, "\n  }");
    }

    std::fprintf(file, "\n}\n");
    std::fclose(file);

    if (debug_var) {
        std::fprintf(stderr, "Sink relations JSON written to: %s\n", output_file);
    }
}

void store_sink_relation(int affected_sink_id, int affector_sink_id, FsNode* node) {
    if (affector_sink_id == -1 || affected_sink_id == -1) {
        return;
    }

    std::string full_path = reconstruct_filepath(node);
    auto& affectors_map = fs_tracker.sink_relations[affected_sink_id];
    auto& paths_list = affectors_map[affector_sink_id];

    if (std::find(paths_list.begin(), paths_list.end(), full_path) == paths_list.end()) {
        paths_list.push_back(full_path);
    }

    if (debug_var) {
        dump_sink_relations_state();
    }
}

void store_subtree_recursive(FsNode &node, bool is_parent_call = false) {
    node.sink_id = sink_id;

    if (!is_parent_call) {
        for (auto &child_entry : node.children) {
            store_subtree_recursive(*child_entry.second);
        }
    }
    else {
        if (node.parent != nullptr) {
            node.parent->sink_id = sink_id;
            store_subtree_recursive(*node.parent, true);
        }
    }
}

void store_subtree(FsNode &node) {
    store_subtree_recursive(node, true);
    store_subtree_recursive(node, false);

    if (debug_var) {
        dump_fs_tree_state();
    }
}

void load_node(FsNode &node) {
    int last_sink_id = node.sink_id;

    if (last_sink_id != sink_id) {
        store_sink_relation(sink_id, last_sink_id, &node);
    }
}

FsNode* open_node(const char* path, int fd, int pid) {
    if (sink_id == -1)
        return NULL;
    
    if (strstr(path, "firmadyne"))
        return NULL;

    if (fs_tracker.root.name != "/") {
        fs_tracker.root.name = "/";
        fs_tracker.root.parent = nullptr;
        fs_tracker.root.deleted = false;
        fs_tracker.root.sink_id = -1;
    }

    std::string full_path = get_full_path(pid, path);

    FsNode* current_node = &fs_tracker.root;
    std::istringstream path_stream(full_path);
    std::string token;

    while (std::getline(path_stream, token, '/')) {
        if (token.empty()) {
            continue;
        }

        auto it = current_node->children.find(token);
        if (it == current_node->children.end()) {
            current_node->children[token] = std::make_unique<FsNode>(FsNode{token, -1, false, current_node});
        }

        current_node = current_node->children[token].get();
    }

    if (fd != -1) {
        fs_tracker.fd_map[pid][fd] = current_node;
    }

    if (debug_var) {
        dump_fs_tree_state();
    }

    return current_node;
}

FsNode* get_node_from_fd(int pid, int fd) {
    auto pid_it = fs_tracker.fd_map.find(pid);
    if (pid_it != fs_tracker.fd_map.end()) {
        auto fd_it = pid_it->second.find(fd);
        if (fd_it != pid_it->second.end()) {
            return fd_it->second;
        }
    }
    return nullptr;
}

FsNode* get_node_from_path(int pid, const char* path) {
    std::string full_path = get_full_path(pid, path);

    FsNode* current_node = &fs_tracker.root;
    std::istringstream path_stream(full_path);
    std::string token;

    while (std::getline(path_stream, token, '/')) {
        if (token.empty()) {
            continue;
        }

        auto it = current_node->children.find(token);
        if (it == current_node->children.end()) {
            return nullptr;
        }

        current_node = it->second.get();
    }

    return current_node;
}

void handle_chdir_syscall(int pid, const char *path) {
    FsNode* node = get_node_from_path(pid, path);
    
    if (node) {
        current_working_dirs[pid] = node;
    }
}

void handle_fchdir_syscall(int pid, int fd) {
    FsNode* node = get_node_from_fd(pid, fd);
    
    if (node) {
        current_working_dirs[pid] = node;
    }
}

void handle_chroot_syscall(int pid, const char *path) {
    FsNode* node = get_node_from_path(pid, path);
    
    if (node) {
        root_dirs[pid] = node;
    }
}

void handle_open_syscall(int pid, int fd, const char *path, int mode) {
    FsNode* node = NULL;
    if (fd != -1) {
        node = open_node(path, fd, pid);
    }

    if (node) {
        if (mode) {
            if (debug_var) {
                std::ofstream debug_file;
                debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

                if (!debug_file.is_open()) {
                    return;
                }

                debug_file << "store_subtree: handle_open_syscall invoked for node: " << node->name 
                        << " with sink_id: " << sink_id << "\n";

                debug_file.close();
            }
            store_subtree(*node);
        } else {
            if (debug_var) {
                std::ofstream debug_file;
                debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

                if (!debug_file.is_open()) {
                    return;
                }

                debug_file << "load_node: handle_open_syscall invoked for node: " << node->name 
                        << " with sink_id: " << sink_id << "\n";

                debug_file.close();
            }
            load_node(*node);
        }
    }
}

void handle_close_syscall(int pid, int fd) {
    auto pid_it = fs_tracker.fd_map.find(pid);
    if (pid_it != fs_tracker.fd_map.end()) {
        pid_it->second.erase(fd);

        if (pid_it->second.empty()) {
            fs_tracker.fd_map.erase(pid);
        }
    }
}

// Store syscalls

void handle_write_syscall(int pid, int fd) {
    FsNode* node = get_node_from_fd(pid, fd);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "store_subtree: handle_write_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        store_subtree(*node);
    }
}

void handle_unlink_syscall(int pid, const char *path) {
    FsNode* node = get_node_from_path(pid, path);
    if (node) {
        mark_node_deleted(*node);
    }
}

void handle_rmdir_syscall(int pid, const char *path) {
    FsNode* node = get_node_from_path(pid, path);
    if (node) {
        mark_node_deleted(*node);
    }
}

void handle_truncate_syscall(int pid, const char *path, off_t length) {
    FsNode* node = get_node_from_path(pid, path);
    if (node) {
        if (node->sink_id != sink_id) {
            if (debug_var) {
                std::ofstream debug_file;
                debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

                if (!debug_file.is_open()) {
                    return;
                }

                debug_file << "store_sink_relation: handle_truncate_syscall invoked for node: " << node->name 
                        << " with sink_id: " << sink_id << "\n";

                debug_file.close();
            }
            store_sink_relation(sink_id, node->sink_id, node);
        }

        if (length == 0) {
            mark_node_deleted(*node);
        } else {
            if (debug_var) {
                std::ofstream debug_file;
                debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

                if (!debug_file.is_open()) {
                    return;
                }

                debug_file << "store_subtree: handle_truncate_syscall invoked for node: " << node->name 
                        << " with sink_id: " << sink_id << "\n";

                debug_file.close();
            }
            store_subtree(*node);
        }
    }
}

void handle_ftruncate_syscall(int pid, int fd, off_t length) {
    FsNode* node = get_node_from_fd(pid, fd);
    if (node) {
        if (node->sink_id != sink_id) {
            if (debug_var) {
                std::ofstream debug_file;
                debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

                if (!debug_file.is_open()) {
                    return;
                }

                debug_file << "store_sink_relation: handle_ftruncate_syscall invoked for node: " << node->name 
                        << " with sink_id: " << sink_id << "\n";

                debug_file.close();
            }
            store_sink_relation(sink_id, node->sink_id, node);
        }

        if (length == 0) {
            mark_node_deleted(*node);
        } else {
            if (debug_var) {
                std::ofstream debug_file;
                debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

                if (!debug_file.is_open()) {
                    return;
                }

                debug_file << "store_subtree: handle_ftruncate_syscall invoked for node: " << node->name 
                        << " with sink_id: " << sink_id << "\n";

                debug_file.close();
            }
            store_subtree(*node);
        }
    }
}

void handle_rename_syscall(int pid, const char *old_path, const char *new_path) {
    FsNode* old_node = get_node_from_path(pid, old_path);

    if (old_node) {
        mark_node_deleted(*old_node);
        FsNode* new_node = open_node(new_path, -1, pid);

        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "store_subtree: handle_rename_syscall invoked for node: " << new_node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        store_subtree(*new_node);
    }
}

void handle_mkdir_syscall(int pid, const char *path) {
    FsNode *node = open_node(path, -1, pid);
    if (node) {
        reset_node_deleted(*node);

        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "store_subtree: handle_mkdir_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        store_subtree(*node);
    }
}

void handle_symlink_syscall(int pid, const char *target, const char *linkpath) {
    FsNode *node = open_node(linkpath, -1, pid);
    if (node) {
        reset_node_deleted(*node);

        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "store_subtree: handle_symlink_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        store_subtree(*node);
    }
}

void handle_link_syscall(int pid, const char *target, const char *linkpath) {
    FsNode *node = open_node(linkpath, -1, pid);
    if (node) {
        reset_node_deleted(*node);

        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "store_subtree: handle_link_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        store_subtree(*node);
    }
}

void handle_fsync_syscall(int pid, int fd) {
    FsNode* node = get_node_from_fd(pid, fd);
    if (node && !node->deleted) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "store_subtree: handle_fsync_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        store_subtree(*node);
    }
}

void handle_fdatasync_syscall(int pid, int fd) {
    handle_fsync_syscall(pid, fd);
}

// Load syscalls

void handle_read_syscall(int pid, int fd) {
    FsNode *node = get_node_from_fd(pid, fd);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_read_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}

void handle_stat_syscall(int pid, const char *path) {
    FsNode *node = get_node_from_path(pid, path);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_stat_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}

void handle_lstat_syscall(int pid, const char *path) {
    FsNode *node = get_node_from_path(pid, path);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_lstat_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}

void handle_fstat_syscall(int pid, int fd) {
    FsNode *node = get_node_from_fd(pid, fd);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_fstat_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}

void handle_getdents_syscall(int pid, int fd) {
    FsNode *node = get_node_from_fd(pid, fd);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_getdents_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}

void handle_access_syscall(int pid, const char *path) {
    FsNode *node = get_node_from_path(pid, path);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_access_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}

void handle_faccessat_syscall(int pid, const char *path) {
    FsNode *node = get_node_from_path(pid, path);
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_faccessat_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}

void handle_statfs_syscall(int pid, const char *path) {
    FsNode* node = get_node_from_path(pid, path);
    
    if (node) {
        if (debug_var) {
            std::ofstream debug_file;
            debug_file.open("debug/fs_load_store_debug.log", std::ios::app);

            if (!debug_file.is_open()) {
                return;
            }

            debug_file << "load_node: handle_statfs_syscall invoked for node: " << node->name 
                    << " with sink_id: " << sink_id << "\n";

            debug_file.close();
        }
        load_node(*node);
    }
}
