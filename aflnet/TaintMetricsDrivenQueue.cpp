#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <queue>
#include <map>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <tuple>
#include <set>
#include <utility>
#include <climits>

#include "nlohmann/json.hpp"
#include "TaintMetricsDrivenQueue.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>


using json = nlohmann::json;
using namespace std;

struct AppTbPCSubsequence {
    std::vector<std::pair<uint64_t, int>> pcs;
    std::vector<int> region_influences;
    std::vector<int> affected_regions;
    std::vector<int> hex_values;
    std::string printable_string;
    std::map<std::string, double> metrics;
    int index;
    size_t offset;
    int count;

    nlohmann::json to_json() const {
        return {
            {"pcs", pcs},
            {"region_influences", region_influences},
            {"affected_regions", affected_regions},
            {"hex_values", hex_values},
            {"printable_string", printable_string},
            {"metrics", metrics},
            {"index", index},
            {"offset", offset},
            {"count", count}
        };
    }
};

struct CovSubsequence {
    std::vector<int> pcs;
    std::vector<int> region_influences;
    std::vector<int> affected_regions;
    std::vector<int> hex_values;
    std::string printable_string;
    std::map<std::string, double> metrics;
    int index;
    size_t offset;
    int count;

    nlohmann::json to_json() const {
        return {
            {"pcs", pcs},
            {"affected_regions", affected_regions},
            {"hex_values", hex_values},
            {"printable_string", printable_string},
            {"metrics", metrics},
            {"index", index},
            {"offset", offset},
            {"count", count}
        };
    }
};

struct AppTbPCSubsequenceComparator {
    std::shared_ptr<std::vector<std::string>> config;

    AppTbPCSubsequenceComparator(const std::shared_ptr<std::vector<std::string>>& cfg) : config(cfg) {}

    bool operator()(const AppTbPCSubsequence& lhs, const AppTbPCSubsequence& rhs) const {
        double lhs_avg = 0.0;
        double rhs_avg = 0.0;

        for (const auto& key : *config) {
            lhs_avg += lhs.metrics.at(key);
            rhs_avg += rhs.metrics.at(key);
        }

        lhs_avg /= config->size();
        rhs_avg /= config->size();

        return lhs_avg < rhs_avg;
    }
};

struct CovSubsequenceComparator {
    std::shared_ptr<std::vector<std::string>> config;

    CovSubsequenceComparator(const std::shared_ptr<std::vector<std::string>>& cfg) : config(cfg) {}

    bool operator()(const CovSubsequence& lhs, const CovSubsequence& rhs) const {
        double lhs_avg = 0.0;
        double rhs_avg = 0.0;

        for (const auto& key : *config) {
            lhs_avg += lhs.metrics.at(key);
            rhs_avg += rhs.metrics.at(key);
        }

        lhs_avg /= config->size();
        rhs_avg /= config->size();

        return lhs_avg < rhs_avg;
    }
};

struct pair_hash {
    template <class T1, class T2>
    std::size_t operator()(const std::pair<T1, T2>& p) const {
        auto h1 = std::hash<T1>{}(p.first);
        auto h2 = std::hash<T2>{}(p.second);
        return h1 ^ (h2 << 1);
    }
};

std::unordered_map<std::string, size_t> alias_cursors;
std::unordered_map<std::string, std::string> queue_aliases;

std::unordered_map<std::pair<uint64_t, int>, int, pair_hash> global_app_tb_pc_frequency;
std::unordered_map<uint64_t, int> global_process_frequency;
std::unordered_map<int, int> global_cov_frequency;
int *covs_shmem = NULL;
struct AppTBPC *app_tb_pcs_shmem = NULL;
int debug_json = 0;

std::vector<std::tuple<std::vector<int>,std::vector<std::tuple<
    int,
    std::vector<int>,
    std::vector<std::pair<uint64_t, int>>,
    std::vector<int>
>>>> global_sources;

std::shared_ptr<std::vector<std::string>> readConfigFile(const std::string& configFile) {
    std::ifstream file(configFile);
    std::string line;
    if (std::getline(file, line)) {
        std::istringstream ss(line);
        std::string metric;
        auto metrics = std::make_shared<std::vector<std::string>>();
        while (std::getline(ss, metric, '/')) {
            metrics->push_back(metric);
        }
        return metrics;
    }
    return nullptr;
}

double computeMean(const std::map<std::string, std::vector<std::vector<double>>>& analysis_results,
                   const std::vector<std::string>& config, size_t i, size_t j) {
    double mean = 0.0;
    for (const auto& metric : config) {
        mean += analysis_results.at(metric)[i][j];
    }
    return mean / config.size();
}

std::string getJsonFilePath(const std::string& fn, const std::string& out_dir) {
    std::filesystem::path outPath(out_dir);
    outPath /= "taint_metadata";
    outPath /= std::filesystem::path(fn).filename().string() + "_metadata.json";
    return outPath.string();
}

std::unordered_map<std::string, std::priority_queue<AppTbPCSubsequence, std::vector<AppTbPCSubsequence>, AppTbPCSubsequenceComparator>> global_subregions_app_tb_pcs;
std::unordered_map<std::string, std::priority_queue<CovSubsequence, std::vector<CovSubsequence>, CovSubsequenceComparator>> global_subregions_covs;
std::shared_ptr<std::vector<std::string>> config;

std::vector<int> getVector(const std::vector<int>& indices, int totalSize) {
    std::vector<int> vectorMap(totalSize, 0);

    for (int idx : indices) {
        if (idx < totalSize) {
            vectorMap[idx] = 1;
        }
    }

    return vectorMap;
}

void mergeVectors(int index, const std::map<int, std::vector<int>>& data,
                  std::set<int>& visited, std::vector<int>& result) {
    if (visited.count(index)) return;
    visited.insert(index);

    result.push_back(index);

    for (int neighbor : data.at(index)) {
        mergeVectors(neighbor, data, visited, result);
    }
}

std::vector<int> getMergedVector(
    int startIndex, const std::map<int, std::vector<int>>& data, int totalSize) {

    std::set<int> visited;
    std::vector<int> result;
    std::vector<int> vectorMap(totalSize, 0);

    mergeVectors(startIndex, data, visited, result);

    for (int idx : result) {
        if (idx < totalSize) {
            vectorMap[idx] = 1;
        }
    }

    return vectorMap;
}

int* getMergedVectorC(const std::vector<int>& vec1, const std::vector<int>& vec2) {
    if (vec1.size() != vec2.size()) {
        return NULL;
    }

    int* buffer = (int*)malloc(vec1.size() * sizeof(int));
    if (!buffer) {
        return NULL;
    }

    for (size_t i = 0; i < vec1.size(); ++i) {
        buffer[i] = vec1[i] | vec2[i];
    }

    return buffer;
}

int fetch_element_from_alias_app_tb_pc(char* alias, QueueElement* result) {
    auto it_alias = queue_aliases.find(alias);
    if (it_alias == queue_aliases.end()) return -1;

    const std::string& original_fn = it_alias->second;

    auto it_queue = global_subregions_app_tb_pcs.find(original_fn);
    if (it_queue == global_subregions_app_tb_pcs.end()) return -1;

    auto& queue = it_queue->second;

    if (queue.empty()) return -1;

    const AppTbPCSubsequence& top = queue.top();

    result->region_num = static_cast<int>(top.index);
    result->offset = static_cast<int>(top.offset);
    result->length = static_cast<int>(top.count);
    result->regions_to_keep = getMergedVectorC(top.affected_regions, top.region_influences);

    queue.pop();
    alias_cursors[alias]++;

    return 0;
}

int fetch_element_from_alias_cov(char* alias, QueueElement* result) {
    auto it_alias = queue_aliases.find(alias);
    if (it_alias == queue_aliases.end()) return -1;

    const std::string& original_fn = it_alias->second;

    auto it_queue = global_subregions_covs.find(original_fn);
    if (it_queue == global_subregions_covs.end()) return -1;

    auto& queue = it_queue->second;

    if (queue.empty()) return -1;

    const CovSubsequence& top = queue.top();

    result->region_num = static_cast<int>(top.index);
    result->offset = static_cast<int>(top.offset);
    result->length = static_cast<int>(top.count);
    result->regions_to_keep = getMergedVectorC(top.affected_regions, top.region_influences);

    queue.pop();
    alias_cursors[alias]++;

    return 0;
}

void add_alias_app_tb_pc(char* fn, char* alias) {
    try {
        auto it_fn = global_subregions_app_tb_pcs.find(fn);
        if (it_fn == global_subregions_app_tb_pcs.end()) return;
        queue_aliases[alias] = fn;
        alias_cursors[alias] = 0;
    } catch (...) {}
}

void add_alias_cov(char* fn, char* alias) {
    try {
        auto it_fn = global_subregions_covs.find(fn);
        if (it_fn == global_subregions_covs.end()) return;
        queue_aliases[alias] = fn;
        alias_cursors[alias] = 0;
    } catch (...) {}
}

void rename_alias(char* old_alias, char* new_alias) {
    try {
        auto it = queue_aliases.find(old_alias);
        if (it == queue_aliases.end()) return;
        queue_aliases[new_alias] = it->second;
        alias_cursors[new_alias] = alias_cursors[old_alias];
        queue_aliases.erase(it);
        alias_cursors.erase(old_alias);
    } catch (...) {}
}

double safe_div(double numerator, double denominator) {
    return denominator != 0.0 ? numerator / denominator : 0.0;
}

void calculate_analysis_results(const std::string& fn) {
    std::vector<std::vector<std::unordered_set<uint64_t>>> unique_processes_per_byte;
    std::vector<std::vector<std::unordered_set<std::pair<uint64_t, int>, pair_hash>>> unique_app_tb_pc_per_byte;
    std::vector<std::vector<std::unordered_set<int>>> unique_region_ids_per_byte;
    std::vector<std::unordered_set<int>> unique_fs_region_ids_per_id;
    std::vector<std::vector<std::unordered_set<int>>> unique_covs_per_byte;

    global_app_tb_pc_frequency.clear();
    global_process_frequency.clear();
    global_cov_frequency.clear();

    for (size_t i = 0; i < global_sources.size(); ++i) {
        unique_processes_per_byte.push_back({});
        unique_app_tb_pc_per_byte.push_back({});
        unique_region_ids_per_byte.push_back({});
        unique_covs_per_byte.push_back({});
        unique_fs_region_ids_per_id.push_back({});

        auto& fs_relations = std::get<0>(global_sources[i]);
        auto& regions = std::get<1>(global_sources[i]);
        for (size_t j = 0; j < fs_relations.size(); ++j) {
            unique_fs_region_ids_per_id[i].insert(fs_relations[j]);
        }

        for (size_t j = 0; j < regions.size(); ++j) {
            unique_processes_per_byte[i].push_back({});
            unique_app_tb_pc_per_byte[i].push_back({});
            unique_region_ids_per_byte[i].push_back({});
            unique_covs_per_byte[i].push_back({});

            auto& byte = std::get<0>(regions[j]);
            auto& region_ids = std::get<1>(regions[j]);
            auto& tb_pcs = std::get<2>(regions[j]);
            auto& covs = std::get<3>(regions[j]);

            for (const auto& tb_pc : tb_pcs) {
                unique_processes_per_byte[i][j].insert(tb_pc.first);
                unique_app_tb_pc_per_byte[i][j].insert(tb_pc);
                global_app_tb_pc_frequency[tb_pc] += 1;
                global_process_frequency[tb_pc.first] += 1;
            }

            for (const auto& kw_id : region_ids) {
                unique_region_ids_per_byte[i][j].insert(kw_id);
            }

            for (const auto& cov : covs) {
                unique_covs_per_byte[i][j].insert(cov);
                global_cov_frequency[cov] += 1;
            }
        }
    }

    int max_unique_processes = 0;
    int min_unique_processes = 0;

    bool found_process = false;
    for (const auto& region : unique_processes_per_byte) {
        for (const auto& processes : region) {
            int len = processes.size();
            if (!found_process) {
                max_unique_processes = min_unique_processes = len;
                found_process = true;
            } else {
                max_unique_processes = std::max(max_unique_processes, len);
                min_unique_processes = std::min(min_unique_processes, len);
            }
        }
    }

    if (!found_process) {
        max_unique_processes = min_unique_processes = 0;
    }

    int max_unique_app_tb_pc = 0;
    int min_unique_app_tb_pc = 0;

    bool found_app_tb_pc = false;
    for (const auto& region : unique_app_tb_pc_per_byte) {
        for (const auto& app_tb_pc : region) {
            int len = app_tb_pc.size();
            if (!found_app_tb_pc) {
                max_unique_app_tb_pc = min_unique_app_tb_pc = len;
                found_app_tb_pc = true;
            } else {
                max_unique_app_tb_pc = std::max(max_unique_app_tb_pc, len);
                min_unique_app_tb_pc = std::min(min_unique_app_tb_pc, len);
            }
        }
    }

    if (!found_app_tb_pc) {
        max_unique_app_tb_pc = min_unique_app_tb_pc = 0;
    }

    int max_unique_regions = 0;
    int min_unique_regions = 0;

    bool found_regions = false;
    for (const auto& region : unique_region_ids_per_byte) {
        for (const auto& region_ids : region) {
            int len = region_ids.size();
            if (!found_regions) {
                max_unique_regions = min_unique_regions = len;
                found_regions = true;
            } else {
                max_unique_regions = std::max(max_unique_regions, len);
                min_unique_regions = std::min(min_unique_regions, len);
            }
        }
    }

    if (!found_regions) {
        max_unique_regions = min_unique_regions = 0;
    }

    int max_unique_fs_regions = 0;
    int min_unique_fs_regions = 0;

    bool found_fs_regions = false;
    for (const auto& region : unique_region_ids_per_byte) {
        for (const auto& region_ids : region) {
            int len = region_ids.size();
            if (!found_fs_regions) {
                max_unique_fs_regions = min_unique_fs_regions = len;
                found_fs_regions = true;
            } else {
                max_unique_fs_regions = std::max(max_unique_fs_regions, len);
                min_unique_fs_regions = std::min(min_unique_fs_regions, len);
            }
        }
    }

    if (!found_fs_regions) {
        max_unique_fs_regions = min_unique_fs_regions = 0;
    }

    int max_unique_covs = 0;
    int min_unique_covs = 0;

    bool found_covs = false;
    for (const auto& region : unique_covs_per_byte) {
        for (const auto& covs : region) {
            int len = covs.size();
            if (!found_covs) {
                max_unique_covs = min_unique_covs = len;
                found_covs = true;
            } else {
                max_unique_covs = std::max(max_unique_covs, len);
                min_unique_covs = std::min(min_unique_covs, len);
            }
        }
    }

    if (!found_covs) {
        max_unique_covs = min_unique_covs = 0;
    }

    int max_frequency_value_app_tb_pc = 0;
    int min_frequency_value_app_tb_pc = 0;

    bool found_app_tb_pc_freq = false;
    for (const auto& pair : global_app_tb_pc_frequency) {
        if (!found_app_tb_pc_freq) {
            max_frequency_value_app_tb_pc = min_frequency_value_app_tb_pc = pair.second;
            found_app_tb_pc_freq = true;
        } else {
            max_frequency_value_app_tb_pc = std::max(max_frequency_value_app_tb_pc, pair.second);
            min_frequency_value_app_tb_pc = std::min(min_frequency_value_app_tb_pc, pair.second);
        }
    }

    if (!found_app_tb_pc_freq) {
        max_frequency_value_app_tb_pc = min_frequency_value_app_tb_pc = 0;
    }

    int max_frequency_value_process = 0;
    int min_frequency_value_process = 0;

    bool found_process_freq = false;
    for (const auto& pair : global_process_frequency) {
        if (!found_process_freq) {
            max_frequency_value_process = min_frequency_value_process = pair.second;
            found_process_freq = true;
        } else {
            max_frequency_value_process = std::max(max_frequency_value_process, pair.second);
            min_frequency_value_process = std::min(min_frequency_value_process, pair.second);
        }
    }

    if (!found_process_freq) {
        max_frequency_value_process = min_frequency_value_process = 0;
    }

    int max_frequency_value_cov = 0;
    int min_frequency_value_cov = 0;

    bool found_cov_freq = false;
    for (const auto& pair : global_cov_frequency) {
        if (!found_cov_freq) {
            max_frequency_value_cov = min_frequency_value_cov = pair.second;
            found_cov_freq = true;
        } else {
            max_frequency_value_cov = std::max(max_frequency_value_cov, pair.second);
            min_frequency_value_cov = std::min(min_frequency_value_cov, pair.second);
        }
    }

    if (!found_cov_freq) {
        max_frequency_value_cov = min_frequency_value_cov = 0;
    }

    std::map<std::string, std::vector<std::vector<double>>> analysis_results;

    for (size_t i = 0; i < global_sources.size(); ++i) {
        analysis_results["rarest_app_tb_pc"].push_back({});
        analysis_results["most_frequent_app_tb_pc"].push_back({});
        analysis_results["rarest_process"].push_back({});
        analysis_results["most_frequent_process"].push_back({});        
        analysis_results["rarest_cov"].push_back({});
        analysis_results["most_frequent_cov"].push_back({});
        analysis_results["number_of_processes"].push_back({});
        analysis_results["number_of_app_tb_pcs"].push_back({});
        analysis_results["number_of_affected_regions_by_taint"].push_back({});
        analysis_results["number_of_affected_regions_by_fs"].push_back({});
        analysis_results["number_of_covs"].push_back({});

        int unique_fs_region_ids = unique_fs_region_ids_per_id[i].size();

        auto& fs_relations = std::get<0>(global_sources[i]);
        auto& regions = std::get<1>(global_sources[i]);

        for (size_t j = 0; j < regions.size(); ++j) {
            auto& tb_pcs = std::get<2>(regions[j]);
            auto& covs = std::get<3>(regions[j]);

            std::vector<int> tb_pc_counts;
            std::vector<int> process_counts;
            std::vector<int> cov_counts;
            for (const auto& tb_pc : tb_pcs) {
                tb_pc_counts.push_back(global_app_tb_pc_frequency[tb_pc]);
                process_counts.push_back(global_process_frequency[tb_pc.first]);
            }
            for (int cov : covs) {
                cov_counts.push_back(global_cov_frequency[cov]);
            }

            int unique_processes = unique_processes_per_byte[i][j].size();
            int unique_app_tb_pc = unique_app_tb_pc_per_byte[i][j].size();
            int unique_region_ids = unique_region_ids_per_byte[i][j].size();
            int unique_covs = unique_covs_per_byte[i][j].size();

            analysis_results["rarest_app_tb_pc"][i].push_back(
                safe_div(max_frequency_value_app_tb_pc - std::accumulate(tb_pc_counts.begin(), tb_pc_counts.end(), 0.0) / tb_pc_counts.size(),
                         max_frequency_value_app_tb_pc - min_frequency_value_app_tb_pc)
            );

            analysis_results["most_frequent_app_tb_pc"][i].push_back(
                safe_div(std::accumulate(tb_pc_counts.begin(), tb_pc_counts.end(), 0.0) / tb_pc_counts.size() - min_frequency_value_app_tb_pc,
                         max_frequency_value_app_tb_pc - min_frequency_value_app_tb_pc)
            );

            analysis_results["rarest_process"][i].push_back(
                safe_div(max_frequency_value_process - std::accumulate(process_counts.begin(), process_counts.end(), 0.0) / process_counts.size(),
                         max_frequency_value_process - min_frequency_value_process)
            );

            analysis_results["most_frequent_process"][i].push_back(
                safe_div(std::accumulate(process_counts.begin(), process_counts.end(), 0.0) / process_counts.size() - min_frequency_value_process,
                         max_frequency_value_process - min_frequency_value_process)
            );

            analysis_results["rarest_cov"][i].push_back(
                safe_div(max_frequency_value_cov - std::accumulate(cov_counts.begin(), cov_counts.end(), 0.0) / cov_counts.size(),
                         max_frequency_value_cov - min_frequency_value_cov)
            );

            analysis_results["most_frequent_cov"][i].push_back(
                safe_div(std::accumulate(cov_counts.begin(), cov_counts.end(), 0.0) / cov_counts.size() - min_frequency_value_cov,
                         max_frequency_value_cov - min_frequency_value_cov)
            );

            analysis_results["number_of_processes"][i].push_back(
                safe_div(unique_processes - min_unique_processes, max_unique_processes - min_unique_processes)
            );

            analysis_results["number_of_app_tb_pcs"][i].push_back(
                safe_div(unique_app_tb_pc - min_unique_app_tb_pc, max_unique_app_tb_pc - min_unique_app_tb_pc)
            );

            analysis_results["number_of_affected_regions_by_taint"][i].push_back(
                safe_div(unique_region_ids - min_unique_regions, max_unique_regions - min_unique_regions)
            );

            analysis_results["number_of_affected_regions_by_fs"][i].push_back(
                safe_div(unique_fs_region_ids - min_unique_fs_regions, max_unique_fs_regions - min_unique_fs_regions)
            );

            analysis_results["number_of_covs"][i].push_back(
                safe_div(unique_covs - min_unique_covs, max_unique_covs - min_unique_covs)
            );
        }
    }

    std::map<int, std::vector<int>> region_influences;
    for (size_t i = 0; i < global_sources.size(); ++i) {
        region_influences[i] = {};
    }

    for (size_t i = 0; i < global_sources.size(); ++i) {
        std::map<std::pair<uint64_t, int>, std::vector<int>> app_tb_pc_set;
        std::map<int, std::vector<int>> coverage_set;
        std::map<std::pair<uint64_t, int>, std::map<std::string, double>> metrics_values_app_tb_pcs;
        std::map<int, std::map<std::string, double>> metrics_values_covs;
        std::map<std::pair<uint64_t, int>, int> count_app_tb_pcs;
        std::map<int, int> count_covs;
        std::map<std::pair<uint64_t, int>, size_t> offset_app_tb_pcs;
        std::map<int, size_t> offset_covs;
        std::map<std::pair<uint64_t, int>, std::vector<std::pair<uint64_t, int>>> pcs_app_tb_pcs;
        std::map<int, std::vector<int>> pcs_covs;
        std::map<std::pair<uint64_t, int>, std::vector<int>> affected_regions_app_tb_pcs;
        std::map<int, std::vector<int>> affected_regions_covs;

        auto& fs_relations = std::get<0>(global_sources[i]);
        auto& regions = std::get<1>(global_sources[i]);

        for (size_t j = 0; j < regions.size(); ++j) {
            auto& hex_value = std::get<0>(regions[j]);
            auto& region_ids = std::get<1>(regions[j]);
            auto& app_tb_pcs = std::get<2>(regions[j]);
            auto& coverages = std::get<3>(regions[j]);

            for (const auto& app_tb_pc : app_tb_pcs) {
                if (metrics_values_app_tb_pcs.find(app_tb_pc) == metrics_values_app_tb_pcs.end()) {
                    metrics_values_app_tb_pcs[app_tb_pc] = {};
                }
                if (count_app_tb_pcs.find(app_tb_pc) == count_app_tb_pcs.end()) {
                    count_app_tb_pcs[app_tb_pc] = 0;
                }
                if (app_tb_pc_set.find(app_tb_pc) == app_tb_pc_set.end()) {
                    app_tb_pc_set[app_tb_pc] = {};
                }
                if (offset_app_tb_pcs.find(app_tb_pc) == offset_app_tb_pcs.end()) {
                    offset_app_tb_pcs[app_tb_pc] = j;
                }
                if (affected_regions_app_tb_pcs.find(app_tb_pc) == affected_regions_app_tb_pcs.end()) {
                    affected_regions_app_tb_pcs[app_tb_pc] = {};
                }
                if (pcs_app_tb_pcs.find(app_tb_pc) == pcs_app_tb_pcs.end()) {
                    pcs_app_tb_pcs[app_tb_pc] = {};
                }

                if (metrics_values_app_tb_pcs[app_tb_pc].empty()) {
                    for (const auto& metric : analysis_results) {
                        metrics_values_app_tb_pcs[app_tb_pc][metric.first] = metric.second[i][j];
                    }
                } else {
                    for (const auto& metric : analysis_results) {
                        metrics_values_app_tb_pcs[app_tb_pc][metric.first] += metric.second[i][j];
                    }
                }

                count_app_tb_pcs[app_tb_pc]++;
                app_tb_pc_set[app_tb_pc].push_back(hex_value);
                for (int kw : region_ids) {
                    if (std::find(affected_regions_app_tb_pcs[app_tb_pc].begin(), 
                                affected_regions_app_tb_pcs[app_tb_pc].end(), kw) == 
                        affected_regions_app_tb_pcs[app_tb_pc].end()) {
                        affected_regions_app_tb_pcs[app_tb_pc].push_back(kw);
                    }
                    if (std::find(region_influences[kw].begin(), region_influences[kw].end(), i) == 
                        region_influences[kw].end()) {
                        region_influences[kw].push_back(i);
                    }
                }
                for (int kw : fs_relations) {
                    if (std::find(region_influences[kw].begin(), region_influences[kw].end(), i) == 
                        region_influences[kw].end()) {
                        region_influences[kw].push_back(i);
                    }                    
                }
                for (const auto& pc : pcs_app_tb_pcs) {
                    if (std::find(pc.second.begin(), pc.second.end(), app_tb_pc) == pc.second.end()) {
                        pcs_app_tb_pcs[pc.first].push_back(app_tb_pc);
                    }
                }
            }

            for (const int coverage : coverages) {
                if (metrics_values_covs.find(coverage) == metrics_values_covs.end()) {
                    metrics_values_covs[coverage] = {};
                }
                if (count_covs.find(coverage) == count_covs.end()) {
                    count_covs[coverage] = 0;
                }
                if (coverage_set.find(coverage) == coverage_set.end()) {
                    coverage_set[coverage] = {};
                }
                if (offset_covs.find(coverage) == offset_covs.end()) {
                    offset_covs[coverage] = j;
                }
                if (affected_regions_covs.find(coverage) == affected_regions_covs.end()) {
                    affected_regions_covs[coverage] = {};
                }
                if (pcs_covs.find(coverage) == pcs_covs.end()) {
                    pcs_covs[coverage] = {};
                }

                if (metrics_values_covs[coverage].empty()) {
                    for (const auto& metric : analysis_results) {
                        metrics_values_covs[coverage][metric.first] = metric.second[i][j];
                    }
                } else {
                    for (const auto& metric : analysis_results) {
                        metrics_values_covs[coverage][metric.first] += metric.second[i][j];
                    }
                }

                count_covs[coverage]++;
                coverage_set[coverage].push_back(hex_value);
                for (int kw : region_ids) {
                    if (std::find(affected_regions_covs[coverage].begin(), 
                                affected_regions_covs[coverage].end(), kw) == 
                        affected_regions_covs[coverage].end()) {
                        affected_regions_covs[coverage].push_back(kw);
                    }
                    if (std::find(region_influences[kw].begin(), region_influences[kw].end(), i) == 
                        region_influences[kw].end()) {
                        region_influences[kw].push_back(i);
                    }
                }
                for (int kw : fs_relations) {
                    if (std::find(region_influences[kw].begin(), region_influences[kw].end(), i) == 
                        region_influences[kw].end()) {
                        region_influences[kw].push_back(i);
                    }                    
                }
                for (const auto& cov : pcs_covs) {
                    if (std::find(cov.second.begin(), cov.second.end(), coverage) == cov.second.end()) {
                        pcs_covs[cov.first].push_back(coverage);
                    }
                }
            }

            std::vector<std::pair<uint64_t, int>> app_tb_pc_to_del;
            for (auto& entry : metrics_values_app_tb_pcs) {
                const auto& app_tb_pc = entry.first;
                if (std::find(app_tb_pcs.begin(), app_tb_pcs.end(), app_tb_pc) == app_tb_pcs.end()) {
                    auto metrics_values = entry.second;
                    for (auto& metric : metrics_values) {
                        metric.second /= count_app_tb_pcs[app_tb_pc];
                    }
                    std::string concatenated_app_tb_pc_set = std::accumulate(app_tb_pc_set[app_tb_pc].begin(), app_tb_pc_set[app_tb_pc].end(), std::string(),
                        [](std::string& acc, const int& value) {
                            return acc + (value > 32 && value < 127 ? static_cast<char>(value) : '.');
                    });
                    AppTbPCSubsequence app_tb_pc_subseq = {
                        pcs_app_tb_pcs[app_tb_pc],
                        getMergedVector(i, region_influences, global_sources.size()),
                        getVector(affected_regions_app_tb_pcs[app_tb_pc], global_sources.size()),
                        app_tb_pc_set[app_tb_pc],
                        concatenated_app_tb_pc_set,
                        metrics_values,
                        i,
                        offset_app_tb_pcs[app_tb_pc],
                        count_app_tb_pcs[app_tb_pc]
                    };
                    auto it = global_subregions_app_tb_pcs.find(fn);
                    if (it == global_subregions_app_tb_pcs.end()) {
                        it = global_subregions_app_tb_pcs.emplace(
                            fn,
                            std::priority_queue<AppTbPCSubsequence, std::vector<AppTbPCSubsequence>, AppTbPCSubsequenceComparator>(
                                AppTbPCSubsequenceComparator(config)
                            )
                        ).first;
                    }
                    it->second.push(app_tb_pc_subseq);
                    app_tb_pc_to_del.push_back(app_tb_pc);
                }
            }

            for (const auto& app_tb_pc : app_tb_pc_to_del) {
                metrics_values_app_tb_pcs.erase(app_tb_pc);
                count_app_tb_pcs.erase(app_tb_pc);
                app_tb_pc_set.erase(app_tb_pc);
                offset_app_tb_pcs.erase(app_tb_pc);
                affected_regions_app_tb_pcs.erase(app_tb_pc);
                pcs_app_tb_pcs.erase(app_tb_pc);
            }

            std::vector<int> cov_to_del;
            for (auto& entry : metrics_values_covs) {
                const auto& coverage = entry.first;
                if (std::find(coverages.begin(), coverages.end(), coverage) == coverages.end()) {
                    auto metrics_values = entry.second;
                    for (auto& metric : metrics_values) {
                        metric.second /= count_covs[coverage];
                    }
                    std::string concatenated_coverage_set = std::accumulate(coverage_set[coverage].begin(), coverage_set[coverage].end(), std::string(),
                        [](std::string& acc, const int& value) {
                            return acc + (value > 32 && value < 127 ? static_cast<char>(value) : '.');
                    });
                    CovSubsequence cov_subseq = {
                        pcs_covs[coverage],
                        getMergedVector(i, region_influences, global_sources.size()),
                        getVector(affected_regions_covs[coverage], global_sources.size()),
                        coverage_set[coverage], 
                        concatenated_coverage_set,
                        metrics_values, 
                        i, 
                        offset_covs[coverage], 
                        count_covs[coverage]
                    };
                    auto it = global_subregions_covs.find(fn);
                    if (it == global_subregions_covs.end()) {
                        it = global_subregions_covs.emplace(
                            fn,
                            std::priority_queue<CovSubsequence, std::vector<CovSubsequence>, CovSubsequenceComparator>(
                                CovSubsequenceComparator(config)
                            )
                        ).first;
                    }
                    it->second.push(cov_subseq);
                    cov_to_del.push_back(coverage);
                }
            }

            for (const auto& cov : cov_to_del) {
                metrics_values_covs.erase(cov);
                count_covs.erase(cov);
                coverage_set.erase(cov);
                offset_covs.erase(cov);
                affected_regions_covs.erase(cov);
                pcs_covs.erase(cov);
            }
        }
    }
}

template <typename T, typename Comparator>
void serialize_queue_to_json(const std::priority_queue<T, std::vector<T>, Comparator>& queue,
                             const std::string& queue_type,
                             const std::string& stage,
                             const std::string& queue_name) {
    std::filesystem::create_directories("debug");

    auto temp_queue = queue;

    nlohmann::json json_output;
    json_output["queue_type"] = queue_type;
    json_output["stage"] = stage;
    json_output["queue_name"] = queue_name;

    std::vector<nlohmann::json> elements;
    while (!temp_queue.empty()) {
        elements.push_back(temp_queue.top().to_json());
        temp_queue.pop();
    }

    json_output["elements"] = elements;

    std::filesystem::path queue_path(queue_name);
    std::string basename = queue_path.filename().string();

    std::ofstream output_file("debug/" + basename + "_" + queue_type + "_" + stage + ".json");
    output_file << json_output.dump(4);
    output_file.close();
}

void filter_and_apply_heuristics() {
    FILE *fp = fopen("debug/debug_json.log", "a+");
    fprintf(fp, "%d", debug_json);
    fclose(fp);
    if (debug_json) {
        for (const auto& entry : global_subregions_app_tb_pcs) {
            serialize_queue_to_json(entry.second, "app_tb_pcs", "pre", entry.first);
        }
        for (const auto& entry : global_subregions_covs) {
            serialize_queue_to_json(entry.second, "covs", "pre", entry.first);
        }
    }

    auto is_overlapping = [](size_t start1, size_t end1, size_t start2, size_t end2) {
        return (start1 < end2 && start2 < end1);
    };

    for (auto& entry : global_subregions_app_tb_pcs) {
        auto& queue = entry.second;
        std::vector<AppTbPCSubsequence> filtered_queue;

        std::vector<AppTbPCSubsequence> queue_copy;
        while (!queue.empty()) {
            queue_copy.push_back(queue.top());
            queue.pop();
        }

        std::sort(queue_copy.begin(), queue_copy.end(), [](const AppTbPCSubsequence& a, const AppTbPCSubsequence& b) {
            return a.offset < b.offset || (a.offset == b.offset && a.count < b.count);
        });

        std::vector<std::pair<size_t, size_t>> covered_ranges;

        for (const auto& subsequence : queue_copy) {
            bool has_overlap = false;

            for (const auto& range : covered_ranges) {
                if (is_overlapping(subsequence.offset, subsequence.offset + subsequence.count, range.first, range.second)) {
                    has_overlap = true;
                    break;
                }
            }

            if (!has_overlap) {
                filtered_queue.push_back(subsequence);
                covered_ranges.push_back({subsequence.offset, subsequence.offset + subsequence.count});
            }
        }

        AppTbPCSubsequenceComparator app_tb_pc_comparator(config);
        std::priority_queue<AppTbPCSubsequence, std::vector<AppTbPCSubsequence>, AppTbPCSubsequenceComparator> new_queue(app_tb_pc_comparator);

        for (const auto& subsequence : filtered_queue) {
            new_queue.push(subsequence);
        }

        queue = std::move(new_queue);

        if (debug_json) {
            serialize_queue_to_json(queue, "app_tb_pcs", "post", entry.first);
        }
    }

    for (auto& entry : global_subregions_covs) {
        auto& queue = entry.second;
        std::vector<CovSubsequence> filtered_queue;

        std::vector<CovSubsequence> queue_copy;
        while (!queue.empty()) {
            queue_copy.push_back(queue.top());
            queue.pop();
        }

        std::sort(queue_copy.begin(), queue_copy.end(), [](const CovSubsequence& a, const CovSubsequence& b) {
            return a.offset < b.offset || (a.offset == b.offset && a.count < b.count);
        });

        std::vector<std::pair<size_t, size_t>> covered_ranges;

        for (const auto& subsequence : queue_copy) {
            bool has_overlap = false;

            for (const auto& range : covered_ranges) {
                if (is_overlapping(subsequence.offset, subsequence.offset + subsequence.count, range.first, range.second)) {
                    has_overlap = true;
                    break;
                }
            }

            if (!has_overlap) {
                filtered_queue.push_back(subsequence);
                covered_ranges.push_back({subsequence.offset, subsequence.offset + subsequence.count});
            }
        }

        CovSubsequenceComparator cov_comparator(config);
        std::priority_queue<CovSubsequence, std::vector<CovSubsequence>, CovSubsequenceComparator> new_queue(cov_comparator);

        for (const auto& subsequence : filtered_queue) {
            new_queue.push(subsequence);
        }

        queue = std::move(new_queue);

        if (debug_json) {
            serialize_queue_to_json(queue, "covs", "post", entry.first);
        }
    }
}

void initialize_queue(char* fn, char* out_dir, const char* config_file, int debug) {
    debug_json = debug;

    if (debug_json) {
        FILE *fp = fopen("debug/initialize_queue.log", "a+");
        fprintf(fp, "Debug: initialize_queue called with fn = %s, out_dir = %s, config_file = %s, debug = %d\n", fn, out_dir, config_file, debug);
        fclose(fp);
    }

    std::string json_file = getJsonFilePath(fn, out_dir);
    
    if (debug_json) {
        FILE *fp = fopen("debug/initialize_queue.log", "a+");
        fprintf(fp, "Debug: JSON file path resolved to %s\n", json_file.c_str());
        fclose(fp);
    }

    std::ifstream jsonFile(json_file);
    if (!jsonFile) {
        if (debug_json) {
            FILE *fp = fopen("debug/initialize_queue.log", "a+");
            fprintf(fp, "Error: Failed to open JSON file: %s\n", json_file.c_str());
            fclose(fp);
        }
        return;
    }

    json inputData = json::parse(jsonFile);

    if (!config || config->empty()) {
        config = readConfigFile(config_file);

        if (debug_json) {
            FILE *fp = fopen("debug/initialize_queue.log", "a+");
            fprintf(fp, "Debug: Configuration file loaded\n");
            fclose(fp);
        }
    }

    global_sources.clear();

    if (debug_json) {
        FILE *fp = fopen("debug/initialize_queue.log", "a+");
        fprintf(fp, "Debug: global_sources cleared\n");
        fclose(fp);
    }

    for (const auto& group : inputData) {
        std::vector<int> fs_region_ids = group[0].get<std::vector<int>>();
        std::vector<std::tuple<int, std::vector<int>, std::vector<std::pair<uint64_t, int>>, std::vector<int>>> source_entry;

        for (const auto& item : group[1]) {
            int byte = item[0];
            std::vector<int> region_ids = item[1].get<std::vector<int>>();
            std::vector<std::pair<uint64_t, int>> tb_pcs;

            for (const auto& tb_pc : item[2]) {
                tb_pcs.emplace_back(tb_pc[0], tb_pc[1]);
            }

            std::vector<int> covs = item[3].get<std::vector<int>>();

            source_entry.emplace_back(byte, region_ids, tb_pcs, covs);
        }

        global_sources.emplace_back(std::move(fs_region_ids), std::move(source_entry));
    }

    if (debug_json) {
        FILE *fp = fopen("debug/initialize_queue.log", "a+");
        fprintf(fp, "Debug: global_sources populated with %zu entries\n", global_sources.size());
        fclose(fp);
    }

    auto it = global_subregions_app_tb_pcs.find(fn);
    if (it == global_subregions_app_tb_pcs.end()) {
        global_subregions_app_tb_pcs.emplace(
            fn,
            std::priority_queue<AppTbPCSubsequence, std::vector<AppTbPCSubsequence>, AppTbPCSubsequenceComparator>(
                AppTbPCSubsequenceComparator(config)
            )
        );

        if (debug_json) {
            FILE *fp = fopen("debug/initialize_queue.log", "a+");
            fprintf(fp, "Debug: Initialized global_subregions_app_tb_pcs for %s\n", fn);
            fclose(fp);
        }
    }

    auto it2 = global_subregions_covs.find(fn);
    if (it2 == global_subregions_covs.end()) {
        global_subregions_covs.emplace(
            fn,
            std::priority_queue<CovSubsequence, std::vector<CovSubsequence>, CovSubsequenceComparator>(
                CovSubsequenceComparator(config)
            )
        );

        if (debug_json) {
            FILE *fp = fopen("debug/initialize_queue.log", "a+");
            fprintf(fp, "Debug: Initialized global_subregions_covs for %s\n", fn);
            fclose(fp);
        }
    }

    calculate_analysis_results(std::string(fn));

    if (debug_json) {
        FILE *fp = fopen("debug/initialize_queue.log", "a+");
        fprintf(fp, "Debug: Finished calculate_analysis_results\n");
        fclose(fp);
    }

    filter_and_apply_heuristics();

    if (debug_json) {
        FILE *fp = fopen("debug/initialize_queue.log", "a+");
        fprintf(fp, "Debug: Finished filter_and_apply_heuristics\n");
        fclose(fp);
    }
}
