#include <set>

#include "trace.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

using namespace std;

int is_trace_zero(const trace_t *t) {
    static const trace_element_t zero_trace[TRACE_LEN] = {0};
    static const uint8_t zero_procname[MAX_PROCESS_NAME_LENGTH] = {0};

    return memcmp(t->procname, zero_procname, MAX_PROCESS_NAME_LENGTH) == 0 &&
           memcmp(t->trace, zero_trace, sizeof(zero_trace)) == 0;
}

int trace_equals(const trace_t *a, const trace_t *b) {
    if (strncmp(a->procname, b->procname, MAX_PROCESS_NAME_LENGTH) != 0)
        return 0;

    for (int i = 0; i < TRACE_COMPARE_LEN; ++i) {
        if (a->trace[i].inode != b->trace[i].inode ||
            a->trace[i].pc != b->trace[i].pc) {
            return 0;
        }
    }
    return 1;
}

int update_traces(trace_t *src, trace_t *dst) {
    int updated = 0;

    for (int i = 0; i < NUM_TRACES; ++i) {
        if (is_trace_zero(&src[i])) continue;

        int duplicate = 0;
        for (int j = 0; j < NUM_TRACES; ++j) {
            if (!is_trace_zero(&dst[j]) && trace_equals(&src[i], &dst[j])) {
                duplicate = 1;
                break;
            }
        }

        if (duplicate) {
            memset(&src[i], 0, sizeof(trace_t));
            continue;
        }

        for (int j = 0; j < NUM_TRACES; ++j) {
            if (is_trace_zero(&dst[j])) {
                memcpy(&dst[j], &src[i], sizeof(trace_t));
                updated = 1;
                break;
            }
        }
    }

    return updated;
}

void create_dir_if_missing(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            perror("mkdir (trace_fn dir)");
            exit(EXIT_FAILURE);
        }
    }
}

void dump_traces_to_file(trace_t *traces, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen (trace dump)");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < NUM_TRACES; ++i) {
        if (is_trace_zero(&traces[i])) continue;

        fprintf(f, "=== Trace %d ===\n", i);
        fprintf(f, "Process: %s\n", traces[i].procname);

        for (int j = 0; j < TRACE_LEN; ++j) {
            trace_element_t *el = &traces[i].trace[j];
            if (el->inode == 0 && el->pc == 0) break;
            fprintf(f, "  [%02d] inode: %lu, pc: 0x%08lx, module: %s\n",
                    j, el->inode, el->pc, el->modname);
        }
        fprintf(f, "\n");
    }

    fclose(f);
}

void update_and_persist_blacklist(trace_t *src, trace_t *blacklist_crash_traces, const char *out_dir, int debug) {
    int updated = update_traces(src, blacklist_crash_traces);
    if (!updated) return;

    char path[512];
    snprintf(path, sizeof(path), "%s/blacklist_crash_traces", out_dir);

    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen (blacklist_crash_traces)");
        exit(EXIT_FAILURE);
    }

    if (fwrite(blacklist_crash_traces, sizeof(trace_t), NUM_TRACES, f) != NUM_TRACES) {
        perror("fwrite (blacklist_crash_traces)");
        fclose(f);
        exit(EXIT_FAILURE);
    }

    fclose(f);


    if (debug) {
        FILE *logf = fopen("debug/blacklist_crash_traces.log", "w");
        if (!logf) {
            perror("fopen (debug/blacklist_crash_traces.log)");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < NUM_TRACES; ++i) {
            if (is_trace_zero(&blacklist_crash_traces[i])) continue;

            fprintf(logf, "=== Trace %d ===\n", i);
            fprintf(logf, "Process: %s\n", blacklist_crash_traces[i].procname);

            for (int j = 0; j < TRACE_LEN; ++j) {
                trace_element_t *el = &blacklist_crash_traces[i].trace[j];
                if (el->inode == 0 && el->pc == 0) break;

                fprintf(logf, "  [%02d] inode: %lu, pc: 0x%08x, module: %s\n",
                        j, (unsigned long)el->inode, el->pc, el->modname);
            }

            fprintf(logf, "\n");
        }

        fclose(logf);
    }
}

int update_and_log_traces(trace_t *src, trace_t *dst, const char *log_file) {
    int changed = update_traces(src, dst);

    if (!changed) return 0;

    char *log_path = strdup(log_file);
    char *dir = dirname(log_path);
    create_dir_if_missing(dir);
    free(log_path);

    dump_traces_to_file(src, log_file);
    return 1;
}

int check_and_filter_traces(trace_t *src, trace_t *blacklist, int debug) {
    trace_t empty_buf[NUM_TRACES] = {0};

    if (memcmp(src, empty_buf, sizeof(trace_t) * NUM_TRACES) == 0) {
        if (debug) {
            FILE *f = fopen("debug/fuzzing.log", "a+");
            if (f) {
                fprintf(f, "\tcheck_and_filter_traces(): src is empty!\n");
                fclose(f);
            }
        }
        return 0;
    }

    char log_buf[32768] = {0};
    int log_offset = 0;

    if (debug) {
        log_offset += snprintf(log_buf + log_offset, sizeof(log_buf) - log_offset,
                               "\tcheck_and_filter_traces():\n");
    }

    for (int i = 0; i < NUM_TRACES; i++) {
        if (is_trace_zero(&src[i])) {
            if (debug && log_offset < sizeof(log_buf)) {
                log_offset += snprintf(log_buf + log_offset, sizeof(log_buf) - log_offset,
                                       "\t\tTrace[%d]: Empty\n", i);
            }
            continue;
        }

        int dropped = 0;
        char trace_info[2048] = {0};
        int trace_offset = 0;

        const char *procname = src[i].procname ? src[i].procname : "<null>";
        trace_offset += snprintf(trace_info + trace_offset, sizeof(trace_info) - trace_offset,
                                 "\t\tTrace[%d]: procname='%s'", i, procname);

        for (int j = 0; j < TRACE_LEN && src[i].trace[j].inode != 0; ++j) {
            const char *modname = src[i].trace[j].modname ? src[i].trace[j].modname : "<null>";
            trace_offset += snprintf(trace_info + trace_offset,
                                     sizeof(trace_info) - trace_offset,
                                     " (mod_name='%s', pc=0x%lx)",
                                     modname,
                                     src[i].trace[j].pc);

            if (trace_offset >= (int)sizeof(trace_info) - 128)
                break;
        }

        for (int j = 0; j < NUM_TRACES; j++) {
            if (!is_trace_zero(&blacklist[j]) &&
                trace_equals(&src[i], &blacklist[j])) {
                memset(&src[i], 0, sizeof(trace_t));
                dropped = 1;
                break;
            }
        }

        if (debug && log_offset < sizeof(log_buf)) {
            log_offset += snprintf(log_buf + log_offset,
                                   sizeof(log_buf) - log_offset,
                                   "%s - %s\n",
                                   trace_info[0] ? trace_info : "<trace_info missing>",
                                   dropped ? "Dropped" : "Kept");
        }
    }

    if (debug) {
        FILE *f = fopen("debug/fuzzing.log", "a");
        if (f) {
            size_t to_write = log_offset < sizeof(log_buf) ? log_offset : sizeof(log_buf);
            fwrite(log_buf, 1, to_write, f);
            fclose(f);
        } else {
            perror("fopen (debug/fuzzing.log)");
        }
    }

    return memcmp(src, empty_buf, sizeof(trace_t) * NUM_TRACES) != 0;
}

int save_traces_binary(trace_t *traces, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t written = fwrite(traces, sizeof(trace_t), NUM_TRACES, f);
    fclose(f);
    return written == NUM_TRACES ? 0 : -1;
}

int load_traces_binary(trace_t *traces, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t read = fread(traces, sizeof(trace_t), NUM_TRACES, f);
    fclose(f);
    return read == NUM_TRACES ? 0 : -1;
}

void clear_traces(trace_t *traces) {
    memset(traces, 0, sizeof(trace_t) * NUM_TRACES);
}