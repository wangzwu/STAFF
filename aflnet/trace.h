#ifndef TRACE_H
#define TRACE_H

#include "config2.h"
#include "alloc-inl.h"

#ifdef __cplusplus
extern "C" {
#endif

int check_and_filter_traces(trace_t *src, trace_t *blacklist, int debug);
void update_and_persist_blacklist(trace_t *src, trace_t *dst, const char *out_dir, int debug);
void dump_traces_to_file_2(trace_t *traces, FILE *f);
int update_and_log_traces(trace_t *src, trace_t *dst, const char *log_file);
void clear_traces(trace_t *traces);
int load_traces_binary(trace_t *traces, const char *path);
int save_traces_binary(trace_t *traces, const char *path);

#ifdef __cplusplus
}
#endif

#endif  // TRACE_H
