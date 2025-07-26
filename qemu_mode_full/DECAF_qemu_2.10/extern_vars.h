#ifndef EXTERN_VARS_H
#define EXTERN_VARS_H

#include <pthread.h>
#include <stdint.h>
#include "memtrace_shm.h"
#include "../../aflnet/config2.h"

extern CircularBuffer *circular_buffer;

#define TAINT_DIR_2 "taint_2"
#define TAINT_DIR "taint"
#define MAX_RETRIES 1000
#define TCG_MAX_TEMPS 512

extern char program_analysis[256];

typedef struct {
    char * aflFile;
    int buf_read_index;
} SharedVariables;

enum EXEC_MODE {
    RUN,
    PREANALYSIS,
    AFLNET,
    TRIFORCE
};

enum COVERAGE_TRACING {
    EDGE,
    BLOCK,
    TAINT_EDGE,
    TAINT_BLOCK
};

extern SharedVariables *extern_struct;
extern int debug, debug_taint, debug_fuzz, debug_fs_trace;
extern int callstack_trace;
extern int child_tmout;
extern int fuzz;
extern unsigned int map_size;
extern enum EXEC_MODE exec_mode;
extern int target_pid;
extern int target_fd;
extern char *start_fork_flag;
extern char *child_retval;
extern char *send_next_region;
extern trace_t *cur_crashes;
extern char *checkpoint_forksrv;
extern int exit_write;
extern int checkpoint_afl_user_fork;
extern int fd_dependencies_track;
extern int include_libraries;

extern void allocate_taint_memory_page_table(void);

extern int taint_tracking_enabled;
extern int taint_nic_enabled;
extern int taint_pointers_enabled;
extern int taint_load_pointers_enabled;
extern int taint_store_pointers_enabled;

extern uint8_t global_taint_flag;
extern int op_index;
// extern int taint_pkt;
extern int flag1;
extern int taint_edge_flag;

#define EXCP12_TNT	39
#define EXCP13_TNT	40
extern int second_ccache_flag;
#define MAX_FUNCTION_NAME_LENGTH 100
#define MAX_PCAP_NAME_LENGTH 100
#define MAX_PROTO_NAME_LENGTH 20
#define MAX_PID 5000
#define MAX_PATH_LENGTH 100
extern char pcap_filename[MAX_PCAP_NAME_LENGTH];
extern char proto[MAX_PROTO_NAME_LENGTH];
extern char taint_json_path[MAX_PATH_LENGTH];
// extern uint32_t global_cov_xxhash[MAX_PID], global_cov_orig[MAX_PID], global_cov_sha1[MAX_PID], global_app_tb_pc[MAX_PID];
#include <semaphore.h>

extern int target_region;
extern int target_offset;
extern int target_len;

/* This is equivalent to afl-as.h: */

extern unsigned char *afl_area_ptr, *afl_area_ptr_eval;
extern int afl_user_fork;
extern enum COVERAGE_TRACING coverage_tracing;

extern int kernel_base;

extern int crash_analysis;
extern int crash_analysis_TRACE_LEN;
extern char *crash_analysis_target_procname;

void remove_directory(const char *path);

extern void init_thread_pool_after_fork();

#endif