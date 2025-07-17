#ifndef CONFIG2_H
#define CONFIG2_H

#define MAP_SIZE_POW2       25
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define SHARED_MEM_NAME "/START_FORK"
#define SHARED_CHILD_RETVAL "/CHILD_RETVAL"
#define BLACKLIST_CRASHES "/BLACKLIST_CRASHES"
#define CUR_CRASHES "/CUR_CRASHES"
#define SEND_NEXT_REGION "/SEND_NEXT_REGION"

/* Designated file descriptors for forkserver commands (the application will
   use FORKSRV_FD and FORKSRV_FD + 1): */

#define FORKSRV_FD          198

/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

#define MAX_MODULE_NAME_LENGTH 20
#define MAX_PROCESS_NAME_LENGTH 30
#define NUM_TRACES          20
#define TRACE_LEN           5
#define TRACE_COMPARE_LEN 5
#define MAX_SLEEP 2000000

struct AppTBPC {
   char procname[MAX_PROCESS_NAME_LENGTH];
   int tb_pc;
};

typedef struct {
   uint8_t modname[MAX_MODULE_NAME_LENGTH];
   uint64_t inode;
   uint32_t pc;
} trace_element_t;

typedef struct {
   uint8_t procname[MAX_PROCESS_NAME_LENGTH];
   trace_element_t trace[TRACE_LEN];
} trace_t;

#endif  // CONFIG2_H