/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */
#include "qemu/osdep.h"
#include "cpu.h"


#include <sys/shm.h>
#include "extern_vars.h"
#include "shared/DECAF_fileio.h" //zyw
#include <stdio.h>

//FILE *file_log=NULL;
//int iteration_times = 0;

static int after_checkpoint = 0;

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#ifdef TARGET_MIPS
#define AFL_QEMU_CPU_SNIPPET2 do { \
    if (fuzz) \
      afl_maybe_log(env->active_tc.PC, pgd, pid); \
  } while (0)
#endif

#ifdef TARGET_ARM
#define AFL_QEMU_CPU_SNIPPET2 do { \
    if (fuzz) \
      afl_maybe_log(env->regs[15], pgd, pid); \
  } while (0)
#endif
  
/*
#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(itb->pc == afl_entry_point) { \
      afl_setup(); \
      afl_forkserver(cpu); \
    } \
    afl_maybe_log(itb->pc); \
  } while (0)
*/

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* Exported variables populated by the code patched into elfload.c: */

target_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAX_MAP_SIZE;

/* Function declarations. */

//static void afl_setup(void);
//static void afl_forkserver(CPUState*);
static inline void afl_maybe_log(target_ulong, target_ulong, target_ulong);
static inline void afl_maybe_log_stateful_analysis(target_ulong);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

//static void afl_setup(void) {
void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR), *id_str_eval = getenv(SHM_ENV_VAR_EVAL),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAX_MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (id_str_eval) {

    shm_id = atoi(id_str_eval);
    afl_area_ptr_eval = shmat(shm_id, NULL, 0);

    if (afl_area_ptr_eval == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr_eval[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (target_ulong)-1;

  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

}


void normal_forkserver(CPUArchState *env){
#ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

//zyw
    // afl_user_fork = 1;
//
    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      return;

    }

    /* Parent. */
    afl_user_fork = 0;

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);

  }

}

void create_nested_directories(const char *path) {
    char temp[256];
    char *p = NULL;
    size_t len;

    snprintf(temp, sizeof(temp), "%s", path);
    len = strlen(temp);
    
    if (temp[len - 1] == '/') {
        temp[len - 1] = '\0';
    }

    for (p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';

            if (mkdir(temp, 0777) == -1 && errno != EEXIST) {
                perror("mkdir");
                exit(EXIT_FAILURE);
            }
            *p = '/';
        }
    }

    if (mkdir(temp, 0777) == -1 && errno != EEXIST) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }
}

void pre_analysis_forkserver(CPUArchState *env){

//zyw
#ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  int i;
  for (i = 0; ; i++) {
    pid_t child_pid;
    int status;

    while (1) {
        if (!access("proto", F_OK) && !access("pcap_filename", F_OK)) {
            break;
        }
        usleep(100000);
    }

    if (access(TAINT_DIR, F_OK) == 0) {
      remove_directory(TAINT_DIR);
    }

    FILE *fp = fopen("proto","r");
    if (fp == NULL) {
      printf("Failed to open file.\n");
      exit(1);
    }
    else {
      fscanf(fp, "%19s", &proto);
      fclose(fp);
    }

    fp = fopen("pcap_filename","r");
    if (fp == NULL) {
      printf("Failed to open file.\n");
      exit(1);
    }
    else {
      fscanf(fp, "%99s", &pcap_filename);
      fclose(fp);
    }

    signal(SIGINT, SIG_DFL);

    afl_user_fork = 1;

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {
      sink_id = 0;

      char dir[MAX_PATH_LENGTH-15];
      snprintf(dir, sizeof(dir), "%s/%s/%s/", TAINT_DIR, proto, pcap_filename);        
      create_nested_directories(dir);
      snprintf(taint_json_path, sizeof(taint_json_path), "%s/taint_mem.log", dir);

      taint_log_init(taint_json_path);

      FILE *fp = fopen("child_pid","w");
      fprintf(fp, "%d", getpid());
      fclose(fp);


      return;
    }
    /* Parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);

  }

  exit(0);
}

/* Fork server logic, invoked once we hit _start. */
void afl_forkserver(CPUArchState *env, uint8_t checkpoint){

//zyw
#ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif

  static unsigned char tmp[4];

  if (!afl_area_ptr || !afl_area_ptr_eval) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (!checkpoint && write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

#ifdef TARGET_MIPS
  afl_end_code = 0x7fffffff;
#elif defined(TARGET_ARM)
  afl_end_code = 0xbfffffff;
#endif

  while (1) {
    pid_t child_pid;
    int status, t_fd[2];
    
    /* Whoops, parent dead? */

    if (debug_fuzz) {
      FILE *fp = fopen("debug/fuzzing.log","a+");
      fprintf(fp, "afl_forkserver (pid %d): BEFORE 'read(FORKSRV_FD, tmp, 4) != 4'\n", getpid());
      fclose(fp);
    }

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    if (debug_fuzz) {
      FILE *fp = fopen("debug/fuzzing.log","a+");
      fprintf(fp, "afl_forkserver (pid %d): AFTER 'read(FORKSRV_FD, tmp, 4) != 4'\n", getpid());
      fclose(fp);
    }

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    afl_user_fork = 1;
    print_loop_count++;

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {
      init_thread_pool_after_fork();
      sink_id = 0;

      gettimeofday(&loop_begin, NULL);
  
      afl_fork_child = 1;

      printf("new child:%d\n",getpid());

      if (checkpoint) {
        checkpoint_afl_user_fork = 1;
        exit_write = 1;
      }

      return;
      

    }
    /* Parent. */

    if(print_loop_count == print_loop_times)
    {
      print_loop_count = 0;
    }
    afl_user_fork = 0;

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    if (debug_fuzz) {
      FILE *fp = fopen("debug/fuzzing.log","a+");
      fprintf(fp, "afl_forkserver (pid %d): BEFORE 'waitpid(child_pid, &status, 0) < 0'\n", getpid());
      fclose(fp);
    }

    if (waitpid(child_pid, &status, 0) < 0) exit(6);

    if (debug_fuzz) {
      FILE *fp = fopen("debug/fuzzing.log","a+");
      fprintf(fp, "afl_forkserver (pid %d): AFTER 'waitpid(child_pid, &status, 0) < 0'\n", getpid());
      fclose(fp);
    }

    if (debug_fuzz) {
      FILE *fp = fopen("debug/fuzzing.log","a+");
      fprintf(fp, "afl_forkserver (pid %d): BEFORE 'write(FORKSRV_FD + 1, &status, 4) != 4'\n", getpid());
      fclose(fp);
    }

    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

    if (debug_fuzz) {
      FILE *fp = fopen("debug/fuzzing.log","a+");
      fprintf(fp, "afl_forkserver (pid %d): AFTER 'write(FORKSRV_FD + 1, &status, 4) != 4'\n", getpid());
      fclose(fp);
    }
  }
}


/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log_stateful_analysis(target_ulong cur_loc) {

  static __thread target_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */
  if (cur_loc > afl_end_code || cur_loc < afl_start_code)
    return;
  /*
  if (file_log!=NULL)
  {
    fprintf(file_log, "pc:%x\n", cur_loc);
  }
  */
  
  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAX_MAP_SIZE - 1;
  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  prev_loc = cur_loc >> 1;

}

/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(target_ulong cur_loc, target_ulong pgd, target_ulong pid) {
  static target_ulong prev_loc;
  static target_ulong prev_pgd;
  static target_ulong prev_pid;
  static target_ulong prev_loc_tmp;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */
  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;
  /*
  if (file_log!=NULL)
  {
    fprintf(file_log, "pc:%x\n", cur_loc);
  }
  */
  
  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  int cur_loc_tmp  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc_tmp &= MAX_MAP_SIZE - 1;
  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc_tmp >= afl_inst_rms) return;

  afl_area_ptr[cur_loc_tmp ^ prev_loc_tmp]++;
  prev_loc_tmp = cur_loc_tmp >> 1;
  prev_loc = cur_loc;
  prev_pgd = pgd;
  prev_pid = pid;

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);

    if(!tb) {
      mmap_lock();
      tb_lock();
      tb_gen_code(-1, cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

  }

  close(fd);

}


//zyw add
#ifdef TARGET_MIPS
r4k_tlb_t before_checkpoint_saved_tlb[MIPS_TLB_MAX];
r4k_tlb_t after_checkpoint_saved_tlb[MIPS_TLB_MAX];

void store_tlb(CPUMIPSState * env)
{
  if (after_checkpoint) {
    for (int i = 0; i < MIPS_TLB_MAX; i++)
    {
      after_checkpoint_saved_tlb[i] = env->tlb->mmu.r4k.tlb[i];
    }
  }
  else {
    for (int i = 0; i < MIPS_TLB_MAX; i++)
    {
      before_checkpoint_saved_tlb[i] = env->tlb->mmu.r4k.tlb[i];
    }    
  }
}

void reload_tlb(CPUMIPSState * env, int restore_checkpoint)
{
  if (restore_checkpoint) {
    for (int i = 0; i < MIPS_TLB_MAX; i++)
    {
      env->tlb->mmu.r4k.tlb[i] = after_checkpoint_saved_tlb[i];
    }
  }
  else {
    for (int i = 0; i < MIPS_TLB_MAX; i++)
    {
      env->tlb->mmu.r4k.tlb[i] = before_checkpoint_saved_tlb[i];
    }    
  }
}
#endif

typedef struct 
{
	int ind;
	target_ulong addr_code;
  target_ulong addr_read;
  target_ulong addr_write;
  uintptr_t addend;
  struct TLB_BACKUP * next;
} TLB_BACKUP;

TLB_BACKUP *before_checkpoint_tlb_backup_head = NULL, *after_checkpoint_tlb_backup_head = NULL;

void record_tlb(target_ulong ind, target_ulong addr_code, target_ulong addr_read, target_ulong addr_write, uintptr_t addend)
{
	TLB_BACKUP * tlb_backup = (TLB_BACKUP *)malloc(sizeof(TLB_BACKUP));
	tlb_backup -> ind =ind;
	tlb_backup -> addr_code =addr_code;
	tlb_backup -> addr_read =addr_read;
	tlb_backup -> addr_write =addr_write;
	tlb_backup -> addend =addend;

  if (after_checkpoint) {
    if(after_checkpoint_tlb_backup_head == NULL)
    {
      after_checkpoint_tlb_backup_head = tlb_backup;
      tlb_backup -> next =NULL;
    }
    else
    {
      TLB_BACKUP * tmp = after_checkpoint_tlb_backup_head;
      after_checkpoint_tlb_backup_head = tlb_backup;
      tlb_backup -> next = tmp;
    }
  }
  else {
    if(before_checkpoint_tlb_backup_head == NULL)
    {
      before_checkpoint_tlb_backup_head = tlb_backup;
      tlb_backup -> next =NULL;
    }
    else
    {
      TLB_BACKUP * tmp = before_checkpoint_tlb_backup_head;
      before_checkpoint_tlb_backup_head = tlb_backup;
      tlb_backup -> next = tmp;
    }
  }
}

bool find_tlb_backup(target_ulong ind)
{
  if (after_checkpoint) {
    for(TLB_BACKUP * curr = after_checkpoint_tlb_backup_head; curr!=NULL; curr = curr->next)
    {
      target_ulong tmp_ind = curr->ind;
      if(tmp_ind == ind)
      {
        return true;
      }
    }
    return false;
  }
  else {
    for(TLB_BACKUP * curr = before_checkpoint_tlb_backup_head; curr!=NULL; curr = curr->next)
    {
      target_ulong tmp_ind = curr->ind;
      if(tmp_ind == ind)
      {
        return true;
      }
    }
    return false;
  }
}

void recover_tlb(CPUArchState *env, int restore_checkpoint)
{
  if (restore_checkpoint) {
    for (TLB_BACKUP * curr = after_checkpoint_tlb_backup_head; curr != NULL; curr = curr->next)
    {
      target_ulong tmp_ind = curr->ind;
#ifdef TARGET_MIPS
      env->tlb_table[2][tmp_ind].addr_code =  curr->addr_code;
      env->tlb_table[2][tmp_ind].addr_read =  curr->addr_read;
      env->tlb_table[2][tmp_ind].addr_write =  curr->addr_write;
      env->tlb_table[2][tmp_ind].addend =  curr->addend;
#elif defined(TARGET_ARM)
      env->tlb_table[0][tmp_ind].addr_code =  curr->addr_code;
      env->tlb_table[0][tmp_ind].addr_read =  curr->addr_read;
      env->tlb_table[0][tmp_ind].addr_write =  curr->addr_write;
      env->tlb_table[0][tmp_ind].addend =  curr->addend;
#endif
    }
  }
  else {
    for (TLB_BACKUP * curr = before_checkpoint_tlb_backup_head; curr != NULL; curr = curr->next)
    {
      target_ulong tmp_ind = curr->ind;
#ifdef TARGET_MIPS
      env->tlb_table[2][tmp_ind].addr_code =  curr->addr_code;
      env->tlb_table[2][tmp_ind].addr_read =  curr->addr_read;
      env->tlb_table[2][tmp_ind].addr_write =  curr->addr_write;
      env->tlb_table[2][tmp_ind].addend =  curr->addend;
#elif defined(TARGET_ARM)
      env->tlb_table[0][tmp_ind].addr_code =  curr->addr_code;
      env->tlb_table[0][tmp_ind].addr_read =  curr->addr_read;
      env->tlb_table[0][tmp_ind].addr_write =  curr->addr_write;
      env->tlb_table[0][tmp_ind].addend =  curr->addend;
#endif
    }    
  }
}

CPUArchState before_checkpoint_backup_cpu, after_checkpoint_backup_cpu;
CPUState before_checkpoint_backup_cpu0, after_checkpoint_backup_cpu0;
CPUTLBEntry before_checkpoint_backup_tlb_table[4][256], after_checkpoint_backup_tlb_table[4][256];

#ifdef TARGET_MIPS
void storeCPUState(CPUState* cpu, CPUArchState *env)
{
  if (after_checkpoint) {
    for (int i = 0; i < 32; i++)
    {
      after_checkpoint_backup_cpu.active_tc.gpr[i] = env->active_tc.gpr[i];
    }
    after_checkpoint_backup_cpu.active_tc.PC = env->active_tc.PC;
    after_checkpoint_backup_cpu.CP0_EPC = env->CP0_EPC;
    after_checkpoint_backup_cpu.CP0_Status = env->CP0_Status;
    after_checkpoint_backup_cpu.CP0_Cause = env->CP0_Cause;
    after_checkpoint_backup_cpu0.exception_index = cpu->exception_index;
    after_checkpoint_backup_cpu0.interrupt_request = cpu->interrupt_request;

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        after_checkpoint_backup_tlb_table[i][j].addr_code = env->tlb_table[i][j].addr_code;
        after_checkpoint_backup_tlb_table[i][j].addr_write = env->tlb_table[i][j].addr_write;
        after_checkpoint_backup_tlb_table[i][j].addr_read = env->tlb_table[i][j].addr_read;
        after_checkpoint_backup_tlb_table[i][j].addend = env->tlb_table[i][j].addend;
      }
    }
  }
  else {
    for (int i = 0; i < 32; i++)
    {
      before_checkpoint_backup_cpu.active_tc.gpr[i] = env->active_tc.gpr[i];
    }
    before_checkpoint_backup_cpu.active_tc.PC = env->active_tc.PC;
    before_checkpoint_backup_cpu.CP0_EPC = env->CP0_EPC;
    before_checkpoint_backup_cpu.CP0_Status = env->CP0_Status;
    before_checkpoint_backup_cpu.CP0_Cause = env->CP0_Cause;
    before_checkpoint_backup_cpu0.exception_index = cpu->exception_index;
    before_checkpoint_backup_cpu0.interrupt_request = cpu->interrupt_request;

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        before_checkpoint_backup_tlb_table[i][j].addr_code = env->tlb_table[i][j].addr_code;
        before_checkpoint_backup_tlb_table[i][j].addr_write = env->tlb_table[i][j].addr_write;
        before_checkpoint_backup_tlb_table[i][j].addr_read = env->tlb_table[i][j].addr_read;
        before_checkpoint_backup_tlb_table[i][j].addend = env->tlb_table[i][j].addend;
      }
    }
  }
}

void loadCPUState(CPUState *cpu, CPUArchState *env, int restore_checkpoint)
{
  if (restore_checkpoint) {
    for (int i = 0; i < 32; i++)
    {
      env->active_tc.gpr[i] = after_checkpoint_backup_cpu.active_tc.gpr[i];
    }
    env->active_tc.PC = after_checkpoint_backup_cpu.active_tc.PC;
    env->CP0_EPC = after_checkpoint_backup_cpu.CP0_EPC;
    env->CP0_Status = after_checkpoint_backup_cpu.CP0_Status;
    env->CP0_Cause = after_checkpoint_backup_cpu.CP0_Cause;
    cpu->exception_index = after_checkpoint_backup_cpu0.exception_index;
    cpu->interrupt_request = after_checkpoint_backup_cpu0.interrupt_request;

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        env->tlb_table[i][j].addr_code = after_checkpoint_backup_tlb_table[i][j].addr_code;
        env->tlb_table[i][j].addr_write = after_checkpoint_backup_tlb_table[i][j].addr_write;
        env->tlb_table[i][j].addr_read = after_checkpoint_backup_tlb_table[i][j].addr_read;
        env->tlb_table[i][j].addend = after_checkpoint_backup_tlb_table[i][j].addend;
      }
    }
  }
  else {
    for (int i = 0; i < 32; i++)
    {
      env->active_tc.gpr[i] = before_checkpoint_backup_cpu.active_tc.gpr[i];
    }
    env->active_tc.PC = before_checkpoint_backup_cpu.active_tc.PC;
    env->CP0_EPC = before_checkpoint_backup_cpu.CP0_EPC;
    env->CP0_Status = before_checkpoint_backup_cpu.CP0_Status;
    env->CP0_Cause = before_checkpoint_backup_cpu.CP0_Cause;
    cpu->exception_index = before_checkpoint_backup_cpu0.exception_index;
    cpu->interrupt_request = before_checkpoint_backup_cpu0.interrupt_request;

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        env->tlb_table[i][j].addr_code = before_checkpoint_backup_tlb_table[i][j].addr_code;
        env->tlb_table[i][j].addr_write = before_checkpoint_backup_tlb_table[i][j].addr_write;
        env->tlb_table[i][j].addr_read = before_checkpoint_backup_tlb_table[i][j].addr_read;
        env->tlb_table[i][j].addend = before_checkpoint_backup_tlb_table[i][j].addend;
      }
    }
  }
}

#elif defined(TARGET_ARM)
void storeCPUState(CPUArchState *env)
{
  if (after_checkpoint) {
    for (int i = 0; i < 16; i++)
    {
      after_checkpoint_backup_cpu.regs[i] =  env->regs[i];
    }

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        after_checkpoint_backup_tlb_table[i][j].addr_code = env->tlb_table[i][j].addr_code;
        after_checkpoint_backup_tlb_table[i][j].addr_write = env->tlb_table[i][j].addr_write;
        after_checkpoint_backup_tlb_table[i][j].addr_read = env->tlb_table[i][j].addr_read;
        after_checkpoint_backup_tlb_table[i][j].addend = env->tlb_table[i][j].addend;
      }
    }
  }
  else {
    for (int i = 0; i < 16; i++)
    {
      before_checkpoint_backup_cpu.regs[i] =  env->regs[i];
    }

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        before_checkpoint_backup_tlb_table[i][j].addr_code = env->tlb_table[i][j].addr_code;
        before_checkpoint_backup_tlb_table[i][j].addr_write = env->tlb_table[i][j].addr_write;
        before_checkpoint_backup_tlb_table[i][j].addr_read = env->tlb_table[i][j].addr_read;
        before_checkpoint_backup_tlb_table[i][j].addend = env->tlb_table[i][j].addend;
      }
    }    
  }
}

void loadCPUState(CPUArchState *env, int restore_checkpoint)
{
  if (restore_checkpoint) {
    for (int i = 0; i < 16; i++)
    {
      env->regs[i] = after_checkpoint_backup_cpu.regs[i];
    }

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        env->tlb_table[i][j].addr_code = after_checkpoint_backup_tlb_table[i][j].addr_code;
        env->tlb_table[i][j].addr_write = after_checkpoint_backup_tlb_table[i][j].addr_write;
        env->tlb_table[i][j].addr_read = after_checkpoint_backup_tlb_table[i][j].addr_read;
        env->tlb_table[i][j].addend = after_checkpoint_backup_tlb_table[i][j].addend;
      }
    }
  }
  else {
    for (int i = 0; i < 16; i++)
    {
      env->regs[i] = before_checkpoint_backup_cpu.regs[i];
    }

    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 256; j++)
      {
        env->tlb_table[i][j].addr_code = before_checkpoint_backup_tlb_table[i][j].addr_code;
        env->tlb_table[i][j].addr_write = before_checkpoint_backup_tlb_table[i][j].addr_write;
        env->tlb_table[i][j].addr_read = before_checkpoint_backup_tlb_table[i][j].addr_read;
        env->tlb_table[i][j].addend = before_checkpoint_backup_tlb_table[i][j].addend;
      }
    }
  }
}
#endif

static ssize_t uninterrupted_read(int fd, void *buf, size_t cnt)
{
  ssize_t n;
  while((n = read(fd, buf, cnt)) == -1 && errno == EINTR)
    continue;
  return n;
}

static target_ulong startTrace(CPUArchState *env, target_ulong start, target_ulong end)
{
  afl_start_code = start;
  afl_end_code   = end;
  return 0;
}

static target_ulong stopTrace()
{
  afl_start_code = 0;
  afl_end_code   = 0;
  return 0;
}

static target_ulong doneWork(target_ulong val)
{
#ifdef LETSNOT 
  if(aflGotLog)
      exit(64 | val);
#endif
  exit(val); /* exit forkserver child */
}

target_ulong afl_noforkserver(CPUArchState *env, int status, int checkpoint)
{

  #ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif

  static unsigned char tmp[4];
  pid_t child_pid;

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: BEFORE 'if (!checkpoint && write(FORKSRV_FD + 1, tmp, 4) != 4) return'\n");
    fclose(fp);
  }

  if (!checkpoint && write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: AFTER 'if (!checkpoint && write(FORKSRV_FD + 1, tmp, 4) != 4) return'\n");
    fclose(fp);
  }

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: BEFORE 'read(FORKSRV_FD, tmp, 4) != 4'\n");
    fclose(fp);
  }

  if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: AFTER 'read(FORKSRV_FD, tmp, 4) != 4'\n");
    fclose(fp);
  }

  child_pid = getpid() + 1;

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: BEFORE 'write(FORKSRV_FD + 1, &child_pid, 4) != 4'\n");
    fclose(fp);
  }

  if (checkpoint) {
    checkpoint_afl_user_fork = 1;
  }

  if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
    perror("afl_noforkserver: Failed to write new forkserver PID");
    exit(5);
  }

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: AFTER 'write(FORKSRV_FD + 1, &child_pid, 4) != 4'\n");
    fclose(fp);
  }

#ifdef TARGET_MIPS
  storeCPUState(cpu, env);
  store_tlb(env);
#endif

  afl_user_fork = 1;

  return 0;
}

int delta = 0;
int feed_times = 0;
target_ulong afl_noforkserver_restart(CPUArchState *env, int status)
{

#ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif

  static unsigned char tmp[4];
  pid_t child_pid;

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_forkserver (pid %d): BEFORE 'write(FORKSRV_FD + 1, &status, 4) != 4'\n", getpid());
    fclose(fp);
  }

  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_forkserver (pid %d): AFTER 'write(FORKSRV_FD + 1, &status, 4) != 4'\n", getpid());
    fclose(fp);
  }

  /* Whoops, parent dead? */

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_forkserver (pid %d): BEFORE 'read(FORKSRV_FD, tmp, 4) != 4'\n", getpid());
    fclose(fp);
  }

  if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_forkserver (pid %d): AFTER 'read(FORKSRV_FD, tmp, 4) != 4'\n", getpid());
    fclose(fp);
  }

  child_pid = getpid() + delta;
  delta++;

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: BEFORE 'write(FORKSRV_FD + 1, &child_pid, 4) != 4'\n");
    fclose(fp);
  }

  if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
    perror("afl_noforkserver: Failed to write new forkserver PID");
    exit(5);
  }

  if (debug_fuzz) {
    FILE *fp = fopen("debug/fuzzing.log","a+");
    fprintf(fp, "afl_noforkserver: AFTER 'write(FORKSRV_FD + 1, &child_pid, 4) != 4'\n");
    fclose(fp);
  }

#ifdef TARGET_MIPS
  loadCPUState(cpu, env, 0);
  reload_tlb(env, 0);
  // restore_page(1, 1);
#endif

  return 0;
}
