/*
 *  Software MMU support
 *
 * Generate helpers used by TCG for qemu_ld/st ops and code load
 * functions.
 *
 * Included from target op helpers and exec.c.
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "zyw_config1.h"
// #include "zyw_config2.h"
#include "extern_vars.h"
#ifdef STORE_PAGE_FUNC
#include "DECAF_callback_to_QEMU.h"
#endif

#if DATA_SIZE == 8
#define SUFFIX q
#define LSUFFIX q
#define SDATA_TYPE  int64_t
#define DATA_TYPE  uint64_t
#elif DATA_SIZE == 4
#define SUFFIX l
#define LSUFFIX l
#define SDATA_TYPE  int32_t
#define DATA_TYPE  uint32_t
#elif DATA_SIZE == 2
#define SUFFIX w
#define LSUFFIX uw
#define SDATA_TYPE  int16_t
#define DATA_TYPE  uint16_t
#elif DATA_SIZE == 1
#define SUFFIX b
#define LSUFFIX ub
#define SDATA_TYPE  int8_t
#define DATA_TYPE  uint8_t
#else
#error unsupported data size
#endif


/* For the benefit of TCG generated code, we want to avoid the complication
   of ABI-specific return type promotion and always return a value extended
   to the register size of the host.  This is tcg_target_long, except in the
   case of a 32-bit host and 64-bit data, and for that we always have
   uint64_t.  Don't bother with this widened value for SOFTMMU_CODE_ACCESS.  */
#if defined(SOFTMMU_CODE_ACCESS) || DATA_SIZE == 8
# define WORD_TYPE  DATA_TYPE
# define USUFFIX    SUFFIX
#else
# define WORD_TYPE  tcg_target_ulong
# define USUFFIX    glue(u, SUFFIX)
# define SSUFFIX    glue(s, SUFFIX)
#endif

#ifdef SOFTMMU_CODE_ACCESS
#define READ_ACCESS_TYPE MMU_INST_FETCH
#define ADDR_READ addr_code
#else
#define READ_ACCESS_TYPE MMU_DATA_LOAD
#define ADDR_READ addr_read
#endif

#if DATA_SIZE == 8
# define BSWAP(X)  bswap64(X)
#elif DATA_SIZE == 4
# define BSWAP(X)  bswap32(X)
#elif DATA_SIZE == 2
# define BSWAP(X)  bswap16(X)
#else
# define BSWAP(X)  (X)
#endif

#if DATA_SIZE == 1
# define helper_le_ld_name  glue(glue(helper_ret_ld, USUFFIX), MMUSUFFIX)
# define helper_be_ld_name  helper_le_ld_name
# define helper_le_lds_name glue(glue(helper_ret_ld, SSUFFIX), MMUSUFFIX)
# define helper_be_lds_name helper_le_lds_name
# define helper_le_st_name  glue(glue(helper_ret_st, SUFFIX), MMUSUFFIX)
# define helper_be_st_name  helper_le_st_name
#else
# define helper_le_ld_name  glue(glue(helper_le_ld, USUFFIX), MMUSUFFIX)
# define helper_be_ld_name  glue(glue(helper_be_ld, USUFFIX), MMUSUFFIX)
# define helper_le_lds_name glue(glue(helper_le_ld, SSUFFIX), MMUSUFFIX)
# define helper_be_lds_name glue(glue(helper_be_ld, SSUFFIX), MMUSUFFIX)
# define helper_le_st_name  glue(glue(helper_le_st, SUFFIX), MMUSUFFIX)
# define helper_be_st_name  glue(glue(helper_be_st, SUFFIX), MMUSUFFIX)
#endif

#ifndef SOFTMMU_CODE_ACCESS
static inline DATA_TYPE glue(io_read, SUFFIX)(CPUArchState *env,
                                              size_t mmu_idx, size_t index,
                                              target_ulong addr,
                                              uintptr_t retaddr)
{
    CPUIOTLBEntry *iotlbentry = &env->iotlb[mmu_idx][index];
    return io_readx(env, iotlbentry, addr, retaddr, DATA_SIZE);
}
#endif

WORD_TYPE helper_le_ld_name(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    unsigned mmu_idx = get_mmuidx(oi);
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    unsigned a_bits = get_alignment_bits(get_memop(oi));
    uintptr_t haddr;
    DATA_TYPE res, taint1, taint2;;
    int deb = 0;

#ifdef TARGET_MIPS
    //Set the taint to zero. Then if we read from a tainted page, it will go through taint_io_read function, which later goes into taint_mem_read
    env->tempidx = 0;
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
    env->tempidx2 = 0;
#endif
#endif

    if (addr & ((1 << a_bits) - 1)) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
    }

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
         != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (!VICTIM_TLB_HIT(ADDR_READ, addr)) {
            tlb_fill(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                     mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        res = glue(io_read, SUFFIX)(env, mmu_idx, index, addr, retaddr);
        res = TGT_LE(res);
        return res;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;
        DATA_TYPE res1, res2;
        unsigned shift;
    do_unaligned_access:
        addr1 = addr & ~(DATA_SIZE - 1);
        addr2 = addr1 + DATA_SIZE;
        res1 = helper_le_ld_name(env, addr1, oi, retaddr);

#ifdef TARGET_MIPS
        //FIXME: need to doublecheck if we handle tempidx2 correctly
/* Special case for 32-bit host/guest and a 64-bit load */
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        taint1 = env->tempidx2;
        taint1 = taint1 << 32;
        taint1 |= env->tempidx;
#else
        taint1 = env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */

        res2 = helper_le_ld_name(env, addr2, oi, retaddr);

#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        taint2 = env->tempidx2;
        taint2 = taint2 << 32;
        taint2 |= env->tempidx;
#else
        taint2 = env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
        shift = (addr & (DATA_SIZE - 1)) * 8;

        res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        env->tempidx = ((taint1 >> shift) | (taint2 << ((DATA_SIZE * 8) - shift))) & 0xFFFFFFFF;
        env->tempidx2 = (((taint1 >> shift) | (taint2 << ((DATA_SIZE * 8) - shift))) >> 32) & 0xFFFFFFFF;
#else
        env->tempidx = (taint1 >> shift) | (taint2 << ((DATA_SIZE * 8) - shift));
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
#endif
        /* Little-endian combine.  */
        res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
        return res;
    }

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
#if DATA_SIZE == 1
    res = glue(glue(ld, LSUFFIX), _p)((uint8_t *)haddr);
#else
    res = glue(glue(ld, LSUFFIX), _le_p)((uint8_t *)haddr);
#endif

#ifdef TARGET_MIPS
    if (debug_taint || debug) {
        if (
            (
                ((res) & 0xff) == 't' || ((res) & 0xff) == 'e' || ((res) & 0xff) == 'E' || ((res) & 0xff) == 'P' || ((res) & 0xff) == 'T' ||
                ((res >> 8) & 0xff) == 't' || ((res >> 8) & 0xff) == 'e' || ((res >> 8) & 0xff) == 'E' || ((res >> 8) & 0xff) == 'P' || ((res >> 8) & 0xff) == 'T' ||
                ((res >> 16) & 0xff) == 't' || ((res >> 16) & 0xff) == 'e' || ((res >> 16) & 0xff) == 'E' || ((res >> 16) & 0xff) == 'P' || ((res >> 16) & 0xff) == 'T' ||
                ((res >> 24) & 0xff) == 't' || ((res >> 24) & 0xff) == 'e' || ((res >> 24) & 0xff) == 'E' || ((res >> 24) & 0xff) == 'P' || ((res >> 24) & 0xff) == 'T'
            )) {

            deb = 1;
        }
    }

    glue(glue(__taint_ld, SUFFIX), _raw)(deb, (unsigned long)(haddr),addr, 0);

    if (debug_taint) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;

        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);

        uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
        if (pgd && !status && guest_pc == 0x802f7b88 ||
            (
                ((res) & 0xff) == 't' || ((res) & 0xff) == 'e' || ((res) & 0xff) == 'E' || ((res) & 0xff) == 'P' || ((res) & 0xff) == 'T' ||
                ((res >> 8) & 0xff) == 't' || ((res >> 8) & 0xff) == 'e' || ((res >> 8) & 0xff) == 'E' || ((res >> 8) & 0xff) == 'P' || ((res >> 8) & 0xff) == 'T' ||
                ((res >> 16) & 0xff) == 't' || ((res >> 16) & 0xff) == 'e' || ((res >> 16) & 0xff) == 'E' || ((res >> 16) & 0xff) == 'P' || ((res >> 16) & 0xff) == 'T' ||
                ((res >> 24) & 0xff) == 't' || ((res >> 24) & 0xff) == 'e' || ((res >> 24) & 0xff) == 'E' || ((res >> 24) & 0xff) == 'P' || ((res >> 24) & 0xff) == 'T'
            )) {
            // uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
            FILE *fp = fopen("debug/softmmu_template.log","a+");
            fprintf(fp, "helper_le_ld_name: %c %c %c %c (0x%lx) 0x%lx %s 0x%lx retaddr: 0x%lx 0x%lx (0x%lx)\n",  
                (res) & 0xff, 
                (res >> 8) & 0xff,
                (res >> 16) & 0xff, 
                (res >> 24) & 0xff, res, addr, procname, qemu_ram_addr_from_host(haddr), retaddr, env->tempidx, guest_pc);
            fclose(fp);
        }
    }

    if (taint_tracking_enabled && env->tempidx) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;
        target_ulong pc = env->active_tc.PC;

        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);

        if (pgd && !status) {
            if (!fuzz) {
                uintptr_t guest_pc = 0;

                if (taint_tracking_enabled == 3)
                    guest_pc = _tb_find_pc(cpu, retaddr);

                if ((env->tempidx) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr), 0, (res) & 0xFF);
                
                if ((env->tempidx >> 8) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+1, 0, (res >> 8) & 0xFF);
                
                if ((env->tempidx >> 16) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+2, 0, (res >> 16) & 0xFF);
                
                if ((env->tempidx >> 24) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+3, 0, (res >> 24) & 0xFF);
            }
            else {
                if (afl_user_fork && (coverage_tracing == TAINT_BLOCK || coverage_tracing == TAINT_EDGE) && ((include_libraries && pc < kernel_base) || (!include_libraries && pc < 0x70000000))) {
                    int adjusted_pc = 0;
                    uint64_t inode_num = 0;
                    get_pc_text_info_wrapper(pid, pc, &adjusted_pc, &inode_num);

                    if (adjusted_pc) {
                        if (coverage_tracing == TAINT_BLOCK) {
                            if (debug_fuzz) {
                                char mod_name[MAX_MODULE_NAME_LENGTH] = {0};
                                get_module_name_from_inode_wrapper(pid, inode_num, mod_name);

                                FILE *fp = fopen("debug/taint_blocks.log", "a+");
                                if (fp) {
                                    fprintf(fp, "procname %s, mod_name %s, inode 0x%lx, adjusted_pc 0x%lx: %d\n",
                                            procname, mod_name, inode_num, adjusted_pc,
                                            (adjusted_pc ^ inode_num) & (map_size - 1));
                                    fclose(fp);
                                }
                            }
                            target_ulong pair[2] = { adjusted_pc, inode_num };
                            uint32_t loc = XXH32(pair, sizeof(pair), pid) & map_size;
                            afl_area_ptr[loc]++;
                        }
                        else if (coverage_tracing == TAINT_EDGE) {
                            uint32_t val = update_cov_xxhash(pid, adjusted_pc, inode_num);
                            afl_area_ptr[val]++;
                            taint_edge_flag = 1;
                        }
                    }
                }
            }
        }  
    }

	if (!second_ccache_flag && env->tempidx){
        CPUState *cpu = ENV_GET_CPU(env);
		cpu->exception_index = EXCP12_TNT; //sina: longjmp works neater in comparison to raise_exception because the latter passes the exception to guest.
		cpu_restore_state(cpu, (unsigned long)retaddr);
		siglongjmp(cpu->jmp_env, 1);;
	}
#endif

    return res;
}

#if DATA_SIZE > 1
WORD_TYPE helper_be_ld_name(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    unsigned mmu_idx = get_mmuidx(oi);
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    unsigned a_bits = get_alignment_bits(get_memop(oi));
    uintptr_t haddr;
    DATA_TYPE res, taint1, taint2;;
    int deb = 0;

#ifdef TARGET_MIPS
    //Set the taint to zero. Then if we read from a tainted page, it will go through taint_io_read function, which later goes into taint_mem_read
    env->tempidx = 0;
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
    env->tempidx2 = 0;
#endif
#endif

    if (addr & ((1 << a_bits) - 1)) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
    }

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
         != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (!VICTIM_TLB_HIT(ADDR_READ, addr)) {
            tlb_fill(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                     mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        res = glue(io_read, SUFFIX)(env, mmu_idx, index, addr, retaddr);
        res = TGT_BE(res);
        return res;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;
        DATA_TYPE res1, res2;
        unsigned shift;
    do_unaligned_access:
        addr1 = addr & ~(DATA_SIZE - 1);
        addr2 = addr1 + DATA_SIZE;
        res1 = helper_be_ld_name(env, addr1, oi, retaddr);

#ifdef TARGET_MIPS
        //FIXME: need to doublecheck if we handle tempidx2 correctly
/* Special case for 32-bit host/guest and a 64-bit load */
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        taint1 = env->tempidx2;
        taint1 = taint1 << 32;
        taint1 |= env->tempidx;
#else
        taint1 = env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */

        res2 = helper_be_ld_name(env, addr2, oi, retaddr);

#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        taint2 = env->tempidx2;
        taint2 = taint2 << 32;
        taint2 |= env->tempidx;
#else
        taint2 = env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
        shift = (addr & (DATA_SIZE - 1)) * 8;

        res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        env->tempidx = ((taint1 << shift) | (taint2 >> ((DATA_SIZE * 8) - shift))) & 0xFFFFFFFF;
        env->tempidx2 = (((taint1 << shift) | (taint2 >> ((DATA_SIZE * 8) - shift))) >> 32) & 0xFFFFFFFF;
#else
        env->tempidx = (taint1 << shift) | (taint2 >> ((DATA_SIZE * 8) - shift));
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
#endif

        /* Big-endian combine.  */
        res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
        return res;
    }

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
    res = glue(glue(ld, LSUFFIX), _be_p)((uint8_t *)haddr);

#ifdef TARGET_MIPS
    if (debug_taint || debug) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;

        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);

        if (pgd && !status &&
            (
                ((res) & 0xff) == 't' || ((res) & 0xff) == 'e' || ((res) & 0xff) == 'E' || ((res) & 0xff) == 'P' || ((res) & 0xff) == 'T' ||
                ((res >> 8) & 0xff) == 't' || ((res >> 8) & 0xff) == 'e' || ((res >> 8) & 0xff) == 'E' || ((res >> 8) & 0xff) == 'P' || ((res >> 8) & 0xff) == 'T' ||
                ((res >> 16) & 0xff) == 't' || ((res >> 16) & 0xff) == 'e' || ((res >> 16) & 0xff) == 'E' || ((res >> 16) & 0xff) == 'P' || ((res >> 16) & 0xff) == 'T' ||
                ((res >> 24) & 0xff) == 't' || ((res >> 24) & 0xff) == 'e' || ((res >> 24) & 0xff) == 'E' || ((res >> 24) & 0xff) == 'P' || ((res >> 24) & 0xff) == 'T'
            )) {

            deb = 1;
        }
    }

    glue(glue(__taint_ld, SUFFIX), _raw)(deb, (unsigned long)(haddr),addr, 1);

    if (debug_taint) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;

        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);
        
        if (pgd && !status) {
            uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
            if (guest_pc == 0x802f7b88 ||
                (
                    ((res) & 0xff) == 't' || ((res) & 0xff) == 'e' || ((res) & 0xff) == 'E' || ((res) & 0xff) == 'P' || ((res) & 0xff) == 'T' ||
                    ((res >> 8) & 0xff) == 't' || ((res >> 8) & 0xff) == 'e' || ((res >> 8) & 0xff) == 'E' || ((res >> 8) & 0xff) == 'P' || ((res >> 8) & 0xff) == 'T' ||
                    ((res >> 16) & 0xff) == 't' || ((res >> 16) & 0xff) == 'e' || ((res >> 16) & 0xff) == 'E' || ((res >> 16) & 0xff) == 'P' || ((res >> 16) & 0xff) == 'T' ||
                    ((res >> 24) & 0xff) == 't' || ((res >> 24) & 0xff) == 'e' || ((res >> 24) & 0xff) == 'E' || ((res >> 24) & 0xff) == 'P' || ((res >> 24) & 0xff) == 'T'
                )) {
                CPUState *cpu = ENV_GET_CPU(env);
                FILE *fp = fopen("debug/softmmu_template.log","a+");
                // uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
                fprintf(fp, "helper_be_ld_name: %c %c %c %c (0x%lx) 0x%lx %s 0x%lx retaddr: 0x%lx 0x%lx (0x%lx)\n",  
                    (res) & 0xff, 
                    (res >> 8) & 0xff,
                    (res >> 16) & 0xff, 
                    (res >> 24) & 0xff, res, addr, procname, qemu_ram_addr_from_host(haddr), retaddr, env->tempidx, guest_pc);
                fclose(fp);

                deb = 1;
            }
        }
    }

    if (taint_tracking_enabled && env->tempidx) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;
        target_ulong pc = env->active_tc.PC;

        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);

        if (pgd && !status) {
            if (!fuzz) {
                uintptr_t guest_pc = 0;
                
                if (taint_tracking_enabled == 3)
                    guest_pc = _tb_find_pc(cpu, retaddr);

                if ((env->tempidx >> 24) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr), 0, (res >> 24) & 0xFF);
                
                if ((env->tempidx >> 16) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+1, 0, (res >> 16) & 0xFF);
                
                if ((env->tempidx >> 8) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+2, 0, (res >> 8) & 0xFF);
                
                if ((env->tempidx) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+3, 0, (res) & 0xFF);
            }
            else {
                if (afl_user_fork && (coverage_tracing == TAINT_BLOCK || coverage_tracing == TAINT_EDGE) && ((include_libraries && pc < kernel_base) || (!include_libraries && pc < 0x70000000))) {
                    int adjusted_pc = 0;
                    uint64_t inode_num = 0;
                    get_pc_text_info_wrapper(pid, pc, &adjusted_pc, &inode_num);

                    if (adjusted_pc) {
                        if (coverage_tracing == TAINT_BLOCK) {
                            if (debug_fuzz) {
                                char mod_name[MAX_MODULE_NAME_LENGTH] = {0};
                                get_module_name_from_inode_wrapper(pid, inode_num, mod_name);

                                FILE *fp = fopen("debug/taint_blocks.log", "a+");
                                if (fp) {
                                    fprintf(fp, "procname %s, mod_name %s, inode 0x%lx, adjusted_pc 0x%lx: %d\n",
                                            procname, mod_name, inode_num, adjusted_pc,
                                            (adjusted_pc ^ inode_num) & (map_size - 1));
                                    fclose(fp);
                                }
                            }
                            target_ulong pair[2] = { adjusted_pc, inode_num };
                            uint32_t loc = XXH32(pair, sizeof(pair), pid) & map_size;
                            afl_area_ptr[loc]++;
                        }
                        else if (coverage_tracing == TAINT_EDGE) {
                            uint32_t val = update_cov_xxhash(pid, adjusted_pc, inode_num);
                            afl_area_ptr[val]++;
                            taint_edge_flag = 1;
                        }
                    }
                }
            }
        }
    }

	if (!second_ccache_flag && env->tempidx){
        CPUState *cpu = ENV_GET_CPU(env);
		cpu->exception_index = EXCP12_TNT; //sina: longjmp works neater in comparison to raise_exception because the latter passes the exception to guest.
		cpu_restore_state(cpu, (unsigned long)retaddr);
		siglongjmp(cpu->jmp_env, 1);;
	}
#endif

    return res;
}
#endif /* DATA_SIZE > 1 */

#ifndef SOFTMMU_CODE_ACCESS

/* Provide signed versions of the load routines as well.  We can of course
   avoid this for 64-bit data, or for 32-bit data on 32-bit host.  */
#if DATA_SIZE * 8 < TCG_TARGET_REG_BITS
WORD_TYPE helper_le_lds_name(CPUArchState *env, target_ulong addr,
                             TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (SDATA_TYPE)helper_le_ld_name(env, addr, oi, retaddr);
}

# if DATA_SIZE > 1
WORD_TYPE helper_be_lds_name(CPUArchState *env, target_ulong addr,
                             TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (SDATA_TYPE)helper_be_ld_name(env, addr, oi, retaddr);
}
# endif
#endif

static inline void glue(io_write, SUFFIX)(CPUArchState *env,
                                          size_t mmu_idx, size_t index,
                                          DATA_TYPE val,
                                          target_ulong addr,
                                          uintptr_t retaddr)
{
    CPUIOTLBEntry *iotlbentry = &env->iotlb[mmu_idx][index];
    return io_writex(env, iotlbentry, val, addr, retaddr, DATA_SIZE);
}

void helper_le_st_name(CPUArchState *env, target_ulong addr, DATA_TYPE val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    unsigned mmu_idx = get_mmuidx(oi);
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    unsigned a_bits = get_alignment_bits(get_memop(oi));
    uintptr_t haddr;
    DATA_TYPE backup_taint;
    int deb = 0;

    if (addr & ((1 << a_bits) - 1)) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
        != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (!VICTIM_TLB_HIT(addr_write, addr)) {
            tlb_fill(ENV_GET_CPU(env), addr, MMU_DATA_STORE, mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        val = TGT_LE(val);
        glue(io_write, SUFFIX)(env, mmu_idx, index, val, addr, retaddr);
        return;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                     >= TARGET_PAGE_SIZE)) {
        int i, index2;
        target_ulong page2, tlb_addr2;
    do_unaligned_access:
        /* Ensure the second page is in the TLB.  Note that the first page
           is already guaranteed to be filled, and that the second page
           cannot evict the first.  */
        page2 = (addr + DATA_SIZE) & TARGET_PAGE_MASK;
        index2 = (page2 >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
        tlb_addr2 = env->tlb_table[mmu_idx][index2].addr_write;
        if (page2 != (tlb_addr2 & (TARGET_PAGE_MASK | TLB_INVALID_MASK))
            && !VICTIM_TLB_HIT(addr_write, page2)) {
            tlb_fill(ENV_GET_CPU(env), page2, MMU_DATA_STORE,
                     mmu_idx, retaddr);
        }

#ifdef TARGET_MIPS
        /* AWH - Backup the taint held in tempidx and tempidx2 and
            setup tempidx for each of these single-byte stores */
        /* Special case for 32-bit host/guest and a 64-bit load */
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        backup_taint = env->tempidx2;
        backup_taint = backup_taint << 32;
        backup_taint |= env->tempidx;
#else
        backup_taint = env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
#endif

        /* XXX: not efficient, but simple.  */
        /* This loop must go in the forward direction to avoid issues
           with self-modifying code in Windows 64-bit.  */
        for (i = 0; i < DATA_SIZE; ++i) {
            /* Little-endian extract.  */
#ifdef TARGET_MIPS
            env->tempidx = backup_taint >> (i * 8);
#endif
            uint8_t val8 = val >> (i * 8);
            glue(helper_ret_stb, MMUSUFFIX)(env, addr + i, val8,
                                            oi, retaddr);
        }
        return;
    }

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
#ifdef STORE_PAGE_FUNC
    if(DECAF_is_callback_needed(DECAF_MEM_WRITE_CB))
        helper_DECAF_invoke_mem_write_callback(addr,qemu_ram_addr_from_host(haddr),haddr, 0 ,1, 3);
#endif

#if DATA_SIZE == 1
    glue(glue(st, SUFFIX), _p)((uint8_t *)haddr, val);
#else
    glue(glue(st, SUFFIX), _le_p)((uint8_t *)haddr, val);
#endif

    if (debug_taint) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;

#ifdef TARGET_MIPS
        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);

        if (pgd && !status) {
            uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
            if (guest_pc == 0x802f7b88 ||
                (
                    ((val) & 0xff) == 't' || ((val) & 0xff) == 'e' || ((val) & 0xff) == 'E' || ((val) & 0xff) == 'P' || ((val) & 0xff) == 'T' ||
                    ((val >> 8) & 0xff) == 't' || ((val >> 8) & 0xff) == 'e' || ((val >> 8) & 0xff) == 'E' || ((val >> 8) & 0xff) == 'P' || ((val >> 8) & 0xff) == 'T' ||
                    ((val >> 16) & 0xff) == 't' || ((val >> 16) & 0xff) == 'e' || ((val >> 16) & 0xff) == 'E' || ((val >> 16) & 0xff) == 'P' || ((val >> 16) & 0xff) == 'T' ||
                    ((val >> 24) & 0xff) == 't' || ((val >> 24) & 0xff) == 'e' || ((val >> 24) & 0xff) == 'E' || ((val >> 24) & 0xff) == 'P' || ((val >> 24) & 0xff) == 'T'
                )) {
                CPUState *cpu = ENV_GET_CPU(env);
                FILE *fp = fopen("debug/softmmu_template.log","a+");
                // uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
                fprintf(fp, "helper_le_st_name: %c %c %c %c (0x%lx) 0x%lx %s 0x%lx retaddr: 0x%lx 0x%lx (0x%lx)\n",  
                    (val) & 0xff, 
                    (val >> 8) & 0xff,
                    (val >> 16) & 0xff, 
                    (val >> 24) & 0xff, val, addr, procname, qemu_ram_addr_from_host(haddr), retaddr, env->tempidx, guest_pc);
                fclose(fp);

                deb = 1;
            }
        }
#endif
    }

#ifdef TARGET_MIPS
    if (taint_tracking_enabled && env->tempidx) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;
        target_ulong pc = env->active_tc.PC;

        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);
        
        if (pgd && !status) {
            if (!fuzz) {
                uintptr_t guest_pc = 0;
                
                if (taint_tracking_enabled == 3)
                    guest_pc = _tb_find_pc(cpu, retaddr);

                if ((env->tempidx) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr), 1, (val) & 0xFF);
                
                if ((env->tempidx >> 8) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+1, 1, (val >> 8) & 0xFF);
                
                if ((env->tempidx >> 16) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+2, 1, (val >> 16) & 0xFF);
                
                if ((env->tempidx >> 24) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+3, 1, (val >> 24) & 0xFF);
            }
            else {
                if (afl_user_fork && (coverage_tracing == TAINT_BLOCK || coverage_tracing == TAINT_EDGE) && ((include_libraries && pc < kernel_base) || (!include_libraries && pc < 0x70000000))) {
                    int adjusted_pc = 0;
                    uint64_t inode_num = 0;
                    get_pc_text_info_wrapper(pid, pc, &adjusted_pc, &inode_num);

                    if (adjusted_pc) {
                        if (coverage_tracing == TAINT_BLOCK) {
                            if (debug_fuzz) {
                                char mod_name[MAX_MODULE_NAME_LENGTH] = {0};
                                get_module_name_from_inode_wrapper(pid, inode_num, mod_name);

                                FILE *fp = fopen("debug/taint_blocks.log", "a+");
                                if (fp) {
                                    fprintf(fp, "procname %s, mod_name %s, inode 0x%lx, adjusted_pc 0x%lx: %d\n",
                                            procname, mod_name, inode_num, adjusted_pc,
                                            (adjusted_pc ^ inode_num) & (map_size - 1));
                                    fclose(fp);
                                }
                            }
                            target_ulong pair[2] = { adjusted_pc, inode_num };
                            uint32_t loc = XXH32(pair, sizeof(pair), pid) & map_size;
                            afl_area_ptr[loc]++;
                        }
                        else if (coverage_tracing == TAINT_EDGE) {
                            uint32_t val = update_cov_xxhash(pid, adjusted_pc, inode_num);
                            afl_area_ptr[val]++;
                            taint_edge_flag = 1;
                        }
                    }
                }
            }
        }  
    }
#endif

// #ifdef TARGET_MIPS
//     //Since tainted pages are marked in io_mem_taint, we have a fast path:
//     //If taint is zero, and it is not accessing io_mem_taint, we don't need to update shadow memory
//     if (unlikely(env->tempidx
// #if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
//         || env->tempidx2
// #endif
//     )) {
//         //Now there is a taint, and this page is not marked in io_mem_taint.
//         //We need to taint it in the shadow memory, in which the corresponding TLB entry will also be marked as io_mem_taint
//         glue(glue(__taint_st, SUFFIX), _raw)(deb, (void *)(haddr), addr, 0);
//     }
// #else
    glue(glue(__taint_st, SUFFIX), _raw)(deb, (unsigned long)(haddr),addr, 0);
// #endif
}

#if DATA_SIZE > 1
void helper_be_st_name(CPUArchState *env, target_ulong addr, DATA_TYPE val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    unsigned mmu_idx = get_mmuidx(oi);
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    unsigned a_bits = get_alignment_bits(get_memop(oi));
    uintptr_t haddr;
    DATA_TYPE backup_taint;
    int deb = 0;

    if (addr & ((1 << a_bits) - 1)) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
        != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (!VICTIM_TLB_HIT(addr_write, addr)) {
            tlb_fill(ENV_GET_CPU(env), addr, MMU_DATA_STORE, mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        val = TGT_BE(val);
        glue(io_write, SUFFIX)(env, mmu_idx, index, val, addr, retaddr);
        return;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                     >= TARGET_PAGE_SIZE)) {
        int i, index2;
        target_ulong page2, tlb_addr2;
    do_unaligned_access:
        /* Ensure the second page is in the TLB.  Note that the first page
           is already guaranteed to be filled, and that the second page
           cannot evict the first.  */
        page2 = (addr + DATA_SIZE) & TARGET_PAGE_MASK;
        index2 = (page2 >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
        tlb_addr2 = env->tlb_table[mmu_idx][index2].addr_write;
        if (page2 != (tlb_addr2 & (TARGET_PAGE_MASK | TLB_INVALID_MASK))
            && !VICTIM_TLB_HIT(addr_write, page2)) {
            tlb_fill(ENV_GET_CPU(env), page2, MMU_DATA_STORE,
                     mmu_idx, retaddr);
        }

#ifdef TARGET_MIPS
        /* AWH - Backup the taint held in tempidx and tempidx2 and
            setup tempidx for each of these single-byte stores */
        /* Special case for 32-bit host/guest and a 64-bit load */
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
        backup_taint = env->tempidx2;
        backup_taint = backup_taint << 32;
        backup_taint |= env->tempidx;
#else
        backup_taint = env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
#endif
        /* XXX: not efficient, but simple */
        /* This loop must go in the forward direction to avoid issues
           with self-modifying code.  */
        for (i = 0; i < DATA_SIZE; ++i) {
            /* Big-endian extract.  */
#ifdef TARGET_MIPS
            env->tempidx = backup_taint >> (((DATA_SIZE - 1) * 8) - (i * 8));
#endif
            uint8_t val8 = val >> (((DATA_SIZE - 1) * 8) - (i * 8));
            glue(helper_ret_stb, MMUSUFFIX)(env, addr + i, val8,
                                            oi, retaddr);
        }
        return;
    }

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
#ifdef STORE_PAGE_FUNC
    if(DECAF_is_callback_needed(DECAF_MEM_WRITE_CB))
        helper_DECAF_invoke_mem_write_callback(addr,qemu_ram_addr_from_host(haddr),haddr, 0 ,1, 3);
#endif
    glue(glue(st, SUFFIX), _be_p)((uint8_t *)haddr, val);

    if (debug_taint) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;

#ifdef TARGET_MIPS
        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);

        if (pgd && !status) {
            uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
            if (guest_pc == 0x802f7b88 ||
                (
                    ((val) & 0xff) == 't' || ((val) & 0xff) == 'e' || ((val) & 0xff) == 'E' || ((val) & 0xff) == 'P' || ((val) & 0xff) == 'T' ||
                    ((val >> 8) & 0xff) == 't' || ((val >> 8) & 0xff) == 'e' || ((val >> 8) & 0xff) == 'E' || ((val >> 8) & 0xff) == 'P' || ((val >> 8) & 0xff) == 'T' ||
                    ((val >> 16) & 0xff) == 't' || ((val >> 16) & 0xff) == 'e' || ((val >> 16) & 0xff) == 'E' || ((val >> 16) & 0xff) == 'P' || ((val >> 16) & 0xff) == 'T' ||
                    ((val >> 24) & 0xff) == 't' || ((val >> 24) & 0xff) == 'e' || ((val >> 24) & 0xff) == 'E' || ((val >> 24) & 0xff) == 'P' || ((val >> 24) & 0xff) == 'T'
                )) {
                CPUState *cpu = ENV_GET_CPU(env);
                FILE *fp = fopen("debug/softmmu_template.log","a+");
                // uintptr_t guest_pc = _tb_find_pc(cpu, retaddr);
                fprintf(fp, "helper_le_st_name: %c %c %c %c (0x%lx) 0x%lx %s 0x%lx retaddr: 0x%lx 0x%lx (0x%lx)\n",  
                    (val) & 0xff, 
                    (val >> 8) & 0xff,
                    (val >> 16) & 0xff, 
                    (val >> 24) & 0xff, val, addr, procname, qemu_ram_addr_from_host(haddr), retaddr, env->tempidx, guest_pc);
                fclose(fp);

                deb = 1;
            }
        }
#endif
    }

#ifdef TARGET_MIPS
    if (taint_tracking_enabled && env->tempidx) {
        char procname[MAX_PROCESS_NAME_LENGTH] = {0};

        uint32_t pid = 0;
        uint32_t par_pid = 0;
        target_ulong pgd = 0;
        int status = -1;
        target_ulong pc = env->active_tc.PC;

        CPUState *cpu = ENV_GET_CPU(env);
        pgd = DECAF_getPGD(cpu);
        if (pgd)
            status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);

        if (pgd && !status) {
            if (!fuzz) {
                uintptr_t guest_pc = 0;
                
                if (taint_tracking_enabled == 3)
                    guest_pc = _tb_find_pc(cpu, retaddr);

                if ((env->tempidx >> 24) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr), 1, (val >> 24) & 0xFF);
                
                if ((env->tempidx >> 16) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+1, 1, (val >> 16) & 0xFF);
                
                if ((env->tempidx >> 8) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+2, 1, (val >> 8) & 0xFF);
                
                if ((env->tempidx) & 0xff == 0xff && pid)
                    taint_mem_log(1, guest_pc, pid, qemu_ram_addr_from_host(haddr)+3, 1, (val) & 0xFF);
            }
            else {
                if (afl_user_fork && (coverage_tracing == TAINT_BLOCK || coverage_tracing == TAINT_EDGE) && ((include_libraries && pc < kernel_base) || (!include_libraries && pc < 0x70000000))) {
                    int adjusted_pc = 0;
                    uint64_t inode_num = 0;
                    get_pc_text_info_wrapper(pid, pc, &adjusted_pc, &inode_num);

                    if (adjusted_pc) {
                        if (coverage_tracing == TAINT_BLOCK) {
                            if (debug_fuzz) {
                                char mod_name[MAX_MODULE_NAME_LENGTH] = {0};
                                get_module_name_from_inode_wrapper(pid, inode_num, mod_name);

                                FILE *fp = fopen("debug/taint_blocks.log", "a+");
                                if (fp) {
                                    fprintf(fp, "procname %s, mod_name %s, inode 0x%lx, adjusted_pc 0x%lx: %d\n",
                                            procname, mod_name, inode_num, adjusted_pc,
                                            (adjusted_pc ^ inode_num) & (map_size - 1));
                                    fclose(fp);
                                }
                            }
                            target_ulong pair[2] = { adjusted_pc, inode_num };
                            uint32_t loc = XXH32(pair, sizeof(pair), pid) & map_size;
                            afl_area_ptr[loc]++;
                        }
                        else if (coverage_tracing == TAINT_EDGE) {
                            uint32_t val = update_cov_xxhash(pid, adjusted_pc, inode_num);
                            afl_area_ptr[val]++;
                            taint_edge_flag = 1;
                        }
                    }
                }
            }
        } 
    }
#endif

// #ifdef TARGET_MIPS
//     //Since tainted pages are marked in io_mem_taint, we have a fast path:
//     //If taint is zero, and it is not accessing io_mem_taint, we don't need to update shadow memory
//     if (unlikely(env->tempidx
// #if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
//         || env->tempidx2
// #endif
//     )) {
//         //Now there is a taint, and this page is not marked in io_mem_taint.
//         //We need to taint it in the shadow memory, in which the corresponding TLB entry will also be marked as io_mem_taint
//         glue(glue(__taint_st, SUFFIX), _raw)(deb, (void *)(haddr), addr, 1);
//     }
// #else
    glue(glue(__taint_st, SUFFIX), _raw)(deb, (unsigned long)(haddr),addr, 1);
// #endif
}
#endif /* DATA_SIZE > 1 */
#endif /* !defined(SOFTMMU_CODE_ACCESS) */

#undef READ_ACCESS_TYPE
#undef DATA_TYPE
#undef SUFFIX
#undef LSUFFIX
#undef DATA_SIZE
#undef ADDR_READ
#undef WORD_TYPE
#undef SDATA_TYPE
#undef USUFFIX
#undef SSUFFIX
#undef BSWAP
#undef helper_le_ld_name
#undef helper_be_ld_name
#undef helper_le_lds_name
#undef helper_be_lds_name
#undef helper_le_st_name
#undef helper_be_st_name
