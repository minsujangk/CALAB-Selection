/*
 * A all-at-once version of mm module 
 */

#include "mm.h"
#include "binfmts.h"
#include "string.h"
#include "exec.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <linux/auxvec.h>
#include <elf.h>
#include <sys/auxv.h>
#include <errno.h>

// 64-bit configuration for simplicity
#define elfhdr Elf64_Ehdr
#define elf_phdr Elf64_Phdr

#define ELF_MIN_ALIGN PAGE_SIZE
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN - 1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN - 1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

static elf_phdr *load_elf_phdrs(const elfhdr *elf_ex,
                                FILE *elf_fp);
static int set_brk(unsigned long start, unsigned long end, int prot,
                   struct usrld_mm_struct *mm);
static inline int make_prot(Elf64_Word p_flags);
static unsigned long elf_map(FILE *fp, unsigned long addr,
                             const elf_phdr *eppnt, int prot, int type,
                             unsigned long total_size, const char *filename);
static int create_elf_tables(struct usrld_binprm *bprm, elfhdr *exec,
                             unsigned long load_addr,
                             unsigned long interp_load_addr);
unsigned long get_aux_value(unsigned long type);
void start_thread(unsigned long start_code, unsigned long elf_entry, unsigned long p);

int load_binary(struct usrld_binprm *bprm)
{
    unsigned long load_addr = 0, load_bias = 0;
    int load_addr_set = 0;
    unsigned long error;
    elf_phdr *elf_ppnt, *elf_phdata;
    unsigned long elf_bss, elf_brk;
    int bss_prot = 0;
    int retval, i;
    unsigned long elf_entry;
    unsigned long start_code, end_code, start_data, end_data;

#ifdef DPAGER
    struct usrld_dpage *dpage;
#endif

    elfhdr *elf_ex = (elfhdr *)bprm->buf;

    if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0)
        goto out_err;

    if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN)
        goto out_err;

    elf_phdata = load_elf_phdrs(elf_ex, bprm->fp);
    if (!elf_phdata)
        goto out_err;

    // pass INTERP
    // pass GNU STACK

    elf_ppnt = elf_phdata;

    // retval = setup_arg_pages(bprm, bprm->vma->vm_end, 0);
    bprm->mm->arg_start = bprm->p;
    bprm->mm->start_stack = bprm->p;

    elf_bss = 0;
    elf_brk = 0;

    start_code = ~0UL;
    end_code = 0;
    start_data = 0;
    end_data = 0;

    for (i = 0, elf_ppnt = elf_phdata;
         i < elf_ex->e_phnum; i++, elf_ppnt++)
    {
        int elf_prot, elf_flags, elf_fixed = 0x00000; // MAP_FIXED_NOREPLACE
        unsigned long k, vaddr;
        unsigned long total_size = 0;

        if (elf_ppnt->p_type != PT_LOAD)
            continue;

        if (elf_brk > elf_bss)
        {
            unsigned long nbyte;

            retval = set_brk(elf_bss + load_bias, elf_brk + load_bias,
                             bss_prot, bprm->mm);
            if (retval)
                goto out_free;
            nbyte = ELF_PAGEOFFSET(elf_bss);
            if (nbyte)
            {
#ifdef DPAGER
                elf_map_partial_page(bprm->fp, dpage->base_vaddr, dpage->base_file_off, ELF_PAGESTART(elf_bss) - dpage->base_vaddr,
                                     dpage->elf_prot, dpage->elf_flags, bprm->filename);
#endif

                nbyte = ELF_MIN_ALIGN - nbyte;
                if (nbyte > elf_brk - elf_bss)
                    nbyte = elf_brk - elf_bss;
                // initialize bss
                memset((void *)elf_bss + load_bias, 0, nbyte);
            }

            elf_fixed = MAP_FIXED;
        }

        elf_prot = make_prot(elf_ppnt->p_flags);

        elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

        vaddr = elf_ppnt->p_vaddr;
        if (elf_ex->e_type == ET_EXEC || load_addr_set)
        {
            elf_flags |= elf_fixed;
        }
        else if (elf_ex->e_type == ET_DYN)
        {
            //later
        }

#ifndef DPAGER
        error = elf_map(bprm->fp, load_bias + vaddr, elf_ppnt,
                        elf_prot, elf_flags, total_size, bprm->filename);
#endif
#ifdef DPAGER
        dpage = malloc(sizeof(struct usrld_dpage));
        dpage->base_vaddr = ELF_PAGESTART(load_bias + vaddr);
        dpage->base_file_off = elf_ppnt->p_offset - ELF_PAGEOFFSET(elf_ppnt->p_vaddr);
        dpage->elf_prot = elf_prot;
        dpage->elf_flags = elf_flags;
        dpage->max_size = ELF_PAGEALIGN(elf_ppnt->p_filesz + ELF_PAGEOFFSET(vaddr));
        list_push_back(&bprm->dpage_list, &dpage->elem);
        error = elf_map_partial_page(bprm->fp, dpage->base_vaddr, dpage->base_file_off, 0, elf_prot, elf_flags, bprm->filename);
        if (IS_DEBUG)
            printf("dpage added %p-%p\n", (void *)dpage->base_vaddr, (void *)(dpage->base_vaddr + dpage->max_size));

#endif

        if (!load_addr_set)
        {
            load_addr_set = 1;
            load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
            if (elf_ex->e_type == ET_DYN)
            {
                load_bias += error - ELF_PAGESTART(load_bias + vaddr);
                load_addr += load_bias;
                // reloc_func_desc = load_bias;
            }
        }

        k = elf_ppnt->p_vaddr;
        if (k < start_code)
            start_code = k;
        if (start_data < k)
            start_data = k;

        k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

        if (k > elf_bss)
            elf_bss = k;
        if ((elf_ppnt->p_flags & PF_X) && end_code < k)
            end_code = k;
        if (end_data < k)
            end_data = k;
        k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
        if (k > elf_brk)
        {
            bss_prot = elf_prot;
            elf_brk = k;
        }
    }

    elf_ex->e_entry += load_bias;
    elf_bss += load_bias;
    elf_brk += load_bias;
    start_code += load_bias;
    end_code += load_bias;
    start_data += load_bias;
    end_data += load_bias;

    retval = set_brk(elf_bss, elf_brk, bss_prot, bprm->mm);
    if (retval)
        goto out_free;
    unsigned long nbyte;
    nbyte = ELF_PAGEOFFSET(elf_bss);
    if (nbyte)
    {
#ifdef DPAGER
        elf_map_partial_page(bprm->fp, dpage->base_vaddr, dpage->base_file_off, ELF_PAGESTART(elf_bss) - dpage->base_vaddr,
                             dpage->elf_prot, dpage->elf_flags, bprm->filename);
#endif

        nbyte = ELF_MIN_ALIGN - nbyte;
        memset((void *)elf_bss, 0, nbyte);
    }
    elf_entry = elf_ex->e_entry;

    free(elf_phdata);

    retval = create_elf_tables(bprm, elf_ex, load_addr, 0);
    if (retval < 0)
        goto out;

    bprm->mm->end_code = end_code;
    bprm->mm->start_code = start_code;
    bprm->mm->start_data = start_data;
    bprm->mm->end_data = end_data;
    bprm->mm->start_stack = bprm->p;

    start_thread(start_code, elf_entry, bprm->p);
    retval = 0;
out:
out_ret:
    return retval;
out_free:
    free(elf_phdata);
    goto out;

out_err:
    return -1;
}

elf_phdr *load_elf_phdrs(const elfhdr *elf_ex,
                         FILE *elf_fp)
{
    elf_phdr *elf_phdata = NULL;
    int retval, err = -1;
    unsigned long pos = elf_ex->e_phoff;
    unsigned int size;

    if (elf_ex->e_phentsize != sizeof(elf_phdr))
        goto out;

    size = elf_ex->e_phnum * sizeof(elf_phdr);
    if (size < 1 || size > 65536 || size > ELF_MIN_ALIGN)
        goto out;

    elf_phdata = malloc(size);
    if (!elf_phdata)
        goto out;

    fseek(elf_fp, elf_ex->e_phoff, SEEK_SET);
    retval = fread(elf_phdata, size, 1, elf_fp);
    if (retval < 0)
    {
        err = (retval < 0) ? retval : -EIO;
        goto out;
    }

    err = 0;
out:
    if (err)
    {
        free(elf_phdata);
        elf_phdata = NULL;
    }
    return elf_phdata;
}

static int set_brk(unsigned long start, unsigned long end, int prot,
                   struct usrld_mm_struct *mm)
{
    start = ELF_PAGEALIGN(start);
    end = ELF_PAGEALIGN(end);
    if (end > start)
    {
        unsigned long addr = start;
        unsigned long request = end - start;

        unsigned long len = PAGE_ALIGN(request);
        void *ret;

        if (len < request)
            return -ENOMEM;
        if (!len)
            return 0;
        if (IS_DEBUG)
            printf("brkb %p-%p\n", (void *)addr, (void *)(addr + len));
        ret = mmap((void *)addr, len, prot,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (ret < 0)
            return -1;
    }
    mm->start_brk = mm->brk = end;

    return 0;
}

static inline int make_prot(Elf64_Word p_flags)
{
    int prot = 0;

    if (p_flags & PF_R)
        prot |= PROT_READ;
    if (p_flags & PF_W)
        prot |= PROT_WRITE;
    if (p_flags & PF_X)
        prot |= PROT_EXEC;
    return prot;
}

static unsigned long elf_map(FILE *fp, unsigned long addr,
                             const elf_phdr *eppnt, int prot, int type,
                             unsigned long total_size, const char *filename)
{
    unsigned long map_addr;
    unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
    unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
    if (IS_DEBUG)
        printf("elf map %p\n", addr);

    if (!addr)
    {
        printf("Load rejected: address space overlapped\n");
        exit(-1);
    }

    addr = ELF_PAGESTART(addr);
    size = ELF_PAGEALIGN(size);

    if (!size)
        return addr;

    int _fd = open(filename, O_RDONLY);
    if (total_size)
    {
        total_size = ELF_PAGEALIGN(total_size);
        map_addr = (unsigned long)mmap((void *)addr, total_size, prot, type, _fd, off);
        if (!(map_addr >= 0xffffffffUL))
            munmap((void *)map_addr + size, total_size - size);
    }
    else
        map_addr = (unsigned long)mmap((void *)addr, size, prot, type, _fd, off);
    close(_fd);

    if (IS_DEBUG)
        printf("mapping %p-%p to %p, %p?, %d\n", (void *)off, (void *)(off + size), (void *)map_addr, (void *)addr, errno);

    return (map_addr);
}

#ifdef DPAGER

static unsigned long elf_map_partial_page(FILE *fp, unsigned long base_addr,
                                          unsigned long base_file_off,
                                          unsigned long off, int prot,
                                          int type, const char *filename)
{
    unsigned long map_addr;
    unsigned long addr_start = base_addr + off;
    unsigned long file_start = base_file_off + off;
    unsigned long size = PAGE_SIZE;

    if (!base_addr)
    {
        printf("Load rejected: address space overlapped\n");
        exit(-1);
    }

    int _fd = open(filename, O_RDONLY);
    map_addr = (unsigned long)mmap((void *)addr_start, size, prot, type, _fd, file_start);
    close(_fd);

    if (IS_DEBUG)
        printf("partial mapping %p-%p to %p, %p?, %d\n", (void *)file_start, (void *)(file_start + size), (void *)map_addr, (void *)addr_start, errno);

    return (map_addr);
}

void *elf_map_dpage(struct usrld_binprm *bprm,
                    unsigned long addr)
{
    // if addr is in dpage list
    struct list_elem *e;
    for (e = list_begin(&bprm->dpage_list);
         e != list_end(&bprm->dpage_list);
         e = list_next(e))
    {
        struct usrld_dpage *dpage = list_entry(e, struct usrld_dpage, elem);
        if (dpage->base_vaddr <= addr && addr < dpage->base_vaddr + dpage->max_size)
        {
            unsigned long off = ELF_PAGESTART(addr - dpage->base_vaddr);
            return (void *)elf_map_partial_page(bprm->fp, dpage->base_vaddr, dpage->base_file_off,
                                                off,
                                                dpage->elf_prot,
                                                dpage->elf_flags,
                                                bprm->filename);
        }
    }
    return -1;
}

#endif

#define STACK_ADD(sp, items) ((Elf64_Addr *)(sp) - (items))
#define STACK_ROUND(sp, items) (((unsigned long)(sp - items)) & ~15UL)
#define STACK_ALLOC(sp, len) \
    ({                       \
        sp -= len;           \
        sp;                  \
    })
static int create_elf_tables(struct usrld_binprm *bprm, elfhdr *exec,
                             unsigned long load_addr,
                             unsigned long interp_load_addr)
{
    unsigned long p = bprm->p;
    int argc = bprm->argc;
    int envc = bprm->envc;
    Elf64_Addr *sp;
    Elf64_Addr *u_platform;
    Elf64_Addr *u_base_platform;
    Elf64_Addr *u_rand_bytes;
    // const char *k_platform = "i686";
    // const char *k_base_platform = NULL;
    // unsigned char k_rand_bytes[16];
    int items;
    Elf64_Addr *elf_info;
    int ei_index = 0;
    struct usrld_vma_struct *vma;

    u_platform = NULL;
    if (get_aux_value(AT_PLATFORM))
    {
        char *platform_ptr = (char *)get_aux_value(AT_PLATFORM);
        size_t len = strlen(platform_ptr) + 1;
        u_platform = (Elf64_Addr *)STACK_ALLOC(p, len);
        memcpy(u_platform, platform_ptr, len);
    }

    u_base_platform = NULL;
    if (get_aux_value(AT_BASE_PLATFORM))
    {
        char *platform_ptr = (char *)get_aux_value(AT_BASE_PLATFORM);
        size_t len = strlen(platform_ptr) + 1;
        u_base_platform = (Elf64_Addr *)STACK_ALLOC(p, len);
        memcpy(u_base_platform, platform_ptr, len);
    }

    u_rand_bytes = NULL;
    if (get_aux_value(AT_RANDOM))
    {
        char *rand_ptr = (char *)get_aux_value(AT_RANDOM);
        size_t len = 16;
        u_rand_bytes = (Elf64_Addr *)STACK_ALLOC(p, len);
        memcpy(u_rand_bytes, rand_ptr, len);
    }

    elf_info = (Elf64_Addr *)bprm->mm->saved_auxv;
#define NEW_AUX_ENT(id, val)                     \
    do                                           \
    {                                            \
        elf_info[ei_index++] = id;               \
        elf_info[ei_index++] = (Elf64_Addr)val;  \
        if (IS_DEBUG)                            \
            printf("%s: %ld\n", #id, (long)val); \
    } while (0)
    NEW_AUX_ENT(AT_HWCAP, get_aux_value(AT_HWCAP));
    NEW_AUX_ENT(AT_PAGESZ, get_aux_value(AT_PAGESZ));
    NEW_AUX_ENT(AT_CLKTCK, get_aux_value(AT_CLKTCK));
    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
    NEW_AUX_ENT(AT_PHENT, sizeof(elf_phdr));
    NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
    NEW_AUX_ENT(AT_BASE, interp_load_addr);
    NEW_AUX_ENT(AT_FLAGS, get_aux_value(AT_FLAGS));
    NEW_AUX_ENT(AT_ENTRY, exec->e_entry);
    NEW_AUX_ENT(AT_UID, get_aux_value(AT_UID));
    NEW_AUX_ENT(AT_EUID, get_aux_value(AT_EUID));
    NEW_AUX_ENT(AT_GID, get_aux_value(AT_GID));
    NEW_AUX_ENT(AT_EGID, get_aux_value(AT_EGID));
    NEW_AUX_ENT(AT_SECURE, get_aux_value(AT_SECURE));
    NEW_AUX_ENT(AT_RANDOM, u_rand_bytes);
    NEW_AUX_ENT(AT_HWCAP2, get_aux_value(AT_HWCAP2));
    NEW_AUX_ENT(AT_EXECFN, bprm->exec);
    if (get_aux_value(AT_PLATFORM))
        NEW_AUX_ENT(AT_PLATFORM, u_platform);
    if (get_aux_value(AT_BASE_PLATFORM))
        NEW_AUX_ENT(AT_BASE_PLATFORM, u_base_platform);
#undef NEW_AUX_ENT
    /* AT_NULL is zero; clear the rest too */
    memset(&elf_info[ei_index], 0,
           sizeof bprm->mm->saved_auxv - ei_index * sizeof elf_info[0]);

    ei_index += 2;

    sp = STACK_ADD(p, ei_index);

    items = (argc + 1) + (envc + 1) + 1;
    bprm->p = STACK_ROUND(sp, items);

    sp = (Elf64_Addr *)bprm->p;

    *sp = argc;
    sp++;

    p = bprm->mm->arg_end = bprm->mm->arg_start;
    while (argc-- > 0)
    {
        size_t len;
        *sp = (Elf64_Addr)p;
        sp++;

        len = strlen((void *)p) + 1;
        p += len;
    }
    *sp = 0;
    sp++;
    bprm->mm->arg_end = p;

    bprm->mm->env_end = bprm->mm->env_start = p;
    while (envc-- > 0)
    {
        size_t len;
        *sp = (Elf64_Addr)p;
        sp++;

        len = strlen((void *)p) + 1;
        p += len;
    }
    *sp = 0;
    sp++;
    bprm->mm->env_end = p;

    memcpy(sp, elf_info, ei_index * sizeof(Elf64_Addr));
    return 0;
}

unsigned long get_aux_value(unsigned long type)
{
    unsigned long aux = getauxval(type);

    return aux;
}

unsigned long get_aux_value_ptr(unsigned long type)
{
    unsigned long aux = getauxval(type);

    return aux;
}

void start_thread(unsigned long start_code, unsigned long elf_entry, unsigned long p)
{
    unsigned long jmp_target = elf_entry;
    unsigned long pp = p;
    short v = 0;
    asm("movq %0, %%rax" ::"r"(jmp_target));
    asm("movq $0, %rbx");
    asm("movq $0, %rcx");
    asm("movq $0, %rdx");

    asm("movq $0, %rsi");
    asm("movq $0, %rdi");

    asm("movq $0, %r8");
    asm("movq $0, %r9");
    asm("movq $0, %r10");
    asm("movq $0, %r11");
    asm("movq $0, %r12");
    asm("movq $0, %r13");
    asm("movq $0, %r14");
    asm("movq $0, %r15");

    asm("mov %0, %%fs" ::"r"(v));
    asm("mov %0, %%gs" ::"r"(v));
    asm("mov %0, %%ds" ::"r"(v));
    asm("mov %0, %%es" ::"r"(v));

    asm("movq %0, %%rsp" ::"r"(pp));
    asm("jmp *%0" ::"r"(jmp_target));
}