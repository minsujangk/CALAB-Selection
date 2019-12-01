#include "prm_loader.h"
#include "binfmt_elf.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int cexecv(const char *filename, char *argv[])
{
    struct exec_prm *eprm;

    eprm = malloc(sizeof(struct exec_prm));
    eprm->filename = filename;

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;
    eprm->fd = fd;

    struct stat stat;
    fstat(eprm->fd, &stat);
    eprm->file_length = stat.st_size;

    // read initial buffer to work with elf
    ssize_t read_size = read(fd, eprm->buf, BUF_SIZE);
    if (read_size < 0)
        return -1;

    eprm->mpinfo = malloc(sizeof(struct mm_prm_info));
    list_init(&eprm->mpinfo->map_list);

    // int is_init = mm_init_exec(eprm);
    // if (is_init < 0)
    //     return -1;

    if (load_elf_binary(eprm) < 0)
        return -1;

    printf("loading elf success\n");

    // jmp to target excutable
    void *return_addr;
    void *addr = 0xc00000 + eprm->entry_point;
    asm volatile("lea 0x12(%rip), %r12");
    asm volatile("push %r12");
    // asm volatile("push %0"::"r"(addr));
    // asm volatile("ret");
    asm volatile("jmp %0" ::"r"(addr));

    // copy strings

    printf("execution complete\n");

    free(eprm->mpinfo);
    free(eprm);

    return 0;
}

int load_elf_binary(struct exec_prm *eprm)
{
    struct elf_phdr *elf_ppnt, *elf_phdata;
    unsigned long elf_bss, elf_brk;
    size_t size;

    unsigned long start_code, end_code, start_data, end_data;

    struct elfhdr *elf_ex = (struct elfhdr *)eprm->buf;

    if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN)
        goto out_err;

    if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
        goto out_err;

    if (elf_ex->e_phnum < 1 || elf_ex->e_phnum > 65536 / sizeof(struct elf_phdr))
        goto out_err;

    size = elf_ex->e_phnum * sizeof(struct elf_phdr);

    elf_phdata = malloc(size);

    ssize_t read_size = pread(eprm->fd, elf_phdata, size, elf_ex->e_phoff);
    if (read_size != size)
        goto out_err;

    elf_ppnt = elf_phdata;
    elf_bss = 0;
    elf_brk = 0;

    start_code = ~0UL;
    end_code = 0;
    start_data = 0;
    end_data = 0;

    // PT_INTERP Later?
    // omit PT_GNU_STACK

    // setup new exec()
    // omit load_bias for now

    int i;
    for (i = 0, elf_ppnt = elf_phdata; i < elf_ex->e_phnum; i++, elf_ppnt++)
    {
        if (elf_ppnt->p_type != PT_LOAD)
            continue;

        unsigned long k;
        unsigned long vaddr = elf_ppnt->p_vaddr;
        if ((elf_ppnt->p_flags & PF_X))
            vaddr = 0xc00000; // map .text in different region.

        printf("size is %p\n", elf_ppnt->p_filesz + elf_ppnt->p_offset);
        _mm_mmap(eprm, vaddr - elf_ppnt->p_offset,
                 0, elf_ppnt->p_filesz + elf_ppnt->p_offset);

        k = elf_ppnt->p_vaddr;
        start_code = 0xc00000; // fix start_code to 0xc00000;
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
            elf_brk = k;
    }

    // simulating set_brk?
    unsigned long brk_start = ELF_PAGEALIGN(elf_bss);
    unsigned long brk_end = ELF_PAGEALIGN(elf_brk);
    if (brk_end > brk_start)
        _mm_mmap(eprm, brk_start, 0, brk_end - brk_start);

    eprm->entry_point = elf_ex->e_entry;

    free(elf_phdata);

    return 0;
out_err:
    return -1;
}