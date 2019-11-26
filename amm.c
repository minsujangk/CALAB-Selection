/*
 * A all-at-once version of mm module 
 */

#include "mm.h"
#include <sys/mman.h>
#include <sys/stat.h>

int mm_init_exec(struct exec_prm *eprm)
{
    // initialize executable
    // if amm, load all-at-once

    void *mmap_addr = _mm_mmap(eprm, 0, eprm->file_length);
    printf("mmap_addr is : %p\n", mmap_addr);
    if (mmap_addr < 0)
        return -1;

    eprm->mmap_addr = mmap_addr;
    return 0;
}

int mm_handle_segfault(struct exec_prm *prm, char *address)
{
    // compute file offset and mmap page in with mm_load_exec
    printf("invalid access to handle segfault in amm mode\n");

    return -1;
}

int mm_load_exec(struct exec_prm *eprm, size_t offset)
{
    return -1; // not necessary for amm
}
