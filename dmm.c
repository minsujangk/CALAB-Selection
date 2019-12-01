/*
 * A demand loading version of mm module 
 */

#include "mm.h"
#include <sys/mman.h>

#define PGSIZE 4096

int mm_init_exec(struct exec_prm *eprm)
{
    // // initialize executable
    // // if amm, load all-at-once

    // void *mmap_addr = _mm_mmap(eprm, 0, PGSIZE);
    // if (mmap_addr < 0)
    //     return -1;

    // eprm->mmap_addr = mmap_addr;
    return 0;
}

int mm_handle_segfault(struct exec_prm *eprm, void *address)
{
    // compute file offset and mmap page in with mm_load_exec
    if (address > eprm->mmap_addr + eprm->file_length)
        return -1;

    void *aligned_address = (void *)(((int)address / PGSIZE) * PGSIZE);
    size_t offset = aligned_address - eprm->mmap_addr;

    return mm_load_exec(eprm, offset);
}

int mm_load_exec(struct exec_prm *eprm, size_t offset)
{
    // void *mmap_addr = _mm_mmap(eprm, offset, PGSIZE);
    // if (mmap_addr < 0)
    //     return -1;

    return 0;
}
