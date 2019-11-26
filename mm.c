
#include "mm.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>

/*
 * mmap file with given offset, length
 * push into mapping info
 */
void *_mm_mmap(struct exec_prm *eprm, size_t offset, size_t length)
{
    struct mm_prm_mapping *mpmapping =
        malloc(sizeof(struct mm_prm_mapping));

    void *mmap_addr = NULL;
    if (eprm->mmap_addr)
        mmap_addr = eprm->mmap_addr + offset;

    mmap_addr = mmap(mmap_addr, length,
                     PROT_READ | PROT_EXEC, MAP_PRIVATE,
                     eprm->fd, offset);

    mpmapping->addr = mmap_addr;
    mpmapping->efile_off_start = offset;
    mpmapping->efile_off_end = offset + length;
    mpmapping->length = length;

    list_push_back(&eprm->mpinfo->map_list, &mpmapping->elem);

    return mmap_addr;
}
