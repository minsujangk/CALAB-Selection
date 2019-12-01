
#include "mm.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>

/*
 * mmap file with given offset, length
 * push into mapping info
 */
void *_mm_mmap(struct exec_prm *eprm, void *vaddr, size_t offset, size_t length)
{
    struct mm_prm_mapping *mpmapping =
        malloc(sizeof(struct mm_prm_mapping));

    void *mmap_addr = NULL;
    // if (eprm->mmap_addr)
    //     mmap_addr = eprm->mmap_addr + offset;

    mmap_addr = mmap(vaddr, length,
                     PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE,
                     eprm->fd, offset);
    //temporarily allow every prot

    mpmapping->addr = mmap_addr;
    mpmapping->efile_off_start = offset;
    mpmapping->efile_off_end = offset + length;
    mpmapping->length = length;

    list_push_back(&eprm->mpinfo->map_list, &mpmapping->elem);

    printf("%d-%d mapped from %p-%p\n", offset, offset + length, mmap_addr, mmap_addr + length);

    return mmap_addr;
}
