//
// Created by ms.jang on 2019-11-25.
//

/*
 * 
 */

#ifndef CALAB_SELECTION_MM_H
#define CALAB_SELECTION_MM_H

#include "prm_loader.h"
#include "list.h"

struct mm_prm_info
{
    struct list map_list; // list of struct mm_prm_mapping
};

struct mm_prm_mapping
{
    struct list_elem elem;
    void *addr;
    size_t length;

    size_t efile_off_start;
    size_t efile_off_end;
};

int mm_init_exec(struct exec_prm *);
int mm_load_exec(struct exec_prm *, size_t);
void* _mm_mmap(struct exec_prm *eprm, size_t offset, size_t length);

#endif //CALAB_SELECTION_MM_H
