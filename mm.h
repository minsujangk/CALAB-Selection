//
// Created by ms.jang on 2019-11-25.
//

/*
 * 
 */

#ifndef CALAB_SELECTION_MM_H
#define CALAB_SELECTION_MM_H

#include <sys/mman.h>
#include "binfmts.h"
#include "list.h"

#define AT_VECTOR_SIZE 2

struct usrld_mm_struct
{
    struct usrld_vma_struct *mmap;

    unsigned long mmap_base;        /* base of mmap area */
    unsigned long mmap_legacy_base; /* base of mmap area in bottom-up allocations */

    // spinlock_t arg_lock; /* protect the below fields */
    unsigned long start_code, end_code, start_data, end_data;
    unsigned long start_brk, brk, start_stack;
    unsigned long arg_start, arg_end, env_start, env_end;

    unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */
};

struct usrld_vma_struct
{
    unsigned long vm_start;
    unsigned long vm_end;

    struct usrld_vma_struct *vm_next, *vm_prev;

    struct usrld_mm_struct *vm_mm;
};

int init_exec(struct usrld_binprm *);
int load_exec(struct usrld_binprm *, unsigned int offset);

#endif //CALAB_SELECTION_MM_H
