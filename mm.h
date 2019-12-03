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

#define PAGE_SIZE 4096
#define PAGE_ALIGN(addr) (addr & ~((unsigned long)(PAGE_SIZE - 1)))

#define AT_VECTOR_SIZE 2

// helper functions from page-types.h
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1 : __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1 : __max2; })

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

#endif //CALAB_SELECTION_MM_H
