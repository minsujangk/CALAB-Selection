//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PRM_LOADER_H
#define CALAB_SELECTION_PRM_LOADER_H

#include <stdio.h>
#include "mm.h"

#define _STK_LIM (8 * 1024 * 1024)
#define MAX_ARG_STRLEN 32 * PAGE_SIZE
#define USRLD_BINPRM_BUF_SIZE 128
#define PAGE_SHIFT 12

struct usrld_binprm
{
    struct usrld_vma_struct *vma;
    unsigned long vma_pages;

    struct usrld_mm_struct *mm;
    unsigned long p;
    unsigned long argmin;

    unsigned int recursion_depth;
    FILE *fp; // file 대체

    int argc, envc;
    const char *filename;
    const char *interp;

    unsigned long loader, exec;

    char buf[USRLD_BINPRM_BUF_SIZE]; // save first 128 byte of file
};

int load_binary(struct usrld_binprm *bprm);

#endif //CALAB_SELECTION_PLOADER_H
