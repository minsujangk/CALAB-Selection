//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PRM_LOADER_H
#define CALAB_SELECTION_PRM_LOADER_H

#include <stdio.h>
#include "mm.h"

#define USRLD_BINPRM_BUF_SIZE 128

struct usrld_binprm
{
    struct usrld_vm_area_struct *vma;
    unsigned long vma_pages;

    struct usrld_mm_struct *mm;
    unsigned long p;

    int fd; // file 대체

    int argc, envc;
    const char *filename;
    const char *interp;

    char buf[USRLD_BINPRM_BUF_SIZE]; // save first 128 byte of file
};

int load_binary(struct usrld_binprm *);

#endif //CALAB_SELECTION_PLOADER_H
