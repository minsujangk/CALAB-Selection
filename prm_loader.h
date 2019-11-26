//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PRM_LOADER_H
#define CALAB_SELECTION_PRM_LOADER_H

#include <stdio.h>
#include "mm.h"

#define BUF_SIZE 128

struct exec_prm
{
    char buf[BUF_SIZE]; // save first 128 byte of file

    int fd;
    const char *filename;
    size_t file_length;

    int argc;

    struct mm_prm_info *mpinfo;

    void *mmap_addr;
    size_t off_max_loaded; // maximum loaded executable size
};

int execv(const char *, char *[]);

#endif //CALAB_SELECTION_PLOADER_H
