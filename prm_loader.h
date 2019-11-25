//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PRM_LOADER_H
#define CALAB_SELECTION_PRM_LOADER_H

#include <stdio.h>

#define BUF_SIZE 128

struct exec_prm
{
    char buf[BUF_SIZE]; // save first 128 byte of file

    int fd;
    const char *filename;
    int argc;

    struct mm_prm_info *mpinfo;

    unsigned int off_max_loaded; // maximum loaded executable size
};

int execv(const char *, const char *[]);

#endif //CALAB_SELECTION_PLOADER_H
