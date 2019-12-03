//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PAGER_H
#define CALAB_SELECTION_PAGER_H

#include "binfmts.h"

static int execve(const char *, const char *[], const char *[]);
int bprm_mm_init(struct usrld_binprm *bprm);
int prepare_arg_pages(struct usrld_binprm *bprm, const char *argv[], const char *envp[]);
int prepare_binprm(struct usrld_binprm *bprm);

#endif //CALAB_SELECTION_PAGER_H
