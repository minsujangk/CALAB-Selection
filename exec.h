//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PAGER_H
#define CALAB_SELECTION_PAGER_H

#include "binfmts.h"

#define IS_DEBUG 0

static int cexecve(const char *, const char *[], const char *[]);
int bprm_mm_init(struct usrld_binprm *bprm);
int prepare_arg_pages(struct usrld_binprm *bprm, const char *argv[], const char *envp[]);
int prepare_binprm(struct usrld_binprm *bprm);
static int copy_strings(int argc, const char *argv[], struct usrld_binprm *bprm);
static int exec_binprm(struct usrld_binprm *bprm);
int setup_arg_pages(struct usrld_binprm *bprm, unsigned long stack_top,
                    int executable_stack);

#endif //CALAB_SELECTION_PAGER_H
