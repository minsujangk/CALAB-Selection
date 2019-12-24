//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PAGER_H
#define CALAB_SELECTION_PAGER_H

#include "binfmts.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#define IS_DEBUG 1

// void *rtl_addr = NULL;
struct exit_function
{
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union {
        void (*at)(void);
        struct
        {
            void (*fn)(int status, void *arg);
            void *arg;
        } on;
        struct
        {
            void (*fn)(void *arg, int status);
            void *arg;
            void *dso_handle;
        } cxa;
    } func;
};
struct exit_function_list
{
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
};
struct exit_function_list *__exit_funcs;

static int cexecve(const char *, const char *[], const char *[], int);
int bprm_mm_init(struct usrld_binprm *bprm);
int prepare_arg_pages(struct usrld_binprm *bprm, const char *argv[], const char *envp[]);
int prepare_binprm(struct usrld_binprm *bprm);
static int copy_strings(int argc, const char *argv[], struct usrld_binprm *bprm);
static int exec_binprm(struct usrld_binprm *bprm);
int setup_arg_pages(struct usrld_binprm *bprm, unsigned long stack_top,
                    int executable_stack);

void register_exit_func(void *atexit_addr, void (*func)(void));
void rtl_advanced();

#ifdef DPAGER
void sig_segv_handler(int signom, siginfo_t *info, void *ucontext);
#endif

#endif //CALAB_SELECTION_PAGER_H
