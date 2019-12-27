//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_PAGER_H
#define CALAB_SELECTION_PAGER_H

#include "binfmts.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "setjmp.h"

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

static int cexecve(const char *, const char *[], const char *[], int);
int bprm_mm_init(struct usrld_binprm *bprm);
int prepare_arg_pages(struct usrld_binprm *bprm, const char *argv[], const char *envp[]);
int prepare_binprm(struct usrld_binprm *bprm);
static int copy_strings(int argc, const char *argv[], struct usrld_binprm *bprm);
int exec_binprm(struct usrld_binprm *bprm);
int setup_arg_pages(struct usrld_binprm *bprm, unsigned long stack_top,
                    int executable_stack);

void register_exit_func(void *atexit_addr, void (*func)(void));
void rtl_advanced();
void finalize_bprm(struct usrld_binprm *bprm);

void *load_mem_pool(int size);

#ifdef DPAGER
void sig_segv_handler(int signom, siginfo_t *info, void *ucontext);
#endif

// threading
struct store_mapping
{
    void *loc_orig;
    void *loc_save;
    size_t len;
};

struct store_info
{
    int count;
    struct store_mapping smap[3];
};

struct list bprm_thread_list;
struct bprm_thread
{
    struct list_elem elem;
    struct usrld_binprm *bprm;
    jmp_buf jbuf;
    struct store_info s_info;
    int is_jbuf_set;
};

#endif //CALAB_SELECTION_PAGER_H
