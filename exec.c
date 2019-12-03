//
// Created by ms.jang on 2019-11-25.
//

#include "exec.h"
#include "mm.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>

static unsigned long usrld_randomize_stack_top(unsigned long stack_top);

int main(int argc, char *argv[], char *envp[])
{
    srand(time(NULL));

    // signal(SIGSEGV, (void *)sig_segv_handler);

    int is_exec = execve(argv[0], &argv[1], envp);

    if (is_exec < 0)
        exit(-1);
}

int execve(const char *filename, const char *argv[], const char *envp[])
{
    struct usrld_binprm *bprm;
    FILE *fp;
    int retval;

    if (!filename)
        return -1;

    retval = -ENOMEM;
    bprm = malloc(sizeof(struct usrld_binprm));
    if (!bprm)
        goto out_ret;

    retval = -EBADFD;
    bprm->fp = fp = fopen(filename, "r");
    if (!fp)
        goto out_free;

    bprm->filename = filename;
    bprm->interp = filename;

    retval = bprm_mm_init(bprm);
    if (retval < 0)
        goto out_free;

    retval = prepare_arg_pages(bprm, argv, envp);
    if (retval < 0)
        goto out_free;

    retval = prepare_binprm(bprm);
    if (retval < 0)
        goto out_free;

out_free:
    free(bprm);

out_ret:
    return retval;
}

int bprm_mm_init(struct usrld_binprm *bprm)
{
    struct usrld_mm_struct *mm = NULL;
    bprm->mm = mm = malloc(sizeof(struct usrld_mm_struct));
    if (!mm)
        return -ENOMEM;

    struct usrld_vma_struct *vma = NULL;

    bprm->vma = vma = calloc(1, sizeof(struct usrld_vma_struct));
    if (!vma)
        return -ENOMEM;

    // __bprm_init
    vma->vm_mm = mm;

    // read rsp to configure program stack top
    // TODO: 이 방법으로 program memory area 할당하는 게 맞는지 체크.
    // otherwise 새 thread 생성하는 방법으로 해야할듯
    register long rsp asm("rsp");
    unsigned long USRLD_STACK_TOP = usrld_randomize_stack_top(rsp);
    vma->vm_end = USRLD_STACK_TOP;
    vma->vm_start = vma->vm_end - PAGE_SIZE;

    *(long *)USRLD_STACK_TOP = 0xd3;

    // simulating insert_vm_struct(mm, vma);
    mm->mmap = vma;

    bprm->p = vma->vm_end - sizeof(void *);
    return 0;
}

static unsigned long usrld_randomize_stack_top(unsigned long stack_top)
{
    int random_variable = rand();
    random_variable &= 0x3ff; // 4MB mask not to exceed stack limit (8MB)
    random_variable <<= PAGE_SHIFT;

    return PAGE_ALIGN(stack_top) - random_variable;
}

int prepare_arg_pages(struct usrld_binprm *bprm, const char *argv[], const char *envp[])
{
    int i, count = 0;
    for (i = 0; i < 0x7FFFFFFF; i++)
    {
        if (!argv[i])
            break;
        ++count;
    }
    bprm->argc = count;

    count = 0;
    for (i = 0; i < 0x7FFFFFFF; i++)
    {
        if (!envp[i])
            break;
        ++count;
    }
    bprm->envc = count;

    int limit, ptr_size;
    limit = _STK_LIM / 4 * 3;
    limit = max_t(unsigned long, limit, 32 * PAGE_SIZE);

    ptr_size = (bprm->argc + bprm->envc) * sizeof(void *);
    if (limit <= ptr_size)
        return -E2BIG;
    limit -= ptr_size;

    bprm->argmin = bprm->p - limit;
    return 0;
}

int prepare_binprm(struct usrld_binprm *bprm)
{
    memset(bprm->buf, 0, USRLD_BINPRM_BUF_SIZE);

    return fread(bprm->buf, USRLD_BINPRM_BUF_SIZE, 1, bprm->fp);
}