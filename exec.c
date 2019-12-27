//
// Created by ms.jang on 2019-11-25.
//

#include "exec.h"
#include "mm.h"
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include "uthread.h"

static unsigned long usrld_randomize_stack_top(unsigned long stack_top);
int loading_binary = 0;
int is_thread_mode = 0;

jmp_buf jbuf;
jmp_buf jbuf1;
jmp_buf jbuf2;

void *mem_pool;

struct usrld_binprm *target_bprm;

void *load_mem_pool(int size)
{
    void *old_mem = mem_pool;
    mem_pool += size;
    return old_mem;
}

int main(int argc, char *argv[], char *envp[])
{
    srand(time(NULL));

#ifdef DPAGER
    struct sigaction act = {0};
    act.sa_sigaction = sig_segv_handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, NULL);
#endif

    mem_pool = malloc(40960000);
    list_init(&bprm_thread_list);

    int idx_arg_start;
    struct bprm_thread *bprmthd;
    int i;

    if (argc > 3 && strcmp(argv[1], "-t") == 0)
    {
        printf("running user-threading mode\n");
        is_thread_mode = 1;

        idx_arg_start = 2;

        for (i = 2; i < argc + 1; i++)
        {
            if (i == argc || strcmp(argv[i], "/") == 0)
            {
                argv[i] = NULL;

                printf("registering binary: %s\n", argv[idx_arg_start]);
                int is_exec = cexecve(argv[idx_arg_start], &argv[idx_arg_start + 1], envp, 0);
                if (is_exec < 0)
                    exit(1);

                bprmthd = load_mem_pool(sizeof(struct bprm_thread));
                bprmthd->bprm = target_bprm;
                bprmthd->is_jbuf_set = 0; // initialization
                target_bprm->bprmthd = bprmthd;

                list_push_back(&bprm_thread_list, &bprmthd->elem);

                if (i == argc)
                    break;

                idx_arg_start = i + 1;
            }
        }
        if (!setjmp(jbuf))
            sched(&bprm_thread_list);

        printf("\n\\(^.^)/ terminating thread program...!\n");

        _exit(0);
    }

    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-2") == 0)
        {
            loading_binary = 1;
            argv[i] = NULL; // change for first binary

            // -2 이후에는 다음 바이너리.
            const char *bin1 = argv[1];
            const char **argv1 = (const char **)&argv[2];
            const char *bin2 = argv[i + 1];
            const char **argv2 = (const char **)&argv[i + 2];
            const char **envps = envp;

            printf("executing binary 1: %s\n", bin1);

            int is_exec;
            if (!setjmp(jbuf1))
                is_exec = cexecve(bin1, argv1, (const char **)envps, 1);

            printf("\nalright! let's go to binary 2: %s\n", bin2);

            loading_binary = 2;

            if (!setjmp(jbuf2))
                is_exec = cexecve(bin2, argv2, (const char **)envps, 1);

            printf("\nall done!\n");

            _exit(0);
            goto out;
        }
    }

    printf("perhaps.. %p\n", &atexit);

    int is_exec;
    if (!setjmp(jbuf))
        is_exec = cexecve(argv[1], (const char **)&argv[2], (const char **)envp, 1);

    if (is_exec < 0)
        exit(-1);

    asm("advance:");
    printf("return success! welcome!!\n");

out:
    _exit(0);
}

int cexecve(const char *filename, const char *argv[], const char *envp[], int is_start)
{
    struct usrld_binprm *bprm;
    FILE *fp;
    int retval;

    if (!filename)
        return -1;

    retval = -ENOMEM;
    // bprm = malloc(sizeof(struct usrld_binprm));
    bprm = load_mem_pool(sizeof(struct usrld_binprm));

    if (!bprm)
        goto out_ret;
#ifdef DPAGER
    list_init(&bprm->dpage_list);
#endif

    list_init(&bprm->map_list);

    retval = -EBADFD;

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

    // instead of copy_strings_kernel
    retval = copy_strings(1, &bprm->filename, bprm);
    if (retval < 0)
        goto out_free;

    bprm->exec = bprm->p;
    retval = copy_strings(bprm->envc, envp, bprm);
    if (retval < 0)
        goto out_free;

    retval = copy_strings(bprm->argc, argv, bprm);
    if (retval < 0)
        goto out_free;

    target_bprm = bprm;
    if (is_start)
    {
        retval = exec_binprm(bprm);
        if (retval < 0)
            goto out_free;

        start_thread(bprm->mm->start_code, bprm->elf_entry, bprm->p);
    }
out_free:
    // free(bprm);

out_ret:
    if (retval)
        printf("there was some error\n");
    return retval;
}

int bprm_mm_init(struct usrld_binprm *bprm)
{
    struct usrld_mm_struct *mm = NULL;
    // bprm->mm = mm = malloc(sizeof(struct usrld_mm_struct));
    bprm->mm = mm = load_mem_pool(sizeof(struct usrld_mm_struct));
    if (!mm)
        return -ENOMEM;

    struct usrld_vma_struct *vma = NULL;

    // bprm->vma = vma = calloc(1, sizeof(struct usrld_vma_struct));
    bprm->vma = vma = load_mem_pool(sizeof(struct usrld_vma_struct));
    if (!vma)
        return -ENOMEM;

    // __bprm_init
    vma->vm_mm = mm;

    // read rsp to configure program stack top
    register long rsp asm("rsp");
    unsigned long USRLD_STACK_TOP = usrld_randomize_stack_top(rsp);
    vma->vm_end = USRLD_STACK_TOP;
    vma->vm_start = vma->vm_end - PAGE_SIZE;

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

    int fd = open(bprm->filename, O_RDONLY);
    read(fd, bprm->buf, USRLD_BINPRM_BUF_SIZE);
    close(fd);

    return 1;
}

int search_binary_handler(struct usrld_binprm *bprm)
{
    int retval;

    if (bprm->recursion_depth > 5)
        return -ELOOP;

    retval = -ENOENT;

    // ignore fmt search loop, just go to elf
    bprm->recursion_depth++;
    retval = load_binary(bprm);
    bprm->recursion_depth--;

    if (retval < 0 && !bprm->mm)
    {
        //force sigsegv
        return retval;
    }
    if (retval != -ENOEXEC)
    {
        return retval;
    }

    return retval;
}

int exec_binprm(struct usrld_binprm *bprm)
{
    int ret;

    ret = search_binary_handler(bprm);

    return ret;
}

static int copy_strings(int argc, const char *argv[],
                        struct usrld_binprm *bprm)
{
    int ret;

    while (argc-- > 0)
    {
        const char *str;
        int len;
        unsigned long pos;

        ret = -EFAULT;
        str = argv[argc];
        if (!str)
            goto out;

        len = strlen(str) + 1; // NULL 포함 (원래는 그렇다)
        if (!len)
            goto out;

        if (IS_DEBUG)
            printf("copying len=%d, %s\n", len, str);

        ret = -E2BIG;
        if (!(len <= MAX_ARG_STRLEN))
            goto out;

        pos = bprm->p;
        // str += len;
        bprm->p -= len;

        if (bprm->p < bprm->argmin)
            goto out;

        memcpy((void *)bprm->p, str, len);
    }
    ret = 0;
out:
    return ret;
}

int setup_arg_pages(struct usrld_binprm *bprm,
                    unsigned long stack_top,
                    int executable_stack)
{
    unsigned long ret;
    unsigned long stack_shift;
    // struct usrld_mm_struct *mm = bprm->mm;
    struct usrld_vma_struct *vma = bprm->vma;
    struct usrld_vma_struct *prev = NULL;
    unsigned long vm_flags;
    unsigned long stack_base;
    unsigned long stack_size;
    unsigned long stack_expand;
    unsigned long rlim_stack;

    stack_top = stack_top & ~((unsigned long)0xf); // arch_align_stack
    stack_top = PAGE_ALIGN(stack_top);

    bprm->mm->arg_start = bprm->p;

    bprm->mm->start_stack = bprm->p;

    // omit stack_shift: bprm_mm_init에서 이미 randomize를 했기 때문
}

void register_exit_func(void *atexit_addr, void (*func)(void))
{

    if (IS_DEBUG)
        printf("pushing func@%p with atexit@%p\n", func, atexit_addr);
    asm("movq %0, %%rdi" ::"r"(func));
    asm("movq $0, %rsi");
    asm("movq $0, %rdx");
    asm("call *%0" ::"r"(atexit_addr));
}

extern struct bprm_thread *cur_bprmthd;

void rtl_advanced()
{
    if (IS_DEBUG)
        printf("rtl_advance started\n");
    if (!is_thread_mode)
    {
        finalize_bprm(target_bprm);

        if (loading_binary == 1)
            longjmp(jbuf1, 1);
        else if (loading_binary == 2)
            longjmp(jbuf2, 1);
        else
            longjmp(jbuf, 1);
    }
    else
    {
        // we are using thread mode
        finalize_bprm(cur_bprmthd->bprm);
        list_remove(&cur_bprmthd->elem);
        sched(&bprm_thread_list);
        printf("finishing thread %s\n", cur_bprmthd->bprm->filename);
        longjmp(jbuf, 1);
    }
}

void finalize_bprm(struct usrld_binprm *bprm)
{
    struct list_elem *e;
    for (e = list_begin(&bprm->map_list);
         e != list_end(&bprm->map_list);
         e = list_next(e))
    {
        struct map_entry *mentry = list_entry(e, struct map_entry, elem);
        if (IS_DEBUG)
            printf("munmap %p, %d\n", mentry->addr, mentry->len);
        void *addr = mentry->addr;
        size_t len = mentry->len;
        int r = munmap(addr, len);
        if (r < 0)
            exit(1);
    }
}

#ifdef DPAGER
void sig_segv_handler(int signo, siginfo_t *info, void *ucontext)
{
    if (IS_DEBUG)
        printf("received SIGSEGV @%p\n", info->si_addr);
    if (info->si_addr == NULL)
    {
        printf("Segmentation fault (core not dumped:))\n");
        _exit(-1);
    }
    if (elf_map_dpage(target_bprm, (unsigned long)info->si_addr) < 0)
    {
        printf("failed mapping exe @%p\n", info->si_addr);
        _exit(-1);
    }
}

#endif