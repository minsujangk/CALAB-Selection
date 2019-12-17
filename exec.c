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

static unsigned long usrld_randomize_stack_top(unsigned long stack_top);

int loading_binary = 0;
unsigned long saved_rsp;
unsigned long saved_rbp;
unsigned long saved_rax;
unsigned long saved_rbx;
unsigned long saved_rcx;
unsigned long saved_rdx;
unsigned long saved_rsi;
unsigned long saved_rdi;
unsigned long saved_r8;
unsigned long saved_r9;
unsigned long saved_r10;
unsigned long saved_r11;
unsigned long saved_r12;
unsigned long saved_r13;
unsigned long saved_r14;
unsigned long saved_r15;
short saved_fs;
short saved_gs;
short saved_ds;
short saved_es;

const char *bin1;
const char **argv1;
const char *bin2;
const char **argv2;

int old_argc;
char **old_argv;
char **old_envp;

int main(int argc, char *argv[], char *envp[])
{
    srand(time(NULL));

#ifdef DPAGER
    struct sigaction act = {0};
    act.sa_sigaction = sig_segv_handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, NULL);
#endif

    printf("perhaps.. %p\n", &atexit);
    // register_exit_func(&atexit, &rtl_advanced);
    // atexit(&rtl_advanced);

    int i;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-2") == 0)
        {
            loading_binary = 1;
            argv[i] = NULL; // change for first binary

            // -2 이후에는 다음 바이너리.
            bin1 = argv[1];
            argv1 = (const char **)&argv[2];
            bin2 = argv[i + 1];
            argv2 = (const char **)&argv[i + 2];

            asm("movq %%rbp, %0"
                : "=r"(saved_rbp));
            asm("movq %%rsp, %0"
                : "=r"(saved_rsp));
            asm("movq %%rax, %0"
                : "=r"(saved_rax));
            asm("movq %%rbx, %0"
                : "=r"(saved_rbx));
            asm("movq %%rcx, %0"
                : "=r"(saved_rcx));
            asm("movq %%rdx, %0"
                : "=r"(saved_rdx));
            asm("movq %%rsi, %0"
                : "=r"(saved_rsi));
            asm("movq %%rdi, %0"
                : "=r"(saved_rdi));

            asm("movq %%r8, %0"
                : "=r"(saved_r8));
            asm("movq %%r9, %0"
                : "=r"(saved_r9));
            asm("movq %%r10, %0"
                : "=r"(saved_r10));
            asm("movq %%r11, %0"
                : "=r"(saved_r11));
            asm("movq %%r12, %0"
                : "=r"(saved_r12));
            asm("movq %%r13, %0"
                : "=r"(saved_r13));
            asm("movq %%r14, %0"
                : "=r"(saved_r14));
            asm("movq %%r15, %0"
                : "=r"(saved_r15));

            asm("mov %%fs, %0"
                : "=r"(saved_fs));
            asm("mov %%gs, %0"
                : "=r"(saved_fs));
            asm("mov %%ds, %0"
                : "=r"(saved_fs));
            asm("mov %%es, %0"
                : "=r"(saved_fs));

            int is_exec = cexecve(bin1, argv1, (const char **)envp);

            asm("advance1:");
            printf("alright! let's go to binary 2: %s\n", bin2);
            loading_binary = 2;

            is_exec = cexecve(bin2, argv2, (const char **)envp);
            asm("advance2:");
            printf("all done!\n");

            goto out;
        }
    }

    int is_exec = cexecve(argv[1], (const char **)&argv[2], (const char **)envp);

    if (is_exec < 0)
        exit(-1);

    asm("advance:");
    printf("return success! welcome!!\n");
out:
    return 0;
}

static struct usrld_binprm init_bprm;
struct usrld_binprm *target_bprm = &init_bprm;

int cexecve(const char *filename, const char *argv[], const char *envp[])
{
    struct usrld_binprm *bprm;
    FILE *fp;
    int retval;

    if (!filename)
        return -1;

    retval = -ENOMEM;
    void *ff = malloc(sizeof(struct usrld_binprm));
    // bprm = ff;
    bprm = &init_bprm;
    if (!bprm)
        goto out_ret;
#ifdef DPAGER
    list_init(&bprm->dpage_list);
#endif
    list_init(&bprm->map_list);

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

    retval = exec_binprm(bprm);
    if (retval < 0)
        goto out_free;

out_free:
    free(bprm);

out_ret:
    printf("exited here?\n");
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
    random_variable &= 0x1ff; // 2MB mask not to exceed stack limit (8MB)
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
    if (retval != -ENOEXEC || !bprm->fp)
    {
        return retval;
    }

    return retval;
}

static int exec_binprm(struct usrld_binprm *bprm)
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

    printf("pushing func@%p with atexit@%p\n", func, atexit_addr);
    asm("movq %0, %%rdi" ::"r"(func));
    asm("movq $0, %rsi");
    asm("movq $0, %rdx");
    asm("call *%0" ::"r"(atexit_addr));
}

void rtl_advanced()
{
    // finalize_bprm(target_bprm);
    printf("htshidsfs %p\n", saved_rsp);

    // asm("movq %0, %%rax" ::"r"(saved_rax));
    // asm("movq %0, %%rbx" ::"r"(saved_rbx));
    // asm("movq %0, %%rcx" ::"r"(saved_rcx));
    // asm("movq %0, %%rdx" ::"r"(saved_rdx));
    // asm("movq %0, %%rsi" ::"r"(saved_rsi));
    // asm("movq %0, %%rdi" ::"r"(saved_rdi));

    // asm("movq %0, %%r8" ::"r"(saved_r8));
    // asm("movq %0, %%r9" ::"r"(saved_r9));
    // asm("movq %0, %%r10" ::"r"(saved_r10));
    // asm("movq %0, %%r11" ::"r"(saved_r11));
    // asm("movq %0, %%r12" ::"r"(saved_r12));
    // asm("movq %0, %%r13" ::"r"(saved_r13));
    // asm("movq %0, %%r14" ::"r"(saved_r14));
    // asm("movq %0, %%r15" ::"r"(saved_r15));

    // asm("mov %0, %%fs" ::"r"(saved_fs));
    // asm("mov %0, %%gs" ::"r"(saved_gs));
    // asm("mov %0, %%ds" ::"r"(saved_ds));
    // asm("mov %0, %%es" ::"r"(saved_es));
    short v = 0;

    // asm("movq $0, %rax");
    // asm("movq $0, %rbx");
    // asm("movq $0, %rcx");
    // asm("movq $0, %rdx");

    // asm("movq $0, %rsi");
    // asm("movq $0, %rdi");

    // asm("movq $0, %r8");
    // asm("movq $0, %r9");
    // asm("movq $0, %r10");
    // asm("movq $0, %r11");
    // asm("movq $0, %r12");
    // asm("movq $0, %r13");
    // asm("movq $0, %r14");
    // asm("movq $0, %r15");

    // asm("mov %0, %%fs" ::"r"(v));
    // asm("mov %0, %%gs" ::"r"(v));
    // asm("mov %0, %%ds" ::"r"(v));
    // asm("mov %0, %%es" ::"r"(v));
    // unsigned long cur_rsp;
    // asm("movq %%rsp, %0"
    //     : "=r"(cur_rsp));
    // memset(cur_rsp, 0, saved_rsp - cur_rsp);

    // asm("movq %0, %%rbp" ::"r"(saved_rbp));
    // asm("movq %0, %%rsp" ::"r"(saved_rsp));

    if (loading_binary == 1)
        asm("jmp advance1");
    else if (loading_binary == 2)
        asm("jmp advance2");
    else
        asm("jmp advance");
}

void finalize_bprm(struct usrld_binprm *bprm)
{
    struct list_elem *e;
    for (e = list_begin(&bprm->map_list);
         e != list_end(&bprm->map_list);
         e = list_next(e))
    {
        struct map_entry *mentry = list_entry(e, struct map_entry, elem);
        printf("munmap %p, %d\n", mentry->addr, mentry->len);
        void *addr = mentry->addr;
        size_t len = mentry->len;
        free(mentry);
        int r = munmap(addr, len);
        if (r < 0)
            exit(1);
        // free(mentry);
    }

    // // struct list_elem *e;
    // for (e = list_begin(&bprm->map_list);
    //      e != list_end(&bprm->map_list);
    //      e = list_next(e))
    // {
    //     struct map_entry *mentry = list_entry(e, struct map_entry, elem);
    //     printf("munmap %p, %d\n", mentry->addr, mentry->len);
    //     void *addr = mentry->addr;
    //     size_t len = mentry->len;
    //     free(mentry);
    //     int r = munmap(addr, len);
    //     if (r < 0)
    //         exit(1);
    //     // free(mentry);
    // }

    // free(bprm->mm);
    // free(bprm->vma);
    // free(bprm);
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