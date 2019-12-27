#include "uthread.h"
#include "setjmp.h"
#include "binfmts.h"
#include "exec.h"
#include "string.h"

struct bprm_thread *cur_bprmthd;

void sched(struct list *t_list)
{
    struct list_elem *e;
    for (e = list_begin(t_list); e != list_end(t_list); e = list_next(e))
    {
        struct bprm_thread *bprmthd = list_entry(e, struct bprm_thread, elem);

        // just choose any other bprm, but if it is the only thread, reschedule it
        if (bprmthd == cur_bprmthd && list_next(e) != list_end(t_list))
            continue;

        // push current thread to back for fair scheduling
        list_remove(e);
        list_push_back(t_list, e);

        cur_bprmthd = bprmthd;
        printf("\nscheduling thread %s\n", bprmthd->bprm->filename);
        if (bprmthd->is_jbuf_set)
        {
            restore_bprm(bprmthd);
            longjmp(bprmthd->jbuf, 1);
        }
        else
        {
            load_binary(bprmthd->bprm);
            start_thread(bprmthd->bprm->mm->start_code, bprmthd->bprm->elf_entry, bprmthd->bprm->p);
        }

        // control never reach here
    }
}

void yield()
{
    if (!setjmp(cur_bprmthd->jbuf))
    {
        cur_bprmthd->is_jbuf_set = 1;
        store_bprm(cur_bprmthd);
        sched(&bprm_thread_list); // if setjmp called by an user program, continue
    }
    return; // else if setjmp returned from sched:longjmp, return to the user program
}

void store_bprm(struct bprm_thread *bprmthd)
{
    struct store_info *s_info = &bprmthd->s_info;

    struct usrld_binprm *bprm = bprmthd->bprm;

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

        struct store_mapping *s_map = &s_info->smap[s_info->count++];
        s_map->loc_orig = addr;
        s_map->loc_save = load_mem_pool(len);
        memcpy(s_map->loc_save, addr, len);
        s_map->len = len;

        int r = munmap(addr, len);
        if (r < 0)
        {
            printf("unmap %p error\n", addr);
            _exit(1);
        }
    }
}
void restore_bprm(struct bprm_thread *bprmthd)
{
    struct store_info *sinfo = &bprmthd->s_info;
    int i;
    for (i = 0; i < sinfo->count; i++)
    {
        void *mmap_addr = mmap(sinfo->smap[i].loc_orig, sinfo->smap[i].len,
                               PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (!mmap_addr)
            _exit(-1);
        memcpy(mmap_addr, sinfo->smap[i].loc_save, sinfo->smap[i].len);
    }
    sinfo->count = 0; // initialize to use it again
}