#include "prm_loader.h"
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

int execv(const char *filename, char *argv[])
{
    struct exec_prm *eprm;

    eprm = malloc(sizeof(struct exec_prm));
    eprm->filename = filename;

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        exit(-1);
    eprm->fd = fd;

    struct stat stat;
    fstat(eprm->fd, &stat);
    eprm->file_length = stat.st_size;

    eprm->mpinfo = malloc(sizeof(struct mm_prm_info));
    list_init(&eprm->mpinfo->map_list);

    int is_init = mm_init_exec(eprm);
    if (is_init < 0)
        exit(-1);

    // jmp to target excutable

    free(eprm->mpinfo);
    free(eprm);

    return 1;
}