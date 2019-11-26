//
// Created by ms.jang on 2019-11-25.
//

#include <stdio.h>
#include <stdlib.h>
#include "pager.h"
#include "prm_loader.h"
#include <signal.h>

int main(int argc, char *argv[])
{

    // signal(SIGSEGV, (void *)sig_segv_handler);

    int is_exec;
    if (argc == 2)
    {
        is_exec = execv(argv[0], NULL);
    }
    else
    {
        is_exec = execv(argv[0], &argv[1]);
    }

    if (is_exec < 0)
        exit(-1);
}

void sig_segv_handler(int signo)
{
    printf("received SIGSEV\n");
}