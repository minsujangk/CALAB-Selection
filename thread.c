#include "thread.h"
#include <stdio.h>

unsigned long yield_func;

void init_thread()
{
    // get yield address of uthread.c
    asm("movq %%r15, %0"
        : "=r"(yield_func));
    asm("movq $0, %r15");
}

void yield()
{
    // call yield function of uthread.c
    asm("call *%0" ::"r"(yield_func));
}