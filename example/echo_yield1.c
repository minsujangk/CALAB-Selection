#include <stdio.h>
#include "../thread.h"

int main(int argc, char *argv[])
{
    init_thread();
    int i = 2;
    i += 3;
    printf("yield1: part1 %d\n", i);

    yield();

    i += 1;
    printf("yield1: part2 %d\n", i);

    
    yield();

    printf("yield1: part3\n");

    yield();
    
    printf("yield1: part4\n");
}