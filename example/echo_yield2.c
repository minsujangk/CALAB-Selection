#include <stdio.h>
#include "../thread.h"

int main(int argc, char *argv[])
{
    init_thread();
    int i = 4;
    i += 3;
    printf("yield2: part1 %d\n", i);

    yield();

    i += 2;
    printf("yield2: part2 %d\n", i);

    yield();

    printf("yield2: part3\n");

    yield();
    
    printf("yield2: part4\n");
}