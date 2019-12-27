#include <stdio.h>
#include "../uthread.h"

int main(int argc, char *argv[])
{
    int i = 2;
    i += 3;
    printf("yield1: part1 %d\n", i);

    yield();

    i += 1;
    printf("yield1: part2 %d\n", i);
}