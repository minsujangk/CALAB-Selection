#include <stdio.h>
#include "../uthread.h"

int main(int argc, char *argv[])
{
    int i = 4;
    i += 3;
    printf("yield2: part1 %d\n", i);

    yield();

    i += 2;
    printf("yield2: part2 %d\n", i);
}