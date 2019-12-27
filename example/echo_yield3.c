#include <stdio.h>
#include "../thread.h"
#include <stdlib.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
    init_thread();
    int i = 2;
    i += 3;
    printf("yield3: part1 %d\n", i);

    yield();

    i += 1;
    printf("yield3: part2 %d\n", i);

    yield();

    printf("yield3: part3\n");

    yield();

    printf("yield3: part4\n");

    int fd = open("/proc/self/status", O_RDONLY);
    char data[4096];
    read(fd, &data, 4096);
    close(fd);
    printf("%s", data);
}