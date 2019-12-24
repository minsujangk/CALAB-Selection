#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
  printf("Hello World!\n");

  int fd = open("/proc/self/status", O_RDONLY);
  char data[4096];
  read(fd, &data, 4096);
  close(fd);
  printf("%s", data);

  return 0;
}
