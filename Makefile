CC = gcc
CFLAGS = -std=gnu99 -g

all: apager dpager

apager : exec.c binfmt_elf.c list.c support.c
	$(CC) $(CFLAGS) -o apager exec.c binfmt_elf.c list.c support.c uthread.c
dpager : exec.c binfmt_elf.c list.c support.c
	$(CC) $(CFLAGS) -DDPAGER -o dpager exec.c binfmt_elf.c list.c support.c uthread.c

clean : 
	rm *.o apager dpager