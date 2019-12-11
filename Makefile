CC = gcc
CFLAGS = -std=gnu99 -g 

all: apager dpager

apager : exec.c binfmt_elf.c list.c support.c
	$(CC) $(CFLAGS) -o apager exec.c binfmt_elf.c list.c support.c
# dpager : pager.c dmm.c list.c support.c
# 	$(CC) -o dpager pager.c dmm.c list.c support.c

clean : 
	rm *.o apager dpager