CC = gcc
CFLAGS = -g

all: apager dpager

apager : pager.c mm.c prm_loader.c amm.c list.c support.c
	$(CC) $(CFLAGS) -o apager pager.c mm.c prm_loader.c amm.c list.c support.c
dpager : pager.c mm.c dmm.c prm_loader.c list.c support.c
	$(CC) $(CFLAGS) -o dpager pager.c mm.c dmm.c prm_loader.c list.c support.c

clean : 
	rm *.o apager dpager