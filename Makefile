CC = gcc

all: apager dpager

apager : pager.c amm.c list.c support.c
	$(CC) -o apager pager.c amm.c list.c support.c
dpager : pager.c dmm.c list.c support.c
	$(CC) -o dpager pager.c dmm.c list.c support.c

clean : 
	rm *.o apager dpager