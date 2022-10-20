CC = gcc
CFLAGS = -ggdb -Wall

all: cnc

cnc.o: cnc.c cnc.h
	$(CC) $(CFLAGS) -c cnc.c

cnc: cnc.o
	$(CC) $(CFLAGS) cnc.o -o cnc
	
clean:
	rm -f *.o cnc
