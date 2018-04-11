whatever: whatever.c
	$(CC) -static -o whatever -ansi -pedantic -O3 -Wall whatever.c

clean:
	rm -f whatever

all: whatever
