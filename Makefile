CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDLIBS  = -lsodium -lsqlite3

pwmanager: main.c backend.c backend.h
	$(CC) $(CFLAGS) main.c backend.c -o $@ $(LDLIBS)

clean:
	rm -f pwmanager

.PHONY: clean
