CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDLIBS  = -lsodium -lsqlite3

pwmanager: main.c backend.c backend.h
	$(CC) $(CFLAGS) main.c backend.c -o $@ $(LDLIBS)

# Unit tests for the parsing helpers, built with AddressSanitizer and
# UndefinedBehaviorSanitizer so memory errors fail the run.
tests/test_backend: tests/test_backend.c backend.c backend.h
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer $< -o $@ $(LDLIBS)

test: tests/test_backend
	./tests/test_backend

clean:
	rm -f pwmanager tests/test_backend

.PHONY: test clean
