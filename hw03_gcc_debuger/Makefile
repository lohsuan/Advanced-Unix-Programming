CC := g++
CFLAGS := -std=c++14 -g -Wall -Wextra -Werror
LDLIBS := -lcapstone

.PHONY: all clean

all: sdb

sdb: sdb.cpp
	$(CC) $^ $(CFLAGS) -o $@ $(LDLIBS) $(LDFLAGS)

clean:
	rm -f sdb
