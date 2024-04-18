.PHONY: all clean run rmlog

CC = gcc
CFLAGS = -Wall -g # for debugging
LDFLAGS = -shared -fPIC # for shared library

all: rmlog logger.so logger

# -ldl for dlopen, dlsym. -lpcre for pcre regex library
logger.so: liblogger.c 
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcre -ldl

logger: logger.c 
	$(CC) $(CFLAGS) -o $@ $< 

clean:
	rm -f logger logger.so
	rm  -f *.log file.txt
	rm -f mytest

rmlog:
	rm -f *.log

run: logger logger.so
	@echo "\n\033[1;32m[+] Run examples 1-1\033[0m"
	@./logger config.txt examples/ex1-1
	@echo "\n\033[1;32m[+] Run examples 1-2\033[0m"
	@./logger config.txt examples/ex1-2

	@echo "\n\033[1;32m[+] Run examples 2\033[0m"
	@./logger config.txt examples/ex2
	
	@echo "\n\033[1;32m[+] Run examples 3-1\033[0m"
	@./logger config.txt examples/ex3-1
	@echo "\n\033[1;32m[+] Run examples 3-2\033[0m"
	@./logger config.txt examples/ex3-2
	
	@echo "\n\033[1;32m[+] Run examples 4\033[0m"
	@./logger config.txt examples/ex4 www.cs.nycu.edu.tw || true
	@./logger config.txt examples/ex4 www.google.com

	@echo "\n\033[1;32m[+] Run examples 5\033[0m"
	@./logger config.txt examples/ex5 172.217.160.100 || true
	
	@echo "\n\033[1;32m[+] Run examples 5-2\033[0m"
	@./logger config.txt examples/ex5 20.27.177.113
	
	@echo "\n\033[1;32m[+] Run examples 6\033[0m"
	@./logger config.txt examples/ex6
	

mytest: mytest.c logger.so logger
	gcc -o mytest mytest.c
	./logger config.txt ./mytest