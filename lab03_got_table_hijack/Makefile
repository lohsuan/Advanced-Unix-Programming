.PHONY: clean server test run

all: libsolver libmaze maze

### -Wl,-rpath,. is to add the current directory to the runtime library search path
maze: maze.c libmaze libsolver
	# gcc -g -o maze maze.c -Wall -L. -lmaze -Wl,-rpath,. 
	gcc -z now -g -o maze maze.c -Wall -L. -lmaze -Wl,-rpath,. 

### generates libmaze.so (shared) library
libmaze: libmaze_dummy.c
	gcc -shared -o libmaze.so -fPIC libmaze_dummy.c

### generates libsolver.so (shared) library
libsolver: libsolver.c
	gcc -shared -o libsolver.so -fPIC libsolver.c -ldl

### generates libsolver.so (shared) library in cross-compile container
### the server environment need "x86 binary"
server:
	rm -f libsolver.so
	x86_64-linux-gnu-gcc -o libsolver.so -shared -fPIC libsolver.c -ldl

### injected libsolver.so library to maze
run:
	LD_PRELOAD=./libsolver.so ./maze 


clean:
	rm -f *.o maze libmaze.so libsolver.so

test:
	python3 submit.py libsolver.so 