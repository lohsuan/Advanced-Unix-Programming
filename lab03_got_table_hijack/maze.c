#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>
#include "libmaze.h"

int main() {
	maze_t *mz = NULL;
	maze_set_ptr(main);
	if(maze_init() != 0)
		return -1;
	if((mz = maze_load("maze.txt")) == NULL)
		return -1;
#define MOVE(n)	move_##n(mz);
#include "moves.c"
#undef MOVE
	printf("\nNo no no ...\n");
	return 0;
}

