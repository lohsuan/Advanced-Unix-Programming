#ifndef __LIBMAZE_H__
#define __LIBMAZE_H__

#define _MAZE_MAXY	101
#define _MAZE_MAXX	101

typedef struct maze_s {
	int w, h;                         // width, height
	int sx, sy;                       // start position (x, y)
	int ex, ey;                       // end position (x, y)
	int cx, cy;                       // current positoin (x, y)
	int blk[_MAZE_MAXY][_MAZE_MAXX];  // content: zero - roads; non-zero - walls
}	maze_t;

int maze_init();                      // initialize the library
void maze_set_ptr(void * ptr);        // set a pointer into the library
void * maze_get_ptr();                // get a pointer previously set by `maze_set_main`
maze_t * maze_load(const char *path); // load a maze from a file
void maze_free(maze_t *mz);           // release a loaded a maze
void move_up(maze_t *mz);             // move the current position of `mz` one step up (if moveable)
void move_down(maze_t *mz);           // move the current position of `mz` one step down (if moveable)
void move_left(maze_t *mz);           // move the current position of `mz` one step to the left (if moveable)
void move_right(maze_t *mz);          // move the current position of `mz` one step to the right (if moveable)

#define MOVE(n)	void move_##n(maze_t *mz);
#include "moves.c"                    // move_NNN: perform one step random movement
#undef MOVE

#endif /* __LIBMAZE_H__ */
