#ifndef __MAZEMOD_H__
#define __MAZEMOD_H__

#include <asm/ioctl.h>

#define _MAZE_MAXUSER 3
#define _MAZE_MAXX    101
#define _MAZE_MAXY    101

typedef struct {
	int x, y;
}	coord_t;

typedef struct {
	int w, h;
	int sx, sy;		// initial position
	int ex, ey;		// target  position
	int cx, cy;		// current position
	char blk[_MAZE_MAXY][_MAZE_MAXX];
}	maze_t;

#define MAZE_CREATE   _IOW('M', 0, coord_t)
#define	MAZE_RESET    _IO ('M', 1)
#define	MAZE_DESTROY  _IO ('M', 2)

#define MAZE_GETSIZE  _IOR('M', 11, coord_t)
#define MAZE_MOVE     _IOW('M', 12, coord_t)
#define MAZE_GETPOS   _IOR('M', 13, coord_t)
#define MAZE_GETSTART _IOR('M', 14, coord_t)
#define MAZE_GETEND   _IOR('M', 15, coord_t)

#ifndef __KERNEL__
void maze_render_raw(maze_t *m, int cx, int cy, int shownum);
void maze_render_box(maze_t *m, int cx, int cy, int shownum);
#endif

#endif
