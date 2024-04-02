#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmaze.h"

static void *__stored_ptr = NULL;


int maze_init() {
    fprintf(stderr, "MAZE: library init - stored pointer = %p.\n", __stored_ptr);
    return 0;
}

void maze_set_ptr(void *ptr) {
    __stored_ptr = ptr;
}

void *
maze_get_ptr() {
    return __stored_ptr;
}

maze_t *
maze_load(const char *fn) {
	

    maze_t *mz = NULL;
    FILE *fp = NULL;
    int i, j, k;
    //
    if ((fp = fopen(fn, "rt")) == NULL) {
        fprintf(stderr, "MAZE: fopen failed - %s.\n", strerror(errno));
        return NULL;
    }
    if ((mz = (maze_t *)malloc(sizeof(maze_t))) == NULL) {
        fprintf(stderr, "MAZE: alloc failed - %s.\n", strerror(errno));
        goto err_quit;
    }
    if (fscanf(fp, "%d %d %d %d %d %d", &mz->w, &mz->h, &mz->sx, &mz->sy, &mz->ex, &mz->ey) != 6) {
        fprintf(stderr, "MAZE: load dimensions failed - %s.\n", strerror(errno));
        goto err_quit;
    }
    mz->cx = mz->sx;
    mz->cy = mz->sy;
    for (i = 0; i < mz->h; i++) {
        for (j = 0; j < mz->w; j++) {
            if (fscanf(fp, "%d", &k) != 1) {
                fprintf(stderr, "MAZE: load blk (%d, %d) failed - %s.\n", j, i, strerror(errno));
                goto err_quit;
            }
            mz->blk[i][j] = k << 20;
        }
    }
    fclose(fp);
    fprintf(stderr, "MAZE: loaded [%d, %d]: (%d, %d) -> (%d, %d)\n",
            mz->w, mz->h, mz->sx, mz->sy, mz->ex, mz->ey);
    return mz;
err_quit:
    if (mz) free(mz);
    if (fp) fclose(fp);
    return NULL;
}

void maze_free(maze_t *mz) {
    free(mz);
}

static int _dirx[] = {0, 0, -1, 1};
static int _diry[] = {-1, 1, 0, 0};

static void
move_dir(maze_t *mz, int d) {
    int nx = mz->cx + _dirx[d];
    int ny = mz->cy + _diry[d];
    //
    if (mz->blk[ny][nx] != 0) return;
    mz->cx = nx;
    mz->cy = ny;
    // reach the END
    if (mz->cx == mz->ex && mz->cy == mz->ey) {
        printf("\nBingo!\n");
        exit(0);
    }
}

void move_up(maze_t *mz) { move_dir(mz, 0); 
    printf("u ");
}
void move_down(maze_t *mz) { move_dir(mz, 1); 
    printf("d ");
}
void move_left(maze_t *mz) { move_dir(mz, 2); 
    printf("l ");
}
void move_right(maze_t *mz) { move_dir(mz, 3); 
    printf("r ");
}
void move_random(maze_t *mz) { move_dir(mz, rand() % 4); 
}

#define MOVE(n) \
    void move_##n(maze_t *mz) { move_random(mz); }
#include "moves.c"
#undef MOVE
