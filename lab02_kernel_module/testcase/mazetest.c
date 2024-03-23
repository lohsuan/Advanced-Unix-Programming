#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "maze.h"

typedef int (*testcase_t)();

static int mz_open() { return open("/dev/maze", O_RDWR); }

static int mz_create(int fd, int x, int y) {
	coord_t c = { x, y };
	fprintf(stderr, "OP: MAZE_CREATE %d %d\n", x, y);
	return ioctl(fd, MAZE_CREATE, &c);
}
static int mz_reset(int fd) {
	fprintf(stderr, "OP: MAZE_RESET\n");
	return ioctl(fd, MAZE_RESET, NULL); }
static int mz_destroy(int fd) {
	fprintf(stderr, "OP: MAZE_DESTROY\n");
	return ioctl(fd, MAZE_DESTROY, NULL); }
static int mz_get_size(int fd, coord_t *coord) {
	fprintf(stderr, "OP: MAZE_GETSIZE\n");
	return ioctl(fd, MAZE_GETSIZE, coord); }
static int mz_get_pos(int fd, coord_t *coord) {
	fprintf(stderr, "OP: MAZE_GETPOS\n");
	return ioctl(fd, MAZE_GETPOS, coord); }
static int mz_get_start(int fd, coord_t *coord) {
	fprintf(stderr, "OP: MAZE_GETSTART\n");
	return ioctl(fd, MAZE_GETSTART, coord); }
static int mz_get_end(int fd, coord_t *coord) {
	fprintf(stderr, "OP: MAZE_GETEND\n");
	return ioctl(fd, MAZE_GETEND, coord); }
static int mz_move(int fd, int x, int y) {
	coord_t c = { x, y };
	fprintf(stderr, "OP: MAZE_MOVE %d %d\n", x, y);
	return ioctl(fd, MAZE_MOVE, &c);
}

static void banner(const char *m) {
	fprintf(stderr, "### %s ###\n", m);
}

static int
case_cat_proc() {
	banner("case - cat /proc/maze");
	return system("cat /proc/maze");
}

static int
case_illegal() {
	int fd;
	coord_t coord;
	banner("case - illegal operations (w/o create first)");
	if((fd = mz_open()) < 0) return fd;
	if(mz_create(fd, -1, -1) < 0)    perror("mz_create(-1, -1)");
	if(mz_get_size(fd, &coord) < 0)  perror("mz_get_size");
	if(mz_get_pos(fd, &coord) < 0)   perror("mz_get_pos");
	if(mz_get_start(fd, &coord) < 0) perror("mz_get_start");
	if(mz_get_end(fd, &coord) < 0)   perror("mz_get_end");
	if(mz_move(fd, 0, -1) < 0)       perror("mz_move");
	close(fd);
	return 0;
}

static int
_case_create1() {
	int fd, x, y;
	if((fd = mz_open()) < 0) return -1;
	x = 3 + rand() % 40;
	y = 3 + rand() % 20;
	if(x % 2 == 0) x++;
	if(y % 2 == 0) y++;
	if(mz_create(fd, x, y) < 0) return -1;
	return fd;
}

static int
case_create() {
	coord_t c;
	int fd;
	banner("case - create a maze");
	if((fd = _case_create1()) < 0) return -1;
	fprintf(stderr, "- Create maze done.\n");
	system("cat /proc/maze");
	//
	if(mz_get_size(fd, &c) < 0) return -1;
	printf("==> SIZE: %d %d\n", c.x, c.y);
	if(mz_get_start(fd, &c) < 0) return -1;
	printf("==> START: %d %d\n", c.x, c.y);
	if(mz_get_end(fd, &c) < 0) return -1;
	printf("==> END: %d %d\n", c.x, c.y);
	if(mz_get_pos(fd, &c) < 0) return -1;
	printf("==> POS: %d %d\n", c.x, c.y);
	if(mz_destroy(fd) < 0) return -1;
	close(fd);
	//
	return 0;
}

static int
case_create_and_move() {
	int fd, i, pid = getpid();
	int dirx[] = { -1, 1, 0, 0 };
	int diry[] = { 0, 0, -1, 1 };
	char cmd[128];
	banner("case - create a maze and then move");
	if((fd = _case_create1()) < 0) return -1;
	fprintf(stderr, "- Create maze done.\n");
	system("cat /proc/maze");
	for(i = 0; i < 4; i++) {
		mz_move(fd, dirx[i], diry[i]);
		snprintf(cmd, sizeof(cmd), "cat /proc/maze | grep 'pid %d'", pid);
		system(cmd);
	}
	if(mz_reset(fd) < 0) return -1;
	close(fd);
	return 0;
}

static int
case_multiuser() {
	int i, fd;
	int pids[4] = { 0 };
	int timeout = 60;
	banner("case - multiple user");
	for(i = 0; i < 4; i++) {
		pids[i] = fork();
		if(pids[i] < 0) {
			perror("fork");
			exit(-1);
		} else if(pids[i] == 0) {
			/* child */
			if((fd = _case_create1()) < 0) {
				perror("child");
				exit(-1);
			}
			sleep(1000000);
		} else {
			/* parent: do nothing */
		}
	}
	while(timeout-- > 0) {
		fprintf(stderr, "waiting for child processes ...\n");
		if(system("cat /proc/maze | grep vaccancy") != 0) {
			system("cat /proc/maze");
			break;
		}
		sleep(1);
	}
	if(timeout <= 0) fprintf(stderr, "timed out!\n");
	for(i = 0; i < 3; i++) {
		if(pids[i] > 0) kill(pids[i], SIGKILL);
	}
	return 0;
}

static maze_t _m;
static char _buf[_MAZE_MAXY*_MAZE_MAXX];

static int
case_read() {
	coord_t c;
	int fd, i, rlen;
	banner("case - create a maze and then read");
	if((fd = _case_create1()) < 0) return -1;
	fprintf(stderr, "- Create maze done.\n");
	system("cat /proc/maze");
	if(mz_get_size(fd, &c) < 0) return -1;
	_m.h = c.y;
	_m.w = c.x;
	if(mz_get_start(fd, &c) < 0) return -1;
	_m.sy = c.y;
	_m.sx = c.x;
	if(mz_get_end(fd, &c) < 0) return -1;
	_m.ey = c.y;
	_m.ex = c.x;
	if(mz_get_pos(fd, &c) < 0) return -1;
	fprintf(stderr, "- Size [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n",
		_m.w, _m.h, _m.sx, _m.sy, _m.ex, _m.ey, c.x, c.y);
	if((rlen = read(fd, _buf, sizeof(_buf))) < 0) return -1;
	if(rlen != _m.w * _m.h) {
		fprintf(stderr, "- Size mismatch: expect %d got %d\n",
			_m.w * _m.h, rlen);
		return 0;
	}
	for(i = 0; i < _m.h; i++)
		memcpy(_m.blk[i], _buf + i*_m.w, _m.w);
	maze_render_box(&_m, c.x, c.y, 1);
	return fd;
}

static int
case_randomwalk() {
	int i, cx, cy, fd = case_read();
	coord_t dir[] = { { -1, 0 }, { 1, 0 }, { 0, -1 }, { 0, 1 } };
	coord_t pos, seq[64];
	banner("case - create a maze and then read + randomwalk");
	if(fd < 0) return -1;
	cx = _m.sx;
	cy = _m.sy;
	for(i = 0; i < sizeof(seq)/sizeof(coord_t); i++) {
		int nx, ny;
		seq[i] = dir[rand() % 4];
		// run local simulation
		nx = cx + seq[i].x;
		ny = cy + seq[i].y;
		if(nx < 0 || ny < 0 || nx >= _m.w || ny >= _m.h) continue;
		if(_m.blk[ny][nx] != 0) continue;
		cx = nx;
		cy = ny;
	}
	if(write(fd, seq, sizeof(seq)) < 0) return -1;
	fprintf(stderr, "- Batch move operations sent\n");
	if(mz_get_pos(fd, &pos) < 0) return -1;
	fprintf(stderr, "- Check position\n");
	maze_render_box(&_m, cx, cy, 1);
	if(pos.x == cx && pos.y == cy) {
		fprintf(stderr, "- Check PASSED!\n");
	} else {
		fprintf(stderr, "- Check FAILED!\n");
	}
	return 0;
}

static testcase_t testcase[] = {
	case_cat_proc,
	case_illegal,
	case_create,
	case_create_and_move,
	case_multiuser,
	case_read,
	case_randomwalk,
};

int main(int argc, char *argv[]) {
	int id;

	srand(time(0));

	if(argc < 2) {
		fprintf(stderr,
				"usage: %s testcase-id\n"
				"\tvalid testcase-id: [0...%zd]\n",
				argv[0], sizeof(testcase)/sizeof(testcase_t*)-1);
		return -1;
	}

	id = strtol(argv[1], NULL, 0);
	if(id < 0 || id >= sizeof(testcase)/sizeof(testcase_t*)) {
		fprintf(stderr, "invalid testcase-id (%d) [0...%zd]\n",
			id, sizeof(testcase)/sizeof(testcase_t*)-1);
		return -2;
	}

	if(testcase[id]() < 0)
		fprintf(stderr, "case#%d: %s\n", id, strerror(errno));

	return 0;
}
