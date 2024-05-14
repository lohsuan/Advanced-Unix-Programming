/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

static int myuid = -1;
static int basesz = -1;
static char base[PATH_MAX];
static char fortune[PATH_MAX];

#define	xerror(x)	{ perror(x); exit(-1); }

void* show_fortune(void *unused) {
	int fd;
	struct stat st;
	char buf[1024], *saveptr;

	if(stat(fortune, &st) < 0) {
		printf("ERROR> stat: %s\n", strerror(errno));
		return NULL;
	}

	if(st.st_uid != myuid) {
		printf("ERROR> this file is protected from being read by a user.\n");
		return NULL;
	}

	if((fd = open(fortune, O_RDONLY)) < 0){
		printf("ERROR> open: %s\n", strerror(errno));
		return NULL;
	}

	if(read(fd, buf, sizeof(buf)) > 0) printf("F> %s\n", strtok_r(buf, "\r\n", &saveptr));

	close(fd);

	return NULL;
}

void read_fortune(const char *fname) {
	pthread_t tid;
	char buf[PATH_MAX*2], fn[PATH_MAX*2];
	if(fname == NULL) return;
	if(fname[0] == '\0') return;
	snprintf(buf, sizeof(buf), "%s/%s", base, fname);
	if(realpath(buf, fn) == NULL) {
		printf("ERROR> realpath: %s\n", strerror(errno));
		return;
	}
	if(strncmp(fn, base, basesz) != 0) {
		printf("ERROR> access to fortune is sandboxed.\n");
		return;
	}
	if(access(fn, R_OK) < 0) {
		printf("ERROR> access: %s\n", strerror(errno));
		return;
	}
	strncpy(fortune, fn, sizeof(fortune));
	pthread_create(&tid, NULL, show_fortune, NULL);
}

void random_fortune() {
	FILE *fp;
	char buf[PATH_MAX*2];
	int count;
	snprintf(buf, sizeof(buf), "find '%s' -type f -name 'fortune*' 2>/dev/null | wc -l", base);
	if((fp = popen(buf, "r")) == NULL) return;
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	if((count = atoi(buf)) > 0) {
		snprintf(buf, sizeof(buf), "fortune%03d", rand() % count);
		read_fortune(buf);
	}
}

void list_fortune() {
	FILE *fp;
	char buf[PATH_MAX*2];
	snprintf(buf, sizeof(buf), "ls -on %s 2>/dev/null | grep ^-", base);
	if((fp = popen(buf, "r")) == NULL) return;
	printf("==== List of Fortunes ====\n");
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		if(buf[0] != '-') continue;
		printf("LIST> %s", buf);
	}
	pclose(fp);
	printf("==== End of List =========\n");
}

int main(int argc, char *argv[]) {
	char buf[PATH_MAX], *saveptr;

	myuid = getuid();
	srand(time(0) ^ getpid());

	if(argc < 2) return -fprintf(stderr, "usage: %s /root/path\n", argv[0]);

	if(myuid == 0) {
		return -fprintf(stderr, "don't run this program by root\n");
	}

	if(realpath(argv[1], base) == NULL) xerror("realpath");
	basesz = strlen(base);

	setvbuf(stdin,  NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	printf("Welcome to the UNIX Fortune database service (%d).\n", myuid);
	printf("Commands: [L] List fortunes; [R] Random fortune; [Q] Quit\n");
	printf("     .... or type a fortune name to read it.\n");

	while(fgets(buf, sizeof(buf), stdin) != NULL) {
		if(buf[0] == 'L') { list_fortune(); continue; }
		if(buf[0] == 'R') { random_fortune(); continue; }
		if(buf[0] == 'Q') { break; }
		read_fortune(strtok_r(buf, " \t\r\n", &saveptr));
	}

	printf("Thank you for using our service!\nBye!\n");

	return 0;
}
