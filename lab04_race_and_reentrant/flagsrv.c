/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <list>
#include <string>
using namespace std;

#define	xerror(x)	{ perror(x); exit(-1); }
#define	NIPQUAD(x)	((uint8_t*) &(x))[0], ((uint8_t*) &(x))[1], ((uint8_t*) &(x))[2], ((uint8_t*) &(x))[3]

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cond = PTHREAD_COND_INITIALIZER;
static list<string> jobs;
static string status[2];

void update_status(long id, string pfx, string msg) {
	pthread_mutex_lock(&mutex);
	status[id] = "[" + pfx + "] " + msg;
	pthread_mutex_unlock(&mutex);
}

void do_job(long id, string server) {
	int i, rlen, port;
	struct sockaddr_in sin;
	struct hostent *ent;
	char buf[1024], addr[64], *tok, *saveptr;
	static const char cmd[] = "GET /\r\n";

	snprintf(buf, sizeof(buf), "%s", server.c_str());
	if((tok = strtok_r(buf, "/", &saveptr)) == NULL) {
		update_status(id, server, "Incorrect server input!");
		return;
	}
	strncpy(addr, tok, sizeof(addr));
	if((tok = strtok_r(NULL, "/", &saveptr)) == NULL) {
		update_status(id, server, "Incorrect server input!");
		return;
	}
	port = atoi(tok);

	if((ent = gethostbyname2(addr, AF_INET)) == NULL) {
		update_status(id, server, "Resolve failed.");
		return;
	}

	if(*((uint32_t*) ent->h_addr_list[0]) == htonl(0x7f000001)) {
		update_status(id, server, "Get from localhost is not allowed!");
		return;
	}

	if(*((uint32_t*) ent->h_addr_list[0]) == 0) {
		update_status(id, server, "Get from * is not allowed!");
		return;
	}

	for(i = 0; i < 2; i++) {
		int s = -1;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
		sin.sin_addr.s_addr = *((uint32_t*) ent->h_addr_list[0]);
		snprintf(buf, sizeof(buf), "Connecting to %u.%u.%u.%u:%u ... (%d)", NIPQUAD(sin.sin_addr.s_addr), ntohs(sin.sin_port), i+1);
		update_status(id, server, buf);

		if((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) goto try_again;
		if(connect(s, (struct sockaddr*) &sin, sizeof(sin)) < 0) goto try_again;
		if(write(s, cmd, sizeof(cmd)-1) < 0) goto try_again;
		if((rlen = read(s, buf, sizeof(buf)-1)) <= 0) goto try_again;

		buf[rlen] = '\0';
		for(i = 0; i < rlen; i++) {
			if(isspace(buf[i])) buf[i] = ' ';
			else if(!isprint(buf[i])) buf[i] = '.';
		}
		/* got it! */
		update_status(id, server, buf);
		break;
try_again:
		update_status(id, server, strerror(errno));
		if(s >= 0) close(s);
	}
}

void * threadproc(void *args) {
	long myid = (long) args;
	while(1) {
		string s = "";
		pthread_mutex_lock(&mutex);
get_job:
		if(jobs.size() > 0) {
			s = jobs.front();
			jobs.pop_front();
		}
		if(s == "") {
			if((errno = pthread_cond_wait(&cond, &mutex)) != 0) xerror("wait");
			goto get_job;
		}
		pthread_mutex_unlock(&mutex);

		do_job(myid, s);
	}
	return NULL;
}

void add_job(string s) {
	pthread_mutex_lock(&mutex);
	jobs.push_back(s);
	pthread_mutex_unlock(&mutex);
	pthread_cond_signal(&cond);
}

void check_job() {
	int i = 0;
	list<string>::iterator li;
	printf("\n==== Pending Jobs ====\n\n");
	pthread_mutex_lock(&mutex);
	for(i = 0, li = jobs.begin(); li != jobs.end(); i++, li++)
		printf("  #%-3d server = %s\n", i+1, (*li).c_str());
	pthread_mutex_unlock(&mutex);
}

void view_job() {
	printf("\n==== Job Status ====\n\n");
	pthread_mutex_lock(&mutex);
	printf("Job #1: %s\n", status[0] == "" ? "<none>" : status[0].c_str());
	printf("Job #2: %s\n", status[1] == "" ? "<none>" : status[1].c_str());
	pthread_mutex_unlock(&mutex);
}

char menu() {
	char buf[64];
	printf("\n==== Menu ====\n\n"
		"[g] get flag from a server\n"
		"[c] check job queue\n"
		"[v] view job status\n"
		"[q] quit\n"
		"\nWhat do you want to do? ");
	if(fgets(buf, sizeof(buf), stdin) == NULL) return '?';
	return buf[0];
}

int main() {
	char c, buf[256], *ptr;
	pthread_t tid;

	setvbuf(stdin,  NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if((errno = pthread_create(&tid, NULL, threadproc, (void*) 0)) != 0) xerror("thread");
	if((errno = pthread_create(&tid, NULL, threadproc, (void*) 1)) != 0) xerror("thread");

	printf("Welcome to the GetFlag Service!\n");
	while((c = menu()) != 'q') {
		switch(c) {
		case 'g':
			printf("Enter flag server addr/port: ");
			if(fgets(buf, sizeof(buf), stdin) != NULL
			&&(ptr = strtok(buf, " \t\n\r")) != NULL) {
				add_job(ptr);
				printf("New job added: %s\n", ptr);
			} else {
				printf("Bad user input!\n");
			}
			break;
		case 'c':
			check_job();
			break;
		case 'v':
			view_job();
			break;
		default:
			printf("\nUnknown command. Please don't hack me! Q_Q\n");
		}
	}
	printf("\nThank you for using our service. Bye!\n");
	return 0;
}
