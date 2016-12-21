/*
 * tc.c		"tc" utility frontend.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Fixes:
 *
 * Petri Mattila <petri@prihateam.fi> 990308: wrong memset's resulted in faults
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/pkt_sched.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <syscall.h>
#include "libnetlink.h"
#include "SNAPSHOT.h"
#include "utils.h"
#include "tc_common.h"
//#include "ll_map.h"
#include "tc_util.h"
#define __USE_GNU
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <signal.h>


// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#ifdef SYS_setns
int setns(int fd, int nstype)
{
    /*return syscall(SYS_setns, fd, nstype);*/
    return syscall(308, fd, nstype);
}
#endif
#endif

extern int tc_core_init(void);
extern int do_qdisc(int argc, char **argv);

// read si
char buffer[16] = "";

int show_stats = 1;
int show_details = 0;
int show_raw = 0;
int show_pretty = 0;
int show_graph = 0;
 
int batch_mode = 0;
int resolve_hosts = 0;
int use_iec = 0;
int force = 0;
bool use_names = false;

static int filter_ifindex = 0;

struct rtnl_handle rth;

struct gnet_stats2 {
	struct gnet_stats_basic bs;
	struct gnet_stats_queue q;
	struct gnet_stats_rate_est64 re;
};

static bool gAbort = true;
void handle_signal(int signo)
{
  if (signo == SIGHUP)
  {
      fprintf(stderr, "TCShow[%d] recv SIGHUP\n", getpid());
      gAbort = false;
  }
}

int SeperateNS(char *ns) {
    // 网络隔离
    char nspath[128] = "/var/run/netns/";
    strncat(nspath, ns, 64);
    int fd = open(nspath, O_RDONLY|O_CLOEXEC);
    if (setns(fd, 0) == -1) {
        fprintf(stderr, "TCShow[%d] %s: setns on net namespace failed: %s\n",
                getpid(), ns, strerror(errno));
        close(fd);
		return -1;
    }
    close(fd);

    // mnt隔离
    unshare(CLONE_NEWNS);
    mount("", "/", "none", MS_REC|MS_SLAVE, NULL);
    umount2("/sys", MNT_DETACH);
    mount(ns, "/sys", "sysfs", 0, NULL);

    // 父进程退出子进程同步退出
    signal(SIGHUP, handle_signal);
    prctl(PR_SET_PDEATHSIG, SIGHUP);

    return 0;
}

int ReadSICycle(FILE **pSIFile, const char *siCyclePath) {
    if (NULL == *pSIFile) {
        *pSIFile = fopen(siCyclePath, "r");
        if (NULL == *pSIFile) {
            fprintf(stderr, "DDOS[%d]: Failed to fopen file[%s]\n", getpid(), siCyclePath);
            buffer[0] = '0';
            buffer[1] = 0;
            write(4, buffer, strlen(buffer));
            continue;
        }
    }

    if (fgets(buffer, sizeof(buffer) - 1 , pSIFile) == NULL ){
        fprintf(stderr, "DDOS[%d]: Failed to read file[%s]\n", getpid(), siCyclePath);
        continue;
    }
    write(4, buffer, strlen(buffer));
    rewind(pSIFile);

    return 0;
}

void main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "TCShow[%d]: usage: %s namespace\n", getpid(), argv[0]);
        return;
    }

    if (geteuid()) {
        fprintf(stderr, "TCShow[%d]: need run tcshow on %s as root\n", getpid(), argv[1]);
        return;
    }

    if (SeperateNS(argv[1]) == -1) {
        fprintf(stderr, "TCShow[%d]: Failed to seperate ns\n", getpid());
        return;
    }
    
	tc_core_init();

	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "TCShow[%d]: Cannot open rtnetlink\n", getpid());
		return;
	}

    char tcPathFile[64] = "";
    sprintf(tcPathFile, "/data/cnat_namespace_traffic/%s/%s-wi", argv[1], argv[1]);
    int fd = open(tcPathFile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (dup2(fd, fileno(stdout)) == -1) {
        fprintf(stderr, "TCShow[%d]: Failed to dup2[path:%s]\n", getpid(), tcPathFile);
        return;
    }

    char wiInterface[16] = "";
    sprintf(wiInterface, "%s-wi", argv[1]);

    char* tcCmd[3] = {"show", "dev", wiInterface};

    char siCyclePath[64] = "";
    sprintf(siCyclePath, "/sys/class/net/%s-li/si_cycles", argv[1]);
    FILE *pSIFile = fopen(siCyclePath, "r");

    while (gAbort) {
        read(3, buffer, sizeof(buffer) - 1);

        // read tc
        do_qdisc(3, tcCmd);
        do_filter(3, tcCmd);
        do_class(3, tcCmd);

        lseek(fd, SEEK_SET, 0);

        // read si
    }
    
    close(fd);
    fclose(pSIFile);
	rtnl_close(&rth);
	return;
}
