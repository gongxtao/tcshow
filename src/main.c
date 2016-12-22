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
#include <sys/types.h>
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


static void parse_gnet_stats2(struct rtattr *rta, struct gnet_stats2 *stats2) {
	struct rtattr *tbs[TCA_STATS_MAX + 1];
	parse_rtattr_nested(tbs, TCA_STATS_MAX, rta);

	if (tbs[TCA_STATS_BASIC]) {
		memcpy(&stats2->bs, RTA_DATA(tbs[TCA_STATS_BASIC]),
				MIN(RTA_PAYLOAD(tbs[TCA_STATS_BASIC]), sizeof(stats2->bs)));
	}

	if (tbs[TCA_STATS_QUEUE]) {
		memcpy(&stats2->q, RTA_DATA(tbs[TCA_STATS_QUEUE]),
				MIN(RTA_PAYLOAD(tbs[TCA_STATS_QUEUE]), sizeof(stats2->q)));
	}

	if (tbs[TCA_STATS_RATE_EST64]) {
		memcpy(&stats2->re, RTA_DATA(tbs[TCA_STATS_RATE_EST64]),
				MIN(RTA_PAYLOAD(tbs[TCA_STATS_RATE_EST64]),
						sizeof(stats2->re)));
	}
	return;
}

int print_qdisc_new(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg) {
	FILE *fp = (FILE *) arg;
	struct tcmsg *t = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[TCA_MAX + 1];
	char abuf[256];
    struct qdisc_util *q = NULL;

	if (n->nlmsg_type != RTM_NEWQDISC && n->nlmsg_type != RTM_DELQDISC) {
		fprintf(stderr, "Not a qdisc\n");
		return 0;
	}
	len -= NLMSG_LENGTH(sizeof(*t));
	if (len < 0) {
		fprintf(stderr, "Wrong len %d\n", len);
		return -1;
	}

    if (filter_ifindex && filter_ifindex != t->tcm_ifindex) {
        return 0;
    }

	parse_rtattr(tb, TCA_MAX, TCA_RTA(t), len);

	if (tb[TCA_KIND] == NULL) {
		fprintf(stderr, "print_qdisc: NULL kind\n");
		return -1;
	}
/*
	if (tb[TCA_STATS2] == NULL) {
		fprintf(stderr, "print_qdisc: NULL stats2\n");
		return -1;
	}

	struct gnet_stats2 stats2 = { 0 };
	parse_gnet_stats2(tb[TCA_STATS2], &stats2);
	fprintf(fp, "dev: %s, sent_bytes: %llu, sent_pkts: %u, dropped: %u, overlimits: %u, requeues: %u, backlog: %u, qlen: %u\n",
			ll_index_to_name(t->tcm_ifindex),
			stats2.bs.bytes, stats2.bs.packets,
			stats2.q.drops, stats2.q.overlimits, stats2.q.requeues, stats2.q.backlog, stats2.q.qlen);
*/
    fprintf(fp, "qdisc %s %x: ", rta_getattr_str(tb[TCA_KIND]), t->tcm_handle>>16);
    if (t->tcm_parent == TC_H_ROOT)
        fprintf(fp, "root ");
    else if (t->tcm_parent) {
        print_tc_classid(abuf, sizeof(abuf), t->tcm_parent);
        fprintf(fp, "parent %s ", abuf);
    }
    if (t->tcm_info != 1) {
        fprintf(fp, "refcnt %d ", t->tcm_info);
    }
    /* pfifo_fast is generic enough to warrant the hardcoding --JHS */

    q = get_qdisc_kind(RTA_DATA(tb[TCA_KIND]));

    if (tb[TCA_OPTIONS]) {
        if (q)
            q->print_qopt(q, fp, tb[TCA_OPTIONS]);
        else
            fprintf(fp, "[cannot parse qdisc parameters]");
    }
    fprintf(fp, "\n");
    if (show_details && tb[TCA_STAB]) {
        print_size_table(fp, " ", tb[TCA_STAB]);
        fprintf(fp, "\n");
    }
    if (show_stats) {
        struct rtattr *xstats = NULL;

        if (tb[TCA_STATS] || tb[TCA_STATS2] || tb[TCA_XSTATS]) {
            print_tcstats_attr(fp, tb, " ", &xstats);
            fprintf(fp, "\n");
        }

        if (q && xstats && q->print_xstats) {
            q->print_xstats(q, fp, xstats);
            fprintf(fp, "\n");
        }
    }
	fflush(fp);
	return 0;
}

static int qdisc_list(FILE *qdiscFile, char *ns) {
	struct tcmsg t = { .tcm_family = AF_UNSPEC };
    if (ns) {
        if ((t.tcm_ifindex = ll_name_to_index(ns)) == 0) {
            fprintf(stderr, "TCShow[%d]: Cannot find device \"%s\"\n", getpid(), ns);
            return 1;
        }
        filter_ifindex = t.tcm_ifindex;
    }

	ll_init_map(&rth);

	if (rtnl_dump_request(&rth, RTM_GETQDISC, &t, sizeof(t)) < 0) {
		perror("Cannot send dump request");
		return 1;
	}

	if (rtnl_dump_filter(&rth, print_qdisc_new, NULL == qdiscFile ? stdout : qdiscFile) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}
	return 0;
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

void main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "TCShow-wo[%d]: usage: %s interface [interface]\n", getpid(), argv[0]);
        return;
    }

    if (geteuid()) {
        fprintf(stderr, "TCShow-wo[%d]: need run tcshow on %s as root\n", getpid(), argv[1]);
        return;
    }
        
	tc_core_init();

	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "TCShow-wo[%d]: Cannot open rtnetlink\n", getpid());
		return;
	}

    char* tcCmd[3] = {"show", "dev", ""};
    char tcPathFile[64] = "/data/cnat_namespace_traffic/tc-wo.data.cache";
    int fd = open(tcPathFile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (dup2(fd, fileno(stdout)) == -1) {
        fprintf(stderr, "TCShow[%d]: Failed to dup2\n", getpid());
        return;
    }
    // flush file
    ftruncate(fd, 0);

    char *p = NULL;
    char *s = argv[1];
    char *d = "\n";

    p = strtok(s, d);
    while (p) {
        tcCmd[2] = p;
        char ns[64] = "";
        sprintf(ns, "@%s\n", tcCmd[2]);
        write(fd, ns, strlen(ns));

        do_qdisc(3, tcCmd);
        do_filter(3, tcCmd);
        do_class(3, tcCmd);

        p = strtok(NULL, d);
    }
    
    close(fd);
	rtnl_close(&rth);
	return;
}
