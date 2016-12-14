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
#include "libnetlink.h"
#include "utils.h"
#include "ll_map.h"
#include "tc_util.h"

extern int tc_core_init(void);
extern int do_qdisc(int argc, char **argv);

int show_stats = 1;
int show_details = 0;
int show_raw = 0;
int show_pretty = 1;
int show_graph = 0;
int timestamp = 0;

int resolve_hosts = 0;
int use_iec = 0;
int use_names = 0;

struct rtnl_handle rth;

struct gnet_stats2 {
	struct gnet_stats_basic bs;
	struct gnet_stats_queue q;
	struct gnet_stats_rate_est64 re;
};

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

int print_qdisc(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg) {
	FILE *fp = (FILE *) arg;
	struct tcmsg *t = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[TCA_MAX + 1];
	char abuf[256];

	if (n->nlmsg_type != RTM_NEWQDISC && n->nlmsg_type != RTM_DELQDISC) {
		fprintf(stderr, "Not a qdisc\n");
		return 0;
	}
	len -= NLMSG_LENGTH(sizeof(*t));
	if (len < 0) {
		fprintf(stderr, "Wrong len %d\n", len);
		return -1;
	}

	parse_rtattr(tb, TCA_MAX, TCA_RTA(t), len);

	if (tb[TCA_KIND] == NULL) {
		fprintf(stderr, "print_qdisc: NULL kind\n");
		return -1;
	}

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
	fflush(fp);
	return 0;
}

static int qdisc_list(void) {
	struct tcmsg t = { .tcm_family = AF_UNSPEC };

	ll_init_map(&rth);

	if (rtnl_dump_request(&rth, RTM_GETQDISC, &t, sizeof(t)) < 0) {
		perror("Cannot send dump request");
		return 1;
	}

	if (rtnl_dump_filter(&rth, print_qdisc, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv) {
	int ret = 0;
	tc_core_init();

	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		exit(1);
	}

//	for (int i = 0; i < 5; i++) {
//		char * tc_argv[] = { "list" };
//		int tc_argc = sizeof(tc_argv) / sizeof(tc_argv[0]);
//		do_qdisc(tc_argc, tc_argv);
//		sleep(5);
//	}

	qdisc_list();

	rtnl_close(&rth);

	return ret;
}
