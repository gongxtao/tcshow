#ifndef __Q_HTB_H__
#define __Q_HTB_H__


int htb_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt);
int htb_parse_class_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n);
int htb_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n);

#endif // __Q_HTB_H__
