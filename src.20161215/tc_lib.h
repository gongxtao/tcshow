#ifndef __TC_LIB_H_
#define __TC_LIB_H_

#include "utils.h"
#include "tc_util.h"

struct filter_util *get_filter_kind(const char *str);
struct qdisc_util *get_qdisc_kind(const char *str);

#endif // __TC_LIB_H_
