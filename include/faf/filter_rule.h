#ifndef FILTER_RULE_H
#define FILTER_RULE_H

#ifndef __VMLINUX_H__
#include "linux/types.h"
#endif

struct filter_rule {
    char* mask;
    size_t mask_size;
};


#endif