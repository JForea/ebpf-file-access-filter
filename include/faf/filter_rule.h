#ifndef FILTER_RULE_H
#define FILTER_RULE_H

#ifndef __VMLINUX_H__
#include "linux/types.h"
#endif

#define MAX_FILE_PATH_SIZE 255
#define MAX_MASK_SIZE 255

struct filter_rule {
    char mask[MAX_FILE_PATH_SIZE];
    __u32 mask_size;
};


#endif