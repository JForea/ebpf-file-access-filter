#include "helpers.bpf.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <faf/filter_rule.h>

#ifndef SIZE_MAX
#define SIZE_MAX ((__u32)0 - 1)
#endif

struct file_args {
    char *file;
    __u32 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILE_PATH_SIZE]);
    __type(value, struct filter_rule);
} masks SEC(".maps");

static long does_match(struct bpf_map *map, const void* key, const void* value, void *ctx) {
    (void)map;
    (void)key;

    struct file_args *args = (struct file_args*)ctx;
    struct filter_rule *rule = (struct filter_rule*)value;

    char *mask = rule->mask,
         *file = args->file; 
    __u32 mask_size, file_size,
           i_mask, i_file,
           rb_mask, rb_file;

    if (!args->file)
        return false;

    mask_size = rule->mask_size;
    file_size = args->size;

    i_mask = 0;
    i_file = 0;
    rb_mask = SIZE_MAX;
    rb_file = SIZE_MAX;

    while (i_file < file_size) {
        if (i_mask < mask_size && mask[i_mask] == '*') {
            while (i_mask + 1 < mask_size && mask[i_mask + 1] == '*') {
                ++i_mask;
            }

            rb_file = i_file;
            rb_mask = i_mask;

            ++i_mask;
        } else if (i_mask < mask_size &&
                (mask[i_mask] == '?' || mask[i_mask] == file[i_file])) {
            ++i_mask;
            ++i_file;
        } else {
            if (rb_mask == SIZE_MAX) {
                return 0;
            }

            i_file = ++rb_file;
            i_mask = rb_mask + 1;
        }
    }

    while (i_mask < mask_size && mask[i_mask] == '*') {
        ++i_mask;
    }

    return i_mask == mask_size;
}

long does_match_any(char* file, size_t size) {
    long match;
    struct file_args args = {
        .file = file,
        .size = size,
    };
    
    match = bpf_for_each_map_elem(&masks, does_match, (void*)&args, 0);

    return match;
}