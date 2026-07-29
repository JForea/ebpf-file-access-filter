#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <faf/filter_rule.h>

#define INVALID_RB_MASK ((__u8)255)
#define INVALID_RB_FILE ((__u8)255)

#ifndef EACCES
#define EACCES 13
#endif

#ifndef EINVAL
#define EINVAL 22
#endif

static long iterate_file(__u64 index, void *ctx);

static long does_match(
    struct bpf_map *map,
    const void *key,
    void *value,
    void *ctx
);

struct file_args {
    char file[MAX_FILE_PATH_SIZE];
    __u8 size;
};

struct iterate_file_args {
    __u8 i_mask;
    __u8 i_file;
    __u8 mask_size;
    __u8 file_size;
    __u8 rb_file;
    __u8 rb_mask;
    const struct filter_rule *rule;
    const struct file_args *file_args;
    __u8 error_occured;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILE_PATH_SIZE]);
    __type(value, struct filter_rule);
} masks SEC(".maps");

extern int bpf_path_d_path(
    struct path *path,
    char *buf,
    __u32 buf_sz
) __ksym;

char _license[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret) {
    (void)ctx;

    struct file_args args;
    long match;

    if (ret != 0) {
        return ret;
    }

    args.size = bpf_path_d_path(&file->f_path, args.file, MAX_FILE_PATH_SIZE);

    if (args.size < 0 || args.size > MAX_FILE_PATH_SIZE) {
        return -EINVAL;
    }

    match = bpf_for_each_map_elem(&masks, does_match, &args, 0);

    if (match) {
        return -EACCES;
    }

    return 0;
}

long does_match(
    struct bpf_map *map,
    const void *key,
    void *value,
    void *ctx
) {
    (void)map;
    (void)key;

    const struct file_args *args = ctx;
    const struct filter_rule *rule = value;

    struct iterate_file_args iterate_file_args = {
        .i_mask = 0,
        .i_file = 0,
        .mask_size = rule->mask_size,
        .file_size = args->size,
        .rb_mask = INVALID_RB_MASK,
        .rb_file = INVALID_RB_FILE,
        .rule = rule,
        .file_args = args,
        .error_occured = 0,
    };

    // __u32 mask_size = rule->mask_size, 
    //       file_size = args->size,
    //       i_mask = 0,
    //       i_file = 0,
    //       rb_mask = SIZE_MAX,
    //       rb_file = SIZE_MAX;

    bpf_loop(1e6, iterate_file, &iterate_file_args, 0);
    // while (i_file < file_size) {
    //     if (i_mask < mask_size && rule->mask[i_mask] == '*') {
    //         while (i_mask + 1 < mask_size && rule->mask[i_mask + 1] == '*') {
    //             ++i_mask;
    //         }

    //         rb_file = i_file;
    //         rb_mask = i_mask;

    //         ++i_mask;
    //     } else if (i_mask < mask_size &&
    //             (rule->mask[i_mask] == '?' || rule->mask[i_mask] == args->file[i_file])) {
    //         ++i_mask;
    //         ++i_file;
    //     } else {
    //         if (rb_mask == SIZE_MAX) {
    //             return 0;
    //         }

    //         i_file = ++rb_file;
    //         i_mask = rb_mask + 1;
    //     }
    // }

    if (iterate_file_args.error_occured) {
        return 0;
    }

    while (iterate_file_args.i_mask < iterate_file_args.mask_size) {
        if (iterate_file_args.i_mask >= MAX_MASK_SIZE)
            return 0;

        if (rule->mask[iterate_file_args.i_mask] != '*')
            break;

        iterate_file_args.i_mask++;
    }

    if (iterate_file_args.i_mask == iterate_file_args.mask_size) {
        return 1;
    }

    return 0;
}

long iterate_file(__u64 index, void *ctx) {
    (void)index;

    struct iterate_file_args *args = ctx;

    if (args->mask_size > MAX_MASK_SIZE) {
        args->mask_size = MAX_MASK_SIZE;
    }

    if (args->file_size > MAX_FILE_PATH_SIZE) {
        args->file_size = MAX_FILE_PATH_SIZE;
    }

    if (args->i_file >= MAX_FILE_PATH_SIZE ||
        args->i_mask >= MAX_MASK_SIZE ||
        args->i_file >= args->file_size) {
        return 1;
    }

    if (args->i_mask < args->mask_size && 
        args->rule->mask[args->i_mask] == '*') {
        // while (args->i_mask < MAX_MASK_SIZE &&
        //     args->i_mask + 1 < args->mask_size && 
        //     args->rule->mask[args->i_mask + 1] == '*') {
        //     ++args->i_mask;
        // }

        args->rb_file = args->i_file;
        args->rb_mask = args->i_mask;

        ++args->i_mask;
    } else if (args->i_mask < args->mask_size &&
            (args->rule->mask[args->i_mask] == '?' || 
            args->rule->mask[args->i_mask] == args->file_args->file[args->i_file])) {
        ++args->i_mask;
        ++args->i_file;
    } else {
        if (args->rb_mask == INVALID_RB_MASK) {
            args->error_occured = 1;
            return 1;
        }

        args->i_file = ++args->rb_file;
        args->i_mask = args->rb_mask + 1;
    }

    return 0;
}
