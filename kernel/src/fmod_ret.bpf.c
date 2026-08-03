#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <faf/filter_rule.h>

#define INVALID_RB_MASK ((__u8)255)
#define INVALID_RB_FILE ((__u8)255)

#define MAX_ITERATION_NUMBER 1000000U

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
    __u8 matched;
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

char _license[] SEC("license") = "GPL";

SEC("fmod_ret/__x64_sys_openat")
int BPF_PROG(handle_file_open, struct pt_regs *regs) {
    (void)ctx;

    struct file_args args;
    long err;
    const char *path;

    path = (char *)BPF_CORE_READ(regs, si);

    args.size = bpf_probe_read_user_str(&args.file, sizeof(args.file), path);
    if (args.size < 0) {
        return 0;
    }

    --args.size;

    args.matched = 0;

    err = bpf_for_each_map_elem(&masks, does_match, &args, 0);

    if (err < 0) {
        bpf_printk("%s: Something went wrong: %d.\n", args.file, err);
        return 0;
    }

    if (args.matched) {
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

    int n;
    struct file_args *args = ctx;
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

    n = bpf_loop(
        MAX_ITERATION_NUMBER, 
        iterate_file, 
        &iterate_file_args, 
        0
    );

    if (n < 0) {
        bpf_printk("%s: Error during loop: %d\n", args->file, n);
    }

    if ((__u32)n >= MAX_ITERATION_NUMBER) {
        bpf_printk("%s: Loop limit exceeded: %d\n", args->file, n);
    }

    bpf_printk("%s: i_file=%u/%u i_mask=%u/%u rb_file=%u rb_mask=%u err=%u\n",
        args->file,
        iterate_file_args.i_file,
        iterate_file_args.file_size,
        iterate_file_args.i_mask,
        iterate_file_args.mask_size,
        iterate_file_args.rb_file,
        iterate_file_args.rb_mask,
        iterate_file_args.error_occured
    );

    if (iterate_file_args.error_occured) {
        bpf_printk("%s: Error occured.\n", args->file);
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
        bpf_printk("%s: Matched.\n", args->file);
        args->matched = 1;
        return 1;
    }

    bpf_printk("%s: Didn't match.\n", args->file);

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

    if (args->i_file >= args->file_size) {
        return 1;
    }

    if (args->i_mask < args->mask_size && 
        args->rule->mask[args->i_mask] == '*') {
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
