#include "vmlinux.h"

#include "helpers.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <faf/filter_rule.h>

#ifndef EACCES
#define EACCES 13
#endif

#ifndef EFAULT
#define EFAULT 14
#endif

extern int bpf_path_d_path(
    struct path *path,
    char *buf,
    __u32 buf_sz
) __ksym;

char _license[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret) {
    (void)ctx;

    int size;
    char path[MAX_FILE_PATH_SIZE];
    
    if (ret != 0) {
        return ret;
    }

    size = bpf_path_d_path(&file->f_path, path, MAX_FILE_PATH_SIZE);

    if (size < 0) {
        return -EFAULT;
    }

    if (does_match_any(path, size)) {
        return -EACCES;
    }

    return 0;
}