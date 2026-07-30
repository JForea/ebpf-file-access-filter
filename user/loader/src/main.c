#include <bpf/libbpf.h>
#include <sys/stat.h>

#include <faf/skel.h>
#include <faf/filter_rule.h>

#include "defaults.h"

/* Uncomment this to add test mask to bpf map */
// #define BPF_TEST

#ifdef BPF_TEST
/* Function that adds test mask to bpf map "*test.txt" */
static int add_test_rule(struct faf_bpf *skel) {
    static const char test_mask[] = "*test.txt";

    char key[MAX_FILE_PATH_SIZE] = {};
    struct filter_rule rule = {};

    memcpy(key, test_mask, sizeof(test_mask));
    memcpy(rule.mask, test_mask, sizeof(test_mask));

    rule.mask_size = sizeof(test_mask) - 1;

    int map_fd = bpf_map__fd(skel->maps.masks);
    if (map_fd < 0) {
        fprintf(stderr, "failed to get masks map fd\n");
        return -1;
    }

    if (bpf_map_update_elem(map_fd, key, &rule, BPF_ANY) < 0) {
        fprintf(stderr,
                "failed to insert test rule: %s\n",
                strerror(errno));
        return -1;
    }

    return 0;
}
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

int main() {
	char map_pin_path[MAX_FILE_PATH_SIZE],
		 link_pin_path[MAX_FILE_PATH_SIZE];
    struct faf_bpf *skel;
	int err;
	int n;

	/* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    skel = faf_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton.\n");
		return 1;
	}

	err = mkdir(bpf_folder_path, 0700);
	if (err) {
		fprintf(stderr, "Failed to create direcory.\n");
		goto cleanup;
	}

	err = snprintf(
		map_pin_path, 
		MAX_FILE_PATH_SIZE, 
		"%s/%s", bpf_folder_path, masks_map_name
	);
	if (err < 0) {
		fprintf(stderr, "Failed to concatenate strings.\n");
		goto cleanup;
	}

	err = bpf_map__pin(
		skel->maps.masks,
		map_pin_path
	);
	if (err) {
		fprintf(stderr, "Failed to pin map.\n");
    	goto cleanup;
	}

#ifdef BPF_TEST
	add_test_rule(skel);
#endif

	err = faf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Couldn't attach program.\n");
		goto cleanup;
	}

	n = snprintf(
        link_pin_path,
        sizeof(link_pin_path),
        "%s/file_open_link",
        bpf_folder_path
    );

    if (n < 0 || n >= sizeof(link_pin_path)) {
        fprintf(stderr, "Link pin path is too long\n");
        err = -ENAMETOOLONG;
        goto cleanup;
    }

    err = bpf_link__pin(
        skel->links.handle_file_open,
        link_pin_path
    );
    if (err) {
        fprintf(stderr, "Failed to pin link.\n");
        goto cleanup;
    }

cleanup:
	faf_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
