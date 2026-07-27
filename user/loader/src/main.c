#include <bpf/libbpf.h>
#include <sys/stat.h>

#include <faf/skel.h>

#include "defaults.h"

#define PATH_MAX_LENGTH 256

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

int main() {
	char pin_path[PATH_MAX_LENGTH];
    struct faf_bpf *skel;
	int err;

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
		pin_path, 
		PATH_MAX_LENGTH, 
		"%s/%s", bpf_folder_path, masks_map_name
	);
	if (err < 0) {
		fprintf(stderr, "Failed to concatenate strings.\n");
		goto cleanup;
	}

	err = bpf_map__pin(
		skel->maps.masks,
		pin_path
	);
	if (err) {
		fprintf(stderr, "Failed to pin map.\n");
    	goto cleanup;
	}

	err = faf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Couldn't attach program.\n");
		goto cleanup;
	}

cleanup:
	faf_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
