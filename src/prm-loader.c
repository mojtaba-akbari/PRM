/*
 * PRM Simple Loader
 * Loads eBPF program and pins it (no user-space process after load)
 */

#include <libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;
    const char *bpf_file = "hookentry.bpf.o";
    const char *pin_path = "/sys/fs/bpf/prm";

    printf("PRM Simple Loader - Loading %s\n", bpf_file);

    // Open BPF object
    obj = bpf_object__open_file(bpf_file, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    // Load BPF object into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF object loaded successfully\n");

    // Attach all LSM programs
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_LSM) {
            link = bpf_program__attach(prog);
            if (!link) {
                fprintf(stderr, "Failed to attach %s: %s\n", 
                        bpf_program__name(prog), strerror(errno));
                bpf_object__close(obj);
                return 1;
            }
            // Pin the link so it persists
            char link_path[512];
            snprintf(link_path, sizeof(link_path), "%s/%s_link", 
                     pin_path, bpf_program__name(prog));
            err = bpf_link__pin(link, link_path);
            if (err) {
                fprintf(stderr, "Failed to pin link %s: %s\n", 
                        link_path, strerror(-err));
            }
        }
    }

    // Create pin directory if not exists
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", pin_path);
    system(cmd);

    // Pin all programs
    err = bpf_object__pin_programs(obj, pin_path);
    if (err) {
        fprintf(stderr, "Failed to pin programs: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    // Pin all maps
    err = bpf_object__pin_maps(obj, pin_path);
    if (err) {
        fprintf(stderr, "Failed to pin maps: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    printf("PRM loaded and pinned to %s\n", pin_path);
    printf("Programs and maps will persist after this process exits\n");
    printf("To unload: rm -rf %s\n", pin_path);

    // Keep object open (optional - can exit and BPF stays loaded)
    if (argc > 1 && strcmp(argv[1], "--daemon") == 0) {
        printf("Running in daemon mode (press Ctrl+C to stop)\n");
        while (1) {
            sleep(3600);
        }
    }

    // Clean exit - BPF programs stay loaded because they're pinned
    bpf_object__close(obj);
    
    return 0;
}
