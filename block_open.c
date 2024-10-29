#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "block_open.skel.h"
#include "block_open.h"

static volatile sig_atomic_t exiting = 0;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct blocked_event *e = data;
    printf("Blocked open of %s by PID %d (%s)\n", e->filename, e->pid, e->comm);
    return 0;
}

void sig_int(int signo)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct block_open_bpf *skel;
    int err;
    FILE *fp;
    char line[MAX_FILENAME_LEN] = {};
    u8 value = 1;
    struct ring_buffer *rb = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        return 1;
    }

    // Open BPF application
    skel = block_open_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = block_open_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // Attach BPF program
    err = block_open_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Read file names from config file and populate the map
    fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        goto cleanup;
    }

    while (fgets(line, sizeof(line), fp)) {
        // Remove newline character
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n')
            line[len - 1] = '\0';

        // Zero pad the rest of the line
        memset(line + len, 0, sizeof(line) - len);

        // Insert into map
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.blocked_files), line, &value, 0);
        if (err) {
            fprintf(stderr, "Failed to insert %s into map: %d\n", line, err);
            fclose(fp);
            goto cleanup;
        }
    }
    fclose(fp);

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // Handle Ctrl-C
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    printf("Monitoring...\n");
    // Process events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            // Interrupted by signal
            break;
        } else if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    block_open_bpf__destroy(skel);
    return -err;
}
