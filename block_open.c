// File: block_open.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include "block_open.skel.h"
#include "block_open.h"

#define MAX_FILENAME_LEN 256

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;

    printf("Access to %s by PID %d (%s)\n", e->filename, e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct block_open_bpf *skel;
    int err;
    struct ring_buffer *rb = NULL;
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    FILE *fp;
    char line[MAX_FILENAME_LEN];
    u8 value = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_list.conf>\n", argv[0]);
        return 1;
    }

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Set resource limit for locked memory
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit");
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
        fprintf(stderr, "Failed to load and verify BPF programs: %d\n", err);
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
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.monitored_files), line, &value, 0);
        if (err) {
            fprintf(stderr, "Failed to insert %s into map: %d\n", line, err);
            fclose(fp);
            goto cleanup;
        }
    }
    fclose(fp);

    // Attach tracepoint handler
    err = block_open_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Monitoring access to files listed in %s...\n", argv[1]);

    // Poll ring buffer for events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err == -EINTR) {
            break; // Interrupted by signal
        } else if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    block_open_bpf__destroy(skel);
    return 0;
}
