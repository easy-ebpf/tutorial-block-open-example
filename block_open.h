#ifndef __BLOCK_OPEN_H
#define __BLOCK_OPEN_H

#define MAX_FILENAME_LEN 256

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u32 u32;
typedef __u8 u8;

#define TASK_COMM_LEN 16

struct blocked_event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif /* __BLOCK_OPEN_H */
