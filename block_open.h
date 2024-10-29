// File: block_open.h
#ifndef __BLOCK_OPEN_H
#define __BLOCK_OPEN_H

#define TASK_COMM_LEN 16

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;


#define MAX_FILENAME_LEN 256
typedef __u32 u32;
typedef __u8 u8;

struct event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif /* __BLOCK_OPEN_H */

