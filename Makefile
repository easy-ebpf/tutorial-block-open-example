ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

run: clean
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -c $(filter-out $@,$(MAKECMDGOALS)).bpf.c -o $(filter-out $@,$(MAKECMDGOALS)).bpf.o
	bpftool gen skeleton $(filter-out $@,$(MAKECMDGOALS)).bpf.o > $(filter-out $@,$(MAKECMDGOALS)).skel.h
	gcc -W -Wall -Wextra -I/usr/include -L/usr/lib -c -o $(filter-out $@,$(MAKECMDGOALS)).o $(filter-out $@,$(MAKECMDGOALS)).c
	gcc -o $(filter-out $@,$(MAKECMDGOALS)) $(filter-out $@,$(MAKECMDGOALS)).o -lbpf -lelf -lz /usr/lib/libargp.a
	./$(filter-out $@,$(MAKECMDGOALS))

trace:
	bpftool prog trace log

clean:
	rm -rf *.o
	rm -rf *.skel.h
	rm -rf vmlinux.h
