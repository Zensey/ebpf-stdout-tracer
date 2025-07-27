BINARY = ebpf-stdout-tracer

.PHONY: build
build: $(BINARY)

$(BINARY):
	/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/vmlinux.h
	go build -o $(BINARY) ./

