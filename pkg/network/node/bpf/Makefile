BPF2GO_TARGETS=bpf_bpfeb.go bpf_bpfel.go bpf_bpfeb.o bpf_bpfel.o

all: $(BPF2GO_TARGETS)

$(BPF2GO_TARGETS): bpf.c include/vmlinux.h
	go generate -mod=vendor .

include/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

clean:
	rm -f include/vmlinux.h $(BPF2GO_TARGETS)
