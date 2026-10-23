CLANG ?= clang-18
CC ?= cc
ROOT := ..
BUILD := $(ROOT)/build
MULTIARCH := $(shell $(CC) -print-multiarch)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Werror \
	-I$(BUILD) -I$(ROOT)/bpf -I/usr/include/$(MULTIARCH)

.PHONY: all clean check-tools
all: $(BUILD)/tripwire-loader

check-tools:
	@command -v $(CLANG) >/dev/null || { echo "missing $(CLANG)" >&2; exit 1; }
	@command -v bpftool >/dev/null || { echo "missing bpftool" >&2; exit 1; }
	@pkg-config --exists libbpf || { echo "libbpf pkg-config metadata missing" >&2; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "missing /sys/kernel/btf/vmlinux" >&2; exit 1; }
	@$(CLANG) -target bpf -x c -c /dev/null -o /dev/null

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD) check-tools
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

$(BUILD)/tripwire.bpf.o: tripwire.bpf.c event.h $(BUILD)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/tripwire.skel.h: $(BUILD)/tripwire.bpf.o
	bpftool gen skeleton $< name tripwire_bpf > $@.tmp
	mv $@.tmp $@

$(BUILD)/tripwire-loader: loader.c event_json.c event_json.h event.h $(BUILD)/tripwire.skel.h
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror \
		$(LIBBPF_CFLAGS) -I$(ROOT)/bpf -I$(BUILD) \
		loader.c event_json.c -o $@ $(LIBBPF_LIBS)

clean:
	rm -f $(BUILD)/tripwire.bpf.o $(BUILD)/tripwire.skel.h $(BUILD)/tripwire-loader
