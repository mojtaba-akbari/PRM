# Target eBPF object file
TARGET = .

# Source file
SRC = ../src/hookentry.c
LOADER_SRC = ../src/prm-loader.c
LOADER_BIN = prm-loader
COLLECTOR_SRC = ../src/trace-collector.c
COLLECTOR_BIN = trace-collector

# Compiler command
ECC = ./ecc
CC = gcc

# Rule to compile the eBPF program
all: ebpf loader collector

ebpf:
	$(ECC) --additional-cflags="-w" $(SRC) -o $(TARGET)

loader:
	@echo "Building PRM simple loader..."
	@# Find libbpf library
	@LIBBPF=$$(find /usr/lib64 /usr/lib -name "libbpf.so*" 2>/dev/null | head -1); \
	if [ -z "$$LIBBPF" ]; then \
		echo "ERROR: libbpf library not found"; \
		echo "Install: sudo dnf install libbpf"; \
		exit 1; \
	fi; \
	KSRC=$$(find /usr/src/kernels -name "libbpf.h" -path "*/tools/lib/bpf/libbpf.h" 2>/dev/null | head -1 | xargs dirname 2>/dev/null); \
	if [ -n "$$KSRC" ] && [ -f "$$KSRC/libbpf.h" ]; then \
		KROOT=$$(echo $$KSRC | sed 's|/tools/lib/bpf||'); \
		echo "Found libbpf headers in: $$KSRC"; \
		echo "Found libbpf library: $$LIBBPF"; \
		$(CC) $(LOADER_SRC) -o $(LOADER_BIN) \
			-I$$KSRC \
			-I$$KROOT/tools/include \
			-I$$KROOT/tools/include/uapi \
			$$LIBBPF -lelf -lz -lncurses || exit 1; \
	elif [ -f /usr/include/bpf/libbpf.h ]; then \
		echo "Found libbpf in /usr/include/bpf/"; \
		$(CC) $(LOADER_SRC) -o $(LOADER_BIN) -I/usr/include -L$$(dirname $$LIBBPF) -lbpf -lelf -lz -lncurses || exit 1; \
	else \
		echo "ERROR: libbpf headers not found"; \
		exit 1; \
	fi
	@echo "Loader built: $(LOADER_BIN)"

collector:
	@echo "Building trace collector..."
	$(CC) $(COLLECTOR_SRC) -o $(COLLECTOR_BIN)
	@echo "Collector built: $(COLLECTOR_BIN)"

# Clean up build artifacts
clean:
	rm -f package.json hookentry.skel.json hookentry.bpf.o $(LOADER_BIN) $(COLLECTOR_BIN)


# Add this part to All sections get automated
# cp filtering-syscall-framework.service /etc/systemd/system/
# systemctl enable filtering-syscall-framework.service
# systemctl start filtering-syscall-framework.service