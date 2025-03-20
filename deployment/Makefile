# Target eBPF object file
TARGET = .

# Source file
SRC = ../src/hookentry.c

# Compiler command
ECC = ./ecc

# Rule to compile the eBPF program
all:
	$(ECC) $(SRC) -o $(TARGET)

# Clean up build artifacts
clean:
	rm -f package.json hookentry.skel.json hookentry.bpf.o


# Add this part to All sections get automated
# cp filtering-syscall-framework.service /etc/systemd/system/
# systemctl enable filtering-syscall-framework.service
# systemctl start filtering-syscall-framework.service