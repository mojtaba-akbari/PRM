#!/bin/bash
# One-command QEMU VM deployment for filtering-syscall-framework

# 1. Install dependencies
# sudo apt-get update && sudo apt-get install -y \
#     qemu-system-x86 \
#     qemu-utils \
#     cloud-image-utils \
#     build-essential \
#     git \
#     pkg-config \
#     libglib2.0-dev \
#     libfdt-dev \
#     libpixman-1-dev \
#     zlib1g-dev \
#     flex bison

# 1. Set paths relative to PROJECT
PROJECT_DIR="$(pwd)/../"
DEPLOY_DIR="$(pwd)"
QEMU_DIR="$HOME/qemu-vms/rocky9-framework"  # Can be changed

# 2. Create QEMU working dir
mkdir -p "$QEMU_DIR" && cd "$QEMU_DIR"

# 3. Download Rocky Linux image (if missing)
if [ ! -f Rocky-9-GenericCloud-Base.latest.x86_64.qcow2 ]; then
    wget https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2
fi

# 4. Prepare cloud-init with PROJECT references
cat > user-data <<EOF
#cloud-config
users:
  - name: rocker
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_rsa.pub)
packages:
  - clang
  - llvm
  - libbpf-dev
  - linux-headers-$(uname -r)
  - bpftool
  - iproute2
  - libelf-dev
  - git
  - make
  - gcc
  - kernel-devel
EOF
#runcmd:
 # - [git, clone, $PROJECT_DIR, /home/rocker/filtering-syscall-framework]
 # - [cd, /home/rocker/filtering-syscall-framework/deployment, &&, make]

# 5. Generate seed image
cloud-localds seed.img user-data <(echo "instance-id: rocky9-framework")

# 6. Launch VM with PROJECT directory mounted
qemu-system-x86_64 \
  -cpu max \
  -machine q35,accel=kvm \
  -smp 4,sockets=1,cores=2,threads=2 \
  -m 2048 \
  -drive file=Rocky-9-GenericCloud-Base.latest.x86_64.qcow2,if=virtio,format=qcow2 \
  -drive file=seed.img,if=virtio,format=raw \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -nographic > qemu.log 2>&1 &
#  -virtfs local,path="$PROJECT_DIR",mount_tag=project,security_model=mapped,id=proj_vol \

while ! nc -z localhost 2222; do sleep 1; done

# 5. Clone and deploy framework
scp -P 2222 -r -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" $PROJECT_DIR/* rocker@localhost:~/rocker/

echo "Framework deployed! Connect with: ssh -p 2222 rocker@localhost"