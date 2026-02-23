#!/bin/bash
# One-command QEMU VM deployment for filtering-syscall-framework on Debian

PROJECT_DIR="$(pwd)/../"
DEPLOY_DIR="$(pwd)"
QEMU_DIR="$HOME/qemu-vms/debian12-framework"
OS="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
OS_file="debian-12-generic-amd64.qcow2"

installation()
{
    # Host environment packages for Debian
    # sudo apt-get update && sudo apt-get install -y \
    # qemu-system-x86 \
    # qemu-utils \
    # cloud-image-utils \
    # build-essential \
    # git \
    # pkg-config \
    # libglib2.0-dev \
    # libfdt-dev \
    # libpixman-1-dev \
    # zlib1g-dev \
    # flex bison
    echo "Installation.... waiting"
    mkdir -p "$QEMU_DIR" && cd "$QEMU_DIR"

    if [ ! -f $OS_file ]; then
        wget $OS
        # Resize disk to 5GB
        qemu-img resize $OS_file 5G
    fi

    # Debian-specific packages for kernel development
    cat > user-data <<EOF
    #cloud-config
    users:
      - name: debian
        sudo: ALL=(ALL) NOPASSWD:ALL
        ssh_authorized_keys:
          - $(cat ~/.ssh/id_rsa.pub)
    packages:
      - clang
      - llvm
      - libbpf-dev
      - bpftool
      - iproute2
      - libelf-dev
      - git
      - make
      - gcc
      - linux-headers-amd64
      - fuse3
      - build-essential
      - pkg-config
      - netcat-openbsd
EOF

    cloud-localds seed.img user-data <(echo "instance-id: debian12-framework")
    
    # Launch QEMU VM
    qemu-system-x86_64 \
      -cpu max \
      -machine q35,accel=kvm \
      -smp 4,sockets=1,cores=2,threads=2 \
      -m 2048 \
      -drive file=debian-12-generic-amd64.qcow2,if=virtio,format=qcow2 \
      -drive file=seed.img,if=virtio,format=raw \
      -device virtio-net-pci,netdev=net0 \
      -netdev user,id=net0,hostfwd=tcp::2223-:22 \
      -nographic > qemu.log 2>&1 &
}

deploy(){
  while ! nc -z localhost 2223; do sleep 1; done

  scp -P 2223 -r -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" $PROJECT_DIR/* debian@localhost:~/filtering-syscall-framwork/
}

pid=$(pgrep -fa "qemu.*debian")

if [[ $pid == "" ]]; then
  echo "Installing...."
  installation
fi

deploy

echo "Framework deployed! Connect with: ssh -p 2223 debian@localhost"