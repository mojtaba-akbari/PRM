#!/bin/bash
# One-command QEMU VM deployment for filtering-syscall-framework

PROJECT_DIR="$(pwd)/../"
DEPLOY_DIR="$(pwd)"
QEMU_DIR="$HOME/qemu-vms/rocky9-framework"  # Can be changed
OS="https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2" # If you need try with another OS
OS_file="Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"

installation()
{
    # This packages for your host enviroment , if you donot need update kernel , do not do this!
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
    fi

    #Notice for packages , because it is kernel level framework , depends on OS try to change packages
    #List
    #- linux-headers-$(uname -r) # sometimes does not work because of repo update. and also uname -r does not work
    #change this depend of OS - libbpf - libbpf-dev
    # sometimes you need just iproute , for our framework you donot need but it is good :)
    # redhat base is elfutils-libelf-devel , debian base libelf-dev
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
      - libbpf
      - bpftool
      - iproute
      - elfutils-libelf-devel
      - git
      - make
      - gcc
      - kernel-devel
      - fuse3
EOF

    cloud-localds seed.img user-data <(echo "instance-id: rocky9-framework")
    #Do not change CPU please 
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
    #  -virtfs local,path="$PROJECT_DIR",mount_tag=project,security_model=mapped,id=proj_vol
}

deploy(){
  while ! nc -z localhost 2222; do sleep 1; done

  scp -P 2222 -r -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" $PROJECT_DIR/* rocker@localhost:~/filtering-syscall-framwork/
}

pid=$(pgrep -fa qemu-system-x86_64)

if [[ $pid == "" ]]; then
  echo "Installing...."
  installation
fi

deploy

echo "Framework deployed! Connect with: ssh -p 2222 rocker@localhost"
