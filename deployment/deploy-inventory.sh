#! /bin/bash

PROJECT_DIR="$(pwd)/../"
DEPLOY_DIR="$(pwd)"
IP=$1

ssh root@$IP "dnf install clang llvm libbpf bpftool iproute elfutils-libelf-devel git make gcc kernel-devel fuse3"
ssh root@$IP "mkdir -p ~/PRM"
scp -r -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" $PROJECT_DIR/* root@$IP:~/PRM/