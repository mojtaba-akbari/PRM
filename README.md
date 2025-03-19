# filtering-syscall-framework

## Name
Filtering Syscalls Framework

## Description
Filtering Syscalls Framework, preventing Jobs from executing any maliuse codes in the HPC cluster like Slurm, K8S
## Installation
dnf install clang llvm bpftool | apt-get install clang llvm bpftool
git clone project in all of nodes <Ansible>
cd deployment
make
Install the service file in your Slurm Worker Nodes. <Ansible>


## Authors and acknowledgment
Mojtaba Akbari
mojtaba.akbari.sec@gmail.com

## License
For open source projects, say how it is licensed.

## Project status
Under Development
