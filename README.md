# filtering-syscall-framework

## Name
Filtering Syscalls Framework

## Description
Filtering Syscalls Framework, preventing Jobs from executing any maliuse codes in the HPC cluster like Slurm, K8S
## Installation
dnf install clang llvm bpftool glibc-devel.i686 | apt-get install clang llvm bpftool g++-multilib
git clone project in all of nodes <Ansible>
cd deployment
make
Install the service file in your Slurm Worker Nodes. <Ansible>

## Table of Syscalls which is commonly abused by Attackers
## The code is ongoing to implement the prevention method to stop being abused

execve	Executes a program. Often used in shellcode and exploits.
execveat	Similar to execve, but allows specifying a file descriptor.
open	Opens a file. Can be used to access sensitive files.
openat	Similar to open, but allows specifying a directory file descriptor.
ptrace	Used for debugging and process manipulation. Often abused in exploits.
mprotect	Changes memory protection. Can be used to make memory executable.
mmap	Maps files or devices into memory. Can be used to create executable memory.
socket	Creates a network socket. Can be used for reverse shells.
connect	Connects to a remote host. Often used in reverse shells.
bind	Binds a socket to an address. Can be used for bind shells.
accept	Accepts a connection on a socket. Can be used for bind shells.
clone	Creates a new process. Can be used to spawn shells.
fork	Creates a child process. Can be used to spawn shells.
vfork	Similar to fork, but shares memory. Can be used to spawn shells.
kill	Sends a signal to a process. Can be used to kill processes or escalate.
prctl	Manipulates process behavior. Can be used to disable security features.
seccomp	Applies seccomp filters. Can be used to bypass seccomp.
chmod	Changes file permissions. Can be used to escalate privileges.
chown	Changes file ownership. Can be used to escalate privileges.
setuid	Sets the user ID. Can be used to escalate privileges.
setgid	Sets the group ID. Can be used to escalate privileges.
capset	Sets capabilities. Can be used to escalate privileges.

## Authors and acknowledgment
Mojtaba Akbari
mojtaba.akbari.sec@gmail.com

## License
For open source projects, say how it is licensed.

## Project status
Under Development
