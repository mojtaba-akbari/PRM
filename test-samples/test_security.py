#!/usr/bin/env python3
import os
import sys
import socket
import subprocess
import mmap
import ctypes
import tempfile

def test_step(step_name, test_func):
    """Test a security step and expect it to be blocked"""
    print(f"[TEST] {step_name}")
    try:
        test_func()
        print(f"[FAIL] {step_name} - Should have been blocked!")
        return False
    except Exception as e:
        print(f"[PASS] {step_name} - Blocked: {e}")
        return True

def test_memory_exec():
    """Test executable memory allocation"""
    print("[DEBUG] Allocating memory...")
    # Allocate memory first (non-executable)
    mem = mmap.mmap(-1, 4096, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE)
    
    print("[DEBUG] Making memory executable with mprotect...")
    # Try to make it executable using mprotect syscall
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
    libc = ctypes.CDLL("libc.so.6")
    result = libc.mprotect(addr, 4096, 0x7)  # PROT_READ|WRITE|EXEC
    print(f"[DEBUG] mprotect returned: {result}")
    
    if result != 0:
        raise Exception(f"mprotect failed with code {result}")
    
    print("[DEBUG] Writing shellcode to memory...")
    # Write simple shellcode that prints and exits
    # This is x86_64 assembly: mov rax, 60; mov rdi, 0; syscall (exit(0))
    shellcode = b'\x48\xc7\xc0\x3c\x00\x00\x00\x48\xc7\xc7\x00\x00\x00\x00\x0f\x05'
    mem.write(shellcode)
    
    print("[DEBUG] Executing code from memory...")
    # Create function pointer and call it
    func = ctypes.CFUNCTYPE(None)(addr)
    func()  # This should execute the shellcode
    print("[DEBUG] Code executed successfully!")

def test_invalid_directory_write():
    """Test writing to invalid directory"""
    with open('/tmp/malicious_file', 'w') as f:
        f.write('malicious content')

def test_socket_connection():
    """Test connecting to blocked IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('8.8.8.8', 53))  # Should be blocked
    s.close()

def test_socket_bind():
    """Test binding to interface"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 1337))
    s.listen(1)
    s.close()

def test_setuid_root():
    """Test privilege escalation"""
    os.setuid(0)

def test_sudo_abuse():
    """Test sudo abuse"""
    subprocess.run(['sudo', 'whoami'], check=True)

def test_module_load():
    """Test kernel module loading"""
    subprocess.run(['modprobe', 'dummy_module'], check=True)

def test_interpreter_exec():
    """Test interpreter execution"""
    subprocess.run(['/bin/bash', '-c', 'whoami'], check=True)

def test_python_exec():
    """Test Python interpreter"""
    subprocess.run(['/usr/bin/python3', '-c', 'print("test")'], check=True)

def test_memory_protection():
    """Test memory protection change"""
    mem = mmap.mmap(-1, 4096, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    # Try to make memory executable
    result = ctypes.CDLL("libc.so.6").mprotect(ctypes.addressof(ctypes.c_char.from_buffer(mem)), 4096, 0x7)  # PROT_READ|WRITE|EXEC
    if result != 0:
        raise Exception(f"mprotect failed with code {result}")

def test_sensitive_file_access():
    """Test accessing sensitive files"""
    with open('/etc/shadow', 'r') as f:
        f.read()

def test_proc_mem_access():
    """Test accessing process memory"""
    with open('/proc/1/mem', 'rb') as f:
        f.read(1024)

def test_hostname_exec():
    """Test executing hostname command"""
    subprocess.run(['hostname'], check=True)

def test_devshm_exec_direct():
    """Write a script to /dev/shm and execute it directly"""
    path = '/dev/shm/.prm_test'
    try:
        with open(path, 'w') as f:
            f.write('#!/bin/sh\necho pwned\n')
        os.chmod(path, 0o755)
        r = subprocess.run([path], capture_output=True, timeout=3)
        if r.returncode == 0:
            raise RuntimeError("executed successfully -- NOT blocked")
        raise PermissionError(f"exit code {r.returncode}")
    finally:
        try: os.unlink(path)
        except: pass

def test_devshm_exec_bash():
    """Write a script to /dev/shm and run it through bash"""
    path = '/dev/shm/.prm_test_bash'
    try:
        with open(path, 'w') as f:
            f.write('echo pwned\n')
        r = subprocess.run(['/bin/bash', path], capture_output=True, timeout=3)
        if r.returncode == 0 and b'pwned' in r.stdout:
            raise RuntimeError("bash executed /dev/shm script -- NOT blocked")
        raise PermissionError(f"exit code {r.returncode}")
    finally:
        try: os.unlink(path)
        except: pass

def test_devshm_exec_python():
    """Write a python script to /dev/shm and run it"""
    path = '/dev/shm/.prm_test_py'
    try:
        with open(path, 'w') as f:
            f.write('print("pwned")\n')
        r = subprocess.run([sys.executable, path], capture_output=True, timeout=3)
        if r.returncode == 0 and b'pwned' in r.stdout:
            raise RuntimeError("python executed /dev/shm script -- NOT blocked")
        raise PermissionError(f"exit code {r.returncode}")
    finally:
        try: os.unlink(path)
        except: pass

def test_devshm_exec_elf():
    """Compile a tiny C program into /dev/shm and execute it"""
    src = '/dev/shm/.prm_test.c'
    binary = '/dev/shm/.prm_test_elf'
    try:
        with open(src, 'w') as f:
            f.write('int main(){return 0;}\n')
        r = subprocess.run(['gcc', '-o', binary, src], capture_output=True, timeout=10)
        if r.returncode != 0:
            raise PermissionError(f"gcc failed (may be blocked): {r.stderr.decode()[:100]}")
        os.chmod(binary, 0o755)
        r = subprocess.run([binary], capture_output=True, timeout=3)
        if r.returncode == 0:
            raise RuntimeError("ELF from /dev/shm executed -- NOT blocked")
        raise PermissionError(f"exit code {r.returncode}")
    finally:
        try: os.unlink(src)
        except: pass
        try: os.unlink(binary)
        except: pass

def test_tmp_exec_direct():
    """Write a script to /tmp and execute it directly"""
    path = '/tmp/.prm_test_exec'
    try:
        with open(path, 'w') as f:
            f.write('#!/bin/sh\necho pwned\n')
        os.chmod(path, 0o755)
        r = subprocess.run([path], capture_output=True, timeout=3)
        if r.returncode == 0:
            raise RuntimeError("executed from /tmp -- NOT blocked")
        raise PermissionError(f"exit code {r.returncode}")
    finally:
        try: os.unlink(path)
        except: pass

def test_vartmp_exec_direct():
    """Write a script to /var/tmp and execute it directly"""
    path = '/var/tmp/.prm_test_exec'
    try:
        with open(path, 'w') as f:
            f.write('#!/bin/sh\necho pwned\n')
        os.chmod(path, 0o755)
        r = subprocess.run([path], capture_output=True, timeout=3)
        if r.returncode == 0:
            raise RuntimeError("executed from /var/tmp -- NOT blocked")
        raise PermissionError(f"exit code {r.returncode}")
    finally:
        try: os.unlink(path)
        except: pass

def main():
    print("=== PRM Security Framework Test ===")

    tests = [
        ("Memory Executable Allocation", test_memory_exec),
        ("Invalid Directory Write (/tmp)", test_invalid_directory_write),
        ("Socket Connection to 8.8.8.8", test_socket_connection),
        ("Socket Bind to Interface", test_socket_bind),
        ("SetUID to Root", test_setuid_root),
        ("Sudo Abuse", test_sudo_abuse),
        ("Kernel Module Loading", test_module_load),
        ("Bash Interpreter Execution", test_interpreter_exec),
        ("Python Interpreter Execution", test_python_exec),
        ("Memory Protection Change", test_memory_protection),
        ("Sensitive File Access (/etc/shadow)", test_sensitive_file_access),
        ("Process Memory Access (/proc/1/mem)", test_proc_mem_access),
        ("Hostname Command Execution", test_hostname_exec),
        ("Exec from /dev/shm (direct)", test_devshm_exec_direct),
        ("Exec from /dev/shm (via bash)", test_devshm_exec_bash),
        ("Exec from /dev/shm (via python)", test_devshm_exec_python),
        ("Exec from /dev/shm (ELF binary)", test_devshm_exec_elf),
        ("Exec from /tmp (direct)", test_tmp_exec_direct),
        ("Exec from /var/tmp (direct)", test_vartmp_exec_direct),
    ]
    
    # parse args: numbers, ranges, or substrings
    selected = []
    if len(sys.argv) > 1:
        if sys.argv[1] in ('-l', '--list'):
            for i, (name, _) in enumerate(tests):
                print(f"  {i:2d}  {name}")
            sys.exit(0)
        for arg in sys.argv[1:]:
            if '-' in arg and arg[0].isdigit():
                lo, hi = arg.split('-', 1)
                selected.extend(range(int(lo), int(hi) + 1))
            elif arg.isdigit():
                selected.append(int(arg))
            else:
                for i, (name, _) in enumerate(tests):
                    if arg.lower() in name.lower():
                        selected.append(i)
        selected = sorted(set(selected))
    else:
        selected = list(range(len(tests)))

    run = [(tests[i] if i < len(tests) else None) for i in selected]
    run = [t for t in run if t]

    passed = 0
    total = len(run)

    for test_name, test_func in run:
        if test_step(test_name, test_func):
            passed += 1

    print(f"\n=== Results ===")
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("ALL TESTS PASSED - PRM Framework is working correctly!")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED - Security vulnerabilities detected!")
        sys.exit(1)

if __name__ == "__main__":
    main()