#!/usr/bin/env python3

import re

# Read the apparmor-block.log file
with open('/home/fire/PRM-FRAMEWORK/apparmor-block.log', 'r') as f:
    content = f.read()

# Extract all timing values
times = []
pattern = r'BLOCKED (\d+\.\d+) μs'
matches = re.findall(pattern, content)

for match in matches:
    times.append(float(match))

# Calculate metrics
total_operations = len(times)
sum_times_microseconds = sum(times)
sum_times_seconds = sum_times_microseconds / 1_000_000

# Calculate average per open() in microseconds
average_per_open = sum_times_microseconds / total_operations

# Calculate syscall throughput (operations per second)
syscall_throughput = total_operations / sum_times_seconds

print(f"Analysis of AppArmor Block Data:")
print(f"Total operations: {total_operations}")
print(f"Sum of all times: {sum_times_microseconds:.2f} μs = {sum_times_seconds:.6f} seconds")
print(f"Average per open(): {average_per_open:.2f} μs")
print(f"Syscall throughput: {syscall_throughput:.0f} opens/sec")
print()
print(f"Current values in log:")
print(f"Total time: 5.1388 seconds (INCORRECT)")
print(f"Average per open(): 11.14 μs (INCORRECT)")
print(f"Syscall throughput: 194596 opens/sec (INCORRECT)")
print()
print(f"Corrected values:")
print(f"Total time: {sum_times_seconds:.6f} seconds")
print(f"Average per open(): {average_per_open:.2f} μs")
print(f"Syscall throughput: {syscall_throughput:.0f} opens/sec")