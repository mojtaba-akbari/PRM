#!/usr/bin/env python3

import re

# Read the apparmor-block.log file
with open('/home/fire/PRM-FRAMEWORK/apparmor-block.log', 'r') as f:
    content = f.read()

# Extract all timing values from samples
times = []
pattern = r'BLOCKED (\d+\.\d+) μs'
matches = re.findall(pattern, content)

for match in matches:
    times.append(float(match))

# The log shows samples every 1000 iterations, but total was 1,000,000 operations
total_operations = 1_000_000  # As stated in the results
sample_count = len(times)
print(f"Sample count: {sample_count}")

# Calculate average from samples
average_per_open_us = sum(times) / len(times)

# Total time calculation: average * total operations
total_time_us = average_per_open_us * total_operations
total_time_s = total_time_us / 1_000_000

# Syscall throughput
syscall_throughput = total_operations / total_time_s

print(f"Analysis of AppArmor Block Data:")
print(f"Total operations: {total_operations:,}")
print(f"Sample average: {average_per_open_us:.2f} μs")
print(f"Total time: {total_time_s:.4f} seconds")
print(f"Average per open(): {average_per_open_us:.2f} μs")
print(f"Syscall throughput: {syscall_throughput:.0f} opens/sec")
print()
print("Formula for average: Sum of all sample times / Number of samples")
print(f"Formula: ({sum(times):.2f} μs) / {len(times)} = {average_per_open_us:.2f} μs")