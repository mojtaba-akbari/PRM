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

# Calculate min and max
min_time = min(times)
max_time = max(times)

print(f"Real AppArmor Block Min: {min_time:.2f} μs")
print(f"Real AppArmor Block Max: {max_time:.2f} μs")
print(f"Total samples: {len(times)}")
print(f"Average: {sum(times)/len(times):.2f} μs")