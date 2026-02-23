#!/usr/bin/env python3

import re

def extract_numbers_from_log(filename):
    numbers = []
    with open(filename, 'r') as f:
        for line in f:
            match = re.search(r'(SUCCESS|BLOCKED)\s+([\d.]+)\s+μs', line)
            if match:
                numbers.append(float(match.group(2)))
    return numbers

def calculate_throughput(avg_time_us):
    return int(1000000 / avg_time_us)

files = {
    'Baseline (No Security)': '../baseline.log',
    'PRM Allow': '../allow.log', 
    'PRM Deny': '../deny.log',
    'AppArmor Allow': '../apparmor-allow.log',
    'AppArmor Block': '../apparmor-block.log'
}

print("Configuration & Average (μs) & Throughput (ops/sec)")
for name, file in files.items():
    try:
        data = extract_numbers_from_log(file)
        if data:
            avg = sum(data) / len(data)
            throughput = calculate_throughput(avg)
            print(f"{name} & {avg:.2f} & {throughput:,}")
    except FileNotFoundError:
        print(f"{name} & N/A & N/A")