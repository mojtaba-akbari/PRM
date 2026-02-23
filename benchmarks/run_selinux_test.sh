#!/bin/bash
# Run SELinux benchmark test

echo "=== SELinux Benchmark Test ==="

# Test 1: Baseline (SELinux permissive)
echo "1. Testing baseline (SELinux permissive)..."
setenforce 0
python3 test_workload.py 100000

echo
echo "2. Testing with SELinux enforcing..."
setenforce 1
python3 test_workload.py 100000

echo
echo "3. Installing blocking policy..."
./setup_selinux_test.sh

echo
echo "4. Testing with blocking policy..."
python3 test_workload.py 100000

echo
echo "5. Removing policy..."
semodule -r benchmark_test 2>/dev/null

echo "Test complete."