#!/bin/bash
# Complete security comparison benchmark

echo "=== Security Framework Comparison Benchmark ==="
echo "Testing: 1M write operations to /tmp/"
echo

# Make scripts executable
chmod +x test_workload.py security_benchmark.sh

# Check system capabilities
echo "System Check:"
echo "- SELinux: $(getenforce 2>/dev/null || echo 'Not available')"
echo "- AppArmor: $(systemctl is-active apparmor 2>/dev/null || echo 'Not available')"
echo "- PRM: $(systemctl is-active filtering-syscall-framework 2>/dev/null || echo 'Not running')"
echo

# Run the benchmark
./security_benchmark.sh

echo
echo "=== Analysis ==="
echo "1. Performance Impact: Check avg_time differences"
echo "2. Security Coverage: Check which systems blocked the operation"
echo "3. Throughput Comparison: Higher = better performance"
echo
echo "Expected Results:"
echo "- Baseline: Fastest (no security overhead)"
echo "- PRM: Fast with caching (should be close to baseline after first run)"
echo "- SELinux/AppArmor: Slower due to policy evaluation overhead"
echo "- Seccomp: Moderate overhead, limited protection"