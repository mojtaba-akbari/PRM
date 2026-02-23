#!/bin/bash
# Simplified benchmark without complex math

ITERATIONS=1000000
echo "=== Simple Security Benchmark ==="

run_test() {
    local name=$1
    echo "Testing $name..."
    
    result=$(python3 test_workload.py $ITERATIONS 2>&1)
    
    if echo "$result" | grep -q "SECURITY BLOCKED"; then
        echo "  BLOCKED by $name"
    elif echo "$result" | grep -q "Completed"; then
        time=$(echo "$result" | grep "Completed" | awk '{print $5}')
        throughput=$(echo "$result" | grep "Throughput" | awk '{print $2}')
        echo "  Time: ${time}s, Throughput: ${throughput} writes/sec"
        echo "$name,$time,$throughput" >> results.csv
    else
        echo "  ERROR"
    fi
}

echo "System,Time_Seconds,Throughput_Writes_Per_Sec" > results.csv

run_test "baseline"
run_test "selinux" 
run_test "prm"

echo
echo "=== Results ==="
cat results.csv