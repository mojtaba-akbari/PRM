#!/bin/bash
# Security Framework Performance Benchmark
# Tests PRM vs SELinux vs AppArmor vs seccomp

ITERATIONS=1000000
RESULTS_DIR="./results"
TEST_SCRIPT="./test_workload.py"

mkdir -p $RESULTS_DIR

echo "=== HPC Security Framework Benchmark ==="
echo "Test: $ITERATIONS write operations to /tmp/"
echo "Date: $(date)"
echo

# Function to run benchmark and capture results
run_benchmark() {
    local security_system=$1
    local config_file=$2
    
    echo "Testing $security_system..."
    
    # Setup security system if needed
    case $security_system in
        "baseline")
            echo "Running baseline (no security)"
            ;;
        "selinux")
            # SELinux already enforcing on Rocky Linux
            echo "SELinux status: $(getenforce)"
            ;;
        "apparmor")
            sudo systemctl start apparmor 2>/dev/null || echo "AppArmor not available"
            ;;
        "seccomp")
            # Would need seccomp profile
            echo "Seccomp test requires profile setup"
            ;;
        "prm")
            sudo systemctl start filtering-syscall-framework 2>/dev/null || echo "PRM not running"
            ;;
    esac
    
    # Run test 3 times for average
    local total_time=0
    local successful_runs=0
    
    for run in {1..3}; do
        echo "  Run $run/3..."
        result=$(python3 $TEST_SCRIPT $ITERATIONS 2>&1)
        
        if echo "$result" | grep -q "SECURITY BLOCKED"; then
            echo "    BLOCKED by $security_system"
            echo "$result" > "$RESULTS_DIR/${security_system}_blocked.log"
            return 1
        elif echo "$result" | grep -q "Completed"; then
            time=$(echo "$result" | grep "Completed" | awk '{print $5}')
            total_time=$(awk "BEGIN {print $total_time + $time}")
            successful_runs=$((successful_runs + 1))
        else
            echo "    ERROR in run $run"
            echo "$result" > "$RESULTS_DIR/${security_system}_error_$run.log"
        fi
    done
    
    if [ $successful_runs -gt 0 ]; then
        avg_time=$(awk "BEGIN {printf \"%.4f\", $total_time / $successful_runs}")
        throughput=$(awk "BEGIN {printf \"%.0f\", $ITERATIONS / $avg_time}")
        echo "  Average time: ${avg_time}s"
        echo "  Throughput: ${throughput} writes/sec"
        echo "$security_system,$avg_time,$throughput,$successful_runs" >> "$RESULTS_DIR/benchmark_results.csv"
    fi
    
    return 0
}

# Initialize results file
echo "Security_System,Avg_Time_Seconds,Throughput_Writes_Per_Sec,Successful_Runs" > "$RESULTS_DIR/benchmark_results.csv"

# Run benchmarks
run_benchmark "baseline"
run_benchmark "selinux"
run_benchmark "apparmor" 
run_benchmark "seccomp"
run_benchmark "prm"

echo
echo "=== Results Summary ==="
cat "$RESULTS_DIR/benchmark_results.csv"

echo
echo "Results saved to: $RESULTS_DIR/"