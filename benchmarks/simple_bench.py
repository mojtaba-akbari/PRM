#!/usr/bin/env python3
import time
import os

def benchmark():
    filename = "/tmp/test.dat"
    iterations = 1000000
    blocked_count = 0
    success_count = 0
    
    print(f"Testing {iterations} open() syscalls on {filename}")
    
    # Overall timing
    start_total = time.perf_counter()
    
    for i in range(iterations):
        try:
            # Per-syscall timing
            start_op = time.perf_counter()
            
            # Just open and close - pure syscall overhead
            f = open(filename, "wb")
            f.close()
            
            end_op = time.perf_counter()
            success_count += 1
            
            # Print every 100k iterations
            if i % 100000 == 0:
                syscall_time = (end_op - start_op) * 1000000  # microseconds
                print(f"Iteration {i}: SUCCESS {syscall_time:.2f} μs")
                
        except (PermissionError, OSError) as e:
            end_op = time.perf_counter()
            blocked_count += 1
            
            # Print every 100k blocks
            if i % 100000 == 0:
                block_time = (end_op - start_op) * 1000000  # microseconds
                print(f"Iteration {i}: BLOCKED {block_time:.2f} μs - {e}")
    
    end_total = time.perf_counter()
    total_time = end_total - start_total
    
    print(f"\nResults:")
    print(f"Total time: {total_time:.4f} seconds")
    print(f"Successful opens: {success_count}")
    print(f"Blocked opens: {blocked_count}")
    print(f"Average per open(): {(total_time/iterations)*1000000:.2f} μs")
    print(f"Syscall throughput: {iterations/total_time:.0f} opens/sec")
    
    # Cleanup if file exists
    try:
        os.remove(filename)
    except:
        pass

if __name__ == "__main__":
    try:
        benchmark()
    except KeyboardInterrupt:
        print("\nBenchmark interrupted")