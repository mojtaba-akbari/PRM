#!/usr/bin/env python3

import time

def benchmark():
    filename = "/tmp/test.dat"
    iterations = 1000000
    
    total_start = time.perf_counter()
    success_count = 0
    blocked_count = 0
    
    for i in range(iterations):
        try:
            start_time = time.perf_counter()
            f = open(filename, "wb")
            f.close()
            end_time = time.perf_counter()
            success_count += 1
            
            if i % 1000 == 0:
                syscall_time = (end_time - start_time) * 1000000
                print(f"Iteration {i}: SUCCESS {syscall_time:.2f} us")
                
        except (PermissionError, OSError) as e:
            end_time = time.perf_counter()
            blocked_count += 1
            block_time = (end_time - start_time) * 1000000
            print(f"Iteration {i}: BLOCKED {block_time:.2f} us")
    
    total_end = time.perf_counter()
    total_time = (total_end - total_start) * 1000  # Convert to ms
    avg_per_call = (total_end - total_start) * 1000000 / iterations  # Convert to μs
    throughput = iterations / (total_end - total_start)  # ops/sec
    
    print(f"\n=== BENCHMARK RESULTS ===")
    print(f"Total iterations: {iterations:,}")
    print(f"Successful operations: {success_count:,}")
    print(f"Blocked operations: {blocked_count:,}")
    print(f"Total time: {total_time:.2f} ms")
    print(f"Average per call: {avg_per_call:.2f} μs")
    print(f"Throughput: {throughput:,.0f} ops/sec")

if __name__ == "__main__":
    benchmark()