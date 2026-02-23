#!/usr/bin/env python3
"""
HPC Security Benchmark Test
Writes 1M iterations to /tmp/ to test security framework overhead
"""
import time
import os
import sys

def benchmark_write_operations(iterations=1000000):
    """Perform 1M write operations to /tmp/benchmark_test.dat"""
    filename = "/tmp/benchmark_test.dat"
    data = b"A" * 8  # 8 bytes per write (simulating double)
    
    print(f"Starting benchmark: {iterations} write operations to {filename}")
    
    start_time = time.perf_counter()
    
    try:
        with open(filename, "wb") as f:
            for i in range(iterations):
                f.write(data)
                if i % 100000 == 0:  # Progress indicator
                    print(f"Progress: {i/iterations*100:.1f}%")
    
    except PermissionError as e:
        print(f"SECURITY BLOCKED: {e}")
        return None
    except Exception as e:
        print(f"ERROR: {e}")
        return None
    
    end_time = time.perf_counter()
    duration = end_time - start_time
    
    # Cleanup
    try:
        os.remove(filename)
    except:
        pass
    
    print(f"Completed {iterations} writes in {duration:.4f} seconds")
    print(f"Throughput: {iterations/duration:.0f} writes/sec")
    
    return duration

if __name__ == "__main__":
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 1000000
    benchmark_write_operations(iterations)