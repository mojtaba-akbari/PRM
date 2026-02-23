#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# Raw data from benchmark results
baseline_data = [148.47, 17.55, 18.19, 17.76, 18.24, 30.52, 22.55, 22.48, 17.42, 17.83]
prm_allow_data = [213.79, 15.96, 20.09, 20.42, 31.07, 20.33, 19.69, 30.81, 19.64, 24.32]
prm_block_data = [97.48, 20.08, 17.72, 25.11, 18.35, 25.44, 17.78, 23.72, 43.99, 20.04]

iterations = [0, 100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000]

plt.figure(figsize=(14, 8))

# Plot three lines
plt.plot(iterations, baseline_data, 'o-', linewidth=2, markersize=8, label='Baseline (No Security)', color='#ff7f0e')
plt.plot(iterations, prm_allow_data, 's-', linewidth=2, markersize=8, label='PRM Allow (Cache)', color='#2ca02c')
plt.plot(iterations, prm_block_data, '^-', linewidth=2, markersize=8, label='PRM Block (Reject)', color='#d62728')

# Add all numbers as text annotations
for i, (iter_num, baseline, allow, block) in enumerate(zip(iterations, baseline_data, prm_allow_data, prm_block_data)):
    plt.annotate(f'{baseline:.2f}μs', (iter_num, baseline), textcoords="offset points", 
                xytext=(0,10), ha='center', fontsize=9, color='#ff7f0e', fontweight='bold')
    plt.annotate(f'{allow:.2f}μs', (iter_num, allow), textcoords="offset points", 
                xytext=(0,10), ha='center', fontsize=9, color='#2ca02c', fontweight='bold')
    plt.annotate(f'{block:.2f}μs', (iter_num, block), textcoords="offset points", 
                xytext=(0,-15), ha='center', fontsize=9, color='#d62728', fontweight='bold')

plt.xlabel('Iteration Number')
plt.ylabel('Time per Syscall (μs)')
plt.title('Syscall Performance Measurements: 1M open() calls\nRocky Linux 9.5, x86_64, 4 CPUs, 2GB RAM')
plt.legend()
plt.grid(True, alpha=0.3)

# Format x-axis
plt.ticklabel_format(style='plain', axis='x')
plt.xticks(iterations, [f'{x//1000}K' if x > 0 else '0' for x in iterations])

# Add summary stats as text box
stats_text = f"""Final Results:
Baseline: 24.84s total, 40,262 ops/sec
PRM Allow: 23.26s total, 42,995 ops/sec  
PRM Block: 21.74s total, 46,004 ops/sec"""

plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes, fontsize=10,
         verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))

plt.tight_layout()
plt.savefig('linear_performance_chart.png', dpi=300, bbox_inches='tight')
plt.savefig('linear_performance_chart.pdf', bbox_inches='tight')
print("Linear chart saved as linear_performance_chart.png and .pdf")

# Print all data points
print("\n=== All Data Points ===")
print("Iteration | Baseline | PRM Allow | PRM Block")
print("----------|----------|-----------|----------")
for i, (iter_num, baseline, allow, block) in enumerate(zip(iterations, baseline_data, prm_allow_data, prm_block_data)):
    print(f"{iter_num:9} | {baseline:8.2f} | {allow:9.2f} | {block:9.2f}")