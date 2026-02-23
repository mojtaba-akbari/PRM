#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# Raw data from benchmark results
baseline_data = [148.47, 17.55, 18.19, 17.76, 18.24, 30.52, 22.55, 22.48, 17.42, 17.83]
prm_allow_data = [213.79, 15.96, 20.09, 20.42, 31.07, 20.33, 19.69, 30.81, 19.64, 24.32]
prm_block_data = [97.48, 20.08, 17.72, 25.11, 18.35, 25.44, 17.78, 23.72, 43.99, 20.04]

iterations = [0, 100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000]

plt.figure(figsize=(14, 8))

# Set up bar positions
x = np.arange(len(iterations))
width = 0.25

# Create bars
bars1 = plt.bar(x - width, baseline_data, width, label='Baseline (No Security)', color='#ff7f0e', alpha=0.8)
bars2 = plt.bar(x, prm_allow_data, width, label='PRM Allow (Cache)', color='#2ca02c', alpha=0.8)
bars3 = plt.bar(x + width, prm_block_data, width, label='PRM Block (Reject)', color='#d62728', alpha=0.8)

# Add value labels on bars (only if under 50)
for i, (baseline, allow, block) in enumerate(zip(baseline_data, prm_allow_data, prm_block_data)):
    if baseline <= 50:
        plt.text(i - width, baseline + 1, f'{baseline:.1f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
    if allow <= 50:
        plt.text(i, allow + 1, f'{allow:.1f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
    if block <= 50:
        plt.text(i + width, block + 1, f'{block:.1f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

# Set Y-axis limit to 50 as requested
plt.ylim(0, 50)

plt.xlabel('Iteration Number')
plt.ylabel('Time per Syscall (μs)')
plt.title('Syscall Performance Measurements: 1M open() calls (Y-axis limited to 50μs)\\nRocky Linux 9.5, x86_64, 4 CPUs, 2GB RAM')
plt.legend()
plt.grid(True, alpha=0.3, axis='y')

# Format x-axis
plt.xticks(x, [f'{iter_num//1000}K' if iter_num > 0 else '0' for iter_num in iterations])

# Add note about truncated values
note_text = "Note: Iteration 0 values truncated (Baseline: 148.47μs, PRM Allow: 213.79μs, PRM Block: 97.48μs)"
plt.text(0.5, 0.02, note_text, transform=plt.gca().transAxes, fontsize=9,
         ha='center', va='bottom', bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))

# Add summary stats
stats_text = f"""Final Results:
Baseline: 24.84s total, 40,262 ops/sec
PRM Allow: 23.26s total, 42,995 ops/sec  
PRM Block: 21.74s total, 46,004 ops/sec"""

plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes, fontsize=10,
         verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))

plt.tight_layout()
plt.savefig('bar_performance_chart.png', dpi=300, bbox_inches='tight')
plt.savefig('bar_performance_chart.pdf', bbox_inches='tight')
print("Bar chart saved as bar_performance_chart.png and .pdf")

# Print all data points
print("\n=== All Data Points ===")
print("Iteration | Baseline | PRM Allow | PRM Block")
print("----------|----------|-----------|----------")
for i, (iter_num, baseline, allow, block) in enumerate(zip(iterations, baseline_data, prm_allow_data, prm_block_data)):
    print(f"{iter_num:9} | {baseline:8.2f} | {allow:9.2f} | {block:9.2f}")