#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# Data from benchmark results
configurations = ['Baseline\n(No Security)', 'PRM Allow\n(Debug On)', 'PRM Block\n(Debug On)']
total_times = [24.84, 23.26, 21.74]
throughput = [40262, 42995, 46004]
avg_per_call = [24.84, 23.26, 21.74]

# Create figure with subplots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Chart 1: Throughput Comparison
bars1 = ax1.bar(configurations, throughput, color=['#ff7f0e', '#2ca02c', '#d62728'])
ax1.set_ylabel('Throughput (operations/second)')
ax1.set_title('PRM Performance: Syscall Throughput\n(1M open() syscalls - Rocky Linux 9.5, 4 CPU, 2GB RAM)')
ax1.set_ylim(0, 50000)

# Add value labels on bars with all details
for i, (bar, value) in enumerate(zip(bars1, throughput)):
    height = bar.get_height()
    # Main throughput value
    ax1.text(bar.get_x() + bar.get_width()/2., height + 1000,
             f'{value:,} ops/s', ha='center', va='bottom', fontweight='bold', fontsize=10)
    # Total time below bar
    ax1.text(bar.get_x() + bar.get_width()/2., height/2,
             f'{total_times[i]:.2f}s', ha='center', va='center', fontweight='bold', color='white', fontsize=9)
    # Average time per call
    ax1.text(bar.get_x() + bar.get_width()/2., height/4,
             f'{avg_per_call[i]:.2f}μs/call', ha='center', va='center', fontweight='bold', color='white', fontsize=8)

# Chart 2: Performance Improvement
improvements = [0, 6.8, 14.3]
bars2 = ax2.bar(configurations, improvements, color=['#ff7f0e', '#2ca02c', '#d62728'])
ax2.set_ylabel('Performance Improvement (%)')
ax2.set_title('PRM Performance Improvement vs Baseline\n(Debug Logging Enabled - Production Would Be Faster)')
ax2.set_ylim(0, 20)

# Add value labels on bars
for i, (bar, value) in enumerate(zip(bars2, improvements)):
    height = bar.get_height()
    if value > 0:
        ax2.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                 f'+{value:.1f}%', ha='center', va='bottom', fontweight='bold', fontsize=12, color='green')
        # Add throughput improvement
        ax2.text(bar.get_x() + bar.get_width()/2., height/2,
                 f'{throughput[i]:,}\nops/s', ha='center', va='center', fontweight='bold', color='white', fontsize=9)
    else:
        ax2.text(bar.get_x() + bar.get_width()/2., 1,
                 'Baseline\n40,262 ops/s', ha='center', va='bottom', fontweight='bold', fontsize=10)

# Add performance improvement annotations with arrows
ax1.annotate('6.8% Faster\n(Intelligent Caching)', xy=(1, 42995), xytext=(0.7, 47000),
            arrowprops=dict(arrowstyle='->', color='green', lw=2),
            fontsize=10, fontweight='bold', color='green', ha='center',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgreen', alpha=0.7))

ax1.annotate('14.3% Faster\n(Early Rejection)', xy=(2, 46004), xytext=(1.7, 48500),
            arrowprops=dict(arrowstyle='->', color='green', lw=2),
            fontsize=10, fontweight='bold', color='green', ha='center',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgreen', alpha=0.7))

# Add system specs text
fig.text(0.5, 0.02, 'Test System: Rocky Linux 9.5, x86_64, 4 CPUs, 2GB RAM | Debug Logging: ON (Production would be faster)',
         ha='center', fontsize=9, style='italic')

plt.tight_layout()
plt.subplots_adjust(bottom=0.15)
plt.savefig('prm_performance_benchmark.png', dpi=300, bbox_inches='tight')
plt.savefig('prm_performance_benchmark.pdf', bbox_inches='tight')
print("Charts saved as prm_performance_benchmark.png and .pdf")

# Create summary table
print("\n=== PRM Performance Summary ===")
print("Configuration          | Time(s) | Avg(μs) | Throughput | Improvement")
print("----------------------|---------|---------|------------|------------")
for i, config in enumerate(configurations):
    config_clean = config.replace('\n', ' ')
    improvement = ((throughput[i] - throughput[0]) / throughput[0] * 100) if i > 0 else 0
    print(f"{config_clean:20} | {total_times[i]:7.2f} | {avg_per_call[i]:7.2f} | {throughput[i]:10,} | {improvement:+6.1f}%")

print("\n=== Key Insights ===")
print("• PRM with caching outperforms baseline by 6.8-14.3%")
print("• Debug logging enabled (production would be faster)")
print("• Early rejection prevents expensive I/O operations")
print("• Intelligent caching eliminates redundant security checks")