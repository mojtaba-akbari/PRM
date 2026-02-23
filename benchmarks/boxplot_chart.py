#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def load_data(filename):
    """Load data from log file, handling large datasets efficiently"""
    try:
        with open(filename, 'r') as f:
            data = []
            for line in f:
                line = line.strip()
                if 'μs' in line and ('SUCCESS' in line or 'BLOCKED' in line):
                    try:
                        # Extract the time value before 'μs'
                        parts = line.split('μs')[0].split()
                        value = float(parts[-1])
                        data.append(value)
                    except (ValueError, IndexError):
                        continue
        return np.array(data)
    except FileNotFoundError:
        print(f"Warning: {filename} not found, using sample data")
        return np.random.normal(20, 5, 1000)  # Sample data

# Load data from log files
baseline_data_raw = load_data('baseline.log')
allow_data_raw = load_data('allow.log') 
deny_data_raw = load_data('deny.log')

# Filter out values above 30μs for extreme zoom
baseline_data = baseline_data_raw[baseline_data_raw <= 30]
allow_data = allow_data_raw[allow_data_raw <= 30]
deny_data = deny_data_raw[deny_data_raw <= 30]

print(f"Loaded data - Baseline: {len(baseline_data)}/{len(baseline_data_raw)} points, Allow: {len(allow_data)}/{len(allow_data_raw)} points, Deny: {len(deny_data)}/{len(deny_data_raw)} points")
print(f"Filtered out {len(baseline_data_raw)-len(baseline_data)} baseline, {len(allow_data_raw)-len(allow_data)} allow, {len(deny_data_raw)-len(deny_data)} deny outliers above 30μs")

# Create boxplot
plt.figure(figsize=(12, 8))

# Prepare data for boxplot
data_to_plot = [baseline_data, allow_data, deny_data]
labels = ['Baseline\n(No Security)', 'PRM Allow\n(Permitted)', 'PRM Deny\n(Blocked)']

# Create boxplot with custom styling
box_plot = plt.boxplot(data_to_plot, labels=labels, patch_artist=True, 
                       showmeans=True, meanline=True,
                       boxprops=dict(facecolor='lightblue', alpha=0.7),
                       medianprops=dict(color='red', linewidth=2),
                       meanprops=dict(color='green', linewidth=2),
                       whiskerprops=dict(color='black', linewidth=1.5),
                       capprops=dict(color='black', linewidth=1.5),
                       flierprops=dict(marker='o', markerfacecolor='red', markersize=4, alpha=0.5))

# Color the boxes differently
colors = ['#ff7f0e', '#2ca02c', '#d62728']
for patch, color in zip(box_plot['boxes'], colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)

plt.ylabel('Time per Syscall (μs)', fontsize=18, fontweight='bold')
plt.title('Syscall Latency Analysis', fontsize=16, fontweight='bold')
plt.ylim(0, 30)
plt.grid(True, alpha=0.3, axis='y')

# Increase tick label sizes significantly
plt.tick_params(axis='both', which='major', labelsize=16)
plt.tick_params(axis='x', which='major', labelsize=14)

# Add statistics text
stats_text = []
for i, (data, label) in enumerate(zip(data_to_plot, ['Baseline', 'PRM Allow', 'PRM Deny'])):
    mean_val = np.mean(data)
    median_val = np.median(data)
    std_val = np.std(data)
    stats_text.append(f"{label}: μ={mean_val:.2f}μs, σ={std_val:.2f}μs")

stats_str = '\n'.join(stats_text)
plt.text(0.02, 0.98, stats_str, transform=plt.gca().transAxes, fontsize=10,
         verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))

# Add legend for boxplot elements
legend_elements = [
    plt.Line2D([0], [0], color='red', linewidth=2, label='Median'),
    plt.Line2D([0], [0], color='green', linewidth=2, label='Mean'),
    plt.Rectangle((0, 0), 1, 1, facecolor='lightblue', alpha=0.7, label='IQR (25%-75%)'),
    plt.Line2D([0], [0], color='black', linewidth=1.5, label='Whiskers (1.5×IQR)'),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=4, label='Outliers')
]
plt.legend(handles=legend_elements, loc='upper right', fontsize=14, prop={'weight': 'bold'})

plt.tight_layout()
plt.savefig('boxplot_performance_chart.png', dpi=300, bbox_inches='tight')
plt.savefig('boxplot_performance_chart.pdf', bbox_inches='tight')
print("Boxplot saved as boxplot_performance_chart.png and .pdf")

# Print summary statistics
print("\n=== Summary Statistics ===")
for data, label in zip(data_to_plot, ['Baseline', 'PRM Allow', 'PRM Deny']):
    print(f"\n{label}:")
    print(f"  Count: {len(data)}")
    print(f"  Mean: {np.mean(data):.3f} μs")
    print(f"  Median: {np.median(data):.3f} μs")
    print(f"  Std Dev: {np.std(data):.3f} μs")
    print(f"  Min: {np.min(data):.3f} μs")
    print(f"  Max: {np.max(data):.3f} μs")
    print(f"  25th percentile: {np.percentile(data, 25):.3f} μs")
    print(f"  75th percentile: {np.percentile(data, 75):.3f} μs")