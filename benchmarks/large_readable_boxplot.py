#!/usr/bin/env python3

import re
import matplotlib.pyplot as plt
import numpy as np

def extract_numbers_from_log(filename):
    """Extract SUCCESS and BLOCKED numbers from log file"""
    numbers = []
    with open(filename, 'r') as f:
        for line in f:
            match = re.search(r'(SUCCESS|BLOCKED)\s+([\d.]+)\s+μs', line)
            if match:
                numbers.append(float(match.group(2)))
    return numbers

def create_large_readable_boxplot():
    """Create large, readable boxplot with bigger fonts"""
    
    # Load all 5 datasets
    try:
        baseline_data = extract_numbers_from_log('../baseline.log')
        allow_data = extract_numbers_from_log('../allow.log')
        deny_data = extract_numbers_from_log('../deny.log')
        apparmor_allow_data = extract_numbers_from_log('../apparmor-allow.log')
        apparmor_block_data = extract_numbers_from_log('../apparmor-block.log')
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return
    
    # Filter outliers for better visualization
    def filter_outliers(data, threshold=50):
        return [x for x in data if x <= threshold]
    
    datasets = [
        filter_outliers(baseline_data),
        filter_outliers(allow_data),
        filter_outliers(deny_data),
        filter_outliers(apparmor_allow_data),
        filter_outliers(apparmor_block_data)
    ]
    
    labels = ['Baseline', 'PRM Allow', 'PRM Deny', 'AppArmor Allow', 'AppArmor Block']
    
    # Create large figure with bigger fonts
    plt.figure(figsize=(18, 12))  # Much larger figure
    
    # Set global font sizes
    plt.rcParams.update({
        'font.size': 16,
        'axes.titlesize': 20,
        'axes.labelsize': 18,
        'xtick.labelsize': 16,
        'ytick.labelsize': 16,
        'legend.fontsize': 14
    })
    
    box_plot = plt.boxplot(datasets, labels=labels, patch_artist=True, 
                          boxprops=dict(linewidth=2),
                          whiskerprops=dict(linewidth=2),
                          capprops=dict(linewidth=2),
                          medianprops=dict(linewidth=3, color='red'))
    
    # Color the boxes with stronger colors
    colors = ['#87CEEB', '#90EE90', '#F08080', '#FFFFE0', '#FFB6C1']
    for patch, color in zip(box_plot['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.8)
    
    plt.title('PRM eBPF LSM call / AppArmor LSM call (outliers >50μs filtered)', 
              fontsize=24, fontweight='bold', pad=20)
    plt.ylabel('Syscall Latency (μs)', fontsize=20, fontweight='bold')
    plt.xlabel('Configuration', fontsize=20, fontweight='bold')
    plt.grid(True, alpha=0.3, linewidth=1)
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=0, ha='center')
    
    # Add statistics with larger, more readable text
    for i, data in enumerate(datasets):
        if len(data) > 0:
            mean_val = np.mean(data)
            median_val = np.median(data)
            std_val = np.std(data)
            plt.text(i+1, max(data)*0.85, f'μ={mean_val:.1f}\\nσ={std_val:.1f}\\nM={median_val:.1f}', 
                    ha='center', va='top', fontsize=14, fontweight='bold',
                    bbox=dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.9, edgecolor='black'))
    
    # Adjust layout to prevent label cutoff
    plt.tight_layout(pad=3.0)
    
    # Save with high DPI for crisp text
    plt.savefig('PRM_vs_AppArmor_LARGE.png', dpi=400, bbox_inches='tight', facecolor='white')
    plt.savefig('PRM_vs_AppArmor_LARGE.pdf', bbox_inches='tight', facecolor='white')
    plt.show()
    
    print(f"Large readable chart created!")
    print(f"Statistics (outliers >50μs removed):")
    for label, data in zip(labels, datasets):
        if len(data) > 0:
            print(f"{label}: μ={np.mean(data):.2f}μs, σ={np.std(data):.2f}μs, n={len(data)}")
        else:
            print(f"{label}: No data found")

if __name__ == "__main__":
    create_large_readable_boxplot()