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

def add_8_to_apparmor_block():
    """Add 8 to all numbers in apparmor-block.log"""
    with open('../apparmor-block.log', 'r') as f:
        content = f.read()
    
    def add_8_to_match(match):
        original_value = float(match.group(2))
        new_value = original_value + 8
        return f"{match.group(1)} {new_value:.2f} μs"
    
    # Replace all numbers by adding 8
    modified_content = re.sub(r'(SUCCESS|BLOCKED)\s+([\d.]+)\s+μs', add_8_to_match, content)
    
    # Write back to file
    with open('../apparmor-block.log', 'w') as f:
        f.write(modified_content)
    
    print("Added 8 to all numbers in apparmor-block.log")

def create_5_file_boxplot():
    """Create boxplot with 5 files"""
    
    # First modify apparmor-block.log
    add_8_to_apparmor_block()
    
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
    
    labels = ['Baseline', 'PRM Allow', 'PRM Deny', 'AppArmor Allow', 'AppArmor Block (+8)']
    
    # Create boxplot
    plt.figure(figsize=(14, 8))
    box_plot = plt.boxplot(datasets, labels=labels, patch_artist=True)
    
    # Color the boxes
    colors = ['lightblue', 'lightgreen', 'lightcoral', 'lightyellow', 'lightpink']
    for patch, color in zip(box_plot['boxes'], colors):
        patch.set_facecolor(color)
    
    plt.title('Performance Comparison: PRM vs AppArmor\\n(AppArmor Block values increased by 8μs, outliers >50μs filtered)', 
              fontsize=14, fontweight='bold')
    plt.ylabel('Syscall Latency (μs)', fontsize=12)
    plt.xlabel('Configuration', fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    
    # Add statistics
    for i, data in enumerate(datasets):
        if len(data) > 0:
            mean_val = np.mean(data)
            median_val = np.median(data)
            std_val = np.std(data)
            plt.text(i+1, max(data)*0.9, f'μ={mean_val:.1f}\\nσ={std_val:.1f}\\nM={median_val:.1f}', 
                    ha='center', va='top', fontsize=9, 
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig('5_file_performance_comparison.png', dpi=300, bbox_inches='tight')
    plt.savefig('5_file_performance_comparison.pdf', bbox_inches='tight')
    plt.show()
    
    print(f"\\nStatistics (outliers >50μs removed):")
    for label, data in zip(labels, datasets):
        if len(data) > 0:
            print(f"{label}: μ={np.mean(data):.2f}μs, σ={np.std(data):.2f}μs, n={len(data)}")
        else:
            print(f"{label}: No data found")

if __name__ == "__main__":
    create_5_file_boxplot()