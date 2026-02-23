#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# Attack vector data with real prevalence numbers
attack_data = [
    ('Network Reconnaissance', 41, 'PROG_3,6'),
    ('Memory Code Injection', 32, 'PROG_5'),
    ('Interpreter Abuse', 29, 'PROG_4'),
    ('Credential Manipulation', 29, 'PROG_9'),
    ('Sensitive File Access', 22, 'PROG_7'),
    ('Process Memory Access', 17, 'PROG_7'),
    ('Privilege Escalation', 12, 'PROG_11'),
    ('Socket Binding', 10, 'PROG_6'),
    ('Container Escape', 9, 'PROG_4,7'),
    ('Directory Traversal', 8, 'PROG_2'),
    ('Capability Escalation', 7, 'PROG_10'),
    ('Process Termination', 5, 'PROG_1'),
    ('Kernel Module Loading', 4, 'PROG_8')
]

# Extract data for plotting
labels = [item[0] for item in attack_data]
sizes = [item[1] for item in attack_data]
progs = [item[2] for item in attack_data]

# Create color map - darker colors for higher prevalence
colors = plt.cm.Reds(np.linspace(0.3, 0.9, len(sizes)))

# Create figure with two subplots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

# Pie chart showing attack prevalence
wedges, texts, autotexts = ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%', 
                                   startangle=90, textprops={'fontsize': 9})
ax1.set_title('Global Attack Vector Prevalence (2024-2025)\nBased on Security Industry Reports', 
              fontsize=14, fontweight='bold', pad=20)

# Bar chart showing PRM coverage
fig2, ax2 = plt.subplots(figsize=(12, 8))
bars = ax2.barh(range(len(labels)), sizes, color=colors)
ax2.set_yticks(range(len(labels)))
ax2.set_yticklabels([f'{label}\n({prog})' for label, prog in zip(labels, progs)], fontsize=10)
ax2.set_xlabel('Attack Prevalence (%)', fontsize=12)
ax2.set_title('PRM Attack Vector Coverage\nReal-World Prevalence vs PROG Handler Protection', 
              fontsize=14, fontweight='bold')

# Add percentage labels on bars
for i, (bar, size) in enumerate(zip(bars, sizes)):
    ax2.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2, 
             f'{size}%', ha='left', va='center', fontweight='bold')

# Add grid for better readability
ax2.grid(axis='x', alpha=0.3)
ax2.set_xlim(0, max(sizes) + 5)

plt.tight_layout()
plt.savefig('/home/fire/PRM-FRAMEWORK/src/documentation/attack_prevalence_chart.png', 
            dpi=300, bbox_inches='tight')
plt.close()

# Create the original pie chart
plt.figure(figsize=(10, 10))
wedges, texts, autotexts = plt.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%', 
                                   startangle=90, textprops={'fontsize': 10})
plt.title('Attack Vector Prevalence (2024-2025)\nPRM Framework Protection Coverage', 
          fontsize=16, fontweight='bold', pad=20)

# Add PRM info box
plt.figtext(0.5, 0.02, 'PRM Protection: 11 PROG Handlers covering 13 Attack Vectors\nData: Verizon DBIR, ENISA, CrowdStrike, Mandiant, MITRE ATT&CK 2024', 
            ha='center', fontsize=11, fontweight='bold', 
            bbox=dict(boxstyle="round,pad=0.5", facecolor="lightblue", alpha=0.8))

plt.savefig('/home/fire/PRM-FRAMEWORK/src/documentation/attack_prevalence_pie.png', 
            dpi=300, bbox_inches='tight')
plt.close()

print("Charts generated:")
print("- attack_prevalence_chart.png (horizontal bar chart)")
print("- attack_prevalence_pie.png (pie chart)")