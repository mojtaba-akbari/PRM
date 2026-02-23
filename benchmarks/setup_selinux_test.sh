#!/bin/bash
# Setup SELinux to block /tmp writes for testing

echo "Setting up SELinux test policy..."

# Create custom SELinux policy
cat > benchmark_test.te << 'EOF'
policy_module(benchmark_test, 1.0)

require {
    type unconfined_t;
    type tmp_t;
    class file { write create open };
}

# Block python writes to /tmp
neverallow unconfined_t tmp_t:file { write create };
EOF

# Compile and install policy
checkmodule -M -m -o benchmark_test.mod benchmark_test.te
semodule_package -o benchmark_test.pp -m benchmark_test.mod
semodule -i benchmark_test.pp

echo "SELinux policy installed. Python writes to /tmp should now be blocked."
echo "To remove: semodule -r benchmark_test"