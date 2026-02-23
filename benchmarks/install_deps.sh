#!/bin/bash
# Install benchmark dependencies for Rocky Linux

dnf install -y python3 libseccomp-devel libseccomp-utils

echo "Dependencies installed. Ready for benchmarking."