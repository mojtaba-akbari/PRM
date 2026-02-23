#!/bin/bash
#SBATCH --job-name=prm_test
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --time=00:10:00
#SBATCH --output=prm_test_%j.out
#SBATCH --error=prm_test_%j.err
#SBATCH --nodelist=node2

cd $SLURM_SUBMIT_DIR
python3 test_security.py