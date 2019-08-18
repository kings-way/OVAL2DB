#!/bin/bash

filepath=`readlink -f $0`
basedir=`dirname $filepath`

echo "basedir:"$basedir
cd $basedir

set -e

# Update the resources
bash common_utils/update.sh

# Generate OVAL Table
echo "OVAL Redhat..."; python ./oval/redhat.py 

echo "OVAL Ubuntu..."; python ./oval/ubuntu.py

echo "OVAL Debian..."; python ./oval/debian.py 

# Generate CVE Table
echo "Parsing CVE..."
python ./common_utils/cve_parser/cve_parser.py
echo "Parsing EXP..."
python ./common_utils/cve_parser/exp_parser.py
echo "Parsing CVE for others"
python ./common_utils/cve_parser/cve_others_parser.py
