#!/bin/bash
# Program name: 4.Enum4Linux_No_Creds.sh
date
cat domain_controller_list |  while read output
do
    echo "Scanning $1 for Null Session"
    echo "Scanning $1 for Null Session" > 4.enum4linux_no_creds_output.txt
    echo enum4linux $1
    enum4linux $1 >> 4.enum4linux_no_creds_output.txt
done