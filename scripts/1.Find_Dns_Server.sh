#!/bin/bash
# Program name: 1.Find_Dns_Server.sh
# 20210409 : sk fixed for Groot

varAddressFile="addresslist"
varLogFile="1.Find_Dns_Server.log"
varOutputFile="dns_list"

date
date > $varLogFile

# If do not include an address in command line argument 
if [[ -z $1 ]]; then

  # If no address and addresslist file exists
  if [ -f "$varAddressFile" ]; then
    echo $varAddressFile found.
  else
    read -p "Enter IP or CIDR address to search :" address

    if [[ -z $address ]]; then
      echo 'Need to enter a valid IP or CIDR address.'
      exit 0
    fi

    IfAddress="True" 
  fi

else

  # If address included in command line argument
  address=$1
  IfAddress="True" 

fi

if [[ -z $IfAddress ]]; then  # If address list file

  cat addresslist |  while read output
  do
      echo "Scanning $output for DNS Servers"
      echo nmap -v -T4 --open -p 53 $output
      nmap -v -T4 --open -p 53 -oG - $output | tee -a $varLogFile
  done

  cat $varLogFile | grep "Ports: 53" | cut -d ':' -f2 | cut -d ' ' -f2 | tee $varOutputFile
  exit 0

else  # If address

  echo "Scanning $address for DNS Servers"
  echo nmap -v -T4 --open -p 53 $address
  nmap -v -T4 --open -p 53 -oG - $address | tee -a $varLogFile
  cat $varLogFile | grep "Ports: 53" | cut -d ':' -f2 | cut -d ' ' -f2 | tee $varOutputFile
  exit 0

fi
