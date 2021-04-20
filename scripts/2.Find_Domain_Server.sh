#!/bin/bash
# Program name: 2.Find_Domain_Server.sh
# 20210409 : sk fixed for Groot

varAddressFile="addresslist"
varLogFile="2.Find_Domain_Server.log"
varDomainNameOutputFile="domain_list"
varDomainControllerOutputFile="domain_controller_list"

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
      echo "Scanning $output for Domain Controllers"
      echo nmap -v -T4 --open -p 389 -sV $output
      nmap -v -T4 --open -p 389 -sV -oG - $output | tee -a $varLogFile
  done

  cat $varLogFile | grep "Domain:" | cut -d ':' -f 4 | cut -d ',' -f1 | sed 's/^ *//' | sort -u | tee $varDomainNameOutputFile
  cat $varLogFile | grep "Ports: 389/open/tcp" | cut -d ':' -f2 | cut -d ' ' -f2 | tee $varDomainControllerOutputFile
  exit 0

else  # If address

  echo "Scanning $output for Domain Controllers"
  echo nmap -v -T4 --open -p 389 -sV $address
  nmap -v -T4 --open -p 389 -sV -oG - $address | tee -a $varLogFile

  cat $varLogFile | grep "Domain:" | cut -d ':' -f 4 | cut -d ',' -f1 | sed 's/^ *//' | sort -u | tee $varDomainNameOutputFile
  cat $varLogFile | grep "Ports: 389/open/tcp" | cut -d ':' -f2 | cut -d ' ' -f2 | tee $varDomainControllerOutputFile
  exit 0

fi
