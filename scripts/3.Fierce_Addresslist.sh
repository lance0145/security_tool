#!/bin/bash
# Program name: 3.Fierce_Addresslist.sh
#
# sk: 20210330 - fierce rewriten in python3 and options changed to allow CIDR range.
# sk: 20210424 - fixed for Groot

date
varAddressFile="addresslist"
varDNSFile="dns_list"
varLogFile="3.fierce.log"
varResultsFile="3.fierce.results.txt"
program_name=3.Fierce_Addresslist.sh


if [[ $1 && $2 ]]; then  # If dns server and range provided in commandline then
  date > $varResultsFile
  echo "Performing fierce dns scan on DNS Server $1 for $2"
  fierce --dns-servers $1 --range $2 > $varLogFile
  # sort -u -V $varTempFile >> $varLogFile
  cat $varLogFile | tr -d '{,},,',' ' | sort -u -V  >> $varResultsFile
  cat $varResultsFile
  exit 0
fi


if [[ $1 == '-h' || $1 == '--help' ]]; then  # If help
  echo "Usage: $program_name <DNS Server IP> <Range Subnet CIDR>"
  exit 0
fi


if [[ -f "$varAddressFile" && -f "$varDNSFile" ]]; then
  echo $varAddressFile found.
  echo $varDNSFile found.
  date > $varResultsFile
  echo > $varLogFile
  paste $varAddressFile | while IFS="$(printf '\t')" read -r f1
  do
    paste $varDNSFile | while IFS="$(printf '\t')" read -r f2
    do
    echo "Performing fierce dns scan on DNS Server $f2 for $f1"
    echo "Performing fierce dns scan on DNS Server $f2 for $f1" >> $varLogFile
    fierce --dns-servers $f2 --range $f1 >> $varLogFile
    #printf 'f1: %s\n' "$f1"
    #printf 'f2: %s\n' "$f2"
    done
  done
  cat $varLogFile | grep -v "Performing fierce" | tr -d '{,},,',' ' | sort -u -V  >> $varResultsFile
  cat $varResultsFile
  exit 0
fi
