#!/bin/bash
# Program name: 5.Find_common_Accounts.sh
#
# sk: 20210410 - Modified for python3 version of dc_userenum
# sk: 20210503 - fixed for Groot

date
dc_item=$(head -n 1 domain_controller_list)
domain_name=$(head -n 1 domain_list)
varLogFile="5.Common_Account_Name_output.log"
varResultsFile="userlist"
varNameListPath="/root/cecuri/groot/scripts/name-lists"
varCommandName="./dc_userenum_ldap.py"
program_name=5.Find_common_Accounts.sh


if [[ $1 && $2 && $3 ]]; then  # If dns server and domain and script provided in commandline then
  date > $varLogFile
  echo "Checking for common account names for $domain_name on $dc_item"
  echo "Checking for common account names for $domain_name on $dc_item" >> $varLogFile

  echo $varCommandName $1 $2 $3
  echo $varCommandName $1 $2 $3 >> $varLogFile
  $varCommandName $1 $2 $3 | grep -v "[*]\|[-]\|[+]" >> $varLogFile


  # Got the output now put it into a list!
  tail -n +2 $varLogFile | grep -v "dc_userenum\|Checking for"  > $varResultsFile
  cat $varResultsFile
  exit 0
fi


if [[ $1 == '-h' || $1 == '--help' ]]; then  # If help
  echo "Usage  : $program_name <DNS Server IP> <Domain FQDN> <Script eg /scripts/name-lists/server.txt>"
  echo "Example: $program_name 10.254.10.20 domain.local /scripts/name-lists/server.txt"
  exit 0
fi


date > $varLogFile
echo "Checking for common account names for $domain_name on $dc_item"
echo "Checking for common account names for $domain_name on $dc_item" >> $varLogFile

echo $varCommandName $dc_item $domain_name $varNameListPath/server.txt
echo $varCommandName $dc_item $domain_name $varNameListPath/server.txt >> $varLogFile
$varCommandName $dc_item $domain_name $varNameListPath/server.txt  | grep -v "[*]\|[-]\|[+]" >> $varLogFile

echo $varCommandName $dc_item $domain_name $varNameListPath/john.smith.txt
echo $varCommandName $dc_item $domain_name $varNameListPath/john.smith.txt >> $varLogFile
$varCommandName $dc_item $domain_name $varNameListPath/john.smith.txt  | grep -v "[*]\|[-]\|[+]" >> $varLogFile

echo $varCommandName $dc_item $domain_name $varNameListPath/jsmith.txt
echo $varCommandName $dc_item $domain_name $varNameListPath/jsmith.txt >> $varLogFile
$varCommandName $dc_item $domain_name $varNameListPath/jsmith.txt  | grep -v "[*]\|[-]\|[+]" >> $varLogFile

# Got the output now put it into a list!
# cat $varLogFile | grep -v "dc_userenum\|Checking for"  > $varResultsFile
tail -n +2 $varLogFile | grep -v "dc_userenum\|Checking for"  > $varResultsFile
cat $varResultsFile
