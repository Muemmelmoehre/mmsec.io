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


IMPACKET
--------
# get TGT for users with UF_DONT_REQUIRE_PREAUTH
/path/to/impacket/examples/GetNPUsers.py domain/ -usersfile /path/to/users.txt -no-pass -outputfile /path/to/tgt.txt

# dump secrets as user
/path/to/impacket-secretsdump -dc-ip IP_here user:password@IP_here

# gather service principal names
/path/to/impacket/examples/GetUserSPNs.py -dc-ip IP_here domain/user


LDAP
----
# nmap script
nmap --script ldap-search IP_here 

ldapsearch -LLL -x -H ldap://IP_here -b '' -s base'(objectclass=*)'

ldapsearch -x -h IP_here -s sub -b 'dc=domain_here,dc=dc2_here'


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


PIP
---
# install pip package
python3 -m pip install package


PYTHON
------
# user python path from env
#!/usr/bin/env python
#!/usr/bin/env python3


REG QUERY
---------
# enumerate registry information, search recursively for password in HKLM
reg query HKLM /f password /t REG_SZ /s

# enumerate registry information, search recursively for password in HKCU
reg query HKCU /f password /t REG_SZ /s


RPC
---------
# connect anonymously
rpcclient -U "" IP_here

# connect as user
rpcclient -U username%password IP_here

# nmap script
nmap --script rpc-grind IP_here


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

# connect to a directory on a share as username
smbclient \\\\IP_here\\some_share -D some_folder -U username%password

# enumerate smb shares
nmap --script=smb-enum-shares IP_here

# enumerate smb shares
smbmap -H IP_here

# enumerate smb shares as user
smbmap -u user -p password -d domain -H IP_here

# upload file
put /path/to/local/file [/path/remote]

# download file
get /path/to/remote/file



SQLMAP
------
# launch sqlmap from a GET / POST request file
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3


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


WINDOWS CLI
-----------
# enumerate hidden files
dir -ah
dir /ah
attrib
```
