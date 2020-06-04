---
title: "Security grimoire"
layout: single
author_profile: true
classes: wide
---
Welcome to [@muemmelmoehre](https://github.com/muemmelmoehre)'s online grimoire / cheat-sheet for useful commands and other security related stuff. Enjoy!


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
nmap --script ldap-search IP_here 

ldapsearch -LLL -x -H ldap://IP_here -b '' -s base'(objectclass=*)'

ldapsearch -x -h IP_here -s sub -b 'dc=domain_here,dc=dc2_here'


MSSQL
-----
# connect to a db server as user
mssql -s IP_db_server -o port -u username -p password


MYSQL / MARIADB
---------------
systemctl start mysql.service (start service)
systemctl restart mysql.service (restart service)
systemctl stop mysql.service (stop service)
mysql -u root -p (launch as default user on kali)
create database 'db_name'; (create new database)
use db_name; (enter database)
show databases; (list existing databases)
create table 'table_name' (column_name1 VARCHAR(20), username VARCHAR(8), email VARCHAR(35), password VARCHAR(25), [...]); (create new table + define columns)
show tables; (list existing tables of current database)
select * from 'table_name'; (list all data from table)
create user 'username'@'localhost' identified by 'password';(create new user@localhost)
create user 'username'@'IP_here' identified by 'password';(create new user@IP_here)
create user 'username'@'%' identified by 'password';(create new user@IP_wildcard)
grant all privileges on *.* to 'username'@'IP_here' identified by 'password'; (grant privileges to user@IP_here for every database)
grant all privileges on 'db_name'.* to 'username'@'IP_here' identified by 'password'; (grant privileges to user@IP_here for every table in db_name database)
grant all privileges on 'db_name'.'table_name' to 'username'@'IP_here' identified by 'password'; (grant privileges to user@IP_here for table table_name in db_name database)
show grants for 'username'@'IP_here'; (show privileges for user)
flush privileges; (apply changes to privileges)
drop user 'username'@'IP_here'; (delete user)


PIP
---
python3 -m pip install package (install pip package)


PYTHON
------
#!/usr/bin/env python (user python path from env)
#!/usr/bin/env python3 (use python3 path from env)


REG QUERY
---------
reg query HKLM /f password /t REG_SZ /s (enumerate registry information, search recursively for password in HKLM)
reg query HKCU /f password /t REG_SZ /s (enumerate registry information, search recursively for password in HKCU)


RPC
---------
rpcclient -U "" IP_here (connect anonymously)
rpcclient -U username%password IP_here (connect as user)
nmap --script rpc-grind IP_here


SFTP
----
sftp -oPort=port user@IP_here (connect as user)
put /path/to/local/file [/path/remote] (upload file)
get /path/to/remote/file (download file)


SIPVICIOUS
----------
svmap IP_range_here (enumerate SIP servers)
svwar -m INVITE IP_here (enumerate valid extensions for SIP endpoints)


SMB
---------
smbclient -L smb -I IP_here (enumerate shares with anonymous login)
smbclient \\\\IP_here\\some_share -D some_folder -U username%password (connect to a directory on a share as username)
nmap --script=smb-enum-shares IP_here (enumerate smb shares)
smbmap -H IP_here (enumerate smb shares)
smbmap -u user -p password -d domain -H IP_here (enumerate smb shares as user)
put /path/to/local/file [/path/remote] (upload file)
get /path/to/remote/file (download file)



SQLMAP
------
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3 (launch sqlmap from a GET / POST request file)


SSH
---
ssh user@IP (connect as user with password)
ssh -i private_key user@IP (connect as user with private key)
ssh -L port_to_forward_to:IP_here:port_to_forward_from (port forwarding)


TCPDUMP
-------
tcpdump -D (list all interfaces)
tcpdump -i interface_here (monitor connections on interface)
tcpdump -i interface_here src IP_here and dst IP_here (monitor specific src and / or dst IP)
tcpdump -i interface_here dst IP_here and port port_here (monitor specific dst IP and port)


WINDOWS CLI
-----------
dir -ah (enumerate hidden files)
dir /ah (enumerate hidden files)
attrib (enumerate hidden files)
```
