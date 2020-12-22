---
layout: single
title: "Lessons learnt from HTB Joker"
author_profile: true
categories:
  - htb
classes:
tags:
  - ...
---

# Lessons learnt from HTB Joker

This blog post isn't so much a write-up as a summary of interesting thing I learnt while working through *Joker*. Check out the *Resources* section for links to awesome write-ups!



## Accelerating slow nmap scans

Ippsec mentions a neat trick for speeding up notoriously slow scans like UDP scans : he locates a box that

* he has access to
* is on the same network as our target
* has *nmap* installed

and uses it to scan our target. The main advantage here is that the scan doesn't need to tunnel home to the attacker's machine through the VPN - therefore, the scan results will come in faster. 

I think this is a smart trick to keep in mind for cases where we already  have a pivoting point into a network!



## Cleaning up text files

`grep` can be a big help when cleaning up text files. In order to remove the clutter from a configurations file, Ippsec uses the following command to remove all the lines containing a comment : `cat squid.conf | grep -v ^\#` and an additional `grep .` to display only the lines that have content. 



## No directory listing in TFTP

As 0xdf mentions in his write-up, TFTP doesn't have a command to do directory listings - instead, we need to deduce existing files by observing error messages (or the lack of them).



## UDP reverse shells

In order to get a shell as the user *werkzeug*, we cannot use TCP due to restrictions in the firewall  - TIL that UDP reverse shells are a thing. A quick look into the iptables rules on this box shows that only UDP connections are allowed to pass through. 

Definitely a good thing to remember, checking for available firewalls configurations...



### Resources

[0xdf's write-up HTB: Joker](https://0xdf.gitlab.io/2020/08/13/htb-joker.html), last visited : 2020-12-14.

[Ippsec's walkthrough](https://www.youtube.com/watch?v=5wyvpJa9LdU), last visited : 2020-12-14.

[Josiah Beverton's write-up](https://reboare.github.io/hackthebox/htb-joker.html), last visited : 2020-12-14.