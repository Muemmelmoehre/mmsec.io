---
layout: single
title: "Web series : IDOR"
author_profile: true
categories:
  - web
classes:
tags:
  - web
  - broken access control
  - access control
  - idor
---


# Insecure Direct Object References (IDOR)

***N.b.:*** *This post is part of my series on web security, heavily inspired by [PortSwigger's Web Security Academy](https://portswigger.net/web-security){:target="_blank"}. They have amazing content and I don't want to simply replicate their work - my goal here is to provide a quick reference, mostly for myself, for those moments when I need to brush up on common web attacks really quick. Enjoy!*

### WHAT
__Insecure direct object references (IDOR) :__ [access control vulnerability](https://mmsec.io/web/web-series-broken-access-control/){:target="_blank"}, user-controlled input is used to directly access an object; mostly for horizontal privilege escalation


### WHY
Depending on what they can access, an attacker can abuse IDORs to fully control another user's account and its data or maybe even escalate their privileges.


### HOW
Abuse user-controlled parameters or naming conventions for static files.


### Look out for :
* user-controlled parameters
* static files with sensible data
* incremental or easy to guess file names, paths, parameter values etc.


### Resources
[1] [https://portswigger.net/web-security/access-control/idor](https://portswigger.net/web-security/access-control/idor){:target="_blank"}, last visited : 2020-08-05.  


-------

# Lab notes for PortSwigger's Web Security Academy labs
## [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references){:target="_blank"}
1. Open burp and access the lab (intercept off). Start a live chat.
2. Click on View transcript and intercept the request. Send it to Repeater.
3. Change the file path to `1.txt` and resend. Retrieve `carlos`' cleartext password from the answer. Log in as `carlos`.
