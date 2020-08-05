---
layout: single
title: "Web series : Directory Traversal"
author_profile: true
categories:
  - web
classes:
tags:
  - web
  - directory traversal
  - file path traversal
---


# Directory Traversal

***N.b.:*** *This post is part of my series on web security, heavily inspired by [PortSwigger's Web Security Academy](https://portswigger.net/web-security){:target="_blank"}. They have amazing content and I don't want to simply replicate their work - my goal here is to provide a quick reference, mostly for myself, for those moments when I need to brush up on common web attacks really quick. Enjoy!*

### WHAT
__Directory traversal :__ access (read, write, or both) arbitrary files on a server


### WHY
Being able to read arbitrary files on an application server allows an attacker to potentially retrieve sensitive data. Maybe we're even able to write or modify files, which may allow us to compromise the server as a whole.


### HOW
* `../../../../some/file`
* use null byte if a specific extension is required, e.g. `some_file%00.png`
* Windows : `../` and `..\` are valid, can be combined
* encoding, e.g. `..%c0%af`, `..%252f`[1]
* nest traversal sequences, e.g. `....//`, `....\/`[1]


### Look out for :
* file inclusions, e.g. images
* filter bypasses
* allowed characters


### Resources
[1] [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal){:target="_blank"}, last visited : 2020-08-05.  

-------

# Lab notes for PortSwigger's Web Security Academy labs
## [File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple){:target="_blank"}
1. Open burp and access the lab.
2. Choose any product and right click on the image to view the image. Intercept that request.
3. Send the request to Repeater and change the `filename` parameter to `filename=../../../../../etc/passwd` and send. Notice the content of `/etc/passwd` in the server's response.
