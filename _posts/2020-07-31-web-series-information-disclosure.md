---
layout: single
title: "Web series : Information Disclosure"
author_profile: true
categories:
  - portswigger web academy
  - web
classes: wide
tags:
  - web
---

# Information Disclosure

***N.b.:*** *This post is part of my series on web security, heavily inspired by [PortSwigger's Web Security Academy](https://portswigger.net/web-security){:target="_blank"}. They have amazing content and I don't want to simply replicate their work - my goal here is to provide a quick reference, mostly for myself, for those moments when I need to brush up on common web attacks really quick. Enjoy!*

### WHAT
Any leaking information that is useful to an attacker. Information disclosure mostly helps in preparing attacks, but is sometimes a vulnerability in itself, depending on the nature of the leaked data.

### WHY
Technical details help narrow down the vast number of exploits out there to possibly fruitful attacks. Sometimes, sensitive data is disclosed directly.

### HOW
* __Fuzzing__ interesting parameters : automation!
* __Technical details__ : e.g. stack traces included in error messages


### Look out for :
Common places for information disclosure :
* files for web crawlers : `robots.txt`, `sitemap.xml`
* directory listings : problematic if combined with bad access control
* developer comments
* error messages
* debugging data : hardcoded credentials, host names, keys, file names etc.
* user account pages
* backup files : e.g. source code, copies of text files being edited (`.swp`, `~`)
* insecure configurations
* version control history




### Resources
[1] [https://portswigger.net/web-security/information-disclosure](https://portswigger.net/web-security/information-disclosure){:target="_blank"}, last visited : 2020-07-31.  
[2] [https://portswigger.net/web-security/information-disclosure/exploiting](https://portswigger.net/web-security/information-disclosure/exploiting){:target="_blank"}, last visited : 2020-07-31.

-------

# Lab notes for PortSwigger's Web Security Academy labs
## [Information disclosure in error messages](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages){:target="_blank"}
1. Open burp band any product page. Intercept the request.
2. Modify the `GET`request so that the `productId`parameter no longer is an integer, but e.g. a string.
3. Send the request and observe the verbose error message with the version at the end.


## [Information disclosure on debug page](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page){:target="_blank"}
1. Open burp and the home page.
2. In Target, notice `cgi-bin/phpinfo.php.
3. Send the request to Repeater and send.
4. Retrieve the `SECRET_KEY` from the server's answer.  


## [Source code disclosure via backup files](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files){:target="_blank"}
1. Navigate to `robots.txt` and discover `/backup`.
2. Navigate to `/backup/` and discover `ProductTemplate.java.bak`.
3. Retrieve the hardcoded credentials.

## [Authentication bypass via information disclosure](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass){:target="_blank"}
1. Open burp and log in as `wiener`.
2. Reload the home page and intercept the request. Send the request to Repeater.
3. Change the request to `GET /admin`. Observe the hint that the admin panel is only accessible for administrators or on localhost.
4. Change the request for `TRACE /admin`. Notice the new header `X-Custom-IP-Authorization: IP_here`.
5. Go to the "Match and replace" section in the proxy options and add the new header `X-Custom-IP-Authorization: 127.0.0.1` to every subsequent request (leave condition blank).
6. Replay `GET /admin` with the new header and delete `Carlos`.
