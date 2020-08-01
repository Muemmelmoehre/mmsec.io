---
layout: single
title: "Web series : Authentication"
author_profile: true
categories:
  - web
classes:
tags:
  - web
  - authentication
---


# Authentication

***N.b.:*** *This post is part of my series on web security, heavily inspired by [PortSwigger's Web Security Academy](https://portswigger.net/web-security){:target="_blank"}. They have amazing content and I don't want to simply replicate their work - my goal here is to provide a quick reference, mostly for myself, for those moments when I need to brush up on common web attacks really quick. Enjoy!*

### WHAT
__Authentication__ : validating that a user is indeed who they claim to be; verified by :  
* knowledge factor : something they know
* possession factor : something they have
* inherence factor : something they are or do

Authentication doesn't manage the user's privileges, it only establishes their verified identity!

### WHY
An attacker that has managed to bypass or break an application's authentication can have full control over a user account and its data, the whole application and potentially the application server, depending on the compromised account. The compromised application may serve us as pivoting point into the internal network and becomes therefore our stepping stone for subsequent attacks.

### HOW
* __Broken authentication :__ don't play their game, find a way around the validations and bypass their authentication mechanisms
* __Brute-force :__ try all possible combinations and look for differing answers


### Look out for :
* login data that is sent over unencrypted connections
* weak password policy
* ways to enumerate existing users, e.g. different error messages, password reset
* no brute-force protection or protections that can be bypassed easily (no CAPTCHA, no lock-out, IP-based lockouts etc.)
* password reset mechanism as robust as login?
* seemingly "M"FA that verifies the same factor twice : e.g. verification codes via email





### Resources
[1] [https://portswigger.net/web-security/authentication](https://portswigger.net/web-security/authentication){:target="_blank"}, last visited : 2020-08-01.  
[2] [https://portswigger.net/web-security/authentication/securing](https://portswigger.net/web-security/authentication/securing){:target="_blank"}, last visited : 2020-08-01.

-------

# Lab notes for PortSwigger's Web Security Academy labs
## [User name enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses){:target="_blank"}
1. Open burp and navigate to the login page.
2. Send some dummy login information and intercept the request.
3. Send the `POST` to Intruder, mark the user name and password in `§` and set the attack mode to Sniper.
4. Paste the given list of user names as payload. Start the attack.
5. Notice that one user name gives a different response length (and response). That's our valid user name!
6. Set that user name and repeat the same procedure for the password.
7. Notice that one password returns a `302` status code. Success!

## [2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass){:target="_blank"}
1. Log in as `wiener` and retrieve your code from the Email client.
2. Go to `My Account`and copy the url `/my-account?id=wiener`.
3. Log out and log in again as `carlos`.
4. When prompted for the code, go to `/my-account?id=carlos` instead. Success!

## [Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic){:target="_blank"}
1. Open burp and log in as `wiener`. Open the Email client.
2. Log out and request a password reset for `wiener`. Click on the reset link.
3. Set a new password (or the same) and intercept the request.
4. In the intercepted request, change the user name to `carlos`. Forward the request.
5. Log in as `carlos`.
