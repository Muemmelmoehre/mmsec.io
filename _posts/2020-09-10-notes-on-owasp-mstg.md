---
layout: single 
title: "Notes on the OWASP Mobile Application Security Testing Guide"
author_profile: true
categories: 
	- mobile
classes:
tags:
	- mobile
	- testing
	- excerpt
---

![image_name_here](/path/to/image.jpg)

# Notes on the OWASP Mobile Security Testing Guide
[OWASP Mobile Security Testing Guide v1.2, May 2020]{https://mobile-security.gitbook.io/mobile-security-testing-guide/}{:target="_blank"}, last visited : 2020-09-08.

## General
IPC = inter-process communication

key areas :
	* local data storage
	* communication with trusted endpoints : network-based attacks
	* authentication / authorization : mostly handled server-side
	* interaction with mobile platform
	* code quality / exploit mitigation
	* anti-tampering / anti-reversing

*native* app :
	* built for that specific platform
	* e.g. Objective-C / Swift for iOS, Java / Kotlin for Android
	* complete device integration / access to components
vs. 
*web* app :
	* multi-platform
	* website in HTML5
	* runs on top of device's browser
	* limited device integration --> sandboxed in browser
vs. 
*hybrid* app :
	* native app that outsources most of its processes to web app
	* e.g. Apache Cordova, Framework7, Ionic, hQuery Mobile, Google Flutter, Native Script, Onsen UI, React Native, Sencha Touch

Progressive Web App (PWA) [2] : web app that works offline, can be installed on device, has limited device integration; runs inside browser, but downloads all its content into browser cache [3]

*static* analysis :
	* manual code review : search for key words (e.g. `executeStatement`, `executeQuery`)
	* automated source code analysis (bets practices ruleset)
vs
*dynamic* analysis
	* usually against mobile platform and backend services
	* automated scanning tools (careful for mobile apps : vulnerabilities that are exploitable in a web browser don't necessarily work for a mobile app! e.g. CSRF --> based on shared cookies; any link would be opened in browser, not app --> has a different cookie store!, XSS)
	* clipboard : accessible system-wide, for any app

setup testing environment, ask for release (prod version) + debug (with some security features disabled, e.g. certificat pinning, root detection) version of app

Pentest :
	* *preparation* : orga, identifying sensitive data
	* *intelligence gathering* : environment (industry, organisation's goals for app, workflows + processes), architecture (app, OS, network, remote services)
	* *mapping the application* : entry points, features, data
	* *exploitation* : confirm findings : damage potential, reproducibility, exploitability, affected users, discoverability
	* *reporting*

CI/CD = Continuous Integration / Continuous Delivery

mobile apps usually use HTTP protocol as transport layer


### Authentication & authorization
baseline : username / password authentication + password policy, brute-force protection; 2FA, recent activity shown to user upon login, step-up authenticatin on sensible actions depending on data sensitivity

*stateful* authentication : 
	* opaque, unique session id (contains no user data) generated upon login
	* reference to user data on server for subsequent requests, authentication recored on client + server
	* usually implemented as random session ID stored in client-side cookie in web apps
	* procedure :
		1. app sends request with user creds to server
		2. server verifies creds + creates new session with random session ID if valid
		3. server sends response to client with session ID
		4. client sends session ID with all following requests, server validates ID + retrieves associated session record
		5. upon logout, server destroys session record + client discards session ID
vs.
*stateless* authentication : 
	* client-side token, often produced by authorization server (handles token generation, signature + encryption [optional])
	* contains all user-identifying information
	* no need to maintain session state on application server
	* common for mobile apps (improves scalability [no session on server], decouple authentication from app)

passive contextual authentication : geolocation, IP address, time of day, used device compared to previous user behaviour

#### Verifying that appropriate authentication is in place
	1. identify all authentication factors in use
	2. locate all endpoints with critical functionality
	3. verify that all (additional) factors are enforced on server-side endpoints

*authentication bypass* = authentication state is not consistently enforced on server, client can tamper with state
tamper protection : 
	* session-based authentication with session data on server only
	or
	* cryptographically signed client-side tokens (e.g. JSON Web Token [JWT])


#### Testing best practices for passwords
	1. password policy? --> [4] verify all password-related functions
	2. helper mechanism to evaluate password robustness, e.g. with zxcvbn [5], haveibeenpwned [6], in place?
	3. login throttling? server-side, tied to account, not session --> [7]
	4. dictionary + brute-force attack login (e.g. Burp Intruder) !!nb : do this at the very end of the pentest to avoid lock out!!

#### Testing stateful session management
	1. locate all endpoints with critical functionality
	2. verify consistent authorization enforcement : backend must verify client's session ID token + authorization each time; server must reject request if session ID token is invalid or missing!
	3. verify :
		* session IDs randomly generated on server
		* IDs with proper length + entropy (can't be guessed easily)
		* IDs exchanged over secure connections (e.g. HTTPS)
		* app doesn't store ID in permanent storage
		* session terminated on server + session information deleted within app after log out or session time out

authentication frameworks : e.g. spring (java), struts (java), laravel (php), ruby on rails

#### Testing session time out
	1. with intercept on, log into app and access a resource that requires authentication
	2. replay request after 5-min delays to find out session time-out
--> can be automated with burp extension Session Timeout Test [8]

#### Testing user logout
	1. with intercept on, log into app and access a resource that requires authentication
	2. log out
	3. replay request : should display error message or redirect to login; if resource still accessible : session ID still valid / hasn't been terminated on server

#### Testing 2FA and step-up authentication







## Android


## iOS


### Resources
[1] [OWASP Mobile Security Testing Guide v1.2, May 2020]{https://mobile-security.gitbook.io/mobile-security-testing-guide/}{:target="_blank"}, last visited : 2020-09-08.
[2] [Flirtman, Maximiliano : Progressive Web Apps on iOS are here, March 2018.]{https://medium.com/@firt/progressive-web-apps-on-ios-are-here-d00430dee3a7}{:target="_blank"}, last visited : 2020-09-08.
[3] [Wolhuter, Samantha : The Differences Between Web, Native, Progressive Web and Hybrid Apps, June 2020.]{https://www.wearebrain.com/blog/software-development/web-native-progressive-web-and-hybrid-apps/}{:target="_blank"}, last visited : 2020-09-08.
[4] [OWASP Authentication Cheat Sheet]{https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls}{:target="_blank"}, last visited : 2020-09-10.}
[5] [Dropbox' zxcvbn]{https://github.com/dropbox/zxcvbn}{:target="_blank"}, last visited : 2020-09-10.}
[6] [Troy Hunt's have i been pwned]{https://haveibeenpwned.com/}{:target="_blank"}, last visited : 2020-09-10.}
[7] [OWASP Blocking Brute Force Attacks]{https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks}{:target="_blank"}, last visited : 2020-09-10.}
[8] [Session Timeout Test]{https://portswigger.net/bappstore/c4bfd29882974712a1d69c6d8f05874e}{:target="_blank"}, last visited : 2020-09-10.}

