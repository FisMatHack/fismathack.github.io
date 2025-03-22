---
layout: post
title: Alert - WriteUp
---

Next you can update your site name, avatar and other options using the _config.yml file in the root of your repository (shown below).

![_config.yml]({{ site.baseurl }}/images/config.png)



Starting with the Nmap scan:


```
sudo nmap --min-rate 5000 -sS -n -vvv -Pn <IP-VICTIM> -oN scan_ports_tcp
```
