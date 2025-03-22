---
layout: post
title: Alert - WriteUp
---

Next you can update your site name, avatar and other options using the _config.yml file in the root of your repository (shown below).

![_config.yml]({{ site.baseurl }}/images/config.png)



Starting with the Nmap scan:


```shell
sudo nmap --min-rate 5000 -sS -n -vvv -Pn <IP-VICTIM> -oN scan_ports_tcp
```

This reports me ports 22 (SSH) and 80 (HTTP) open. Then, I add the IP address to point to alert.htb
in the /etc/hosts file.


